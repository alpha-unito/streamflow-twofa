import asyncio
import time
from collections.abc import MutableMapping, MutableSequence
from importlib.resources import files
from typing import Any

import asyncssh
import pyotp
from streamflow.deployment.connector import SSHConnector
from streamflow.deployment.connector.ssh import (
    SSHConfig,
    SSHContext,
    get_param_from_file,
    parse_hostname,
)
from streamflow.log_handler import logger


class TOTPGenerator:
    def __init__(self, totp_secret_file: str, interval: int = 30):
        self.interval: int = interval
        self.totp_gen = pyotp.TOTP(
            get_param_from_file(totp_secret_file), interval=interval
        )
        self._last_totp_used: str | None = None

    async def next(self) -> str:
        while (totp := self.totp_gen.now()) == self._last_totp_used:
            await asyncio.sleep(self.interval - (int(time.time()) % self.interval))
        self._last_totp_used = totp
        return totp


class TotpSSHClient(asyncssh.SSHClient):
    def __init__(self, totp_generator: TOTPGenerator):
        super().__init__()
        self.totp_generator: TOTPGenerator = totp_generator

    async def kbdint_auth_requested(self):
        return ""

    async def kbdint_challenge_received(
        self, name: str, instructions: str, lang: str, prompts
    ):
        if len(prompts) > 1:
            logger.error(f"There are too many prompts: {prompts}")
            raise NotImplementedError
        elif prompts:
            return [await self.totp_generator.next()]
        else:
            return []


class TotpConfig(SSHConfig):
    def __init__(
        self,
        check_host_key: bool,
        client_keys: MutableSequence[str],
        connect_timeout: int,
        hostname: str,
        password_file: str | None,
        ssh_key_passphrase_file: str | None,
        totp_generator: TOTPGenerator,
        tunnel: SSHConfig | None,
        username: str,
    ):
        super().__init__(
            check_host_key=check_host_key,
            client_keys=client_keys,
            connect_timeout=connect_timeout,
            hostname=hostname,
            password_file=password_file,
            ssh_key_passphrase_file=ssh_key_passphrase_file,
            tunnel=tunnel,
            username=username,
        )
        self.totp_generator: TOTPGenerator = totp_generator


class TotpContext(SSHContext):
    def __init__(
        self,
        streamflow_config_dir: str,
        config: SSHConfig,
        max_concurrent_sessions: int,
    ):
        super().__init__(streamflow_config_dir, config, max_concurrent_sessions)

    async def _get_connection(
        self, config: TotpConfig | None
    ) -> asyncssh.SSHClientConnection | None:
        if config is None:
            return None
        (hostname, port) = parse_hostname(config.hostname)

        def get_client_factory():
            return TotpSSHClient(config.totp_generator)

        return await asyncssh.connect(
            client_keys=config.client_keys,
            compression_algs=None,
            encryption_algs=[
                "aes128-gcm@openssh.com",
                "aes256-ctr",
                "aes192-ctr",
                "aes128-ctr",
            ],
            known_hosts=() if config.check_host_key else None,
            host=hostname,
            passphrase=get_param_from_file(config.ssh_key_passphrase_file),
            password=get_param_from_file(config.password_file),
            port=port,
            tunnel=await self._get_connection(config.tunnel),
            username=config.username,
            client_factory=get_client_factory,
        )


class TotpSSHConnector(SSHConnector):
    def __init__(
        self,
        deployment_name: str,
        config_dir: str,
        nodes: MutableSequence[Any],
        totpSecretFile: str,
        username: str | None = None,
        checkHostKey: bool = True,
        dataTransferConnection: str | MutableMapping[str, Any] | None = None,
        file: str | None = None,
        maxConcurrentSessions: int = 10,
        maxConnections: int = 1,
        retries: int = 3,
        retryDelay: int = 5,
        passwordFile: str | None = None,
        services: MutableMapping[str, str] | None = None,
        sharedPaths: MutableSequence[str] | None = None,
        sshKey: str | None = None,
        sshKeyPassphraseFile: str | None = None,
        totpInterval: int = 30,
        tunnel: MutableMapping[str, Any] | None = None,
        transferBufferSize: int = 2**16,
    ):
        # totp_generator attribute must be defined before the parent init
        self.totp_generator = TOTPGenerator(totpSecretFile, totpInterval)
        super().__init__(
            deployment_name=deployment_name,
            config_dir=config_dir,
            nodes=nodes,
            username=username,
            checkHostKey=checkHostKey,
            dataTransferConnection=dataTransferConnection,
            file=file,
            maxConcurrentSessions=maxConcurrentSessions,
            maxConnections=maxConnections,
            retries=retries,
            retryDelay=retryDelay,
            passwordFile=passwordFile,
            services=services,
            sharedPaths=sharedPaths,
            sshKey=sshKey,
            sshKeyPassphraseFile=sshKeyPassphraseFile,
            tunnel=tunnel,
            transferBufferSize=transferBufferSize,
        )
        self._cls_context: type[SSHContext] = TotpContext

    @classmethod
    def get_schema(cls) -> str:
        return (
            files(__package__)
            .joinpath("schemas")
            .joinpath("totp_ssh.json")
            .read_text("utf-8")
        )

    def _get_config(self, node: str | MutableMapping[str, Any]) -> SSHConfig | None:
        if config := super()._get_config(node):
            config = TotpConfig(
                check_host_key=config.check_host_key,
                client_keys=config.client_keys,
                connect_timeout=config.connect_timeout,
                hostname=config.hostname,
                password_file=config.password_file,
                ssh_key_passphrase_file=config.ssh_key_passphrase_file,
                totp_generator=self.totp_generator,
                tunnel=config.tunnel,
                username=config.username,
            )
        return config
