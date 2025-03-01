from streamflow.ext.plugin import StreamFlowPlugin

from streamflow.plugins.unito.twofa.connector import TotpSSHConnector


class TwoFAStreamFlowPlugin(StreamFlowPlugin):
    def register(self) -> None:
        self.register_connector("unito.twofa.totp-ssh", TotpSSHConnector)
