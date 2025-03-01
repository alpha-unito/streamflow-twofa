# Two-Factor Authentication Plugin for StreamFlow

## Installation
Simply install the package directory from [PyPI]() using [pip](https://pip.pypa.io/en/stable/). StreamFlow will automatically recognise it as a plugin and load it at each workflow execution.
```bash
pip install streamflow-twofa
```

If everything worked correctly, whenever a workflow execution starts, the following message should be printed in the log:
```bash
Successfully registered plugin streamflow.plugins.unito.twofa.plugin.TwoFAStreamFlowPlugin
```

## Usage
This plugin registers a new `Connector` component called `TotpSSHConnector`, which extends the StreamFlow `SSHConnector` class. The example below shows a possible `streamflow.yml` configuration file. The `totpSecretFile` option should contain the path to the TOTP generator's secret key.
```bash
deployments:
  facility:
    type: unito.twofa.totp-ssh
    config:
      nodes:
        - 10.0.0.1
      sshKey: /path/to/ssh/key
      username: <username>
      totpSecretFile: /path/to/secret
```