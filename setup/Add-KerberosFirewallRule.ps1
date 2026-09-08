<#
This script adds a firewall rule for the Auth0 Kerberos connector.
The rule allows inbound traffic to the KerberosProxy.exe, which is used by the connector
to handle Kerberos authentication.
#>

$InstallDirectory = Join-Path $PSScriptRoot ".." -Resolve

netsh advfirewall firewall show rule name="Auth0ConnectorKerberos"
if ($?) {
    echo "Rule exists!"
} else {
    $proxyPath = Join-Path $InstallDirectory "./node_modules/kerberos-server/kerberosproxy.net/KerberosProxy/bin/Debug/KerberosProxy.exe"
    netsh advfirewall firewall add rule name="Auth0ConnectorKerberos" dir=in action=allow program="$proxyPath" profile=domain,private enable=yes
    if ($?) {
        echo "Rule added!"
    } else {
        echo "Failed to add rule!"
        exit 1
    }
}
