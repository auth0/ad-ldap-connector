<#
This script installs the AD LDAP Connector services using NSSM. It sets up two services:
1. "Auth0 ADLDAP Admin" - This service runs the admin server for the connector, which provides the
    web interface for configuration and management.
2. "Auth0 ADLDAP" - This service runs the main connector server that handles authentication requests.
Both services are configured to run under their respective virtual service accounts for security.
#>

Set-Location $PSScriptRoot

function Remove-ExistingService {
    param (
        [string]$serviceName,
        [string]$nssmPath
    )

    # Skip if the service is not registered.
    if (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
        Write-Host "Service '$serviceName' not present, nothing to remove."
        return
    }

    Write-Host "Existing service '$serviceName' found, removing before install..."

    # Stop it first so removal is not blocked by a running instance. Both calls are
    # best-effort: a stopped or already-absent service should not abort the install.
    & $nssmPath stop "$serviceName" 2>$null | Out-Null
    & $nssmPath remove "$serviceName" confirm 2>$null | Out-Null

    # Fallback in case the service was registered by something other than nssm.
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        sc.exe stop "$serviceName" 2>$null | Out-Null
        sc.exe delete "$serviceName" 2>$null | Out-Null
    }

    # Windows marks a deleted service pending until all handles close; wait briefly so
    # the subsequent nssm install does not hit "service is marked for deletion".
    for ($i = 0; $i -lt 10; $i++) {
        if (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Milliseconds 500
    }

    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        Write-Host "Warning: service '$serviceName' still present after removal attempt."
    } else {
        Write-Host "Service '$serviceName' removed."
    }
}

function Set-AdminConsoleRestartPermissions {
    param (
        [string]$serviceName
    )

    # Get the SID of the admin service
    $adminServiceSid = (New-Object System.Security.Principal.NTAccount("NT SERVICE\Auth0 ADLDAP Admin")).Translate([System.Security.Principal.SecurityIdentifier]).Value

    # Get the current SDDL of the service
    $currentSddl = ((sc.exe sdshow $serviceName) | Where-Object { $_ -match '\(' }).Trim()

    # Create a new ACE for the admin service
    $newAce = "(A;;RPWP;;;$adminServiceSid)"

    # Insert before the SACL if present, otherwise append to the end of the DACL
    if ($currentSddl -match '(S:[A-Z]*)(\(.*)') {
        $newSddl = $currentSddl -replace '(S:[A-Z]*)(\(.*)', "$newAce`$1`$2"
    } else {
        $newSddl = $currentSddl + $newAce
    }

    # Set the new SDDL for the service
    sc.exe sdset $serviceName $newSddl
}

$InstallDirectory = Join-Path $PSScriptRoot ".." -Resolve

echo ""
echo "Ensure data directory exists..."
echo "-----------------------------------------------------------------------"
$dataDir = Join-Path $InstallDirectory "data"
if (-not (Test-Path -Path $dataDir)) {
    New-Item -Path $dataDir -ItemType Directory | Out-Null
    Write-Host "Created data directory at $dataDir"
} else {
    Write-Host "Data directory already exists at $dataDir"
}
echo "----- [Done] ----------------------------------------------------------"

echo ""
echo "Installing AD LDAP Connector Admin..."
echo "-----------------------------------------------------------------------"
$adminServiceName = "Auth0 ADLDAP Admin"
Remove-ExistingService -serviceName $adminServiceName -nssmPath "$InstallDirectory\nssm.exe"
& "$InstallDirectory\nssm.exe" install "$adminServiceName" "$InstallDirectory\node.exe"
& "$InstallDirectory\nssm.exe" set "$adminServiceName" AppParameters "server.js"
& "$InstallDirectory\nssm.exe" set "$adminServiceName" AppDirectory "$InstallDirectory\admin"
& "$InstallDirectory\nssm.exe" set "$adminServiceName" AppStdout "$InstallDirectory\data\logs\admin\admin-service.log"
& "$InstallDirectory\nssm.exe" set "$adminServiceName" AppStderr "$InstallDirectory\data\logs\admin\admin-service.log"
sc.exe config "$adminServiceName" obj= "NT SERVICE\$adminServiceName"
echo "----- [Done] ----------------------------------------------------------"

echo ""
echo "Installing AD LDAP Connector Service..."
echo "-----------------------------------------------------------------------"
$connectorServiceName = "Auth0 ADLDAP"
Remove-ExistingService -serviceName $connectorServiceName -nssmPath "$InstallDirectory\nssm.exe"
& "$InstallDirectory\nssm.exe" install "$connectorServiceName" "$InstallDirectory\node.exe"
& "$InstallDirectory\nssm.exe" set "$connectorServiceName" AppParameters "server.js"
& "$InstallDirectory\nssm.exe" set "$connectorServiceName" AppDirectory "$InstallDirectory"
sc.exe config "$connectorServiceName" obj= "NT SERVICE\$connectorServiceName"
Set-AdminConsoleRestartPermissions -serviceName $connectorServiceName
echo "----- [Done] ----------------------------------------------------------"

echo ""
echo "Installing Firewall Rule for Kerberos Proxy..."
echo "-----------------------------------------------------------------------"
./Add-KerberosFirewallRule.ps1
echo "----- [Done] ----------------------------------------------------------"

echo ""
echo "Migrating data from previous versions if they exist..."
echo "-----------------------------------------------------------------------"
& "$InstallDirectory\node.exe" "$InstallDirectory/setup/migrateData.js"
echo "----- [Done] ----------------------------------------------------------"

echo ""
echo "Limiting permissions on install directory..."
echo "-----------------------------------------------------------------------"
./Limit-FilePermissions.ps1
echo "----- [Done] ----------------------------------------------------------"

echo ""
echo ""
