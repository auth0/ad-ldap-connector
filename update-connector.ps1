$updateLogsPath = [io.path]::combine($env:TEMP, 'adldap-update.log')
If (Test-Path $updateLogsPath){
	Remove-Item $updateLogsPath
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# Function: Log informational message.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function Log([string]$msg)
{
  $now = [datetime]::Now.ToString("HH:mm:ss")
  Write-Host " ", $now, " - ", $msg
  Add-Content $updateLogsPath "$now - DEBUG: $msg`n"
} 

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# Function: Log error message.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function LogError([string]$msg)
{
  $now = [datetime]::Now.ToString("HH:mm:ss")
  Write-Host -Fore Red " ", $now, " - ", $msg
  Add-Content $updateLogsPath "$now - ERROR: $msg`n"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# Function: Log success message.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function LogSuccess([string]$msg)
{
  $now = [datetime]::Now.ToString("HH:mm:ss")
  Write-Host -Fore Green " ", $now, " - ", $msg
  Add-Content $updateLogsPath "$now - INFO: $msg`n"
}

Write-Host ""
Write-Host "  Updating AD LDAP Connector"
Write-Host ""

# Find the current directory.
$serviceDirectory = $null
$service = gwmi win32_service | ?{ $_.name -eq "Auth0 ADLDAP" }
If ($service -eq $null) {
  Log "Auth0 ADLDAP Service not found. Using default installation path."
} Else {
  $servicePath = $service.PathName 
  $serviceDirectory = (Get-Item $servicePath).Directory
  Log "Current install location: $serviceDirectory"
}

# Get current version.
$currentVersion = $null
$packageLocation = [io.path]::combine($serviceDirectory, 'package.json')
If (Test-Path $packageLocation){
  $package = Get-Content -Raw -Path $packageLocation | ConvertFrom-Json
  $currentVersion = $package.version
  Log "Current version: $currentVersion"
} Else {
  Log "Unable to find package.json file. Assuming update is required."
}

# Get latest version.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12  # TLS 1.0 and 1.1 are no longer supported
$latest = Invoke-RestMethod -Uri "https://github.com/auth0/ad-ldap-connector/releases/download/latest/version.txt" -Method Get;
$latestVersion = $latest.Trim()
$latestUrl =  "https://github.com/auth0/ad-ldap-connector/releases/download/latest/adldap-v$latestVersion.txt"
Log "Latest version: $latestVersion"

# Update not required?
If ($currentVersion -eq $latestVersion) {
  LogSuccess "The connector is already up to date. (Installation-Stop)"
  Write-Host ""
  Break
}

# Update required
Log "Updating to $latestVersion"
Log "Installer url: $latestUrl"

# Backup configuration.
$backupLocation = $null
if ($serviceDirectory -ne $null) {
  Write-Host ""
    
  $backupLocation = [io.path]::combine($serviceDirectory, 'backups', $(Get-Date -f yyyyMMdd-HHmmss))
  Log "Backing up configuration to: $backupLocation"
    
  Try
  {
    New-Item -ItemType Directory -Force -Path $backupLocation | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path -Path $backupLocation -ChildPath 'lib') | Out-Null
      
    Copy-Item -Recurse -Filter *.* -Path (Join-Path -Path $serviceDirectory -ChildPath 'certs') -Destination $backupLocation
    Copy-Item -Path (Join-Path -Path $serviceDirectory -ChildPath 'config.json') -Destination (Join-Path -Path $backupLocation -ChildPath 'config.json')
    Copy-Item -Path (Join-Path -Path $serviceDirectory -ChildPath 'lib\\profileMapper.js') -Destination (Join-Path -Path $backupLocation -ChildPath 'lib\\profileMapper.js')

    LogSuccess "Backup complete"
  }
  Catch
  {
      $ErrorMessage = $_.Exception.Message
      LogError "Error creating backup. $ErrorMessage"
      Write-Host ""
      Break
  }
}

# Uninstall the AD Connector.
Try
{
  Write-Host ""
  
  Log "Uninstalling the AD Connector"
  $app = Get-WmiObject -Class Win32_Product | Where-Object { 
      $_.Name -match "Auth0 AD LDAP Connector" 
  }
  
  if ($app -eq $null) {
  	Log "AD Connector is not installed."
  }
  else {
    $app.Uninstall()
    LogSuccess "AD Connector has been uninstalled."
  }
}
Catch
{
    $ErrorMessage = $_.Exception.Message
    LogError "Error uninstalling the AD Connector. $ErrorMessage"
    Write-Host ""
    Break
}

# Install update.
Try
{
  Write-Host ""
    
  # Download.
  $downloadPath = [io.path]::combine($env:TEMP, 'adldap-' + $(Get-Date -f yyyyMMdd-HHmmss) + '.msi')
  Log "Downloading installer to: $downloadPath"
    
  $wc = New-Object System.Net.WebClient
  $wc.DownloadFile($latestUrl, $downloadPath)
  LogSuccess "Download complete, installing..."
  
   
  # Install.   
  $logsPath = [io.path]::combine($env:TEMP, 'adldap-installation.log')
  $msiArgs = @()
  $msiArgs += "/i "
  $msiArgs += "`"$downloadPath`" "
  $msiArgs += "/l "
  $msiArgs += "`"$logsPath`" "
  $msiArgs += "/qn "
  $msiArgs += "RebootYesNo=`"No`" "
  $msiArgs += "REBOOT=`"Suppress`" "
  $msiArgs += "/quiet "
  if ($serviceDirectory -ne $null) {
    Log "Installing to: $serviceDirectory"
    $msiArgs += "INSTALLDIR=`"$serviceDirectory`" "
  }
  
  Start-Process "msiexec.exe" -ArgumentList $msiArgs -Wait
  Log "Installation done. Logs are available here: $logsPath"
  
  # Verify installation.
  $app = Get-WmiObject -Class Win32_Product | Where-Object { 
      $_.Name -match "Auth0 AD LDAP Connector" 
  }
  if ($app -eq $null) {
  	LogError "AD Connector was not installed correctly."
  }
  else {
    LogSuccess "AD Connector was successfully installed."
  }
  
  # Restore backup.
  if ($backupLocation -ne $null) {
    Log "Restoring settings from $backupLocation"
    Copy-Item -Recurse -Filter *.* -Path "$backupLocation\*" -Destination $serviceLocation -Force
    LogSuccess "Restore complete."
  }
  
  # Start service if we find a provisioning ticket.
  $configLocation = [io.path]::combine($serviceDirectory, 'config.json')
  If (Test-Path $configLocation){
    $config = Get-Content -Raw -Path $configLocation | ConvertFrom-Json
    $provisioningTicket = $config.PROVISIONING_TICKET
    if ($provisioningTicket -ne $null -And $provisioningTicket -ne '') {
      Write-Host ""
      Log "Found provisioning ticket. Ensuring the service is started."
        
      $connectorService = Get-Service "Auth0 ADLDAP"
      if ($connectorService -eq $null) {
        LogError "Unable to find the Auth0 ADLDAP service."
      } else {
        $status = $connectorService.Status
        Log "Auth0 ADLDAP service status: $status"
          
        if ($status -eq "Stopped") {
          Log "Starting service..."
          Start-Service "Auth0 ADLDAP"
          $connectorService = Get-Service "Auth0 ADLDAP"
          $connectorService.WaitForStatus('Running','00:00:30')
              
          $status = $connectorService.Status
          if ($status -eq "Running") { 
            LogSuccess "The service is running."
          }
          else {
            LogError "The service is not running: $status"
          }
        }
      }
    }
  }
}
Catch
{
    $ErrorMessage = $_.Exception.Message
    LogError "Error installing the AD Connector. $ErrorMessage"
    Write-Host ""
    Break
}
