$msiDependencies = @(
    @{'Name'='Python'; 'Url'="https://www.python.org/ftp/python/2.7.12/python-2.7.12.msi";'Path'='C:\Python27\'} ;
    @{'Name'='nodejs'; 'Url'="https://nodejs.org/dist/v4.4.7/node-v4.4.7-x86.msi"; 'Path' = 'C:\Program Files (x86)\nodejs'}
    )

$zipDependencies = @(
    @{'Name'='Wix'; 'Url'="https://wix.codeplex.com/downloads/get/1587180"; 'Path'= "C:\Program Files (x86)\WiX Toolset v3.8\bin"} ;
    @{'Name'='nssm'; 'Url'="http://nssm.cc/release/nssm-2.24.zip"; 'Path'= "C:\Program Files (x86)\"} 
    )

$npmPackages = @(
    @{'Name'='npm'; 'Version'="3.10.5"} ;
    @{'Name'='node-gyp'; 'Version'="3.4.0"} 
    )

function Get-TempPath
{
    [io.path]::GetTempPath()
}

function Get-TempFileName
{
    [io.path]::GetTempFileName()
}

function Expand-ZipFile
{
    param(
        [Parameter(Mandatory=$true)][String] $File,
        [Parameter(Mandatory=$true)][String] $Path
    )

    if (-not (Test-Path $Path) )
    {
        Write-Verbose "Creting Directory $Path"
        New-Item -Path $Path -ItemType directory -force | Out-Null
    }

    $shell = New-Object -com Shell.Application
    $zip = $shell.NameSpace($File)
    foreach($item in $zip.items())
    {
        $shell.Namespace($Path).copyhere($item)
    }
}

function InstallFrom-Url
{
    param(
        [Parameter(Mandatory=$true)][String] $Url,
        [Parameter(Mandatory=$false)][String] $Path= $null,
        [Parameter(Mandatory=$false)][String] $TempFile = (Get-TempFileName)
    )

    Write-Verbose "   ==>Downloading installer  $Url ==> $TempFile"
    Invoke-WebRequest -Uri $Url -OutFile $TempFile

    Write-Verbose "Starting msiexec process"
    $args = @("/i";$TempFile;"/qb")
    if ($Path -ne $null) 
    {
        $args = @("/i";$TempFile;"TARGETDIR=`"$Path`""; "INSTALLDIR=`"$Path`"", "/qb")
    }
    else
    {
        $args = @("/i";$TempFile;"/qb")
    }

    Start-Process -Wait -Verb runas -FilePath msiexec  -ArgumentList $args

    Write-Debug "Removing $TempFile"
    Remove-Item $TempFile
}

function UnpackFrom-Url
{
    param(
        [Parameter(Mandatory=$true)][String] $Url,
        [Parameter(Mandatory=$true)][String] $Path,
        [Parameter(Mandatory=$false)][String] $TempFile = (Get-TempFileName)
    )

    $TempFile = $TempFile + ".zip"

    Write-Verbose "   ==> Downloading Package  $Url ==> $TempFile"
    Invoke-WebRequest -Uri $Url -OutFile $TempFile

    Write-Verbose "Unpacking file into $Path"
    Expand-ZipFile -File $TempFile -Path $Path

    Write-Debug "Removing $TempFile"
    #Remove-Item $TempFile
}

function Install-NpmPackage
{
    param(
        [Parameter(Mandatory=$true)][String] $Name,
        [Parameter(Mandatory=$false)][String] $Version=$null,
        [Parameter(Mandatory=$false)][switch] $Global
    )

    if ($Version -ne $null)
    {
        $Name = $Name + "@" + $Version
    }

    Write-Verbose "Starting NPM install of package $Name"

    if ($global)
    {
        $args = @("install";$Name; "-g")
    }
    else
    {
        $args = @("install";$Name)
    }

    Start-Process -FilePath "npm" -ArgumentList $args -Wait -NoNewWindow
}

function Test-IsAdmin() 
{
    $windowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $windowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($windowsID)
    $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
 
    $windowsPrincipal.IsInRole($adminRole)
}

if (-not (Test-IsAdmin))
{
    $args = @('-ExecutionPolicy Bypass';'-File';$PSScriptRoot)

    try
    {    
        $process = Start-Process PowerShell.exe -PassThru -Verb Runas -Wait -WorkingDirectory $pwd -ArgumentList $argList
        exit $process.ExitCode
    }
    catch {}

    # Generic failure code
    exit 1 
}
else
{
    Write-Host "Installing Dependencies"

    $msiDependencies | ForEach-Object { 
            Write-Host "==> Installing $($_.Name)" ; 
            InstallFrom-Url -Url $_.Url -Path $_.Path
        }

    $zipDependencies | ForEach-Object { 
            Write-Host "==> Installing $($_.Name)" ; 
            UnpackFrom-Url -Url $_.Url -Path $_.Path
         }
    
    #reloads path to execute NPM
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

    Write-Host "Updating NPM packages"

    $npmPackages | ForEach-Object { 
            Write-Host "==> Installing $($_.Name) version $($_.Version)" ; 
            Install-NpmPackage -Name $_.Name -Version $_.Version -Global
        }

    Write-Host "Adding Python path to NPM"
    Start-Process -FilePath "npm" -ArgumentList @("config";"set";"python";"C:\Python27\python.exe") -Wait -NoNewWindow

}
