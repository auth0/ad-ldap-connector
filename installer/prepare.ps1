$exeDependencies = @(
    @{
        'Name'='git';
        'Url'='https://github.com/git-for-windows/git/releases/download/v2.9.2.windows.1/Git-2.9.2-32-bit.exe';
        'Args'=@('/silent';'/norestart');
        'Test'=@{
          'Cmd'='git';
          'Args'=@('--version')
        }
    } )

$msiDependencies = @(
    @{
        'Name'='Python';
        'Url'="https://www.python.org/ftp/python/2.7.12/python-2.7.12.msi";
        'Path'='C:\Python27\'
        'Test'=@{
          'Cmd'='C:\Python27\python.exe';
          'Args'=@('-V')
        }
    } ;
    @{
        'Name'='nodejs';
        'Url'="https://nodejs.org/dist/v12.19.0/node-v12.19.0-x86.msi";
        'Path' = 'C:\Program Files (x86)\nodejs'
        'Test'=@{
          'Cmd'='C:\Program Files (x86)\nodejs\node.exe';
          'Args'=@('-v')
        }
    } )

$zipDependencies = @(
    @{
        'Name'='Wix';
        'Url'="https://wix.codeplex.com/downloads/get/1587180";
        'Path'= "C:\Program Files (x86)\WiX Toolset v3.8\bin"
        'Test'=@{
          'Cmd'='C:\Program Files (x86)\WiX Toolset v3.8\bin\heat.exe';
          'Args'=@('-?')
        }
    } ;
    @{
        'Name'='nssm';
        'Url'="http://nssm.cc/release/nssm-2.24.zip";
        'Path'= "C:\Program Files (x86)\"
        'Test'=@{
          'Path'='C:\Program Files (x86)\nssm-2.24\win32\nssm.exe'
        }
    } )

$npmPackages = @(
    @{'Name'='npm'; 'Version'="6.14.8"} ;
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

function Test-Command
{
    param(
         [Parameter(Mandatory=$true)] $Command
    )

    try
    {
        $result = $true;
        if ($Command.Cmd -ne $null) 
        {
          if ($Command.Args -eq $null)
          {
              $Command.Args = @();
          }
        
          $process = Start-Process -Wait -PassThru -File $Command.Cmd -ArgumentList $Command.Args -NoNewWindow
          $result = $result -and ($process.exitCode -eq 0)
        }

        if ($Command.Path -ne $null)
        {
          $result = $result -and (Test-Path $Command.Path)
        }

        $result
    }
    catch
    {
        $false
    }
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

function InstallFrom-Exe
{
    param(
        [Parameter(Mandatory=$true)][String] $Url,
        [Parameter(Mandatory=$false)]$Args= @(),
        [Parameter(Mandatory=$false)][String] $TempFile = (Get-TempFileName) + '.exe'
    )

    Write-Verbose "   ==>Downloading executable  $Url ==> $TempFile"
    Invoke-WebRequest -Uri $Url -OutFile $TempFile

    Write-Verbose "Starting process"

    Start-Process -Wait -Verb runas -FilePath $TempFile  -ArgumentList $Args

    Write-Debug "Removing $TempFile"
    Remove-Item $TempFile
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

    $exeDependencies | ForEach-Object { 
            if (-not (Test-Command $_.Test))
            {
                Write-Host "==> Installing $($_.Name)" ;
                InstallFrom-Exe -Url $_.Url -Args $_.Args
            }
        }
    
    $msiDependencies | ForEach-Object { 
            if (-not (Test-Command $_.Test))
            {
                Write-Host "==> Installing $($_.Name)" ;
                InstallFrom-Url -Url $_.Url -Path $_.Path
            }
        }

    $zipDependencies | ForEach-Object { 
            if (-not (Test-Command $_.Test))
            {
                Write-Host "==> Installing $($_.Name)" ; 
                UnpackFrom-Url -Url $_.Url -Path $_.Path
            }
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
