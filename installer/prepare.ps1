$zipDependencies = @(
    @{
        'Name'='nssm';
        'Url'="http://nssm.cc/release/nssm-2.24.zip";
        'Path'= "C:\Program Files (x86)\"
        'Test'=@{
          'Path'='C:\Program Files (x86)\nssm-2.24\win32\nssm.exe'
        }
    } )

function Get-TempPath
{
    [io.path]::GetTempPath()
}

function Get-TempFileName
{
    [io.path]::GetTempFileName()
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
    Expand-Archive -Path $TempFile -DestinationPath $Path -Force
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
    $zipDependencies | ForEach-Object { 
        Write-Host "==> Installing $($_.Name)" ;
        UnpackFrom-Url -Url $_.Url -Path $_.Path
    }
    
    #reloads path to execute NPM
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

    Write-Host "Adding Python path to NPM"
    Start-Process -FilePath "npm" -ArgumentList @("config";"set";"python";"C:\Python27\python.exe") -Wait -NoNewWindow
}
