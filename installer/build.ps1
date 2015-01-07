$ErrorActionPreference = "Stop"
# $PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

$ProjectPath = [System.IO.Path]::GetFullPath("$PSScriptRoot\..\") -replace "\\$"
$ProjectPathUnix = $ProjectPath.replace("\", "/")
$InstallerPath = "$ProjectPath\Installer"

echo "installer path is $InstallerPath"

# remember to manually remove this after npm install... it fails because the path is too long.
# Remove-Item -Recurse -Force "..\node_modules\jsonwebtoken\node_modules\jws\node_modules\base64url\node_modules\tap"

#Clean
@(
    'output'
    'adldap.msi'
    'directory.wxs'
) |
Where-Object { Test-Path $_ } |
ForEach-Object { Remove-Item $_ -Recurse -Force -ErrorAction Stop }

#create output dir
mkdir output

#Create a tmpdir
$tmp_dir = [io.path]::GetTempFileName()
Remove-Item $tmp_dir
mkdir $tmp_dir

#Copy excluding .git and installer
robocopy $ProjectPath\ $tmp_dir /COPYALL /S /NFL /NDL /NS /NC /NJH /NJS /XD .git installer bin

Copy-Item "C:\Program Files (x86)\nodejs\node.exe" $tmp_dir\bin

If (Test-Path $tmp_dir\config.json){
    Remove-Item $tmp_dir\config.json
}
If (Test-Path $tmp_dir\logs.log){
    Remove-Item $tmp_dir\logs.log
}

$version = (. "node" -e "console.log(require('$ProjectPathUnix/package.json').version);") | Out-String

$version = $version.Trim()

#Generate the installer
$wix_dir="c:\Program Files (x86)\WiX Toolset v3.8\bin"

. "$wix_dir\heat.exe" dir $tmp_dir -srd -dr INSTALLDIR -cg MainComponentGroup -out $InstallerPath\directory.wxs -ke -sfrag -gg -var var.SourceDir -sreg -scom
. "$wix_dir\candle.exe" -dSourceDir="$tmp_dir" -dProductVersion="$version" -dRTMProductVersion="0.0.0" -dUpgradeCode="{1072AB9E-1842-4AFA-9CF2-545462CD60E2}" $InstallerPath\*.wxs -o $InstallerPath\output\ -ext WiXUtilExtension
. "$wix_dir\light.exe" -o $InstallerPath\output\adldap.msi $InstallerPath\output\*.wixobj -cultures:en-US -ext WixUIExtension.dll -ext WiXUtilExtension -ext WiXNetFxExtension
. "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Bin\signtool.exe" sign /n "Auth0" $InstallerPath\output\adldap.msi

#Remove the temp
Remove-Item -Recurse -Force $tmp_dir
