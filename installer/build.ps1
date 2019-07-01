$ErrorActionPreference = "Stop"
# $PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

$ProjectPath = [System.IO.Path]::GetFullPath("$PSScriptRoot\..\") -replace "\\$"
$ProjectPathUnix = $ProjectPath.replace("\", "/")
$InstallerPath = "$ProjectPath\Installer"

echo "installer path is $InstallerPath"

# remember to manually remove this after npm install... it fails because the path is too long.
# rimraf "..\node_modules\jsonwebtoken\node_modules\jws\node_modules\base64url\node_modules\tap"

#Clean
@(
    'output'
    'adldap.msi'
    'directory.wxs'
) |
Where-Object { Test-Path $_ } |
ForEach-Object { rimraf $_ }

#create output dir
mkdir output | Out-Null

#Create a tmpdir
$tmp_dir = [io.path]::GetTempFileName()
Remove-Item $tmp_dir
mkdir $tmp_dir | Out-Null

rimraf $ProjectPath\node_modules\edge\test
rimraf $ProjectPath\node_modules\leveldown\build\Release\obj
rimraf $ProjectPath\node_modules\leveldown\deps
rimraf $ProjectPath\node_modules\leveldown\build\Release\leveldb.lib

npm --no-color prune --production

#Copy excluding .git and installer
robocopy $ProjectPath\ $tmp_dir /COPYALL /S /NFL /NDL /NS /NC /NJH /NJS /XD .git installer

If (Test-Path $tmp_dir\bin){
    rimraf $tmp_dir\bin
}

If (Test-Path $tmp_dir\config.json){
    rimraf $tmp_dir\config.json
}

If (Test-Path $tmp_dir\logs.log){
    rimraf $tmp_dir\logs.log
}

rimraf $tmp_dir\config.json.enc

$version = (. "node" -e "console.log(require('$ProjectPathUnix/package.json').version);") | Out-String

$version = $version.Trim()

$nodeBin = (gcm node).Path

#Generate the installer
$wix_dir="c:\Program Files (x86)\WiX Toolset v3.11\bin"

. "$wix_dir\heat.exe" dir $tmp_dir -srd -dr INSTALLDIR -cg MainComponentGroup -out $InstallerPath\directory.wxs -ke -sfrag -gg -var var.SourceDir -sreg -scom
. "$wix_dir\candle.exe" -dNodeBin="$nodeBin" -dSourceDir="$tmp_dir" -dProductVersion="$version" -dRTMProductVersion="0.0.0" -dUpgradeCode="{1072AB9E-1842-4AFA-9CF2-545462CD60E2}" $InstallerPath\*.wxs -o $InstallerPath\output\ -ext WiXUtilExtension
. "$wix_dir\light.exe" -o $InstallerPath\output\adldap.msi $InstallerPath\output\*.wixobj -cultures:en-US -ext WixUIExtension.dll -ext WiXUtilExtension -ext WiXNetFxExtension
# . "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Bin\signtool.exe" sign /n "Auth0" $InstallerPath\output\adldap.msi

#Remove the temp
echo "removing temp folder"
rimraf $tmp_dir
echo "temp folder removed"
