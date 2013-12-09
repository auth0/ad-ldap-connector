$ErrorActionPreference = "Stop"

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
robocopy ..\ $tmp_dir /COPYALL /S /NFL /NDL /NS /NC /NJH /NJS /XD .git installer
Copy-Item "C:\Program Files (x86)\nodejs\node.exe" $tmp_dir\bin

If (Test-Path $tmp_dir\config.json){
    Remove-Item $tmp_dir\config.json
}

$version = (. "node" -e "console.log(require('../package.json').version);") | Out-String

$version = $version.Trim()

#Generate the installer
$wix_dir="c:\Program Files (x86)\WiX Toolset v3.8\bin"

. "$wix_dir\heat.exe" dir $tmp_dir -srd -dr INSTALLDIR -cg MainComponentGroup -out directory.wxs -ke -sfrag -gg -var var.SourceDir -sreg -scom 
. "$wix_dir\candle.exe" -dSourceDir="$tmp_dir" -dVers="$version" *.wxs -o output\ -ext WiXUtilExtension
. "$wix_dir\light.exe" -o output\adldap.msi output\*.wixobj -cultures:en-US -ext WixUIExtension.dll -ext WiXUtilExtension
. "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Bin\signtool.exe" sign /n "Auth10" .\output\adldap.msi

#Remove the temp
Remove-Item -Recurse -Force $tmp_dir