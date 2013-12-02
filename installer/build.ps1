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

#Generate the installer
$wix_dir="c:\Program Files (x86)\WiX Toolset v3.8\bin"

. "$wix_dir\heat.exe" dir $tmp_dir -srd -dr INSTALLDIR -cg MainComponentGroup -out directory.wxs -ke -sfrag -gg -var var.SourceDir -sreg -scom 
. "$wix_dir\candle.exe" -dSourceDir="$tmp_dir" *.wxs -o output\ -ext WiXUtilExtension
. "$wix_dir\light.exe" -o output\adldap.msi output\*.wixobj -cultures:en-US -ext WixUIExtension.dll -ext WiXUtilExtension
. ".\sign.ps1"

#Remove the temp
Remove-Item -Recurse -Force $tmp_dir