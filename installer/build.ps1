#Recreate output dir
Remove-Item adldap.msi
Remove-Item -Recurse -Force output
mkdir output

#Create a tmpdir
$tmp_dir = [io.path]::GetTempFileName()
Remove-Item $tmp_dir
mkdir $tmp_dir

#Copy excluding .git and installer
robocopy ..\ $tmp_dir /COPYALL /S /NFL /NDL /NS /NC /NJH /NJS /XD .git installer

#Generate the installer
$wix_dir="c:\Program Files (x86)\WiX Toolset v3.8\bin"

Remove-Item directory.wxs
. "$wix_dir\heat.exe" dir $tmp_dir -srd -dr INSTALLDIR -cg MainComponentGroup -out directory.wxs -ke -sfrag -gg -var var.SourceDir -sreg -scom
. "$wix_dir\candle.exe" -dSourceDir="$tmp_dir" installer.wxs WixUI.wxs DirDialog.wxs directory.wxs -o output\
. "$wix_dir\light.exe" -o output\adldap.msi output\installer.wixobj output\directory.wixobj output\DirDialog.wixobj output\WixUI.wixobj -cultures:en-US -ext WixUIExtension.dll

#Remove the temp
Remove-Item -Recurse -Force $tmp_dir