param (
    [String] $ForceVersion
)

$ErrorActionPreference = "Stop"

$ProjectPath = [System.IO.Path]::GetFullPath("$PSScriptRoot\..\") -replace "\\$"
$ProjectPathUnix = $ProjectPath.replace("\", "/")
$InstallerPath = "$ProjectPath\installer"

$version = ((. "node" -e "console.log(require('$ProjectPathUnix/package.json').version);") | Out-String).Trim()
if ($ForceVersion) {
    $version = $ForceVersion
}
if ($version -eq "0.0.0") {
    throw "Invalid or default version in package.json: $version. If you are building this locally, update the version field in package.json temporarily to a valid version above 0.0.0"
}

# create output dir
rm -Recurse -Force output -ErrorAction Ignore
mkdir output | Out-Null

# Create a temp directory with files we pass to the installer, this is what will 
# eventually end up in the install location on the end user's machine. 
# We do this to exclude files we don't want in the installer and to make sure we have a clean directory to work with.
$tmpInstallSourcesDir = [io.path]::GetTempFileName()
rm $tmpInstallSourcesDir -ErrorAction Ignore
mkdir $tmpInstallSourcesDir | Out-Null

echo "Project path is $ProjectPath"
echo "Installer path is $InstallerPath"
echo "Temp install sources path is $tmpInstallSourcesDir"

npm --no-color prune --production

# Copy explicit allow list of files/dirs to include in the installer
$itemsToCopy = @(
    'admin',
    'mock-ldap',
    'lib',
    'node_modules',
    'public',
    'setup',
    'views',
    '.nvmrc',
    '.npmrc',
    'CENTOS.md',
    'CHANGELOG.md',
    'endpoints.js',
    'eventlog.js',
    'latency_test.js',
    'LICENSE.rtf',
    'LICENSE.txt',
    'package.json',
    'package-lock.json',
    'README.md',
    'server.js',
    'troubleshoot.cmd',
    'troubleshoot.js',
    'ws_validator.js'
)
foreach ($item in $itemsToCopy) {
    cp "$ProjectPath\$item" $tmpInstallSourcesDir -Recurse -Force
}
ls $tmpInstallSourcesDir

$nodeBin = (gcm node).Path
$nssmBin = "$InstallerPath\nssm.exe"

#Generate the installer
. "heat.exe" dir $tmpInstallSourcesDir -srd -dr INSTALLDIR -cg MainComponentGroup -out $InstallerPath\directory.wxs -ke -sfrag -gg -var var.SourceDir -sreg -scom
. "candle.exe" -dNodeBin="$nodeBin" -dNssmBin="$nssmBin" -dSourceDir="$tmpInstallSourcesDir" -dProductVersion="$version" -dRTMProductVersion="0.0.0" -dUpgradeCode="{1072AB9E-1842-4AFA-9CF2-545462CD60E2}" $InstallerPath\*.wxs -o $InstallerPath\output\ -ext WixUIExtension -ext WiXUtilExtension
. "light.exe" -o $InstallerPath\output\adldap.msi $InstallerPath\output\*.wixobj -cultures:en-US -ext WixUIExtension -ext WiXUtilExtension -ext WiXNetFxExtension

#Remove the temp
echo "removing temp folder"
rm -Recurse -Force $tmpInstallSourcesDir
echo "temp folder removed"
