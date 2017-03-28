This directory contains the scripts to generate an MSI installer.

## Pre-requisites

1.  Visual Studio 2013. Current build pipeline does not work with 2015.
2.  Node 4.4.x for Windows. Check you have node.exe in `C:\Program Files (x86)\nodejs\node.exe`.
3.  Update NPM to version 3.10.5
4.  [Wix](https://wix.codeplex.com/releases/) Binaries. Check you have the bin in `c:\Program Files (x86)\WiX Toolset v3.8\bin`
5.  Your [node-gyp](https://github.com/TooTallNate/node-gyp/#installation) should be able to build native dependencies. Use version 3.4.0
6.  Download [nssm](http://nssm.cc/release/nssm-2.24.zip) and copy the content to `c:\Program Files (x86)\nssm-2.24\` folder.

> If you are running on Windows 2012R2 once you have installed VS2013 you can run `iwr https://raw.githubusercontent.com/auth0/ad-ldap-connector/master/installer/prepare.ps1 -UseBasicParsing | iex` from an Elevated Powershell console and it will download and install all other components.

If you intent to sign the installer you will also need 
1.  If you are building on Windows 2008 or earlier versions you need Microsoft SDK v7.1A. Verify you have `C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Bin\signtool.exe`
2.  You need to install Auth0's certificate to sign components and installer in your local certificate storage. Just double click on it.

## How to build

1.  git clone this repository
2.  run `npm i --production`
3.  remove unnecessary files `node_modules\edge\test`, `node_modules\leveldown\build\Release\obj` and `node_modules\leveldown\build\Release\leveldb.lib`
4.  run `npm version patch`
5.  from an Elevated Powershell console, run `cd installer` and then `.\build.ps1`.
