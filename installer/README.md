This directory contains the scripts to generate an MSI installer.

## Pre-requisites

1.  Visual Studio 2013. Current build pipeline does not work with 2015.
2.  Node 0.10.x for Windows. Check you have node.exe in `C:\Program Files (x86)\nodejs\node.exe`.
3.  Update NPM to version 1.4.28
4.  [Wix 3.8](https://wix.codeplex.com/releases/view/115492). Check you have the bin in `c:\Program Files (x86)\WiX Toolset v3.8\bin`
5.  Your [node-gyp](https://github.com/TooTallNate/node-gyp/#installation) should be able to build native dependencies. Use version 1.0.2
6.  Download [nssm](http://nssm.cc/ci/nssm-2.21-136-ga8cb477.zip) and copy the content to `c:\Program Files (x86)\nssm-2.21.1\` folder.

> If you are running on Windows 2012R2 once you have installed VS2013 you can run `prepare.ps1` from an Elevated Powershell console and it will download and install all other components.

If you intent to sign the installer you will also need 
1.  If you are building on Windows 2008 or earlier versions you need Microsoft SDK v7.1A. Verify you have `C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Bin\signtool.exe`
2.  You need to install Auth0's certificate to sign components and installer in your local certificate storage. Just double click on it.

## How to build

1.  git clone this repository
2.  run `npm i`
3.  run `npm version patch`
4.  from an Elevated Powershell console, run `cd installer` and then `.\build.ps1`.
