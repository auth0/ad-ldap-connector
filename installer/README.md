This directory contains the scripts to generate an MSI installer.

## Pre-requisites

1.  Node for Windows. Check you have node.exe in `C:\Program Files (x86)\nodejs\node.exe`.
2.  [Wix 3.8](https://wix.codeplex.com/releases/view/115492). Check you have the bin in `c:\Program Files (x86)\WiX Toolset v3.8\bin`
3.  Microsoft SDK v7.1A. Verify you have `C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Bin\signtool.exe`
4.  You need to install Auth0's certificate to sign components and installer in your local certificate storage. Just double click on it.
5.  Your [node-gyp](https://github.com/TooTallNate/node-gyp/#installation) should be able to build native dependencies.
6.  Not sure about this step, but I think you need `C:\Program Files (x86)\msxml.exe`
7.  Download [nssm](http://nssm.cc/ci/nssm-2.21-136-ga8cb477.zip) and copy the content to `c:\Program Files (x86)\nssm-2.21.1\` folder.

## How to build

1.  git clone this repository
2.  run `npm i`
3.  run `npm version patch`
4.  from an Elevated Powershell console, run `cd installer` and then `.\build.ps1`.
