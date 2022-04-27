# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

Invoke-WebRequest 'https://community.chocolatey.org/install.ps1' -OutFile $env:TEMP\install_choco.ps1
if ((get-filehash $env:TEMP\install_choco.ps1).Hash -ne '6B2C4EF29B871090B758E403AEE3EFAF9018B21F90FFA03CD4E0C27506331F01') { throw "Wrong file hash for Chocolatey installer"}
&"$env:TEMP\install_choco.ps1"
choco install git --version 2.36.0 -y
choco install visualstudio2019community --version 16.11.12.0 -y
choco install visualstudio2019-workload-nativedesktop --version 1.0.1 -y
choco install visualstudio2019buildtools --version 16.11.12.0 -y
choco install windowsdriverkit10 --version 10.0.19041.685 -y
choco install windowsdriverkit11 --version 10.0.22000.1 -y
choco install llvm --version 11.0.1 -y
choco install nuget.commandline --version 6.1.0 -y
choco install cmake.portable --version 3.23.1 -y
Start-Process "${Env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Community\Common7\IDE\VSIXInstaller.exe" -ArgumentList @("/q", "/a", "${Env:ProgramFiles(x86)}\Windows Kits\10\vsix\vs2019\WDK.vsix") -Wait
