# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

Invoke-WebRequest 'https://community.chocolatey.org/install.ps1' -OutFile $env:TEMP\install_choco.ps1
if ((get-filehash $env:TEMP\install_choco.ps1).Hash -ne '6B2C4EF29B871090B758E403AEE3EFAF9018B21F90FFA03CD4E0C27506331F01') { throw "Wrong file hash for Chocolatey installer"}
&"$env:TEMP\install_choco.ps1"
choco install git --version 2.38.1 -y
choco install visualstudio2022community --version 117.4.2.0 -y
choco install visualstudio2022-workload-nativedesktop --version 1.0.0 -y
choco install visualstudio2022buildtools --version 117.4.2.0 -y

# WDK for Windows 11 not currently available on Chocolate!
#choco install windowsdriverkit11 --version 10.0.22621.382 -y

choco install llvm --version 11.0.1 -y
choco install nuget.commandline --version 6.4.0 -y
choco install cmake.portable --version 3.25.1 -y
choco install wixtoolset
Start-Process "${Env:ProgramFiles}\Microsoft Visual Studio\2022\Community\Common7\IDE\VSIXInstaller.exe" -ArgumentList @("/q", "/a", "${Env:ProgramFiles}\Windows Kits\10\vsix\vs2022\WDK.vsix") -Wait
