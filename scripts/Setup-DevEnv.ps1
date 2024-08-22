# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

Invoke-WebRequest 'https://community.chocolatey.org/install.ps1' -OutFile $env:TEMP\install_choco.ps1
if ((get-filehash -Algorithm SHA256 $env:TEMP\install_choco.ps1).Hash -ne '44E045ED5350758616D664C5AF631E7F2CD10165F5BF2BD82CBF3A0BB8F63462') { throw "Wrong file hash for Chocolatey installer"}
&"$env:TEMP\install_choco.ps1"
choco install git --version 2.38.1 -y
choco install visualstudio2022community --version 117.4.2.0 -y
choco install visualstudio2022-workload-nativedesktop --version 1.0.0 -y
choco install visualstudio2022buildtools --version 117.4.2.0 -y
vs_installer.exe modify --installpath "$Env:ProgramFiles\Microsoft Visual Studio\2022\Community" --add Microsoft.VisualStudio.Component.VC.Llvm.ClangToolset --quiet

# WDK for Windows 11 not currently available on Chocolate!
#choco install windowsdriverkit11 --version 10.0.22621.382 -y

choco install nuget.commandline --version 6.4.0 -y
choco install cmake.portable --version 3.25.1 -y
choco install wixtoolset -y
Start-Process "${Env:ProgramFiles}\Microsoft Visual Studio\2022\Community\Common7\IDE\VSIXInstaller.exe" -ArgumentList @("/q", "/a", "${Env:ProgramFiles}\Windows Kits\10\vsix\vs2022\WDK.vsix") -Wait
