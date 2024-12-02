# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

Invoke-WebRequest 'https://community.chocolatey.org/install.ps1' -OutFile $env:TEMP\install_choco.ps1
if ((get-filehash -Algorithm SHA256 $env:TEMP\install_choco.ps1).Hash -ne '44E045ED5350758616D664C5AF631E7F2CD10165F5BF2BD82CBF3A0BB8F63462') { throw "Wrong file hash for Chocolatey installer"}
&"$env:TEMP\install_choco.ps1"

choco install git -y --params "'/GitAndUnixToolsOnPath /WindowsTerminal /NoAutoCrlf'"
choco install visualstudio2022community --version 117.4.2.0 -y
choco install visualstudio2022buildtools --version 117.4.2.0 -y

echo "Adding required components to Visual Studio"
Invoke-WebRequest 'https://raw.githubusercontent.com/microsoft/ebpf-for-windows/main/.vsconfig' -OutFile $env:TEMP\ebpf-for-windows.vsconfig
# The out-null seems to be required to make powershell wait
# for the command to exit.
&"C:\Program Files (x86)\Microsoft Visual Studio\Installer\setup.exe" modify --installpath "$env:ProgramFiles\Microsoft Visual Studio\2022\Community" --config "$env:TEMP\ebpf-for-windows.vsconfig" --quiet | out-null

choco install nuget.commandline --version 6.4.0 -y
choco install cmake.portable --version 3.25.1 -y
