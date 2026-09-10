# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param (
    [parameter(Mandatory = $false)][ValidateSet("2026", "2022")][string] $VisualStudioVersion = "2026"
)

$ErrorActionPreference = "Stop"

Invoke-WebRequest 'https://community.chocolatey.org/install.ps1' -OutFile $env:TEMP\install_choco.ps1
if ((get-filehash -Algorithm SHA256 $env:TEMP\install_choco.ps1).Hash -ne '44E045ED5350758616D664C5AF631E7F2CD10165F5BF2BD82CBF3A0BB8F63462') { throw "Wrong file hash for Chocolatey installer"}
&"$env:TEMP\install_choco.ps1"

choco install git -y --params "'/GitAndUnixToolsOnPath /WindowsTerminal /NoAutoCrlf'"

if ($VisualStudioVersion -eq "2026") {
    choco install visualstudio2026community --version 118.8.2 -y
} else {
    choco install visualstudio2022community --version 117.4.2.0 -y
}

echo "Adding required components to Visual Studio"
Invoke-WebRequest 'https://raw.githubusercontent.com/microsoft/ebpf-for-windows/main/.vsconfig' -OutFile $env:TEMP\ebpf-for-windows.vsconfig

$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsRange = if ($VisualStudioVersion -eq "2026") { "[18.0,19.0)" } else { "[17.0,18.0)" }
$vsInstallPath = & $vsWhere -latest -version $vsRange -products '*' -property installationPath | Select-Object -First 1
if (-not $vsInstallPath) { throw "Could not locate a Visual Studio $VisualStudioVersion installation ($vsRange) via vswhere." }
echo "Visual Studio install path: $vsInstallPath"
& "C:\Program Files (x86)\Microsoft Visual Studio\Installer\setup.exe" modify --installpath "$vsInstallPath" --config "$env:TEMP\ebpf-for-windows.vsconfig" --passive

choco install llvm --version=18.1.8 -y
choco install nuget.commandline --version 6.4.0 -y
# CMake 4.2 or later is required for the "Visual Studio 18 2026" generator.
choco install cmake.portable --version 4.4.2 -y
