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

$llvmToolchainManifest = Join-Path $PSScriptRoot "clang-toolchain.props"
if (-not (Test-Path $llvmToolchainManifest)) {
    $llvmToolchainManifest = Join-Path $env:TEMP "ebpf-clang-toolchain.props"
    Invoke-WebRequest 'https://raw.githubusercontent.com/microsoft/ebpf-for-windows/main/scripts/clang-toolchain.props' -OutFile $llvmToolchainManifest
}
[xml]$llvmToolchain = Get-Content -Path $llvmToolchainManifest -Raw
$namespaceManager = New-Object System.Xml.XmlNamespaceManager($llvmToolchain.NameTable)
$namespaceManager.AddNamespace("m", "http://schemas.microsoft.com/developer/msbuild/2003")
$llvmVersionNode = $llvmToolchain.SelectSingleNode("/m:Project/m:PropertyGroup/m:EbpfPublicClangVersion", $namespaceManager)
if (-not $llvmVersionNode -or [string]::IsNullOrWhiteSpace($llvmVersionNode.InnerText)) {
    throw "The Public Clang version is missing from '$llvmToolchainManifest'."
}
$llvmVersion = $llvmVersionNode.InnerText
choco install llvm --version=$llvmVersion --allow-downgrade -y
if ($LASTEXITCODE -ne 0) { throw "Failed to install LLVM $llvmVersion." }
$clangPath = "$env:ProgramFiles\LLVM\bin\clang.exe"
if (-not (Test-Path $clangPath)) { throw "LLVM installation did not create '$clangPath'." }
$clangVersionOutput = & $clangPath --version 2>&1
$clangVersionPattern = "(?m)^clang version $([regex]::Escape($llvmVersion))(\s|$)"
if ($LASTEXITCODE -ne 0 -or ($clangVersionOutput -join "`n") -notmatch $clangVersionPattern) {
    throw "Expected Clang $llvmVersion, got: $($clangVersionOutput -join ' ')"
}

choco install nuget.commandline --version 6.4.0 -y
# CMake 4.2 or later is required for the "Visual Studio 18 2026" generator.
choco install cmake.portable --version 4.4.2 -y
