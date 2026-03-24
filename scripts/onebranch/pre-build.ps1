# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

$OneBranchArch = if ($env:ONEBRANCH_ARCH) { $env:ONEBRANCH_ARCH } else { "x64" }

# Get the path where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Change the parent directory for the script directory
Set-Location $scriptPath\..\..

try {
    Copy-Item .\scripts\onebranch\nuget.config .\nuget.config
    .\scripts\initialize_ebpf_repo.ps1 -Architecture $OneBranchArch

    # Install LLVM tools (clang with BPF target support) for compiling eBPF programs.
    Write-Host "Installing LLVM tools..."
    nuget install llvm.tools -OutputDirectory packages -version 19.1.4-34 -ExcludeVersion
    if ($LASTEXITCODE -ne 0) { throw "Failed to install llvm.tools" }
    nuget install clang.headers -OutputDirectory packages -version 19.1.4-34 -ExcludeVersion
    if ($LASTEXITCODE -ne 0) { throw "Failed to install clang.headers" }

    # Add LLVM tools to PATH so clang is available for BPF compilation.
    $llvmPath = Join-Path (Get-Location) "packages\llvm.tools"
    $env:Path = "$llvmPath;$env:Path"
    Write-Host "##vso[task.prependpath]$llvmPath"
    Write-Host "LLVM tools installed. Clang version:"
    clang --version
}
catch {
    throw "Failed to initialize the eBPF for Windows repository."
}

Get-ChildItem -Path ./external -Filter *.dll -Recurse | Remove-Item
