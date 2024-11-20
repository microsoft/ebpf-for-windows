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
}
catch {
    throw "Failed to initialize the eBPF for Windows repository."
}

Get-ChildItem -Path ./external -Filter *.dll -Recurse | Remove-Item
