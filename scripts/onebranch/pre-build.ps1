# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

$OneBranchArch = $env:ONEBRANCH_ARCH

# Get the path where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Change the parent directory for the script directory
Set-Location $scriptPath\..\..

.\scripts\initialize_ebpf_repo.ps1 -Architecture $OneBranchArch

Get-ChildItem -Path ./external -Filter *.dll -Recurse | Remove-Item
