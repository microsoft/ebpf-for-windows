# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# Get the path where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Change the parent directory for the script directory
Set-Location $scriptPath\..\..

.\scripts\initialize_ebpf_repo.ps1

Get-ChildItem -Path ./external -Filter *.dll -Recurse | Remove-Item
