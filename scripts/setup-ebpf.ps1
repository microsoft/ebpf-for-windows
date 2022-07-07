# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# .SYNOPSIS
# Install or uninstall eBPF
# .PARAMETER Uninstall
# Uninstall eBPF rather than installing it
# .PARAMETER WorkingDirectory
# Directory containing the files to install
# .PARAMETER LogFileName
# Log file name, defaulting to TestLog.log

param ([switch]$Uninstall,
       [parameter(Mandatory=$false)][string] $WorkingDirectory = $pwd.ToString(),
       [parameter(Mandatory=$false)][string] $LogFileName = "TestLog.log")

Import-Module $PSScriptRoot\install_ebpf.psm1 -Force -ArgumentList ($WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue

if ($Uninstall) {
    Write-Host "Uninstalling eBPF..."
    Uninstall-eBPFComponents
    exit 0
}

Write-Host "Installing eBPF..."
Install-eBPFComponents
exit 0
