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
       [parameter(Mandatory=$false)][string] $LogFileName = "TestLog.log")

$WorkingDirectory = "$PSScriptRoot"
Write-Host "PSScriptRoot is $PSScriptRoot"
Write-Host "WorkingDirectory is $WorkingDirectory"
Write-Host "LogFileName is $LogFileName"

Import-Module $PSScriptRoot\install_ebpf.psm1 -Force -ArgumentList ($WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue

Push-Location $WorkingDirectory

if ($Uninstall) {
    Write-Host "Uninstalling eBPF..."
    Uninstall-eBPFComponents
} else {
    Write-Host "Installing eBPF..."
    Install-eBPFComponents
}

Pop-Location
exit 0
