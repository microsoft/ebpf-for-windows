# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# .SYNOPSIS
# Install or uninstall eBPF
# .PARAMETER Uninstall
# Uninstall eBPF rather than installing it

param ([switch]$Uninstall)

$WorkingDirectory = "$PSScriptRoot"
Write-Host "PSScriptRoot is $PSScriptRoot"
Write-Host "WorkingDirectory is $WorkingDirectory"

Push-Location $WorkingDirectory

# Import the install_ebpf module
Import-Module "$PSScriptRoot\install_ebpf.psm1" -ArgumentList ($WorkingDirectory, "setup-ebpf.log") -Force -WarningAction SilentlyContinue

if ($Uninstall) {
    # Stop services and drivers first
    Stop-eBPFServiceAndDrivers

    # Uninstall using the module
    Uninstall-eBPFComponents
} else {
    # Download PsExec if needed
    Get-PSExec

    # Install using the module
    Install-eBPFComponents -KmTracing $false -KmTraceType "file" -TestMode "Normal"
}

Pop-Location
exit 0
