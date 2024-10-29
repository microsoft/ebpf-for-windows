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

$MsiPath = Join-Path $WorkingDirectory "ebpf-for-windows.msi"
$System32Path = Join-Path $env:SystemRoot "System32"
$VcRedistPath = Join-Path $WorkingDirectory "vc_redist.x64.exe"

Push-Location $WorkingDirectory

if ($Uninstall) {
    # Uninstall the MSI package.
    $arguments = "/x $MsiPath /qn /norestart /l*v msi-uninstall.log"
    Write-Host("Uninstalling eBPF MSI package at 'msiexec.exe $arguments'...")
    $process = Start-Process -FilePath msiexec.exe -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -eq 0) {
        Write-Host("Uninstallation successful!") -ForegroundColor Green
    } else {
        Write-Host("Uninstallation FAILED. Exit code: $($process.ExitCode)") -ForegroundColor Red
        throw ("MSI uninstallation FAILED. Exit code: $($process.ExitCode).")
    }
    Write-Host("MSI uninstallation completed successfully!") -ForegroundColor Green
} else {
    # Install the Visual C++ Redistributable Release version, which is required for the MSI installation.
    # If the VC++ Redist is not present, it means it has been already installed (its MSI auto-delets itself).
    if (Test-Path $VcRedistPath) {
        Write-Host("Installing Visual C++ Redistributable from '$VcRedistPath'...")
        $process = Start-Process -FilePath $VcRedistPath -ArgumentList "/quiet", "/norestart" -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            Write-Host("Visual C++ Redistributable installation FAILED. Exit code: $($process.ExitCode).") -ForegroundColor Red
            throw ("Visual C++ Redistributable installation FAILED. Exit code: $($process.ExitCode).")
        }
        Write-Host("Cleaning up...")
        Remove-Item $VcRedistPath -Force
        Write-Host("Visual C++ Redistributable installation completed successfully!") -ForegroundColor Green
    }

    # Install the MSI package.
    $arguments = "/i $MsiPath ADDLOCAL=ALL /qn /norestart /l*v msi-install.log"
    Write-Host("Installing the eBPF MSI package: 'msiexec.exe $arguments'...")
    $process = Start-Process -FilePath msiexec.exe -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        Write-Host("MSI installation FAILED. Exit code: $($process.ExitCode).") -ForegroundColor Red
        throw ("MSI installation FAILED. Exit code: $($process.ExitCode).")
    }
    Write-Host("eBPF MSI installation completed successfully!") -ForegroundColor Green
}

Pop-Location
exit 0
