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

# VC++ Redistributable Debug Runtime DLLs.
$VCDebugRuntime = @(
    "concrt140d.dll",
    "msvcp140d.dll",
    "msvcp140d_atomic_wait.dll",
    "msvcp140d_codecvt_ids.dll",
    "msvcp140_1d.dll",
    "msvcp140_2d.dll",
    "vccorlib140d.dll",
    "vcruntime140d.dll",
    "vcruntime140_1d.dll",
    "vcruntime140_threadsd.dll",
    "ucrtbased.dll"
)

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

    # Move the Visual C++ Redistributable Debug DLLs to the system32 directory,
    # so that debug versions of the MSI can be installed (i.e., export_program_info.exe will not fail).
    Write-Host("Copying Visual C++ Redistributable debug runtime DLLs to the $System32Path directory...")
    # Test if the VC debug runtime DLLs are present in the working directory (indicating a debug build).
    $VCDebugRuntime = $VCDebugRuntime | Where-Object { Test-Path (Join-Path $WorkingDirectory $_) }
    if (-not $VCDebugRuntime) {
        Write-Host("Visual C++ Redistributable debug runtime DLLs not found in the working directory (i.e., release build or already installed). Skipping this step.") -ForegroundColor Yellow
    } else {
        $System32Path = Join-Path $env:SystemRoot "System32"
        $VCDebugRuntime | ForEach-Object {
            $sourcePath = Join-Path $WorkingDirectory $_
            $destinationPath = Join-Path $System32Path $_
            Move-Item -Path $sourcePath -Destination $destinationPath -Force
        }
        Write-Host("Visual C++ Redistributable debug runtime DLLs copied successfully!") -ForegroundColor Green
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
