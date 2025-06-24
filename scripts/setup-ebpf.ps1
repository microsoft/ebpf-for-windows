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
    "ucrtbased.dll"
)

$InstallPath = Join-Path $env:ProgramFiles "ebpf-for-windows"
$EbpfSvcPath = Join-Path $InstallPath "JIT"
$MsiPath = Join-Path $WorkingDirectory "ebpf-for-windows.msi"
$VcRedistPath = Join-Path $WorkingDirectory "vc_redist.x64.exe"

Push-Location $WorkingDirectory

if ($Uninstall) {
    # Uninstall the MSI package using the MSI product code. Product code from: installer\Product.wxs
    $arguments = "/x {022C44B5-8969-4B75-8DB0-73F98B1BD7DC} /qn /norestart /l*v msi-uninstall.log"
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

    # Copy the Visual C++ Redistributable Debug DLLs to the JIT directory and give
    # LOCAL SERVICE read access.
    # This is so that ebpfsvc.exe does not fail to start with error 1053.
    Write-Host("Copying Visual C++ Redistributable debug runtime DLLs to the $EbpfSvcPath directory...")
    # Test if the VC debug runtime DLLs are present in the working directory (indicating a debug build).
    $VCDebugRuntime = $VCDebugRuntime | Where-Object { Test-Path (Join-Path $WorkingDirectory $_) }
    if (-not $VCDebugRuntime) {
        Write-Host("Visual C++ Redistributable debug runtime DLLs not found in the working directory. Skipping this step.") -ForegroundColor Yellow
    } else {
        if (-not (Test-Path $EbpfSvcPath)) {
            New-Item -Path $EbpfSvcPath -ItemType Directory
        }

        $VCDebugRuntime | ForEach-Object {
            $sourcePath = Join-Path $WorkingDirectory $_
            $destinationPath = Join-Path $EbpfSvcPath $_
            Copy-Item -Path $sourcePath -Destination $destinationPath -Force
            $acl = Get-Acl $destinationPath
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\LOCAL SERVICE", "ReadAndExecute", "Allow")))
            Set-Acl $destinationPath $acl
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
