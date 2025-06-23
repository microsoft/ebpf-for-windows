# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# MSI Installation Test Script
# 
# This script tests MSI package installation, verification, and uninstall.
# It includes a regression test for issue #4467 that verifies the eBPF service
# is properly stopped during uninstall to prevent "files in use" dialogs.
#
# Usage: .\check_msi_installation.ps1 -BuildArtifact "Build-x64_Debug" -MsiPath "path\to\installer.msi"

param (
        [Parameter(Mandatory=$true)] [string]$BuildArtifact,
        [Parameter(Mandatory=$true)] [string]$MsiPath)

Push-Location $WorkingDirectory

$InstallPath = "$env:ProgramFiles\ebpf-for-windows";

# Define a map with:
# - The additional arguments to pass to the MSI installer for each build artifact
# - The expected file lists for each build artifact
$buildArtifactParams = @{
    "Build-x64_Debug" = @{
        "InstallComponents" = "ADDLOCAL=eBPF_Runtime_Components"
        "ExpectedFileList" = "..\..\scripts\check_msi_installation_files_regular_debug.txt"
    }
    "Build-x64-native-only_NativeOnlyRelease" = @{
        "InstallComponents" = "ADDLOCAL=eBPF_Runtime_Components"
        "ExpectedFileList" = "..\..\scripts\check_msi_installation_files_nativeonly_release.txt"
    }
}

# Define the eBPF components to check
$eBpfDrivers =
@{
    "EbpfCore" = "ebpfcore.sys";
    "NetEbpfExt" = "netebpfext.sys";
}
$eBpfNetshExtensionName = "ebpfnetsh"
$eBpfServiceName = "ebpfsvc"

function CompareFiles {
    param(
        [string]$targetPath,
        [string]$listFilePath
    )

    Write-Host "Comparing files in '$targetPath' with the expected list in '$listFilePath'..."
    try {
        # Get all files installed in the target directory.
        $InstalledFiles = Get-ChildItem -Path $targetPath -File -Recurse | ForEach-Object { $_.FullName }

        # Read the list of files from the file containing the expected file list.
        $ExpectedFiles = Get-Content $listFilePath

        # Compare the installed files with the expected binaries.
        $MissingFiles = Compare-Object -ReferenceObject $ExpectedFiles -DifferenceObject $InstalledFiles -PassThru | Where-Object { $_.SideIndicator -eq '<=' }
        $ExtraFiles = Compare-Object -ReferenceObject $ExpectedFiles -DifferenceObject $InstalledFiles | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject
        if ($MissingFiles -or $ExtraFiles) {
            Write-Host "Mismatch found between the installed files and the ones in the expected list:" -ForegroundColor Red
            Write-Host "Missing Files:" -ForegroundColor Red
            Write-Host $MissingFiles
            Write-Host "Extra Files:" -ForegroundColor Red
            Write-Host $ExtraFiles
            return $false
        } else {
            Write-Host "All installed files match the expected list." -ForegroundColor Green
            return $true
        }
    } catch {
        Write-Host "An error occurred while comparing the installed files with the expected list: $_" -ForegroundColor Red
        return $false
    }
}

function Install-MsiPackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] [string]$MsiPath,
        [Parameter(Mandatory=$true)] [string]$MsiAdditionalArguments
    )

    $res = $true

    $arguments = "/i $MsiPath /qn /norestart /l*v msi-install.log $MsiAdditionalArguments"
    Write-Host "Installing MSI package with arguments: '$arguments'..."
    $process = Start-Process -FilePath msiexec.exe -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -eq 0) {
        Write-Host "Installation successful!"
    } else {
        $res = $false
        $exceptionMessage = "Installation FAILED. Exit code: $($process.ExitCode)"
        Write-Host $exceptionMessage
        $logContents = Get-Content -Path "msi-install.log" -ErrorAction SilentlyContinue
        if ($logContents) {
            Write-Host "Contents of msi-install.log:"
            Write-Host $logContents
        } else {
            Write-Host "msi-install.log not found or empty."
        }
    }

    return $res
}

function Uninstall-MsiPackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] [string]$MsiPath
    )

    Write-Host "Uninstalling MSI package..."
    $res = $true
    $process = Start-Process -FilePath msiexec.exe -ArgumentList "/x $MsiPath /qn /norestart /l*v msi-uninstall.log" -Wait -PassThru
    if ($process.ExitCode -eq 0) {
        Write-Host "Uninstallation successful!"
    } else {
        $res = $false
        $exceptionMessage = "Uninstallation FAILED. Exit code: $($process.ExitCode)"
        Write-Host $exceptionMessage
        $logContents = Get-Content -Path "msi-uninstall.log" -ErrorAction SilentlyContinue
        if ($logContents) {
            Write-Host "Contents of msi-uninstall.log:"
            Write-Host $logContents
        } else {
            Write-Host "msi-uninstall.log not found or empty."
        }
    }

    return $res
}

function Test-ServiceStopDuringUninstall {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] [string]$MsiPath
    )

    Write-Host "Testing eBPF service stop behavior during uninstall (regression test for issue #4467)..."
    $res = $true

    try {
        # Verify service is running before uninstall
        $service = Get-Service -Name $eBpfServiceName -ErrorAction SilentlyContinue
        if (-not $service -or $service.Status -ne "Running") {
            Write-Host "ERROR: eBPF service is not running before uninstall test" -ForegroundColor Red
            return $false
        }
        Write-Host "✓ eBPF service is running before uninstall"

        # Check for any existing eBPF processes
        $ebpfProcessesBefore = Get-Process -Name "*ebpf*" -ErrorAction SilentlyContinue
        Write-Host "eBPF processes before uninstall: $($ebpfProcessesBefore.Count)"

        # Start monitoring service status in background job
        $monitorJob = Start-Job -ScriptBlock {
            param($serviceName)
            $timestamps = @()
            $maxDuration = 120 # 2 minutes max
            $startTime = Get-Date
            
            while ((Get-Date).Subtract($startTime).TotalSeconds -lt $maxDuration) {
                try {
                    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                    $timestamp = @{
                        Time = Get-Date
                        Status = if ($svc) { $svc.Status } else { "NotFound" }
                        ElapsedSeconds = (Get-Date).Subtract($startTime).TotalSeconds
                    }
                    $timestamps += $timestamp
                    
                    # If service is stopped or removed, we can exit early
                    if (-not $svc -or $svc.Status -eq "Stopped") {
                        break
                    }
                } catch {
                    # Service might be in transition, continue monitoring
                }
                Start-Sleep -Milliseconds 500
            }
            return $timestamps
        } -ArgumentList $eBpfServiceName

        # Perform the uninstall
        Write-Host "Starting MSI uninstall with service monitoring..."
        $uninstallStart = Get-Date
        $process = Start-Process -FilePath msiexec.exe -ArgumentList "/x $MsiPath /qn /norestart /l*v msi-uninstall-service-test.log" -Wait -PassThru
        $uninstallEnd = Get-Date
        $uninstallDuration = $uninstallEnd.Subtract($uninstallStart).TotalSeconds

        # Get monitoring results
        $monitorResults = Receive-Job -Job $monitorJob -Wait
        Remove-Job -Job $monitorJob

        Write-Host "Uninstall completed in $([math]::Round($uninstallDuration, 2)) seconds"

        # Analyze the results
        if ($process.ExitCode -eq 0) {
            Write-Host "✓ Uninstall completed successfully without user intervention"
            
            # Check when service was stopped
            $serviceStoppedTime = $monitorResults | Where-Object { $_.Status -eq "Stopped" -or $_.Status -eq "NotFound" } | Select-Object -First 1
            
            if ($serviceStoppedTime) {
                Write-Host "✓ eBPF service was stopped at $([math]::Round($serviceStoppedTime.ElapsedSeconds, 2)) seconds into uninstall"
                
                # Service should be stopped early (within first 30 seconds)
                if ($serviceStoppedTime.ElapsedSeconds -le 30) {
                    Write-Host "✓ Service stopped early in uninstall process (within 30 seconds)" -ForegroundColor Green
                } else {
                    Write-Host "⚠ Service stopped later than expected ($([math]::Round($serviceStoppedTime.ElapsedSeconds, 2)) seconds)" -ForegroundColor Yellow
                }
            } else {
                Write-Host "⚠ Could not determine when service was stopped" -ForegroundColor Yellow
            }

            # Verify no eBPF processes remain
            Start-Sleep -Seconds 2
            $ebpfProcessesAfter = Get-Process -Name "*ebpf*" -ErrorAction SilentlyContinue
            if ($ebpfProcessesAfter.Count -eq 0) {
                Write-Host "✓ No eBPF processes remain after uninstall" -ForegroundColor Green
            } else {
                Write-Host "⚠ Found $($ebpfProcessesAfter.Count) eBPF processes still running after uninstall" -ForegroundColor Yellow
                $ebpfProcessesAfter | ForEach-Object { Write-Host "  - $($_.ProcessName) (PID: $($_.Id))" }
            }

            # Check uninstall log for any dialog-related errors
            $logContent = Get-Content -Path "msi-uninstall-service-test.log" -ErrorAction SilentlyContinue
            if ($logContent) {
                $dialogErrors = $logContent | Where-Object { $_ -match "files that need to be updated|applications are using files|RestartManager" }
                if ($dialogErrors.Count -eq 0) {
                    Write-Host "✓ No file-in-use or dialog-related errors found in uninstall log" -ForegroundColor Green
                } else {
                    Write-Host "⚠ Found potential dialog-related entries in log:" -ForegroundColor Yellow
                    $dialogErrors | ForEach-Object { Write-Host "  $_" }
                }
            }

        } else {
            Write-Host "✗ Uninstall failed with exit code: $($process.ExitCode)" -ForegroundColor Red
            $res = $false
            
            # Show uninstall log for debugging
            $logContents = Get-Content -Path "msi-uninstall-service-test.log" -ErrorAction SilentlyContinue
            if ($logContents) {
                Write-Host "Uninstall log contents:" -ForegroundColor Yellow
                $logContents | Select-Object -Last 20 | ForEach-Object { Write-Host "  $_" }
            }
        }

    } catch {
        Write-Host "✗ Error during service stop test: $_" -ForegroundColor Red
        $res = $false
    }

    return $res
}

function Check-eBPF-Installation {

    $res = $true

    # Check if the eBPF drivers are registered correctly.
    Write-Host "Checking if the eBPF drivers are registered correctly..."
    try {
        $eBpfDrivers.GetEnumerator() | ForEach-Object {
            $driverName = $_.Key
            Write-Host "Verifying that the service '$driverName' is registered correctly..."
            # Query for the service and search for the BINARY_PATH_NAME line using regex.
            $scQueryOutput = & "sc.exe" qc $driverName
            $binaryPathLine = $scQueryOutput -split "`n" | Where-Object { $_ -match "BINARY_PATH_NAME\s+:\s+(.*)" }
            if ($binaryPathLine) {
                # Extract the full disk path using regex.
                $binaryPath = $matches[1]
                $fullDiskPath = [regex]::Match($binaryPath, '(?<=\\)\w:.+')
                if ($fullDiskPath.Success) {
                    $pathValue = $fullDiskPath.Value
                    Write-Host "[$driverName] is registered correctly at '$pathValue'."
                }else {
                    Write-Host "[$driverName] is NOT registered correctly!"
                    $res = $false
                }
            }
        }
    }
    catch {
        Write-Host "An error occurred while starting the eBPF drivers: $_"
        $res = $false
    }

    # Run netsh command, capture the output, and check if the output contains information about the extension.
    Write-Host "Checking if the '$eBpfNetshExtensionName' netsh extension is registered correctly..."
    Push-Location $InstallPath
    try {
        $output = netsh ebpf
        if ($output -match "The following commands are available:") {
            Write-Host "The '$eBpfNetshExtensionName' netsh extension is correctly registered."
        } else {
            Write-Host "The '$eBpfNetshExtensionName' netsh extension is NOT registered."
            Write-Host "Output of 'netsh $eBpfNetshExtensionName show helper':"
            Write-Host $output
            $res = $false
        }
    } catch {
        Write-Host "An error occurred while running the 'netsh $eBpfNetshExtensionName show helper' command: $_"
        $res = $false
    }
    Pop-Location

    Write-Host "Checking if the eBPF service is running..."
    try {
        $service = Get-Service -Name $eBpfServiceName
        if ($service.Status -eq "Running") {
            Write-Host "The '$eBpfServiceName' service is running."
        } else {
            Write-Host "The '$eBpfServiceName' service is NOT running."
            $res = $false
        }
    } catch {
        Write-Host "An error occurred while checking the '$eBpfServiceName' service: $_"
        $res = $false
    }

    return $res
}

# Test the MSI package
$allTestsPassed = $true
try {
    # Install the MSI package.
    $allTestsPassed = Install-MsiPackage -MsiPath "$MsiPath" -MsiAdditionalArguments $buildArtifactParams[$BuildArtifact]["InstallComponents"]

    # Check if the installed files correspond to the expected list.
    $res =  CompareFiles -targetPath "$InstallPath" -listFilePath $buildArtifactParams[$BuildArtifact]["ExpectedFileList"]
    $allTestsPassed = $allTestsPassed -and $res

    # Check if the eBPF platform is installed correctly.
    $res = Check-eBPF-Installation
    $allTestsPassed = $allTestsPassed -and $res

    # Test service stop behavior during uninstall (regression test for issue #4467).
    $res = Test-ServiceStopDuringUninstall -MsiPath "$MsiPath"
    $allTestsPassed = $allTestsPassed -and $res

    # Note: Test-ServiceStopDuringUninstall performs the uninstall, so we don't call Uninstall-MsiPackage separately
} catch {
    $allTestsPassed = $false
    Write-Host "Error: $_"
}

Pop-Location

if (-not $allTestsPassed) {
    Write-Host "One or more tests FAILED!" -ForegroundColor Red
    exit 1
}
exit 0
