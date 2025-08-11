# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
       [Parameter(Mandatory=$True)] [string] $LogFileName)

Push-Location $WorkingDirectory
Import-Module $PSScriptRoot\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
Import-Module $PSScriptRoot\tracing_utils.psm1 -Force -ArgumentList ($LogFileName, $WorkingDirectory) -WarningAction SilentlyContinue

$MsiPath = Join-Path $WorkingDirectory "ebpf-for-windows.msi"

# eBPF drivers and services.
$EbpfDrivers = @{
    "EbpfCore" = [PSCustomObject]@{
        "Name" = "ebpfcore.sys"
        "IsDriver" = $true
        "InstalledByMsi" = $true
        "ReplaceForRegressionTest" = $false
    }
    "NetEbpfExt" = [PSCustomObject]@{
        "Name" = "netebpfext.sys"
        "IsDriver" = $true
        "InstalledByMsi" = $true
        "ReplaceForRegressionTest" = $true
    }
    "SampleEbpfExt" = [PSCustomObject]@{
        "Name" = "sample_ebpf_ext.sys"
        "IsDriver" = $true
        "InstalledByMsi" = $false
        "ReplaceForRegressionTest" = $true
    }
    "EbpfSvc" = [PSCustomObject]@{
        "Name" = "ebpfsvc.exe"
        "IsDriver" = $false
        "InstalledByMsi" = $true
        "ReplaceForRegressionTest" = $false
    }
}

# eBPF Debug Runtime DLLs.
$VCDebugRuntime = @(
    "ucrtbased.dll"
)

function Enable-KMDFVerifier
{
    # Enable KMDF verifier for the eBPF drivers.
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        if ($_.Value.IsDriver) {
            Write-Log("Enabling KMDF verifier for $($_.Key)...")
            New-Item -Path ("HKLM:\System\CurrentControlSet\Services\{0}\Parameters\Wdf" -f $_.Name) -Force -ErrorAction Stop
            New-ItemProperty -Path ("HKLM:\System\CurrentControlSet\Services\{0}\Parameters\Wdf" -f $_.Name) -Name "VerifierOn" -Value 1 -PropertyType DWord -Force -ErrorAction Stop
            New-ItemProperty -Path ("HKLM:\System\CurrentControlSet\Services\{0}\Parameters\Wdf" -f $_.Name) -Name "TrackHandles" -Value "*" -PropertyType MultiString -Force  -ErrorAction Stop
        }
    }
}

#
# Start file/memory based wpr tracing (if enabled).
#
function Start-WPRTrace
{
    param([parameter(Mandatory=$true)][bool] $KmTracing,
          [parameter(Mandatory=$true)][string] $KmTraceType)

    Write-Log("kernel mode ETW tracing: " + $KmTracing)

    if ($KmTracing) {
        if ($KmTraceType -eq "file") {
            Write-Log "Starting KM ETW tracing (File)"
            $ProcInfo = Start-Process -FilePath "wpr.exe" `
                -ArgumentList "-start EbpfForWindows.wprp!EbpfForWindowsProvider-File -filemode" `
                -NoNewWindow -Wait -PassThru `
                -RedirectStandardError .\StdErr.txt
        } else {
            Write-Log "Starting KM ETW tracing (Memory)"
            $ProcInfo = Start-Process -FilePath "wpr.exe" `
                -ArgumentList "-start EbpfForWindows.wprp!EbpfForWindowsProvider-Memory" `
                -NoNewWindow -Wait -PassThru `
                -RedirectStandardError .\StdErr.txt
        }

        if ($ProcInfo.ExitCode -ne 0) {
            Write-Log("wpr.exe start ETL trace failed. Exit code: " + $ProcInfo.ExitCode)
            Write-log "wpr.exe (start) error output: "
            foreach ($line in get-content -Path .\StdErr.txt) {
                Write-Log( "`t" + $line)
            }
            throw "Start ETL trace failed."
        }
        Write-Log("Start ETL trace success. wpr.exe exit code: " + $ProcInfo.ExitCode + "`n")

        Write-Log "Query ETL tracing status after trace start"
        $ProcInfo = Start-Process -FilePath "wpr.exe" `
            -ArgumentList "-status profiles collectors -details" `
            -NoNewWindow -Wait -PassThru `
            -RedirectStandardOut .\StdOut.txt -RedirectStandardError .\StdErr.txt
        if ($ProcInfo.ExitCode -ne 0) {
            Write-Log("wpr.exe query ETL trace status failed. Exit code: " + $ProcInfo.ExitCode)
            Write-log "wpr.exe (query) error output: "
            foreach ($line in get-content -Path .\StdErr.txt) {
                Write-Log( "`t" + $line)
            }
            throw "Query ETL trace status failed."
        } else {
            Write-log "wpr.exe (query) results: "
            foreach ($line in get-content -Path .\StdOut.txt) {
                Write-Log( "  `t" + $line)
            }
        }
        Write-Log("Query ETL trace status success. wpr.exe exit code: " + $ProcInfo.ExitCode + "`n" )
    }
}

function Stop-DriverWithTimeout {
    param([parameter(Mandatory=$true)][string] $DriverName,
          [parameter(Mandatory=$false)][int] $Timeout = 60)

    Write-Log "Stopping driver $DriverName ..."
    $Service = Get-Service $DriverName
    if ($Service.Status -eq "Running") {
        # Start the job to stop the driver.
        $Job = Start-Job -ScriptBlock {
            param($DriverName)
            Stop-Service -Name $DriverName -Force
        } -ArgumentList $DriverName

        # Wait for the job to complete with a timeout
        Write-Log "Waiting for $DriverName to stop in $Timeout seconds..."
        if (Wait-Job -Job $Job -Timeout $Timeout) {
            Write-Output "$DriverName stopped successfully within $Timeout seconds."
        } else {
            # If timeout occurs, stop the job and handle the timeout scenario
            Stop-Job -Job $Job
            Remove-Job -Job $Job
            throw [System.TimeoutException]::new("Failed to stop $DriverName driver in $Timeout seconds.")
        }
        # Cleanup the job
        Remove-Job -Job $Job -Force
        Write-Log "$DriverName driver stopped." -ForegroundColor Green
    } else {
        Write-Log "$DriverName driver is not running." -ForegroundColor Green
    }
}

# This function specifically tests that all eBPF drivers and services can be stopped.
function Stop-eBPFComponents {
    param([parameter(Mandatory=$false)] [bool] $GranularTracing = $false)

    if ($GranularTracing) {
        Start-WPRTrace
    }

    # First, stop user mode service, so that EbpfCore does not hang on stop.
    if (Get-Service "eBPFSvc" -ErrorAction SilentlyContinue) {
        try {
            Stop-Service "eBPFSvc" -ErrorAction Stop 2>&1 | Write-Log
            Write-Log "eBPFSvc service stopped." -ForegroundColor Green
        } catch {
            throw "Failed to stop 'eBPFSvc' service: $_."
        }
    } else {
        Write-Log "'eBPFSvc' service is not present (i.e., release build), skipping stopping." -ForegroundColor Green
    }
    # Stop the drivers and services.
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        if ($_.Value.IsDriver) {
            Stop-DriverWithTimeout -DriverName $_.Key
        }
    }

    if ($GranularTracing) {
        Stop-WPRTrace -FileName "stop_ebpf"
    }
}

function Print-eBPFComponentsStatus([string] $message = "")
{
    # Print the status of the eBPF drivers and services.
    Write-Log($message)
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        Write-Log "Querying the status of $($_.Key)..."
        sc.exe query $_.Key  2>&1 | Write-Log
    }
}
function Install-eBPFComponents
{
    param([parameter(Mandatory=$true)] [bool] $KmTracing,
          [parameter(Mandatory=$true)] [string] $KmTraceType,
          [parameter(Mandatory=$false)] [bool] $KMDFVerifier = $false,
          [parameter(Mandatory=$true)] [string] $TestMode,
          [parameter(Mandatory=$false)] [switch] $SkipRebootOperations,
          [parameter(Mandatory=$false)] [bool] $GranularTracing = $false)

    # Print the status of the eBPF drivers and services before installation.
    # This is useful for detecting issues with the runner baselines.
    Print-eBPFComponentsStatus "Querying the status of eBPF drivers and services before the installation (none should be present)..." | Out-Null

    # Start granular tracing before installation if enabled.
    if ($GranularTracing) {
        Start-WPRTrace -KmTracing $KmTracing -KmTraceType $KmTraceType
    }

    # Start the Windows Installer service.
    Write-Log("Starting the Windows Installer service...")
    $service = Get-Service -Name "msiserver" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne "Running") {
        Start-Service -Name "msiserver" -ErrorAction Stop
        Write-Log("Windows Installer service started successfully!") -ForegroundColor Green
    } else {
        Write-Log("Windows Installer service is already running or not present.") -ForegroundColor Yellow
    }

    # Copy the VC debug runtime DLLs to the system32 directory,
    # so that debug versions of the MSI can be installed (i.e., export_program_info.exe will not fail).
    Write-Log("Copying VC debug runtime DLLs to the $system32Path directory...")
    # Test if the VC debug runtime DLLs are present in the working directory (indicating a debug build).
    $VCDebugRuntime = $VCDebugRuntime | Where-Object { Test-Path (Join-Path $WorkingDirectory $_) }
    if (-not $VCDebugRuntime) {
        Write-Log("VC debug runtime DLLs not found in the working directory (i.e., release build). Skipping this step.") -ForegroundColor Yellow
    } else {
        $system32Path = Join-Path $env:SystemRoot "System32"
        $VCDebugRuntime | ForEach-Object {
            $sourcePath = Join-Path $WorkingDirectory $_
            $destinationPath = Join-Path $system32Path $_
            Write-Log("Copying '$sourcePath' to '$destinationPath'...")
            Copy-Item -Path $sourcePath -Destination $destinationPath -Force
        }
        Write-Log("VC debug runtime DLLs copied successfully!") -ForegroundColor Green
    }

    # Install the MSI package.
    $arguments = "/i $MsiPath ADDLOCAL=ALL /qn /norestart /l*v msi-install.log"
    Write-Log("Installing the eBPF MSI package: 'msiexec.exe $arguments'...")
    $process = Start-Process -FilePath msiexec.exe -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        Write-Log("MSI installation FAILED. Exit code: $($process.ExitCode).") -ForegroundColor Red

        # For clear readability within the CICD pipeline and final uploaded log output,
        # read each line of the log file and print it (otherwise all the log content is printed as a single line).
        Write-Log("Contents of msi-install.log:")
        Get-Content -Path "msi-install.log" | ForEach-Object {
            Write-Log($_)
        }
        throw ("MSI installation FAILED. Exit code: $($process.ExitCode).")
    }
    Write-Log("eBPF MSI installation completed successfully!") -ForegroundColor Green

    # Install the extra drivers that are not installed by the MSI package.
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        if (-not $_.Value.InstalledByMsi) {
            $driverPath = if (Test-Path -Path ("$pwd\{0}" -f $_.Value.Name)) {
                "$pwd\{0}" -f $_.Value.Name
            } elseif (Test-Path -Path ("$pwd\drivers\{0}" -f $_.Value.Name)) {
                "$pwd\drivers\{0}" -f $_.Value.Name
            } else {
                throw ("Driver file not found for $($_.Key).")
            }
            Write-Log("Installing $($_.Key)...") -ForegroundColor Green
            sc.exe create $_.Key type=kernel start=demand binpath=$driverPath 2>&1 | Write-Log
            if ($LASTEXITCODE -ne 0) {
                throw ("Failed to create $($_.Key) driver.")
            } else {
                Write-Log("$($_.Key) driver created.") -ForegroundColor Green
                # Start the service.
                Write-Log("Starting $($_.Key) service...") -ForegroundColor Green
                sc.exe start $_.Key 2>&1 | Write-Log
                if ($LASTEXITCODE -ne 0) {
                    throw ("Failed to start $($_.Key) service.")
                } else {
                    Write-Log("$($_.Key) service started.") -ForegroundColor Green
                }
            }
        }
    }

    # If TestMode is "Regression", reinstall the extension drivers from the regression test artifacts.
    if ($TestMode -eq "Regression") {
        Write-Log("Reinstalling the extension drivers from the regression test artifacts...") -ForegroundColor Green
        $EbpfDrivers.GetEnumerator() | ForEach-Object {
            if ($_.Value.InstalledByMsi) {
                if ($_.Value.ReplaceForRegressionTest) {

                    # Stop and delete the service.
                    Write-Log("Regression Tests: Stopping $($_.Key) service...") -ForegroundColor Green
                    sc.exe stop $_.Key 2>&1 | Write-Log
                    if ($LASTEXITCODE -ne 0) {
                        throw ("Failed to stop $($_.Key) service.")
                    } else {
                        Write-Log("$($_.Key) service stopped.") -ForegroundColor Green
                        Write-Log("Deleting $($_.Key) service...") -ForegroundColor Green
                        sc.exe delete $_.Key 2>&1 | Write-Log
                        if ($LASTEXITCODE -ne 0) {
                            throw ("Failed to delete $($_.Key) service.")
                        } else {
                            Write-Log("$($_.Key) service deleted.") -ForegroundColor Green
                        }
                    }

                    # Install the driver.
                    $driverPath = if (Test-Path -Path ("$pwd\{0}" -f $_.Value.Name)) {
                        "$pwd\{0}" -f $_.Value.Name
                    } elseif (Test-Path -Path ("$pwd\drivers\{0}" -f $_.Value.Name)) {
                        "$pwd\drivers\{0}" -f $_.Value.Name
                    } else {
                        throw ("Driver file not found for $($_.Key).")
                    }
                    Write-Log("Installing $($_.Key) from path $driverPath ...") -ForegroundColor Green
                    sc.exe create $_.Key type=kernel start=demand binpath=$driverPath 2>&1 | Write-Log
                    if ($LASTEXITCODE -ne 0) {
                        throw ("Failed to create $($_.Key) driver.")
                    } else {
                        Write-Log("$($_.Key) driver created.") -ForegroundColor Green
                        # Start the service.
                        Write-Log("Starting $($_.Key) service...") -ForegroundColor Green
                        sc.exe start $_.Key 2>&1 | Write-Log
                        if ($LASTEXITCODE -ne 0) {
                            throw ("Failed to start $($_.Key) service.")
                        } else {
                            Write-Log("$($_.Key) service started.") -ForegroundColor Green
                        }
                    }
                }
            }
        }
    }


    # Refresh Path so EbpfApi.dll can be found.
    $machinepath = [system.environment]::getenvironmentvariable("path", [system.environmentvariabletarget]::machine)
    $userpath = [system.environment]::getenvironmentvariable("path", [system.environmentvariabletarget]::user)
    $env:path = $machinepath + ";" + $userpath

    # Export program info for the sample driver.
    Write-Log("Running 'export_program_info_sample.exe'...")
    if (Test-Path -Path "export_program_info_sample.exe") {
        .\export_program_info_sample.exe 2>&1 | Write-Log
        if ($LASTEXITCODE -ne 0) {
            throw ("Failed to run 'export_program_info_sample.exe'.");
        } else {
            Write-Log "'export_program_info_sample.exe' succeeded." -ForegroundColor Green
        }
    }

    # Export program info for the sample driver as SYSTEM.
    Write-Log("Running 'export_program_info_sample.exe' as SYSTEM...")
    if (Test-Path -Path "export_program_info_sample.exe") {
        $TestCommand = "$pwd\PsExec64.exe"
        $Arguments = "-accepteula -nobanner -s -w `"$pwd`" `"$pwd\export_program_info_sample.exe`""
        Start-Process -NoNewWindow -Wait "$TestCommand" -ArgumentList "$Arguments"
        if ($LASTEXITCODE -ne 0) {
            throw ("Failed to run 'export_program_info_sample.exe as SYSTEM'.");
        } else {
            Write-Log "'export_program_info_sample.exe' succeeded." -ForegroundColor Green
        }
    }

    # Print the status of the eBPF drivers and services after installation.
    Print-eBPFComponentsStatus "Verifying the status of eBPF drivers and services after the installation..." | Out-Null

    # Optionally enable KMDF verifier and tag tracking.
    if ($KMDFVerifier) {
        if (-not $SkipRebootOperations) {
            Enable-KMDFVerifier
        } else {
            Write-Log "SkipRebootOperations enabled - skipping KMDF verifier configuration" -ForegroundColor Yellow
        }
    }

    if ($GranularTracing) {
        Stop-WPRTrace -FileName "install_ebpf"
    } else {
        # Start regular KM tracing if not using granular tracing
        Start-WPRTrace -KmTracing $KmTracing -KmTraceType $KmTraceType
    }
}

function Uninstall-eBPFComponents
{
    # This section double-checks that all drivers and services are stopped before proceeding with uninstallation.
    # It iterates through each driver and service, retrieving its status, and if any service is found to be running, it throws an error.
    $allStopped = $true
    if (Get-Service "eBPFSvc" -ErrorAction SilentlyContinue) {
        $serviceStatus = (Get-Service "eBPFSvc").Status
        if ($serviceStatus -ne "Stopped") {
            Write-Log "eBPFSvc service is not stopped." -ForegroundColor Red
            $allStopped = $false
        }
        Write-Log "eBPFSvc service stopped." -ForegroundColor Green
    } else {
        Write-Log "'eBPFSvc' service is not present (i.e., release build), skipping stopping." -ForegroundColor Green
    }
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        if ($_.Value.IsDriver) {
            $driverStatus = (Get-Service $_.Key).Status
            if ($driverStatus -ne "Stopped") {
                Write-Log "$($_.Key) driver is not stopped." -ForegroundColor Red
                $allStopped = $false
            }
        }
    }
    if (-not $allStopped) {
        throw "One or more services are not stopped."
    }

    # Firstly, uninstall the extra drivers that are not installed by the MSI package.
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        if (-not $_.Value.InstalledByMsi) {
            Write-Log("Deleting $($_.Key) service...") -ForegroundColor Green
            sc.exe delete $_.Key 2>&1 | Write-Log
            if ($LASTEXITCODE -ne 0) {
                throw ("Failed to delete $($_.Key) service.")
            } else {
                Write-Log("$($_.Key) service deleted.") -ForegroundColor Green
            }
        }
    }

    # Clear export program info for the sample driver.
    Write-Log("Running 'export_program_info_sample.exe --clear'...")
    if (Test-Path -Path "export_program_info_sample.exe --clear") {
        .\export_program_info_sample.exe --clear
        if ($LASTEXITCODE -ne 0) {
            throw ("Failed to run 'export_program_info_sample.exe --clear'.")
        } else {
            Write-Log("'export_program_info_sample.exe --clear' succeeded.") -ForegroundColor Green
        }
    }
    Write-Log("Clearing export program info for the sample driver completed successfully!") -ForegroundColor Green

    # Uninstall the MSI package.
    $arguments = "/x $MsiPath /qn /norestart /l*v msi-uninstall.log"
    Write-Log("Uninstalling eBPF MSI package at 'msiexec.exe $arguments'...")
    $process = Start-Process -FilePath msiexec.exe -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -eq 0) {
        Write-Log("Uninstallation successful!") -ForegroundColor Green
    } else {
        Write-Log("Uninstallation FAILED. Exit code: $($process.ExitCode)") -ForegroundColor Red

        # For clear readability within the CICD pipeline and final uploaded log output,
        # read each line of the log file and print it (otherwise all the log content is printed as a single line).
        Write-Log("Contents of msi-uninstall.log:")
        Get-Content -Path "msi-uninstall.log" | ForEach-Object {
            Write-Log($_)
        }
        throw ("MSI uninstallation FAILED. Exit code: $($process.ExitCode).")
    }
    Write-Log("MSI uninstallation completed successfully!") -ForegroundColor Green

    # Stop KM tracing.
    $process = Start-Process -FilePath wpr.exe -ArgumentList "-cancel" -NoNewWindow -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        Write-Log("Failed to stop WPR session with error: $($process.ExitCode)")
    }
}
