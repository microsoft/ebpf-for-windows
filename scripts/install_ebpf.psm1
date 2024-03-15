# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
       [Parameter(Mandatory=$True)] [string] $LogFileName)

Push-Location $WorkingDirectory
Import-Module $PSScriptRoot\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

$VcRedistPath = Join-Path $WorkingDirectory "vc_redist.x64.exe"
$MsiPath = Join-Path $WorkingDirectory "ebpf-for-windows.msi"

# eBPF Drivers.
$EbpfDrivers = @{
    "EbpfCore" = [PSCustomObject]@{
        "Name" = "ebpfcore.sys"
        "IsDriver" = $true
        "InstalledByMsi" = $true
    }
    "NetEbpfExt" = [PSCustomObject]@{
        "Name" = "netebpfext.sys"
        "IsDriver" = $true
        "InstalledByMsi" = $true
    }
    "SampleEbpfExt" = [PSCustomObject]@{
        "Name" = "sample_ebpf_ext.sys"
        "IsDriver" = $true
        "InstalledByMsi" = $false
    }
    "EbpfSvc" = [PSCustomObject]@{
        "Name" = "ebpfsvc.exe"
        "IsDriver" = $false
        "InstalledByMsi" = $true
    }
}

# eBPF Debug Runtime DLLs.
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

function Enable-KMDFVerifier
{
    # Enable KMDF verifier for the eBPF drivers.
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        if ($_.Value.IsDriver) {
            Write-Log ("Enabling KMDF verifier for $($_.Key)...")
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

    Write-Log ("kernel mode ETW tracing: " + $KmTracing)

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
            Write-log ("wpr.exe start ETL trace failed. Exit code: " + $ProcInfo.ExitCode)
            Write-log "wpr.exe (start) error output: "
            foreach ($line in get-content -Path .\StdErr.txt) {
                write-log ( "`t" + $line)
            }
            throw "Start ETL trace failed."
        }
        Write-Log ("Start ETL trace success. wpr.exe exit code: " + $ProcInfo.ExitCode + "`n")

        Write-Log "Query ETL tracing status after trace start"
        $ProcInfo = Start-Process -FilePath "wpr.exe" `
            -ArgumentList "-status profiles collectors -details" `
            -NoNewWindow -Wait -PassThru `
            -RedirectStandardOut .\StdOut.txt -RedirectStandardError .\StdErr.txt
        if ($ProcInfo.ExitCode -ne 0) {
            Write-log ("wpr.exe query ETL trace status failed. Exit code: " + $ProcInfo.ExitCode)
            Write-log "wpr.exe (query) error output: "
            foreach ($line in get-content -Path .\StdErr.txt) {
                write-log ( "`t" + $line)
            }
            throw "Query ETL trace status failed."
        } else {
            Write-log "wpr.exe (query) results: "
            foreach ($line in get-content -Path .\StdOut.txt) {
                write-log ( "  `t" + $line)
            }
        }
        Write-Log ("Query ETL trace status success. wpr.exe exit code: " + $ProcInfo.ExitCode + "`n" )
    }
}

function Stop-eBPFComponents
{
    # First, stop user mode service, so that EbpfCore does not hang on stop.
    Stop-Service "eBPFSvc" -ErrorAction Ignore 2>&1 | Write-Log

     # Stop the drivers and services.
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        Stop-Service $_.Name -ErrorAction Ignore 2>&1 | Write-Log
    }
}

function Install-eBPFComponents
{
    param([parameter(Mandatory=$true)] [bool] $KmTracing,
          [parameter(Mandatory=$true)] [string] $KmTraceType,
          [parameter(Mandatory=$false)] [bool] $KMDFVerifier = $false)

    # Install the Visual C++ Redistributable (Release version, which is required for the MSI installation).
    try {
        Write-Log("Installing Visual C++ Redistributable from '$VcRedistPath'...")
        $process = Start-Process -FilePath $VcRedistPath -ArgumentList "/quiet", "/norestart" -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            Write-Log("Visual C++ Redistributable installation FAILED. Exit code: $($process.ExitCode)") -ForegroundColor Red
            throw ("Visual C++ Redistributable installation FAILED. Exit code: $($process.ExitCode)")
        }
        Write-Log("Cleaning up...")
        Remove-Item $VcRedistPath -Force
        Write-Log("Visual C++ Redistributable installation completed successfully!") -ForegroundColor Green
    } catch {
        Write-Log("An exception occurred while installing Visual C++ Redistributable: $_") -ForegroundColor Red
        throw ("An exception occurred while installing Visual C++ Redistributable: $_")
    }

    # Copy the VC debug runtime DLLs to the system32 directory,
    # so that debug versions of the MSI can be installed (i.e. export_program_info.exe will not fail).
    try {
        Write-Log("Copying VC debug runtime DLLs to the $system32Path directory...")
        # Test is the VC debuf runtime DLLs are present in the working directory (indicating a debug build).
        $VCDebugRuntime = $VCDebugRuntime | Where-Object { Test-Path (Join-Path $WorkingDirectory $_) }
        if (-not $VCDebugRuntime) {
            Write-Log("VC debug runtime DLLs not found in the working directory (i.e. release build). Skipping this step.") -ForegroundColor Yellow
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
    }
    catch {
        Write-Log("An exception occurred while copying VC debug runtime DLLs: $_") -ForegroundColor Red
        throw ("An exception occurred while copying VC debug runtime DLLs: $_")
    }

    # Install the MSI package.
    try {
        $arguments = "/i $MsiPath ADDLOCAL=ALL /qn /norestart /l*v msi-install.log"
        Write-Log("Installing the eBPF MSI package: 'msiexec.exe $arguments'...")
        $process = Start-Process -FilePath msiexec.exe -ArgumentList $arguments -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            Write-Log("MSI installation FAILED. Exit code: $($process.ExitCode)") -ForegroundColor Red

            # For clear readability within the CICD pipeline and final uploaded log output,
            # read each line of the log file and print it (otherwise all the log content is printed as a single line).
            Write-Log("Contents of msi-install.log:")
            Get-Content -Path "msi-install.log" | ForEach-Object {
                Write-Log($_)
            }
            throw ("MSI installation FAILED. Exit code: $($process.ExitCode)")
        }
        Write-Log("eBPF MSI installation completed successfully!") -ForegroundColor Green
    } catch {
        Write-Log("An error occurred while installing the MSI package: $_") -ForegroundColor Red
        throw ("An error occurred while installing the MSI package: $_")
    }

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

            Write-Log ("Installing $($_.Key)...") -ForegroundColor Green
            $createServiceOutput = sc.exe create $_.Key type=kernel start=demand binpath=$driverPath 2>&1
            Write-Log $createServiceOutput

            if ($LASTEXITCODE -ne 0) {
                throw ("Failed to create $($_.Key) driver.")
            } else {
                Write-Log ("$($_.Key) driver created.") -ForegroundColor Green

                # Start the service
                Write-Log ("Starting $($_.Key) service...") -ForegroundColor Green
                $startServiceOutput = sc.exe start $_.Key 2>&1
                Write-Log $startServiceOutput

                if ($LASTEXITCODE -ne 0) {
                    throw ("Failed to start $($_.Key) service.")
                } else {
                    Write-Log ("$($_.Key) service started.") -ForegroundColor Green
                }
            }
        }
    }

    # Export program info for the sample driver.
    Write-Log("Running 'export_program_info_sample.exe'...")
    if (Test-Path -Path "export_program_info_sample.exe") {
        .\export_program_info_sample.exe
        if ($LASTEXITCODE -ne 0) {
            throw ("Failed to run 'export_program_info_sample.exe'.");
        } else {
            Write-Log "'export_program_info_sample.exe' succeeded." -ForegroundColor Green
        }
    }

    # Debugging information.
    Write-Log("Querying the status of eBPF drivers and services...")
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        sc.exe query $_.Key | Write-Log
    }

    # Optionally enable KMDF verifier and tag tracking.
    if ($KMDFVerifier) {
        Enable-KMDFVerifier
    }

    # Start KM tracing.
    Start-WPRTrace -KmTracing $KmTracing -KmTraceType $KmTraceType
}

function Uninstall-eBPFComponents
{
    # Firstly, uninstall the extra drivers that are not installed by the MSI package.
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        if (-not $_.Value.InstalledByMsi) {
            # Stop the service
            Write-Log ("Stopping $($_.Key) service...") -ForegroundColor Green
            $stopServiceOutput = sc.exe stop $_.Key 2>&1
            Write-Log $stopServiceOutput

            if ($LASTEXITCODE -ne 0) {
                Write-Log ("Failed to stop $($_.Key) service.") -ForegroundColor Red
            } else {
                Write-Log ("$($_.Key) service stopped.") -ForegroundColor Green

                # Delete the service
                Write-Log ("Deleting $($_.Key) service...") -ForegroundColor Green
                $deleteServiceOutput = sc.exe delete $_.Key 2>&1
                Write-Log $deleteServiceOutput

                if ($LASTEXITCODE -ne 0) {
                    Write-Log ("Failed to delete $($_.Key) service.") -ForegroundColor Red
                } else {
                    Write-Log ("$($_.Key) service deleted.") -ForegroundColor Green
                }
            }

            # Check if the driver file exists and delete it
            $driverPath = if (Test-Path -Path ("$pwd\{0}" -f $_.Value.Name)) {
                "$pwd\{0}" -f $_.Value.Name
            } elseif (Test-Path -Path ("$pwd\drivers\{0}" -f $_.Value.Name)) {
                "$pwd\drivers\{0}" -f $_.Value.Name
            }

            if ($driverPath -ne $null) {
                Write-Log ("Deleting driver file: $driverPath") -ForegroundColor Green
                Remove-Item -Path $driverPath -Force -ErrorAction SilentlyContinue
            } else {
                Write-Log ("Driver file not found for $($_.Key).") -ForegroundColor Red
            }
        }
    }

    # Uninstall the MSI package.
    Write-Log("Uninstalling eBPF MSI package at '$MsiPath'...")
    $process = Start-Process -FilePath msiexec.exe -ArgumentList "/x $MsiPath /qn /norestart /l*v msi-uninstall.log" -Wait -PassThru
    if ($process.ExitCode -eq 0) {
        Write-Log("Uninstallation successful!") -ForegroundColor Green
    } else {
        $exceptionMessage = "Uninstallation FAILED. Exit code: $($process.ExitCode)"
        Write-Log($exceptionMessage) -ForegroundColor Red

        # For clear readability within the CICD pipeline and final uploaded log output,
        # read each line of the log file and print it (otherwise all the log content is printed as a single line).
        Write-Log("Contents of msi-uninstall.log:")
        Get-Content -Path "msi-uninstall.log" | ForEach-Object {
            Write-Log($_)
        }
    }

    # Stop KM tracing.
    wpr.exe -cancel
}
