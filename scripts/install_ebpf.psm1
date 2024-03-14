# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
       [Parameter(Mandatory=$True)] [string] $LogFileName)

Push-Location $WorkingDirectory
Import-Module $PSScriptRoot\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

$VcRedistPath = Join-Path $WorkingDirectory "vc_redist.x64.exe"
$MsiPath = Join-Path $WorkingDirectory "ebpf-for-windows.msi"

# eBPF Drivers.
$EbpfDrivers =
@{
    "EbpfCore" = "ebpfcore.sys";
    "NetEbpfExt" = "netebpfext.sys";
    "SampleEbpfExt" = "sample_ebpf_ext.sys"
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
    # Install drivers.
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        New-Item -Path ("HKLM:\System\CurrentControlSet\Services\{0}\Parameters\Wdf" -f $_.Name) -Force -ErrorAction Stop
        New-ItemProperty -Path ("HKLM:\System\CurrentControlSet\Services\{0}\Parameters\Wdf" -f $_.Name) -Name "VerifierOn" -Value 1 -PropertyType DWord -Force -ErrorAction Stop
        New-ItemProperty -Path ("HKLM:\System\CurrentControlSet\Services\{0}\Parameters\Wdf" -f $_.Name) -Name "TrackHandles" -Value "*" -PropertyType MultiString -Force  -ErrorAction Stop
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
    # Stop user mode service.
    Stop-Service "eBPFSvc" -ErrorAction Ignore 2>&1 | Write-Log

    # Stop the drivers.
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
            exit 1
        }
        Write-Log("Cleaning up...")
        Remove-Item $VcRedistPath -Force
        Write-Log("Visual C++ Redistributable installation completed successfully!") -ForegroundColor Green
    } catch {
        Write-Log("An exception occurred while installing Visual C++ Redistributable: $_") -ForegroundColor Red
        exit 1
    }

    # Copy the VC debug runtime DLLs to the system32 directory,
    # so that debug versions of the MSI can be installed (i.e. export_program_info.exe will not fail).
    try {
        $system32Path = Join-Path $env:SystemRoot "System32"
        Write-Log("Copying VC debug runtime DLLs to the $system32Path directory...")
        $VCDebugRuntime | ForEach-Object {
            $sourcePath = Join-Path $WorkingDirectory $_
            $destinationPath = Join-Path $system32Path $_
            Write-Log("Copying '$sourcePath' to '$destinationPath'...")
            Copy-Item -Path $sourcePath -Destination $destinationPath -Force
        }
        Write-Log("VC debug runtime DLLs copied successfully!") -ForegroundColor Green
    }
    catch {
        Write-Log("An exception occurred while copying VC debug runtime DLLs: $_") -ForegroundColor Red
        exit 1
    }

    # Install the MSI package.
    try {
        $arguments = "/i $MsiPath ADDLOCAL=ALL /qn /norestart /l*vx msi-install.log"
        Write-Log("Installing the eBPF MSI package: 'msiexec.exe $arguments'...")
        $process = Start-Process -FilePath msiexec.exe -ArgumentList $arguments -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            Write-Log("MSI installation FAILED. Exit code: $($process.ExitCode)") -ForegroundColor Red
            $logContents = Get-Content -Path "msi-install.log" -ErrorAction SilentlyContinue
            if ($logContents) {
                Write-Log("Contents of msi-install.log:")
                Write-Log($logContents)
            } else {
                Write-Log("msi-install.log not found or empty.") -ForegroundColor Red
            }
            exit 1;
        }
        Write-Log("eBPF MSI installation completed successfully!") -ForegroundColor Green
    } catch {
        Write-Log("An error occurred while installing the MSI package: $_") -ForegroundColor Red
        exit 1;
    }

    # Debugging information.
    Write-Log("Querying the status of eBPF services...")
    sc.exe query ebpfcore | Write-Log
    sc.exe query netebpfext | Write-Log
    sc.exe query ebpfsvc | Write-Log

    # Optionally enable KMDF verifier and tag tracking.
    if ($KMDFVerifier) {
        Enable-KMDFVerifier
    }

    # Start KM tracing.
    Start-WPRTrace -KmTracing $KmTracing -KmTraceType $KmTraceType
}

function Uninstall-eBPFComponents
{
    # Uninstall the MSI package.
    Write-Log("Uninstalling eBPF MSI package at '$MsiPath'...")
    $process = Start-Process -FilePath msiexec.exe -ArgumentList "/x $MsiPath /qn /norestart /l*v msi-uninstall.log" -Wait -PassThru
    if ($process.ExitCode -eq 0) {
        Write-Log("Uninstallation successful!") -ForegroundColor Green
    } else {
        $exceptionMessage = "Uninstallation FAILED. Exit code: $($process.ExitCode)"
        Write-Log($exceptionMessage) -ForegroundColor Red
        $logContents = Get-Content -Path "msi-uninstall.log" -ErrorAction SilentlyContinue
        if ($logContents) {
            Write-Log("Contents of msi-uninstall.log:")
            Write-Log($logContents)
        } else {
            Write-Log("msi-uninstall.log not found or empty.") -ForegroundColor Red
        }
    }

    # Stop KM tracing.
    wpr.exe -cancel
}
