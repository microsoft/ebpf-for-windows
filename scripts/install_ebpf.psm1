# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
       [Parameter(Mandatory=$True)] [string] $LogFileName)

Push-Location $WorkingDirectory
Import-Module $PSScriptRoot\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

$VcRedistPath = Join-Path $WorkingDirectory "vc_redist.x64.exe"
$MsiPath = Join-Path $WorkingDirectory "ebpf-for-windows.msi"
$MsiInstallPath = Join-Path $env:ProgramFiles "ebpf-for-windows"

Write-Host "install_ebpf - Modules imported"

# eBPF Drivers.
$EbpfDrivers =
@{
    "EbpfCore" = "ebpfcore.sys";
    "NetEbpfExt" = "netebpfext.sys";
    "SampleEbpfExt" = "sample_ebpf_ext.sys"
}

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

function Install-eBPFComponents
{
    param([parameter(Mandatory=$true)] [bool] $KmTracing,
          [parameter(Mandatory=$true)] [string] $KmTraceType,
          [parameter(Mandatory=$false)] [bool] $KMDFVerifier = $false)

    # Install the Visual C++ Redistributable.
    try {
        Write-Host "Installing Visual C++ Redistributable from '$VcRedistPath'..."
        $process = Start-Process -FilePath $VcRedistPath -ArgumentList "/quiet", "/norestart" -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            Write-Host "Visual C++ Redistributable installation FAILED. Exit code: $($process.ExitCode)"
            exit 1
        }
        Write-Host "Cleaning up..."
        Remove-Item $VcRedistPath -Force
        Write-Host "Visual C++ Redistributable installation completed successfully!"
    } catch {
        Write-Host "An exception occurred while installing Visual C++ Redistributable: $_"
        exit 1
    }

    # Install the MSI package.
    try {
        $arguments = "/i $MsiPath /qn /norestart /l*v msi-install.log ADDLOCAL=ADDLOCAL=eBPF_Runtime_Components,eBPF_Runtime_Components_JIT"
        Write-Host "Installing the eBPF MSI package with arguments: '$arguments'..."
        $process = Start-Process -FilePath msiexec.exe -ArgumentList $arguments -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            Write-Host "MSI installation FAILED. Exit code: $($process.ExitCode)"
            $logContents = Get-Content -Path "msi-install.log" -ErrorAction SilentlyContinue
            if ($logContents) {
                Write-Host "Contents of msi-install.log:"
                Write-Host $logContents
            } else {
                Write-Host "msi-install.log not found or empty."
            }
            exit 1;
        }
        Write-Host "eBPF MSI installation completed successfully!"
    } catch {
        Write-Host "An error occurred while installing the MSI package: $_"
        exit 1;
    }

    # Optionally enable KMDF verifier and tag tracking.
    if ($KMDFVerifier) {
        Enable-KMDFVerifier
    }

    # Start KM tracing.
    Start-WPRTrace -KmTracing $KmTracing -KmTraceType $KmTraceType
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

function Uninstall-eBPFComponents
{
    # Uninstall the MSI package.
    Write-Host "Uninstalling eBPF MSI package at '$MsiPath'..."
    $process = Start-Process -FilePath msiexec.exe -ArgumentList "/x $MsiPath /qn /norestart /log msi-uninstall.log" -Wait -PassThru
    if ($process.ExitCode -eq 0) {
        Write-Host "Uninstallation successful!"
    } else {
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

    # Stop KM tracing.
    wpr.exe -cancel
}
