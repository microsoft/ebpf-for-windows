# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
       [Parameter(Mandatory=$True)] [string] $LogFileName)

Push-Location $WorkingDirectory

$BinaryPath = "$Env:systemroot\system32";

Import-Module $PSScriptRoot\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

# eBPF Drivers.
$EbpfDrivers =
@{
    "EbpfCore" = "ebpfcore.sys";
    "NetEbpfExt" = "netebpfext.sys";
    "SampleEbpfExt" = "sample_ebpf_ext.sys"
}

#
# Uninstall eBPF components.
#
function Unregister-eBPFComponents
{
    # Uninstall drivers.
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        # New-Service does not support installing drivers.
        sc.exe delete $_.Name 2>&1 | Write-Log
    }

    # Uninstall user mode service.
    sc.exe delete eBPFSvc 2>&1 | Write-Log

    # Delete the eBPF netsh helper.
    netsh delete helper ebpfnetsh.dll 2>&1 | Write-Log

    # Execute export_program_info
    if (Test-Path -Path "export_program_info.exe") {
        .\export_program_info.exe --clear
        if ($LASTEXITCODE -ne 0) {
            throw ("Failed to run 'export_program_info.exe --clear'.");
        } else {
            Write-Log "'export_program_info.exe --clear' succeeded." -ForegroundColor Green
        }
    }
}

#
# Install eBPF components.
#

function Register-eBPFComponents
{
    # Uninstall previous installations (if any).
    Unregister-eBPFComponents

    # Install drivers.
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        if (Test-Path -Path ("$BinaryPath\{0}" -f $_.Value)) {
            Write-Log ("Installing {0}..." -f $_.Name) -ForegroundColor Green
            # New-Service does not support installing drivers.
            sc.exe create $_.Name type=kernel start=demand binpath=("$BinaryPath\{0}" -f $_.Value) 2>&1 | Write-Log
            if ($LASTEXITCODE -ne 0) {
                throw ("Failed to create $_.Name driver.")
            } else {
                Write-Log ("{0} driver created." -f $_.Name) -ForegroundColor Green
            }
        }
        if (Test-Path -Path ("$BinaryPath\drivers\{0}" -f $_.Value)) {
            Write-Log ("Installing {0}..." -f $_.Name) -ForegroundColor Green
            # New-Service does not support installing drivers.
            sc.exe create $_.Name type=kernel start=demand binpath=("$BinaryPath\drivers\{0}" -f $_.Value) 2>&1 | Write-Log
            if ($LASTEXITCODE -ne 0) {
                throw ("Failed to create $_.Name driver.")
            } else {
                Write-Log ("{0} driver created." -f $_.Name) -ForegroundColor Green
            }
        }
    }

    # Install user mode service.
    if (Test-Path -Path "ebpfsvc.exe") {
        .\eBPFSvc.exe install 2>&1 | Write-Log
        if ($LASTEXITCODE -ne 0) {
            throw ("Failed to create eBPF user mode service.")
        } else {
            Write-Log "eBPF user mode service created." -ForegroundColor Green
        }
    }

    # Add the eBPF netsh helper.
    netsh add helper ebpfnetsh.dll 2>&1 | Write-Log
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

#
# Start service and drivers.
#
function Start-eBPFComponents
{
    param([parameter(Mandatory=$true)] [bool] $KmTracing,
          [parameter(Mandatory=$true)] [string] $KmTraceType)

    Start-WPRTrace -KmTracing $KmTracing -KmTraceType $KmTraceType

    # Start drivers.
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        if (Test-Path -Path ("$BinaryPath\drivers\{0}" -f $_.Value)) {
            Start-Service $_.Name -ErrorAction Stop | Write-Log
            Write-Host ("{0} Driver started." -f $_.Name)
        }
    }

    if (Test-Path -Path "ebpfsvc.exe") {
        # Start user mode service.
        Start-Service "eBPFSvc" -ErrorAction Stop | Write-Log
        Write-Host "eBPFSvc service started."
    }
}

function Install-eBPFComponents
{
    param([parameter(Mandatory=$true)] [bool] $KmTracing,
          [parameter(Mandatory=$true)] [string] $KmTraceType,
          [parameter(Mandatory=$false)] [bool] $KMDFVerifier = $false)

    # Stop eBPF Components
    Stop-eBPFComponents

    # Copy all binaries to system32.
    Copy-Item *.sys -Destination "$Env:systemroot\system32\drivers" -Force -ErrorAction Stop 2>&1 | Write-Log
    if (Test-Path -Path "drivers") {
        Copy-Item drivers\*.sys -Destination "$Env:systemroot\system32\drivers" -Force -ErrorAction Stop 2>&1 | Write-Log
    }
    if (Test-Path -Path "testing\testing") {
        Copy-Item testing\testing\*.sys -Destination "$Env:systemroot\system32\drivers" -Force -ErrorAction Stop 2>&1 | Write-Log
    }
    Copy-Item *.dll -Destination "$Env:systemroot\system32" -Force -ErrorAction Stop 2>&1 | Write-Log
    Copy-Item *.exe -Destination "$Env:systemroot\system32" -Force -ErrorAction Stop 2>&1 | Write-Log

    # Register all components.
    Register-eBPFComponents

    if ($KMDFVerifier) {
        # Enable KMDF verifier and tag tracking.
        Enable-KMDFVerifier
    }

    # Start all components.
    Start-eBPFComponents -KmTracing $KmTracing -KmTraceType $KmTraceType
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
    Stop-eBPFComponents
    Unregister-eBPFComponents
    Remove-Item "$Env:systemroot\system32\drivers\*bpf*" -Force -ErrorAction Stop 2>&1 | Write-Log
    Remove-Item "$Env:systemroot\system32\*bpf*" -Force -ErrorAction Stop 2>&1 | Write-Log
    wpr.exe -cancel
}
