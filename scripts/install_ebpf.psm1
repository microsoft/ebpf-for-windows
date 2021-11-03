# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
       [Parameter(Mandatory=$True)] [string] $LogFileName)

Push-Location $WorkingDirectory

Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

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
    netsh delete helper "$Env:systemroot\system32\ebpfnetsh.dll"  2>&1 | Write-Log
}

#
# Install eBPF components.
#

function Register-eBPFComponents
{
    # Uinstall previous installations (if any).
    Unregister-eBPFComponents

    # Install drivers.
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        # New-Service does not support installing drivers.
        sc.exe create $_.Name type=kernel start=demand binpath=("$Env:systemroot\system32\drivers\{0}" -f $_.Value) 2>&1 | Write-Log
        if ($LASTEXITCODE -ne 0) {
            throw ("Failed to create $_.Name driver.")
        } else {
            Write-Log ("{0} driver created." -f $_.Name) -ForegroundColor Green
        }
    }

    # Install user mode service.
    eBPFSvc.exe install 2>&1 | Write-Log
    if ($LASTEXITCODE -ne 0) {
        throw ("Failed to create eBPF user mode service.")
    } else {
        Write-Log "eBPF user mode service created." -ForegroundColor Green
    }

    # Add the eBPF netsh helper.
    netsh add helper "$Env:systemroot\system32\ebpfnetsh.dll" 2>&1 | Write-Log
}

#
# Start service and drivers.
#
function Start-eBPFComponents
{
    Write-Log "Starting ETW tracing"
    Start-Process -FilePath "wpr.exe" -ArgumentList @("-start", "EbpfForWindows.wprp", "-filemode") -NoNewWindow -Wait

    # Start drivers.
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        Start-Service $_.Name -ErrorAction Stop | Write-Log
        Write-Host ("{0} Driver started." -f $_.Name)
    }

    # Start user mode service.
    Start-Service "eBPFSvc" -ErrorAction Stop | Write-Log
    Write-Host "eBPFSvc service started."
}

function Install-eBPFComponents
{
    # Stop eBPF Components
    Stop-eBPFComponents

    # Copy all binaries to system32.
    Copy-Item *.sys -Destination "$Env:systemroot\system32\drivers" -Force -ErrorAction Stop 2>&1 | Write-Log
    Copy-Item *.dll -Destination "$Env:systemroot\system32" -Force -ErrorAction Stop 2>&1 | Write-Log
    Copy-Item *.exe -Destination "$Env:systemroot\system32" -Force -ErrorAction Stop 2>&1 | Write-Log

    # Register all components.
    Register-eBPFComponents

    # Start all components.
    Start-eBPFComponents
}

function Stop-eBPFComponents
{
    # Stop user mode service.
    Stop-Service "eBPFSvc" -ErrorAction Ignore 2>&1 | Write-Log

    # Stop the drivers.
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        Stop-Service $_.Name -ErrorAction Ignore 2>&1 | Write-Log
    }

    $EtlFile = $LogFileName.Substring(0, $LogFileName.IndexOf('.')) + ".etl";
    Write-Log ("Stopping ETW tracing, creating file: " + $EtlFile)
    Start-Process -FilePath "wpr.exe" -ArgumentList @("-stop", $EtlFile) -NoNewWindow -Wait
}