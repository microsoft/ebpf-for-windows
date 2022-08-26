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
    .\eBPFSvc.exe install 2>&1 | Write-Log
    if ($LASTEXITCODE -ne 0) {
        throw ("Failed to create eBPF user mode service.")
    } else {
        Write-Log "eBPF user mode service created." -ForegroundColor Green
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
# Start service and drivers.
#
function Start-eBPFComponents
{
    param([parameter(Mandatory=$false)] [bool] $Tracing = $false)

    if ($Tracing) {
        Write-Log "Starting ETW tracing"
        Start-Process -FilePath "wpr.exe" -ArgumentList @("-start", "EbpfForWindows.wprp", "-filemode") -NoNewWindow -Wait
    }

    # Start drivers.
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        if (Test-Path -Path ("$BinaryPath\drivers\{0}" -f $_.Value)) {
            Start-Service $_.Name -ErrorAction Stop | Write-Log
            Write-Host ("{0} Driver started." -f $_.Name)
        }
    }

    # Start user mode service.
    Start-Service "eBPFSvc" -ErrorAction Stop | Write-Log
    Write-Host "eBPFSvc service started."
}

#
# Update eBPF store.
#
function Update-eBPFStore
{
    Write-Log "Clearing eBPF store"
    .\export_program_info.exe --clear

    Write-Log "Populating eBPF store"
    .\export_program_info.exe
}

function Install-eBPFComponents
{
    param([parameter(Mandatory=$false)] [bool] $Tracing = $false,
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
    Start-eBPFComponents -Tracing $Tracing

    ## TODO: Issue 1231, remove this step when this issue is fixed.
    # Update eBPF store.
    Update-eBPFStore
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
    .\export_program_info.exe --clear
    Remove-Item "$Env:systemroot\system32\drivers\*bpf*" -Force -ErrorAction Stop 2>&1 | Write-Log
    Remove-Item "$Env:systemroot\system32\*bpf*" -Force -ErrorAction Stop 2>&1 | Write-Log
    wpr.exe -cancel
}
