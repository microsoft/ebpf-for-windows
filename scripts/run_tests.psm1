# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
       [Parameter(Mandatory=$True)] [string] $LogFileName)

Push-Location $WorkingDirectory

Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

# eBPF Ddrivers.
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
    sc.exe delete eBPFSvc.exe 2>&1 | Write-Log

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
    # Start drivers.
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        Start-Service $_.Name -ErrorAction Stop 2>&1 | Write-Log
    }

    # Start user mode service.
    Start-Service "eBPFSvc" -ErrorAction Stop 2>&1 | Write-Log
}

function Install-eBPF
{
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
    Stop-Service "eBPFSvc" -ErrorAction Stop 2>&1 | Write-Log

    # Stop the drivers.
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        Stop-Service $_.Name -ErrorAction Stop 2>&1 | Write-Log
    }
}

#
# Execute tests on VM.
#

function Invoke-Test
{
    param([string] $TestName,[bool] $VerboseLogs)

    Write-Log "Starting ETL tracing"
    Start-Process -FilePath "wpr.exe" -ArgumentList @("-start", "EbpfForWindows.wprp", "-filemode") -NoNewWindow -Wait

    Write-Log "Executing $Testname"

    # Execute Test.
    if ($VerboseLogs -eq $true) {
        &$TestName -s 2>&1 | Write-Log
    } else {
        &$TestName 2>&1 | Write-Log
    }

    # Check for errors.
    if ($LASTEXITCODE -ne 0) {
        throw ("$TestName failed.")
    } else {
        Write-Log "$TestName passed" -ForegroundColor Green
    }

    Write-Log "Stopping ETL tracing"
    Start-Process -FilePath "wpr.exe" -ArgumentList @("-stop", $TestName + ".etl") -NoNewWindow -Wait
}

function Invoke-CICDTests
{
    param([parameter(Mandatory=$true)] [bool] $VerboseLogs)

    try {

         $TestList = @(
            "unit_tests.exe",
            "ebpf_client.exe",
            "api_test.exe",
            "sample_ext_app.exe")

        foreach ($Test in $TestList) {
            Invoke-Test -TestName $Test -VerboseLogs $VerboseLogs
        }

        if ($Env:BUILD_CONFIGURATION -eq "Release") {
            Invoke-Test -TestName "ebpf_performance.exe" -VerboseLogs $VerboseLogs
        }
    } catch {
        # Do nothing.
    }

    # Stop the components, so that Driver Verifier can catch memory leaks etc.
    Stop-eBPFComponents
}