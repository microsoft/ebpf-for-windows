# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
       [Parameter(Mandatory=$True)] [string] $LogFileName)

Push-Location $WorkingDirectory

Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
Import-Module .\install_ebpf.psm1 -Force -ArgumentList ($WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue

# eBPF drivers.
$EbpfDrivers =
@{
    "EbpfCore" = "ebpfcore.sys";
    "NetEbpfExt" = "netebpfext.sys";
    "SampleEbpfExt" = "sample_ebpf_ext.sys"
}

#
# Execute tests on VM.
#

function Invoke-Test
{
    param([string] $TestName,[bool] $VerboseLogs)

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
        Write-Log "One or more tests failed."
        throw
    }
}