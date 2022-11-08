# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ([parameter(Mandatory=$false)][string] $Target = "TEST_VM",
       [parameter(Mandatory=$false)][string] $LogFileName = "TestLog.log",
       [parameter(Mandatory=$false)][string] $WorkingDirectory = $pwd.ToString(),
       [parameter(Mandatory=$false)][string] $TestExecutionJsonFileName = "test_execution.json",
       [parameter(Mandatory=$false)][bool] $Coverage = $true)

Push-Location $WorkingDirectory

$TestVMCredential = Get-StoredCredential -Target $Target -ErrorAction Stop

# Load other utility modules.
Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
Import-Module .\vm_run_tests.psm1  -Force -ArgumentList ($TestVMCredential.UserName, $TestVMCredential.Password, $WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue

# Read the test execution json.
$Config = Get-Content ("{0}\{1}" -f $PSScriptRoot, $TestExecutionJsonFileName) | ConvertFrom-Json
$BasicTest = $Config.BasicTest

# Run tests on test VMs.
foreach ($VM in $BasicTest) {
    Invoke-CICDTestsOnVM -VMName $VM.Name -Coverage $Coverage
}

# Run XDP Tests.
Invoke-XDPTestsOnVM $Config.MultiVMTest

# Run Connect Redirect Tests
Invoke-ConnectRedirectTestsOnVM $Config.MultiVMTest

# Stop eBPF components on test VMs.
foreach ($VM in $Config.MultiVMTest) {
    Stop-eBPFComponentsOnVM -VMName $VM.Name
}

Pop-Location