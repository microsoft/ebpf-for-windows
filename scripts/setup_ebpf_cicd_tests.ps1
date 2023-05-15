# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ([parameter(Mandatory=$false)][string] $Target = "TEST_VM",
       [parameter(Mandatory=$false)][string] $LogFileName = "TestLog.log",
       [parameter(Mandatory=$false)][string] $WorkingDirectory = $pwd.ToString(),
       [parameter(Mandatory=$false)][string] $VMListJsonFileName = "vm_list.json",
       [parameter(Mandatory=$false)][string] $TestExecutionJsonFileName = "test_execution.json")

Push-Location $WorkingDirectory

$TestVMCredential = Get-StoredCredential -Target $Target -ErrorAction Stop

# Load other utility modules.
Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
Import-Module .\config_test_vm.psm1 -Force -ArgumentList ($TestVMCredential.UserName, $TestVMCredential.Password, $WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue

# Read the config json.
$Config = Get-Content ("{0}\{1}" -f $PSScriptRoot, $VMListJsonFileName) | ConvertFrom-Json
$VMList = $Config.VMList

# Read the test execution json.
$TestExecutionConfig = Get-Content ("{0}\{1}" -f $PSScriptRoot, $TestExecutionJsonFileName) | ConvertFrom-Json
$MultiVMTestConfig = $TestExecutionConfig.MultiVMTest

# Delete old log files if any.
Remove-Item "$env:TEMP\$LogFileName" -ErrorAction SilentlyContinue
foreach($VM in $VMList) {
    $VMName = $VM.Name
    Remove-Item $env:TEMP\$LogFileName -ErrorAction SilentlyContinue
}
Remove-Item ".\TestLogs" -Recurse -Confirm:$false -ErrorAction SilentlyContinue

# Get all VMs to ready state.
Initialize-AllVMs -VMList $VMList -ErrorAction Stop

# Download the release artifacts for regression tests.
Get-RegressionTestArtifacts

# Export build artifacts to the test VMs.
Export-BuildArtifactsToVMs -VMList $VMList -ErrorAction Stop

# Configure network adapters on VMs.
Initialize-NetworkInterfacesOnVMs $MultiVMTestConfig -ErrorAction Stop

# Install eBPF Components on the test VM.
foreach($VM in $VMList) {
    $VMName = $VM.Name
    Install-eBPFComponentsOnVM -VMName $VMname -ErrorAction Stop
}

Pop-Location
