# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ([parameter(Mandatory=$false)][string] $Target = "TEST_VM",
       [parameter(Mandatory=$true)][bool] $KmTracing,
       [parameter(Mandatory=$false)][string] $LogFileName = "TestLog.log",
       [parameter(Mandatory=$false)][string] $WorkingDirectory = $pwd.ToString(),
       [parameter(Mandatory=$false)][string] $TestExecutionJsonFileName = "test_execution.json",
       [parameter(Mandatory=$false)][string] $SelfHostedRunnerName)

Push-Location $WorkingDirectory

$TestVMCredential = Get-StoredCredential -Target $Target -ErrorAction Stop

# Load other utility modules.
Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
Import-Module .\config_test_vm.psm1 -Force -ArgumentList ($TestVMCredential.UserName, $TestVMCredential.Password, $WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue
Import-Module .\install_ebpf.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue

# Read the test execution json.
$TestExecutionConfig = Get-Content ("{0}\{1}" -f $PSScriptRoot, $TestExecutionJsonFileName) | ConvertFrom-Json
$VMList = $TestExecutionConfig.VMMap.$SelfHostedRunnerName

# Import logs from VMs.
Import-ResultsFromVM -VMList $VMList -KmTracing $KmTracing

# Uninstall eBPF Components on the test VM.
foreach($VM in $VMList) {
       $VMName = $VM.Name
       Write-Host "Uninstalling eBPF components on VM $VMName..."
       Uninstall-eBPFComponentsOnVM -VMName $VMname -WorkingDirectory $WorkingDirectory -ErrorAction Stop
}

# Stop the VMs.
Stop-AllVMs -VMList $VMList
Restore-AllVMs -VMList $VMList

Pop-Location