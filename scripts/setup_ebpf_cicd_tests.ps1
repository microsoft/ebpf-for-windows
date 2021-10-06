# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ([parameter(Mandatory=$false)][string] $Target = "TEST_VM",
       [parameter(Mandatory=$false)][string] $LogFileName = "TestLog.log",
       [parameter(Mandatory=$false)][string] $WorkingDirectory = $pwd.ToString(),
       [parameter(Mandatory=$false)][string] $VMListJsonFileName = "vm_list.json")

Push-Location $WorkingDirectory

$TestVMCredential = Get-StoredCredential -Target $Target -ErrorAction Stop

# Load other utility modules.
Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
Import-Module .\config_test_vm.psm1 -Force -ArgumentList ($TestVMCredential.UserName, $TestVMCredential.Password, $WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue

# Read the config json.
$Config = Get-Content ("{0}\{1}" -f $PSScriptRoot, $VMListJsonFileName) | ConvertFrom-Json
$VMList = $Config.VMList

# Delete old log files if any.
Remove-Item "$PSScriptRoot\$LogFileName" -ErrorAction SilentlyContinue
foreach($VM in $VMList) {
    $VMName = $VM.Name
    Remove-Item ("$PSScriptRoot\{0}_{1}" -f $VMName, $LogFileName) -ErrorAction SilentlyContinue
}
Remove-Item ".\TestLogs" -Recurse -Confirm:$false -ErrorAction SilentlyContinue

# Get all VMs to ready state.
Initialize-AllVMs -VMList $VMList

# Export build artifacts to the test VMs.
Export-BuildArtifactsToVMs -VMList $VMList

# Install eBPF Components on the test VM.
foreach($VM in $VMList) {
    $VMName = $VM.Name
    Install-eBPFComponentsOnVM -VMName $VMname
}

Pop-Location