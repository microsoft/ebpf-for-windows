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
Import-Module .\vm_run_tests.psm1  -Force -ArgumentList ($TestVMCredential.UserName, $TestVMCredential.Password, $WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue

# Read the config json.
$Config = Get-Content ("{0}\{1}" -f $PSScriptRoot, $VMListJsonFileName) | ConvertFrom-Json
$VMList = $Config.VMList

# Launch test script on test VMs.
foreach ($VM in $VMList) {
    Invoke-CICDTestsOnVM -VMName $VM.Name
}

Pop-Location