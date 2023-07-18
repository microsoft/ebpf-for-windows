# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ([parameter(Mandatory=$false)][string] $AdminTarget = "TEST_VM",
       [parameter(Mandatory=$false)][string] $StandardUserTarget = "TEST_VM_STANDARD",
       [parameter(Mandatory=$false)][string] $LogFileName = "TestLog.log",
       [parameter(Mandatory=$false)][string] $WorkingDirectory = $pwd.ToString(),
       [parameter(Mandatory=$false)][string] $TestExecutionJsonFileName = "test_execution.json",
       [parameter(Mandatory=$false)][bool] $Coverage = $false,
       [parameter(Mandatory=$false)][string] $SelfHostedRunnerName)

Push-Location $WorkingDirectory

$AdminTestVMCredential = Get-StoredCredential -Target $AdminTarget -ErrorAction Stop
$StandardUserTestVMCredential = Get-StoredCredential -Target $StandardUserTarget -ErrorAction Stop

# Load other utility modules.
Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
Import-Module .\vm_run_tests.psm1  -Force -ArgumentList ($AdminTestVMCredential.UserName, $AdminTestVMCredential.Password, $StandardUserTestVMCredential.UserName, $StandardUserTestVMCredential.Password, $WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue

# Read the test execution json.
$Config = Get-Content ("{0}\{1}" -f $PSScriptRoot, $TestExecutionJsonFileName) | ConvertFrom-Json
$BasicTest = $Config.BasicTest.$SelfHostedRunnerName

# Run tests on test VMs.
#foreach ($VM in $BasicTest) {
#    Invoke-CICDTestsOnVM -VMName $VM.Name -Coverage $Coverage
#}

# Run XDP Tests.
Invoke-XDPTestsOnVM $Config.MultiVMTest.$SelfHostedRunnerName

# Run Connect Redirect Tests.
Invoke-ConnectRedirectTestsOnVM $Config.MultiVMTest.$SelfHostedRunnerName $Config.ConnectRedirectTest.$SelfHostedRunnerName -UserType "Administrator"
#Invoke-ConnectRedirectTestsOnVM $Config.MultiVMTest.$SelfHostedRunnerName $Config.ConnectRedirectTest.$SelfHostedRunnerName -UserType "StandardUser"

# Stop eBPF components on test VMs.
foreach ($VM in $Config.MultiVMTest.$SelfHostedRunnerName) {
    Stop-eBPFComponentsOnVM -VMName $VM.Name
}

Pop-Location