# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ([parameter(Mandatory=$false)][string] $AdminTarget = "TEST_VM",
       [parameter(Mandatory=$false)][string] $StandardUserTarget = "TEST_VM_STANDARD",
       [parameter(Mandatory=$false)][string] $LogFileName = "TestLog.log",
       [parameter(Mandatory=$false)][string] $WorkingDirectory = $pwd.ToString(),
       [parameter(Mandatory=$false)][string] $TestExecutionJsonFileName = "test_execution.json",
       [parameter(Mandatory=$false)][bool] $Coverage = $false,
       [parameter(Mandatory=$false)][string] $TestMode = "CI/CD",
       [parameter(Mandatory=$false)][string[]] $Options = @("None"),
       [parameter(Mandatory=$false)][string] $SelfHostedRunnerName)

Push-Location $WorkingDirectory

$AdminTestVMCredential = Get-StoredCredential -Target $AdminTarget -ErrorAction Stop
$StandardUserTestVMCredential = Get-StoredCredential -Target $StandardUserTarget -ErrorAction Stop

# Load other utility modules.
Import-Module $PSScriptRoot\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
Import-Module $PSScriptRoot\vm_run_tests.psm1  -Force -ArgumentList ($AdminTestVMCredential.UserName, $AdminTestVMCredential.Password, $StandardUserTestVMCredential.UserName, $StandardUserTestVMCredential.Password, $WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue

# Read the test execution json.
$Config = Get-Content ("{0}\{1}" -f $PSScriptRoot, $TestExecutionJsonFileName) | ConvertFrom-Json
$VMList = $Config.VMMap.$SelfHostedRunnerName

# Run tests on test VMs.
foreach ($VM in $VMList) {
    Invoke-CICDTestsOnVM `
        -VMName $VM.Name `
        -Coverage $Coverage `
        -TestMode $TestMode `
        -Options $Options
}

# This script is used to execute the various kernel mode tests. The required behavior is selected by the $TestMode
# parameter.
if ($TestMode -eq "CI/CD") {

    # Run XDP Tests.
    Invoke-XDPTestsOnVM $Config.Interfaces $VMList[0].Name

    # Run Connect Redirect Tests.
    Invoke-ConnectRedirectTestsOnVM $Config.Interfaces $Config.ConnectRedirectTest `
        -UserType "Administrator" $VMList[0].Name
    Invoke-ConnectRedirectTestsOnVM $Config.Interfaces $Config.ConnectRedirectTest `
        -UserType "StandardUser" $VMList[0].Name
}

# Stop eBPF components on test VMs.
foreach ($VM in $VMList) {
    Stop-eBPFComponentsOnVM -VMName $VM.Name
}

Pop-Location