# Copyright (c) eBPF for Windows contributors
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

# Wait for all VMs to be in ready state, in case the test run caused any VM to crash.
Wait-AllVMsToInitialize `
    -VMList $VMList `
    -UserName $TestVMCredential.UserName `
    -AdminPassword $TestVMCredential.Password

# Check if we're here after a crash (we are if c:\windows\memory.dmp exists on the VM).  If so,
# we need to skip the stopping of the drivers as they may be in a wedged state as a result of the
# crash.  We will be restoring the VM's 'baseline' snapshot next, so the step is redundant anyway.
foreach ($VM in $VMList) {
    $VMName = $VM.Name
    $DumpFound = Invoke-Command `
        -VMName $VMName `
        -Credential $TestVMCredential `
        -ScriptBlock {
            Test-Path -Path "c:\windows\memory.dmp" -PathType leaf
        }

    if ($DumpFound -eq $True) {
        Write-Host "`n=== Post-crash reboot detected on VM $VMName ===`n"
    } else {
        # Stop eBPF Components on the test VM. (Un-install is not necessary.)
        # We *MUST* be able to stop all drivers cleanly after a test.  Failure to do so indicates a fatal bug in
        # one/some of the ebpf driver-set.
        Stop-eBPFComponentsOnVM -VMName $VMname -ErrorAction Stop
    }
}

# Import logs from VMs.
Import-ResultsFromVM -VMList $VMList -KmTracing $KmTracing

# Stop the VMs.
Stop-AllVMs -VMList $VMList
Restore-AllVMs -VMList $VMList

Pop-Location
