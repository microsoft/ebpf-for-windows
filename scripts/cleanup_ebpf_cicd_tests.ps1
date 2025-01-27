# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ([parameter(Mandatory=$false)][string] $Target = "TEST_VM",
       [parameter(Mandatory=$false)][bool] $KmTracing = $true,
       [parameter(Mandatory=$false)][string] $LogFileName = "TestLog.log",
       [parameter(Mandatory=$false)][string] $WorkingDirectory = $pwd.ToString(),
       [parameter(Mandatory=$false)][string] $TestExecutionJsonFileName = "test_execution.json",
       [parameter(Mandatory=$false)][string] $SelfHostedRunnerName = [System.Net.Dns]::GetHostName(),
       [Parameter(Mandatory = $false)][int] $TestJobTimeout = (30*60))

Push-Location $WorkingDirectory

Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
if ($SelfHostedRunnerName -eq "1ESRunner") {
    Write-Log "Fetching the test VM credential using target: $Target"
    $TestVMCredential = Retrieve-StoredCredential -Target $Target
    if ($null -eq $TestVMCredential) {
        ThrowWithErrorMessage "Failed to retrieve the test VM credential."
    } else {
        Write-Log "Successfully retrieved the test VM credential."
    }
} else {
    $TestVMCredential = Get-StoredCredential -Target $Target -ErrorAction Stop
}

# Read the test execution json.
$Config = Get-Content ("{0}\{1}" -f $PSScriptRoot, $TestExecutionJsonFileName) | ConvertFrom-Json

$Job = Start-Job -ScriptBlock {
    param ([Parameter(Mandatory = $True)] [PSCredential] $TestVMCredential,
           [Parameter(Mandatory = $true)] [PSCustomObject] $Config,
           [Parameter(Mandatory = $true)] [string] $SelfHostedRunnerName,
           [parameter(Mandatory = $true)] [string] $LogFileName,
           [parameter(Mandatory = $true)] [string] $WorkingDirectory = $pwd.ToString(),
           [parameter(Mandatory = $true)] [bool] $KmTracing
    )
    Push-Location $WorkingDirectory

    # Load other utility modules.
    Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
    Import-Module .\config_test_vm.psm1 -Force -ArgumentList ($TestVMCredential.UserName, $TestVMCredential.Password, $WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue

    $VMList = $Config.VMMap.$SelfHostedRunnerName
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
            Write-Log "Post-crash reboot detected on VM $VMName"
        }
    }

    # Import logs from VMs.
    Import-ResultsFromVM -VMList $VMList -KmTracing $KmTracing

    # Stop the VMs.
    Stop-AllVMs -VMList $VMList

    Pop-Location

}  -ArgumentList (
    $TestVMCredential,
    $Config,
    $SelfHostedRunnerName,
    $LogFileName,
    $WorkingDirectory,
    $KmTracing)


# Wait for the job to complete
$JobTimedOut = `
    Wait-TestJobToComplete -Job $Job `
    -Config $Config `
    -SelfHostedRunnerName $SelfHostedRunnerName `
    -TestJobTimeout $TestJobTimeout `
    -CheckpointPrefix "Cleanup"

# Clean up
Remove-Job -Job $Job -Force

Pop-Location

if ($JobTimedOut) {
    exit 1
}

