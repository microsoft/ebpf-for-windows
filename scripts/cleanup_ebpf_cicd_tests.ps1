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

$TestVMCredential = Get-StoredCredential -Target $Target -ErrorAction Stop

# Read the test execution json.
$TestExecutionConfig = Get-Content ("{0}\{1}" -f $PSScriptRoot, $TestExecutionJsonFileName) | ConvertFrom-Json

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

    Pop-Location

}  -ArgumentList (
    $TestVMCredential,
    $TestExecutionConfig,
    $SelfHostedRunnerName,
    $LogFileName,
    $WorkingDirectory,
    $KmTracing)

# Keep track of the last received output count
$TimeElapsed = 0
$JobTimedOut = $false

# Loop to fetch and print job output in near real-time
while ($Job.State -eq 'Running') {
    $JobOutput = Receive-Job -Job $job
	$JobOutput | ForEach-Object { Write-Host $_ }

    Start-Sleep -Seconds 2
    $TimeElapsed += 2

    if ($TimeElapsed -gt $TestJobTimeout) {
        if ($Job.State -eq "Running") {
            $VMList = $Config.VMMap.$SelfHostedRunnerName
            # currently one VM is used per runner.
            $TestVMName = $VMList[0].Name
            Write-Host "Cleaning up VM $TestVMName for Kernel Tests has timed out after one hour" -ForegroundColor Yellow
            $Timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
            $CheckpointName = "Cleanup-Hang-$TestVMName-Checkpoint-$Timestamp"
            Write-Log "Taking snapshot $CheckpointName of $TestVMName"
            Checkpoint-VM -Name $TestVMName -SnapshotName $CheckpointName
            $JobTimedOut = $true
            break
        }
    }
}

# Print any remaining output after the job completes
$JobOutput = Receive-Job -Job $job
$JobOutput | ForEach-Object { Write-Host $_ }

# Clean up
Remove-Job -Job $Job -Force

Pop-Location

if ($JobTimedOut) {
    exit 1
}

