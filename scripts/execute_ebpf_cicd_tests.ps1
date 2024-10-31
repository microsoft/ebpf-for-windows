# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ([Parameter(Mandatory = $false)][string] $AdminTarget = "TEST_VM",
       [Parameter(Mandatory = $false)][string] $StandardUserTarget = "TEST_VM_STANDARD",
       [Parameter(Mandatory = $false)][string] $LogFileName = "TestLog.log",
       [Parameter(Mandatory = $false)][string] $WorkingDirectory = $pwd.ToString(),
       [Parameter(Mandatory = $false)][string] $TestExecutionJsonFileName = "test_execution.json",
       [Parameter(Mandatory = $false)][string] $TestMode = "CI/CD",
       [Parameter(Mandatory = $false)][string[]] $Options = @("None"),
       [Parameter(Mandatory = $false)][string] $SelfHostedRunnerName = [System.Net.Dns]::GetHostName(),
       [Parameter(Mandatory = $false)][int] $TestHangTimeout = (10*60),
       [Parameter(Mandatory = $false)][string] $UserModeDumpFolder = "C:\Dumps",
       [Parameter(Mandatory = $false)][int] $TestJobTimeout = (60*60)
)

Push-Location $WorkingDirectory

Import-Module $WorkingDirectory\common.psm1 -Force -ArgumentList ($LogFileName) -ErrorAction Stop

$AdminTestVMCredential = Get-StoredCredential -Target $AdminTarget -ErrorAction Stop
$StandardUserTestVMCredential = Get-StoredCredential -Target $StandardUserTarget -ErrorAction Stop

# Read the test execution json.
$Config = Get-Content ("{0}\{1}" -f $PSScriptRoot, $TestExecutionJsonFileName) | ConvertFrom-Json

$Job = Start-Job -ScriptBlock {
    param ([Parameter(Mandatory = $True)] [PSCredential] $AdminTestVMCredential,
           [Parameter(Mandatory = $True)] [PSCredential] $StandardUserTestVMCredential, 
           [Parameter(Mandatory = $true)] [PSCustomObject] $Config, 
           [Parameter(Mandatory = $true)] [string] $SelfHostedRunnerName,
           [Parameter(Mandatory = $True)] [string] $WorkingDirectory,
           [Parameter(Mandatory = $True)] [string] $LogFileName,
           [Parameter(Mandatory = $True)] [string] $TestMode,
           [Parameter(Mandatory = $True)] [string[]] $Options,
           [Parameter(Mandatory = $True)] [int] $TestHangTimeout,
           [Parameter(Mandatory = $True)] [string] $UserModeDumpFolder)

    Push-Location $WorkingDirectory

    # Load other utility modules.
    Import-Module $WorkingDirectory\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
    Import-Module $WorkingDirectory\vm_run_tests.psm1 `
        -Force `
        -ArgumentList (
            $AdminTestVMCredential.UserName,
            $AdminTestVMCredential.Password,
            $StandardUserTestVMCredential.UserName,
            $StandardUserTestVMCredential.Password,
            $WorkingDirectory,
            $LogFileName,
            $TestMode,
            $Options,
            $TestHangTimeout,
            $UserModeDumpFolder) `
        -WarningAction SilentlyContinue

    $VMList = $Config.VMMap.$SelfHostedRunnerName
    # currently one VM runs per runner.
    $TestVMName = $VMList[0].Name

    # Run Kernel tests on test VM.
    Write-Log "Running kernel tests on $TestVMName"
    Run-KernelTestsOnVM -VMName $TestVMName -Config $Config

    # Stop eBPF components on test VMs.
    Stop-eBPFComponentsOnVM -VMName $TestVMName

    Pop-Location
} -ArgumentList (
    $AdminTestVMCredential,
    $StandardUserTestVMCredential,
    $Config,
    $SelfHostedRunnerName,
    $WorkingDirectory,
    $LogFileName,
    $TestMode,
    $Options,
    $TestHangTimeout,
    $UserModeDumpFolder)

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
            Write-Host "Running kernel tests on $TestVMName has timed out after one hour" -ForegroundColor Yellow
            $Timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
            $CheckpointName = "Execution-Hang-$TestVMName-Checkpoint-$Timestamp"
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
