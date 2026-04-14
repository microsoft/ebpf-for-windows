# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ([parameter(Mandatory=$false)][bool] $KmTracing = $true,
       [parameter(Mandatory=$false)][string] $LogFileName = "TestLog.log",
       [parameter(Mandatory=$false)][string] $WorkingDirectory = $pwd.ToString(),
       [parameter(Mandatory=$false)][string] $TestExecutionJsonFileName = "test_execution.json",
       [parameter(Mandatory=$false)][string] $SelfHostedRunnerName = [System.Net.Dns]::GetHostName(),
       [Parameter(Mandatory = $false)][int] $TestJobTimeout = (30*60),
       [Parameter(Mandatory = $false)][switch] $ExecuteOnHost,
       [Parameter(Mandatory = $false)][switch] $VMIsRemote)

$ExecuteOnHost = [bool]$ExecuteOnHost
$ExecuteOnVM = (-not $ExecuteOnHost)
$VMIsRemote = [bool]$VMIsRemote

Push-Location $WorkingDirectory

Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

# Read the test execution json.
$Config = Get-Content ("{0}\{1}" -f $PSScriptRoot, $TestExecutionJsonFileName) | ConvertFrom-Json

$Job = Start-Job -ScriptBlock {
    param ([Parameter(Mandatory = $True)] [bool] $ExecuteOnHost,
           [Parameter(Mandatory = $True)] [bool] $ExecuteOnVM,
           [Parameter(Mandatory = $True)] [bool] $VMIsRemote,
           [Parameter(Mandatory = $true)] [PSCustomObject] $Config,
           [Parameter(Mandatory = $true)] [string] $SelfHostedRunnerName,
           [parameter(Mandatory = $true)] [string] $LogFileName,
           [parameter(Mandatory = $true)] [string] $WorkingDirectory = $pwd.ToString(),
           [parameter(Mandatory = $true)] [bool] $KmTracing
    )
    Push-Location $WorkingDirectory

    # Load other utility modules.
    Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
    Import-Module .\config_test_vm.psm1 -Force -ArgumentList ($WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue

    if ($ExecuteOnVM) {
        $VMList = $Config.VMMap.$SelfHostedRunnerName
        # Wait for all VMs to be in ready state, in case the test run caused any VM to crash.
        Wait-AllVMsToInitialize -VMList $VMList -VMIsRemote $VMIsRemote

        # Import logs from VMs.
        Import-ResultsFromVM -VMList $VMList -KmTracing $KmTracing

        # Stop the VMs.
        Stop-AllVMs -VMList $VMList
    } else {
        try {
            Import-ResultsFromHost -KmTracing $KmTracing
        } catch {
            Write-Log "Failed to obtain results. Treating as non-fatal error. Error: $_"
        }
    }

    Pop-Location

}  -ArgumentList (
    $ExecuteOnHost,
    $ExecuteOnVM,
    $VMIsRemote,
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
    -CheckpointPrefix "Cleanup" `
    -ExecuteOnHost $ExecuteOnHost `
    -ExecuteOnVM $ExecuteOnVM `
    -VMIsRemote $VMIsRemote `
    -TestWorkingDirectory $(if ($ExecuteOnVM) { "C:\ebpf" } else { $WorkingDirectory }) `
    -LogFileName $LogFileName `
    -TestMode "CI/CD" `
    -Options @("None") `
    -TestHangTimeout (10*60) `
    -UserModeDumpFolder "C:\Dumps"

# Re-import common.psm1 in case Wait-TestJobToComplete's timeout handler
# forcefully re-imported it (via vm_run_tests.psm1), removing it from this scope.
Import-Module $WorkingDirectory\common.psm1 -Force -ArgumentList ($LogFileName) -ErrorAction SilentlyContinue

# Check job result before cleanup.
$JobFailed = $Job.State -eq 'Failed'
if ($JobFailed) {
    try {
        $childJob = $Job.ChildJobs[0]
        if ($childJob -and $childJob.JobStateInfo.Reason) {
            Write-Log "Cleanup job failed: $($childJob.JobStateInfo.Reason.Message)"
        }
    } catch {
        Write-Log "Warning: Failed to read cleanup job state: $($_.Exception.Message)"
    }
    try {
        Receive-Job -Job $Job -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Warning: Failed to receive cleanup job output: $($_.Exception.Message)"
    }
}

# Safe cleanup (bounded to prevent hangs on stuck transports).
Remove-JobSafely -Job $Job

Pop-Location

if ($JobTimedOut -or $JobFailed) {
    if ($JobTimedOut) { Write-Log "Cleanup timed out" }
    if ($JobFailed) { Write-Log "Cleanup job failed" }
    exit 1
}

