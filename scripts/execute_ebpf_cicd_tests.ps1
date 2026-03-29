# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ([Parameter(Mandatory = $false)][string] $LogFileName = "TestLog.log",
       [Parameter(Mandatory = $false)][string] $WorkingDirectory = $pwd.ToString(),
       [Parameter(Mandatory = $false)][string] $TestExecutionJsonFileName = "test_execution.json",
       [Parameter(Mandatory = $false)][string] $TestMode = "CI/CD",
       [Parameter(Mandatory = $false)][string[]] $Options = @("None"),
       [Parameter(Mandatory = $false)][string] $SelfHostedRunnerName = [System.Net.Dns]::GetHostName(),
       [Parameter(Mandatory = $false)][int] $TestHangTimeout = (30*60),
       [Parameter(Mandatory = $false)][string] $UserModeDumpFolder = "C:\Dumps",
       [Parameter(Mandatory = $false)][int] $TestJobTimeout = (60*60),
       [Parameter(Mandatory = $false)][switch] $GranularTracing = $false,
       # Boolean parameter indicating if XDP tests should be run.
       [Parameter(Mandatory = $false)][bool] $RunXdpTests = $false,
       [Parameter(Mandatory = $false)][switch] $ExecuteOnHost,
       # This parameter is only used when ExecuteOnHost is false.
       [Parameter(Mandatory = $false)][switch] $VMIsRemote)

$ExecuteOnHost = [bool]$ExecuteOnHost
$ExecuteOnVM = (-not $ExecuteOnHost)
$VMIsRemote = [bool]$VMIsRemote

Push-Location $WorkingDirectory

Import-Module $WorkingDirectory\common.psm1 -Force -ArgumentList ($LogFileName) -ErrorAction Stop

Write-Log "Execute starting (TestMode=$TestMode, ExecuteOnHost=$ExecuteOnHost, ExecuteOnVM=$ExecuteOnVM, VMIsRemote=$VMIsRemote, Timeout=${TestJobTimeout}s)"

# Read the test execution json.
$Config = Get-Content ("{0}\{1}" -f $PSScriptRoot, $TestExecutionJsonFileName) | ConvertFrom-Json

if ($ExecuteOnVM) {
    Write-Log "Tests will be executed on VM"
} else {
    Write-Log "Executing on host"
}

$Job = Start-Job -ScriptBlock {
    param (
        [Parameter(Mandatory = $True)] [bool] $ExecuteOnHost,
        [Parameter(Mandatory = $True)] [bool] $ExecuteOnVM,
        [Parameter(Mandatory = $True)] [bool] $VMIsRemote,
        [Parameter(Mandatory = $True)] [PSCustomObject] $Config,
        [Parameter(Mandatory = $True)] [string] $SelfHostedRunnerName,
        [Parameter(Mandatory = $True)] [string] $WorkingDirectory,
        [Parameter(Mandatory = $True)] [string] $LogFileName,
        [Parameter(Mandatory = $True)] [string] $TestMode,
        [Parameter(Mandatory = $True)] [string[]] $Options,
        [Parameter(Mandatory = $True)] [int] $TestHangTimeout,
        [Parameter(Mandatory = $True)] [string] $UserModeDumpFolder,
        [Parameter(Mandatory = $True)] [bool] $GranularTracing,
        [Parameter(Mandatory = $True)] [bool] $RunXdpTests
    )
    Push-Location $WorkingDirectory
    # Load other utility modules.
    Import-Module $WorkingDirectory\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

    if ($ExecuteOnVM) {
        Write-Log "Tests will be executed on VM" -ForegroundColor Cyan
        $VMList = $Config.VMMap.$SelfHostedRunnerName
        $VMName = $VMList[0].Name
        $TestWorkingDirectory = "C:\ebpf"
    } else {
        Write-Log "Executing on host" -ForegroundColor Cyan
        $VMName = $null
        $TestWorkingDirectory = $WorkingDirectory
    }
    Import-Module $WorkingDirectory\vm_run_tests.psm1 `
        -Force `
        -ArgumentList(
            $ExecuteOnHost,
            $ExecuteOnVM,
            $VMIsRemote,
            $VMName,
            $TestWorkingDirectory,
            $LogFileName,
            $TestMode,
            $Options,
            $TestHangTimeout,
            $UserModeDumpFolder,
            $GranularTracing,
            $RunXdpTests) `
        -WarningAction SilentlyContinue
    try {
        Write-Log "Running kernel tests"
        Run-KernelTests -Config $Config
        Write-Log "Running kernel tests completed"

        Stop-eBPFComponents -GranularTracing $GranularTracing
    } catch {
        Write-Log $_.Exception.Message
        Write-Log $_.ScriptStackTrace
        if ($_.CategoryInfo.Reason -eq "TimeoutException") {
            Generate-KernelDumpOnVM
        }
        throw $_.Exception.Message
    }
    Pop-Location
} -ArgumentList (
    $ExecuteOnHost,
    $ExecuteOnVM,
    $VMIsRemote,
    $Config,
    $SelfHostedRunnerName,
    $WorkingDirectory,
    $LogFileName,
    $TestMode,
    $Options,
    $TestHangTimeout,
    $UserModeDumpFolder,
    $GranularTracing,
    $RunXdpTests)

# Keep track of the last received output count
$JobTimedOut = `
    Wait-TestJobToComplete -Job $Job `
    -Config $Config `
    -SelfHostedRunnerName $SelfHostedRunnerName `
    -TestJobTimeout $TestJobTimeout `
    -CheckpointPrefix "Execute" `
    -ExecuteOnHost $ExecuteOnHost `
    -ExecuteOnVM $ExecuteOnVM `
    -VMIsRemote $VMIsRemote `
    -TestWorkingDirectory $(if ($ExecuteOnVM) { "C:\ebpf" } else { $WorkingDirectory }) `
    -LogFileName $LogFileName `
    -TestMode $TestMode `
    -Options $Options `
    -TestHangTimeout $TestHangTimeout `
    -UserModeDumpFolder $UserModeDumpFolder

# Check if the job failed (e.g., VM session died, test threw an exception).
$JobFailed = $Job.State -eq 'Failed'
if ($JobFailed) {
    # Surface the failure reason directly from the job state info.
    try {
        $childJob = $Job.ChildJobs[0]
        if ($childJob -and $childJob.JobStateInfo.Reason) {
            Write-Log "*** JOB FAILED *** $($childJob.JobStateInfo.Reason.GetType().Name): $($childJob.JobStateInfo.Reason.Message)"
        } else {
            Write-Log "*** JOB FAILED *** (no reason available, job state: $($Job.State))"
        }
    } catch {
        Write-Log "*** JOB FAILED *** Could not retrieve reason: $($_.Exception.Message)"
    }
    # Drain any remaining output.
    try {
        $drainJob = Start-Job -ScriptBlock { param($Id); Receive-Job -Job (Get-Job -Id $Id) -ErrorAction SilentlyContinue 2>&1 } -ArgumentList $Job.Id
        $drainDone = $drainJob | Wait-Job -Timeout 30
        if ($drainDone) { Receive-Job -Job $drainJob -ErrorAction SilentlyContinue | ForEach-Object { Write-Log $_ } }
        else { Write-Log "Warning: Timed out draining job output (30s)."; Stop-Job -Job $drainJob -ErrorAction SilentlyContinue }
        Remove-Job -Job $drainJob -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Job drain error: $($_.Exception.Message)"
    }
}

# Clean up -- Stop-Job first (with timeout) to avoid Remove-Job hanging on a
# blocked runspace (e.g. Invoke-Command stuck on a dead PS Direct transport).
try {
    Stop-Job -Job $Job -ErrorAction SilentlyContinue
    $Job | Wait-Job -Timeout 30 | Out-Null
} catch {}
Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue

Pop-Location

if ($JobTimedOut) {
    Write-Log "exiting with error as job timed out"
    exit 1
}

if ($JobFailed) {
    Write-Log "exiting with error as job failed"
    exit 1
}

Write-Log "execute_ebpf_cicd_tests.ps1 completed successfully"