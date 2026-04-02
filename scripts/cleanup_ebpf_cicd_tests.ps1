# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ([parameter(Mandatory=$false)][bool] $KmTracing = $true,
       [parameter(Mandatory=$false)][string] $LogFileName = "TestLog.log",
       [parameter(Mandatory=$false)][string] $WorkingDirectory = $pwd.ToString(),
       [parameter(Mandatory=$false)][string] $TestExecutionJsonFileName = "test_execution.json",
       [parameter(Mandatory=$false)][string] $SelfHostedRunnerName = [System.Net.Dns]::GetHostName(),
       [Parameter(Mandatory = $false)][int] $TestJobTimeout = (5*60),
       [Parameter(Mandatory = $false)][switch] $ExecuteOnHost,
       [Parameter(Mandatory = $false)][switch] $VMIsRemote)

$ExecuteOnHost = [bool]$ExecuteOnHost
$ExecuteOnVM = (-not $ExecuteOnHost)
$VMIsRemote = [bool]$VMIsRemote

Push-Location $WorkingDirectory

Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

Write-Log "Cleanup starting (ExecuteOnHost=$ExecuteOnHost, ExecuteOnVM=$ExecuteOnVM, VMIsRemote=$VMIsRemote, Timeout=${TestJobTimeout}s)"

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

        # Wait for VMs to be ready.  If the VM crashed during the test, this
        # may take a few minutes while it writes a crash dump and reboots.
        # The function has a built-in 5-minute timeout; wrap in try/catch so
        # a dead VM doesn't abort the entire cleanup.
        $vmReady = $false
        try {
            Wait-AllVMsToInitialize -VMList $VMList -VMIsRemote $VMIsRemote
            $vmReady = $true
        } catch {
            Write-Log "*** WARNING *** VM did not become ready: $($_.Exception.Message). Will attempt log import anyway."
        }

        # Check if we're here after a crash (only if VM is reachable).
        if ($vmReady) {
            foreach ($VM in $VMList) {
                $VMName = $VM.Name
                $TestCredential = Get-VMCredential -Username 'Administrator' -VMIsRemote $VMIsRemote
                try {
                    $DumpFound = Invoke-CommandOnVM `
                        -VMName $VMName `
                        -VMIsRemote $VMIsRemote `
                        -Credential $TestCredential `
                        -TimeoutSeconds 120 `
                        -ScriptBlock {
                            Test-Path -Path "c:\windows\memory.dmp" -PathType leaf
                        }

                    if ($DumpFound -eq $True) {
                        Write-Log "Post-crash reboot detected on VM $VMName"
                    }
                } catch {
                    Write-Log "*** WARNING *** Failed to check for crash dump on ${VMName}: $($_.Exception.Message). Continuing cleanup."
                }
            }
        }

        # Import logs from VMs.  Each step inside Import-ResultsFromVM is
        # wrapped in try/catch with [Step N/6] labels.  If a Copy-Item hangs
        # (VMBus stall), the outer Wait-TestJobToComplete timeout (300s) will
        # kill this entire job.  We intentionally do NOT nest a sub-job here
        # because PS Direct sessions can't be created from a doubly-nested
        # background process.
        try {
            Write-Log "Starting log import from VMs..."
            Import-ResultsFromVM -VMList $VMList -KmTracing $KmTracing -VMIsRemote $VMIsRemote
            Write-Log "Log import completed."
        } catch {
            Write-Log "*** WARNING *** Failed to import results from VMs: $($_.Exception.Message). Continuing cleanup."
        }

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
    -UserModeDumpFolder "C:\Dumps" `
    -SkipDumpOnTimeout $true

# Check if the job failed (e.g., VM session died, cleanup threw an exception).
$JobFailed = $Job.State -eq 'Failed'
if ($JobFailed) {
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
    try {
        Receive-Job -Job $Job -ErrorAction SilentlyContinue | ForEach-Object { Write-Log $_ }
    } catch {
        Write-Log "Job drain error: $($_.Exception.Message)"
    }
}

# Clean up -- Stop-Job can hang if the inner runspace is stuck on a dead
# PS Direct transport, so run it on a background thread with a timeout.
try {
    $stopTask = [powershell]::Create().AddScript({ param($j) Stop-Job -Job $j -ErrorAction SilentlyContinue }).AddArgument($Job)
    $stopAsync = $stopTask.BeginInvoke()
    if (-not $stopAsync.AsyncWaitHandle.WaitOne(30000)) {
        Write-Log "Warning: Stop-Job timed out in cleanup -- proceeding anyway."
    }
    try { $stopTask.EndInvoke($stopAsync) } catch {}
    $stopTask.Dispose()
} catch {}
try {
    $removeTask = [powershell]::Create().AddScript({ param($j) Remove-Job -Job $j -Force -ErrorAction SilentlyContinue }).AddArgument($Job)
    $asyncResult = $removeTask.BeginInvoke()
    if (-not $asyncResult.AsyncWaitHandle.WaitOne(15000)) {
        Write-Log "Warning: Remove-Job timed out -- proceeding anyway."
    }
    $removeTask.Dispose()
} catch {
    Write-Log "Warning: Remove-Job cleanup failed: $($_.Exception.Message)"
}

Pop-Location

if ($JobTimedOut) {
    Write-Log "*** WARNING *** Cleanup timed out -- some logs may be missing but this is non-fatal."
} elseif ($JobFailed) {
    Write-Log "*** WARNING *** Cleanup job failed -- some logs may be missing but this is non-fatal."
} else {
    Write-Log "Cleanup completed successfully."
}

