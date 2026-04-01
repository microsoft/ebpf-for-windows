# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ([parameter(Mandatory=$false)][bool] $KmTracing = $true,
       [parameter(Mandatory=$false)][string] $LogFileName = "TestLog.log",
       [parameter(Mandatory=$false)][string] $WorkingDirectory = $pwd.ToString(),
       [parameter(Mandatory=$false)][string] $TestExecutionJsonFileName = "test_execution.json",
       [parameter(Mandatory=$false)][string] $SelfHostedRunnerName = [System.Net.Dns]::GetHostName(),
       [Parameter(Mandatory = $false)][int] $TestJobTimeout = (10*60),
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
        # Wait for all VMs to be in ready state, in case the test run caused any VM to crash.
        Wait-AllVMsToInitialize -VMList $VMList -VMIsRemote $VMIsRemote

        # Check if we're here after a crash (we are if c:\windows\memory.dmp exists on the VM).  If so,
        # we need to skip the stopping of the drivers as they may be in a wedged state as a result of the
        # crash.  We will be restoring the VM's 'baseline' snapshot next, so the step is redundant anyway.
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

        # Import logs from VMs with a bounded timeout.  Copy-Item -FromSession
        # operations through PS Direct have no timeout mechanism; if the VMBus
        # session hangs mid-copy the call blocks indefinitely.  Run the import
        # in a sub-job so we can kill it if it takes too long.
        $importTimeout = 300  # 5 minutes — enough for logs, dumps, ETL.
        try {
            Write-Log "Starting log import from VMs (timeout: ${importTimeout}s)..."
            $importJob = Start-Job -ScriptBlock {
                param($WorkingDirectory, $LogFileName, $VMListJson, $KmTracing, $VMIsRemote)
                Push-Location $WorkingDirectory
                Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
                Import-Module .\config_test_vm.psm1 -Force -ArgumentList ($WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue
                $VMList = $VMListJson | ConvertFrom-Json
                Import-ResultsFromVM -VMList $VMList -KmTracing $KmTracing -VMIsRemote $VMIsRemote
                Pop-Location
            } -ArgumentList @($WorkingDirectory, $LogFileName, ($VMList | ConvertTo-Json -Depth 10), $KmTracing, $VMIsRemote)

            $importCompleted = $importJob | Wait-Job -Timeout $importTimeout
            if (-not $importCompleted) {
                Write-Log "*** WARNING *** Log import timed out after ${importTimeout}s. Some logs may be missing."
                Stop-Job -Job $importJob -ErrorAction SilentlyContinue
            } else {
                Receive-Job -Job $importJob -ErrorAction SilentlyContinue | ForEach-Object { Write-Log $_ }
                Write-Log "Log import completed."
            }
            # This is a local Start-Job (not PS Direct), so Remove-Job won't
            # hang on VMBus.  Simple cleanup is sufficient.
            $importJob | Wait-Job -Timeout 15 | Out-Null
            Remove-Job -Job $importJob -Force -ErrorAction SilentlyContinue
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

# Clean up -- Stop-Job first (with timeout) to avoid Remove-Job hanging on a
# blocked runspace (e.g. Invoke-Command stuck on a dead PS Direct transport).
try {
    Stop-Job -Job $Job -ErrorAction SilentlyContinue
    $Job | Wait-Job -Timeout 30 | Out-Null
} catch {}
try {
    $removeBlock = { Remove-Job -Job $using:Job -Force -ErrorAction SilentlyContinue }
    $removeTask = [powershell]::Create().AddScript($removeBlock)
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
    Write-Log "Cleanup exiting with error: job timed out"
    [Environment]::Exit(1)
}

if ($JobFailed) {
    Write-Log "Cleanup exiting with error: job failed"
    [Environment]::Exit(1)
}

Write-Log "Cleanup completed successfully"

