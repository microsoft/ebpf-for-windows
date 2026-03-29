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

        # Import logs from VMs.
        try {
            Import-ResultsFromVM -VMList $VMList -KmTracing $KmTracing -VMIsRemote $VMIsRemote
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
    -UserModeDumpFolder "C:\Dumps"

# Check if the job failed (e.g., VM session died, cleanup threw an exception).
$JobFailed = $Job.State -eq 'Failed'
if ($JobFailed) {
    try {
        # Use a sub-job with timeout to prevent Receive-Job from hanging on a broken transport.
        $drainJob = Start-Job -ScriptBlock { param($Id); Receive-Job -Job (Get-Job -Id $Id) -ErrorAction SilentlyContinue 2>&1 } -ArgumentList $Job.Id
        $drainDone = $drainJob | Wait-Job -Timeout 30
        if ($drainDone) { Receive-Job -Job $drainJob -ErrorAction SilentlyContinue | ForEach-Object { Write-Log $_ } }
        else { Write-Log "Warning: Timed out draining job output (30s)."; Stop-Job -Job $drainJob -ErrorAction SilentlyContinue }
        Remove-Job -Job $drainJob -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Job error: $($_.Exception.Message)"
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
    Write-Log "Cleanup exiting with error: job timed out"
    exit 1
}

if ($JobFailed) {
    Write-Log "Cleanup exiting with error: job failed"
    exit 1
}

Write-Log "Cleanup completed successfully"

