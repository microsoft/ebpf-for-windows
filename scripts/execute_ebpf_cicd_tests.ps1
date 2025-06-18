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
       [Parameter(Mandatory = $false)][int] $TestJobTimeout = (60*60),
       [Parameter(Mandatory = $false)][switch] $ExecuteOnHost,
       [Parameter(Mandatory = $false)][switch] $SkipPSExecTests,
       [Parameter(Mandatory = $false)][string] $Architecture = "x64"
)

Write-Output "execute_ebpf_cicd_tests.ps1: Starting test execution"

# # Normalize the working directory path to avoid issues with relative path components
# $WorkingDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($WorkingDirectory)

Push-Location $WorkingDirectory

# List all filenames in the working directory
Write-Output "Working Directory: $WorkingDirectory"
Get-ChildItem -Path $WorkingDirectory -File -Recurse | ForEach-Object {
    Write-Output "Found file: $($_.FullName)"
}

Import-Module $WorkingDirectory\common.psm1 -Force -ArgumentList ($LogFileName) -ErrorAction Stop
Get-CoreNetTools -Architecture $Architecture

if (-not $ExecuteOnHost) {
    if ($SelfHostedRunnerName -eq "1ESRunner") {
        $AdminTestVMCredential = Retrieve-StoredCredential -Target $AdminTarget
        $StandardUserTestVMCredential = Retrieve-StoredCredential -Target $StandardUserTarget
    } else {
        $AdminTestVMCredential = Get-StoredCredential -Target $AdminTarget -ErrorAction Stop
        $StandardUserTestVMCredential = Get-StoredCredential -Target $StandardUserTarget -ErrorAction Stop
    }
}

# Read the test execution json.
$Config = Get-Content ("{0}\{1}" -f $PSScriptRoot, $TestExecutionJsonFileName) | ConvertFrom-Json

if (-not $ExecuteOnHost) {
    # Execute tests on VM
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
               [Parameter(Mandatory = $True)] [string] $UserModeDumpFolder,
               [Parameter(Mandatory = $True)] [bool] $SkipPSExecTests)

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
                $UserModeDumpFolder,
                $SkipPSExecTests) `
            -WarningAction SilentlyContinue

        $VMList = $Config.VMMap.$SelfHostedRunnerName
        # currently one VM runs per runner.
        $TestVMName = $VMList[0].Name

        try {
            # Run Kernel tests on test VM.
            Write-Log "Running kernel tests on $TestVMName"
            Run-KernelTestsOnVM -VMName $TestVMName -Config $Config

            # Stop eBPF components on test VMs.
            Stop-eBPFComponentsOnVM -VMName $TestVMName
        } catch [System.Management.Automation.RemoteException] {
            # Next, generate kernel dump.
            Write-Log $_.Exception.Message
            Write-Log $_.ScriptStackTrace
            if ($_.CategoryInfo.Reason -eq "TimeoutException") {
                Generate-KernelDumpOnVM($TestVMName)
            }

            # Throw to ensure the job is marked as failed.
            throw $_.Exception.Message
        }

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
        $UserModeDumpFolder,
        $SkipPSExecTests.ToBool())

    # Keep track of the last received output count
    $JobTimedOut = `
        Wait-TestJobToComplete -Job $Job `
        -Config $Config `
        -SelfHostedRunnerName $SelfHostedRunnerName `
        -TestJobTimeout $TestJobTimeout `
        -CheckpointPrefix "Execute"

    # Clean up
    Remove-Job -Job $Job -Force

    if ($JobTimedOut) {
        exit 1
    }
} else {
    # Execute tests directly on host
    Write-Log "ExecuteOnHost enabled - running tests directly on host" -ForegroundColor Yellow

    try {
        # Load test execution modules
        Import-Module $WorkingDirectory\run_driver_tests.psm1 -Force -ArgumentList ($WorkingDirectory, $LogFileName, $TestHangTimeout, $UserModeDumpFolder) -WarningAction SilentlyContinue

        # Run tests based on test mode
        $TestMode = $TestMode.ToLower()
        switch ($TestMode)
        {
            "ci/cd" {
                Write-Log "Running CI/CD tests on host"
                Invoke-CICDTests -VerboseLogs $false -ExecuteSystemTests $true -SkipPSExecTests:$SkipPSExecTests
            }
            "regression" {
                Write-Log "Running regression tests on host"
                Invoke-CICDTests -VerboseLogs $false -ExecuteSystemTests $false -SkipPSExecTests:$SkipPSExecTests
            }
            "stress" {
                Write-Log "Running stress tests on host"
                # Set RestartExtension to true if options contains that string
                $RestartExtension = $Options -contains "RestartExtension"
                Invoke-CICDStressTests -VerboseLogs $false -RestartExtension $RestartExtension
            }
            "performance" {
                Write-Log "Running performance tests on host"
                # Set CaptureProfile to true if options contains that string
                $CaptureProfile = $Options -contains "CaptureProfile"
                Invoke-CICDPerformanceTests -VerboseLogs $false -CaptureProfile $CaptureProfile
            }
            default {
                throw "Invalid test mode: $TestMode"
            }
        }
    } catch {
        Write-Log "Test execution failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log $_.ScriptStackTrace -ForegroundColor Red
        exit 1
    }
}

Pop-Location
