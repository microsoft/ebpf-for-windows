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

$SelfHostedRunnerName = "runner_host"
Write-Host "SelfHostedRunnerName: $SelfHostedRunnerName, AdminTarget: $AdminTarget, StandardUserTarget: $StandardUserTarget"
try {
    $AdminTestVMCredential = Get-StoredCredential -Target $AdminTarget -ErrorAction Stop
    $StandardUserTestVMCredential = Get-StoredCredential -Target $StandardUserTarget -ErrorAction Stop
} catch {
    Write-Host "Failed to get credentials for $AdminTarget or $StandardUserTarget. Using default credentials."
    $AdminTestVMCredential = New-Credential -UserName 'Administrator' -AdminPassword 'P@ssw0rd'
    $StandardUserTestVMCredential = New-Credential -UserName 'VMStandardUser' -AdminPassword 'P@ssw0rd'
}

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
$JobTimedOut = `
    Wait-TestJobToComplete -Job $Job `
    -Config $Config `
    -SelfHostedRunnerName $SelfHostedRunnerName `
    -TestJobTimeout $TestJobTimeout `
    -CheckpointPrefix "Execute"

# Clean up
Remove-Job -Job $Job -Force

Pop-Location

if ($JobTimedOut) {
    exit 1
}
