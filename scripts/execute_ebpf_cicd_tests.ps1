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
       [Parameter(Mandatory = $false)][int] $TestHangTimeout = (30*60),
       [Parameter(Mandatory = $false)][string] $UserModeDumpFolder = "C:\Dumps",
       [Parameter(Mandatory = $false)][int] $TestJobTimeout = (60*60),
       [Parameter(Mandatory = $false)][switch] $GranularTracing = $false,
       [Parameter(Mandatory = $false)][switch] $ExecuteOnHost,
        # This parameter is only used when ExecuteOnHost is false.
       [Parameter(Mandatory = $false)][switch] $VMIsRemote)

$ExecuteOnHost = [bool]$ExecuteOnHost
$ExecuteOnVM = (-not $ExecuteOnHost)
$VMIsRemote = [bool]$VMIsRemote

Push-Location $WorkingDirectory

Import-Module $WorkingDirectory\common.psm1 -Force -ArgumentList ($LogFileName) -ErrorAction Stop

# Read the test execution json.
$Config = Get-Content ("{0}\{1}" -f $PSScriptRoot, $TestExecutionJsonFileName) | ConvertFrom-Json

if ($ExecuteOnVM) {
    if ($SelfHostedRunnerName -eq "1ESRunner") {
        $AdminTestVMCredential = Retrieve-StoredCredential -Target $AdminTarget
        $StandardUserTestVMCredential = Retrieve-StoredCredential -Target $StandardUserTarget
    } else {
        $AdminTestVMCredential = Get-StoredCredential -Target $AdminTarget -ErrorAction Stop
        $StandardUserTestVMCredential = Get-StoredCredential -Target $StandardUserTarget -ErrorAction Stop
    }
} else {
    # Username and password are not used when running on host - use empty but non-null values.
    $EmptySecureString = ConvertTo-SecureString -String 'empty' -AsPlainText -Force
    $AdminTestVMCredential = New-Object System.Management.Automation.PSCredential($env:USERNAME, $EmptySecureString)
    $StandardUserTestVMCredential = New-Object System.Management.Automation.PSCredential("TestStandardUser", $EmptySecureString)
}

$Job = Start-Job -ScriptBlock {
    param (
        [Parameter(Mandatory = $True)] [bool] $ExecuteOnHost,
        [Parameter(Mandatory = $True)] [bool] $ExecuteOnVM,
        [Parameter(Mandatory = $True)] [bool] $VMIsRemote,
        [Parameter(Mandatory = $True)] [PSCredential] $AdminTestVMCredential,
        [Parameter(Mandatory = $True)] [PSCredential] $StandardUserTestVMCredential,
        [Parameter(Mandatory = $True)] [PSCustomObject] $Config,
        [Parameter(Mandatory = $True)] [string] $SelfHostedRunnerName,
        [Parameter(Mandatory = $True)] [string] $WorkingDirectory,
        [Parameter(Mandatory = $True)] [string] $LogFileName,
        [Parameter(Mandatory = $True)] [string] $TestMode,
        [Parameter(Mandatory = $True)] [string[]] $Options,
        [Parameter(Mandatory = $True)] [int] $TestHangTimeout,
        [Parameter(Mandatory = $True)] [string] $UserModeDumpFolder,
        [Parameter(Mandatory = $True)] [bool] $GranularTracing
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
            $AdminTestVMCredential.UserName,
            $AdminTestVMCredential.Password,
            $StandardUserTestVMCredential.UserName,
            $StandardUserTestVMCredential.Password,
            $TestWorkingDirectory,
            $LogFileName,
            $TestMode,
            $Options,
            $TestHangTimeout,
            $UserModeDumpFolder,
            $GranularTracing) `
        -WarningAction SilentlyContinue
    try {
        Write-Log "Running kernel tests"
        Run-KernelTests -Config $Config
        Write-Log "Running kernel tests completed"

        Stop-eBPFComponents -GranularTracing $GranularTracing
    } catch [System.Management.Automation.RemoteException] {
        Write-Log $_.Exception.Message
        Write-Log $_.ScriptStackTrace
        if ($_.CategoryInfo.Reason -eq "TimeoutException") {
            Generate-KernelDump
        }
        throw $_.Exception.Message
    }
    Pop-Location
} -ArgumentList (
    $ExecuteOnHost,
    $ExecuteOnVM,
    $VMIsRemote,
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
    $GranularTracing)

# Keep track of the last received output count
$JobTimedOut = `
    Wait-TestJobToComplete -Job $Job `
    -Config $Config `
    -SelfHostedRunnerName $SelfHostedRunnerName `
    -TestJobTimeout $TestJobTimeout `
    -CheckpointPrefix "Execute" `
    -ExecuteOnVM $ExecuteOnVM

# Clean up
Remove-Job -Job $Job -Force

Pop-Location

if ($JobTimedOut) {
    Write-Log "exiting with error as job timed out"
    exit 1
}

Write-Log "execute_ebpf_cicd_tests.ps1 completed successfully"