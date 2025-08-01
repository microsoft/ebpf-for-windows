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
        # This parameter is only used when ExecuteOnHost is false.
       [Parameter(Mandatory = $false)][switch] $VMIsRemote,
       [Parameter(Mandatory = $false)][switch] $GranularTracing = $false,
       [Parameter(Mandatory = $false)][switch] $KmTracing = $false,
       [Parameter(Mandatory = $false)][string] $KmTraceType = "file")

$ExecuteOnHost = [bool]$ExecuteOnHost
$ExecuteOnVM = (-not $ExecuteOnHost)
$VMIsRemote = [bool]$VMIsRemote

Push-Location $WorkingDirectory

Import-Module $WorkingDirectory\common.psm1 -Force -ArgumentList ($LogFileName) -ErrorAction Stop

# Initialize granular tracing if enabled
$tracingInitialized = $false
$traceDir = $null
if ($GranularTracing -and $KmTracing) {
    try {
        Import-Module .\tracing_utils.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
        if (Initialize-TracingUtils -WorkingDirectory $WorkingDirectory) {
            Write-Log "Starting granular tracing for test execution"
            # Create TestLogs directory for trace files
            $traceDir = Join-Path $WorkingDirectory "TestLogs"
            if (-not (Test-Path $traceDir)) {
                New-Item -ItemType Directory -Path $traceDir -Force | Out-Null
            }
            $tracingInitialized = $true
            Write-Log "Granular tracing initialized successfully" -ForegroundColor Green
        }
    } catch {
        Write-Log "Warning: Failed to initialize granular tracing for test execution: $_" -ForegroundColor Yellow
    }
}

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
        [Parameter(Mandatory = $True)] [bool] $GranularTracing,
        [Parameter(Mandatory = $True)] [bool] $KmTracing,
        [Parameter(Mandatory = $True)] [string] $KmTraceType,
        [Parameter(Mandatory = $True)] [string] $TraceDir
    )
    Push-Location $WorkingDirectory
    # Load other utility modules.
    Import-Module $WorkingDirectory\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

    # Initialize granular tracing in the job context if enabled
    $tracingInitialized = $false
    if ($GranularTracing -and $KmTracing -and $TraceDir) {
        try {
            Import-Module $WorkingDirectory\tracing_utils.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
            if (Initialize-TracingUtils -WorkingDirectory $WorkingDirectory) {
                $tracingInitialized = $true
                Write-Output "Granular tracing initialized in job context"
            }
        } catch {
            Write-Output "Warning: Failed to initialize granular tracing in job context: $_"
        }
    }

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
            $GranularTracing,
            $TraceDir,
            $KmTraceType) `
        -WarningAction SilentlyContinue
    try {
        Write-Log "Running kernel tests"
        Run-KernelTests -Config $Config

        Stop-eBPFComponents
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
    $GranularTracing,
    $KmTracing,
    $KmTraceType,
    $traceDir)

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

# Stop granular tracing if it was started
if ($GranularTracing -and $tracingInitialized) {
    try {
        # Any remaining cleanup for tracing
        Write-Log "Cleaning up granular tracing resources" -ForegroundColor Yellow
    } catch {
        Write-Log "Warning: Error during tracing cleanup: $_" -ForegroundColor Yellow
    }
}

Pop-Location

if ($JobTimedOut) {
    exit 1
}
