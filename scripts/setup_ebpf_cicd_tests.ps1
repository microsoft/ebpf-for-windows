# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ([parameter(Mandatory=$false)][string] $Target = "TEST_VM",
       [parameter(Mandatory=$false)][bool] $KmTracing = $true,
       [parameter(Mandatory=$false)][string] $KmTraceType = "file",
       [parameter(Mandatory=$false)][string] $TestMode = "CI/CD",
       [parameter(Mandatory=$false)][string] $LogFileName = "TestLog.log",
       [parameter(Mandatory=$false)][string] $WorkingDirectory = $pwd.ToString(),
       [parameter(Mandatory=$false)][string] $RegressionArtifactsVersion = "",
       [parameter(Mandatory=$false)][string] $RegressionArtifactsConfiguration = "",
       [parameter(Mandatory=$false)][string] $TestExecutionJsonFileName = "test_execution.json",
       [parameter(Mandatory=$false)][string] $SelfHostedRunnerName = [System.Net.Dns]::GetHostName(),
       [Parameter(Mandatory = $false)][int] $TestJobTimeout = (30*60))

Push-Location $WorkingDirectory

$TestVMCredential = Get-StoredCredential -Target $Target -ErrorAction Stop

# Load other utility modules.
Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
Import-Module .\config_test_vm.psm1 -Force -ArgumentList ($TestVMCredential.UserName, $TestVMCredential.Password, $WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue

# Read the test execution json.
$TestExecutionConfig = Get-Content ("{0}\{1}" -f $PSScriptRoot, $TestExecutionJsonFileName) | ConvertFrom-Json
$VMList = $Config.VMMap.$SelfHostedRunnerName

# Delete old log files if any.
Remove-Item "$env:TEMP\$LogFileName" -ErrorAction SilentlyContinue
foreach($VM in $VMList) {
    $VMName = $VM.Name
    Remove-Item $env:TEMP\$LogFileName -ErrorAction SilentlyContinue
}
Remove-Item ".\TestLogs" -Recurse -Confirm:$false -ErrorAction SilentlyContinue

if ($TestMode -eq "Regression") {

    # Download the release artifacts for regression tests.
    Get-RegressionTestArtifacts -ArtifactVersion $RegressionArtifactsVersion -Configuration $RegressionArtifactsConfiguration
}

if ($TestMode -eq "CI/CD" -or $TestMode -eq "Regression") {

    # Download the release artifacts for legacy regression tests.
    Get-LegacyRegressionTestArtifacts
}

Get-CoreNetTools
Get-PSExec

$Job = Start-Job -ScriptBlock {
    param ([Parameter(Mandatory = $True)] [PSCredential] $TestVMCredential,
           [Parameter(Mandatory = $true)] [PSCustomObject] $Config,
           [Parameter(Mandatory = $true)] [string] $SelfHostedRunnerName,
           [parameter(Mandatory = $true)] [string] $TestMode,
           [parameter(Mandatory = $true)] [string] $LogFileName,
           [parameter(Mandatory = $true)] [string] $WorkingDirectory = $pwd.ToString(),
           [parameter(Mandatory = $true)] [bool] $KmTracing,
           [parameter(Mandatory = $true)] [string] $KmTraceType
    )
    Push-Location $WorkingDirectory

    # Load other utility modules.
    Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
    Import-Module .\config_test_vm.psm1 -Force -ArgumentList ($TestVMCredential.UserName, $TestVMCredential.Password, $WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue

    $VMList = $Config.VMMap.$SelfHostedRunnerName

    # Get all VMs to ready state.
    Initialize-AllVMs -VMList $VMList -ErrorAction Stop

    # Export build artifacts to the test VMs.
    Export-BuildArtifactsToVMs -VMList $VMList -ErrorAction Stop

    # Configure network adapters on VMs.
    Initialize-NetworkInterfacesOnVMs $VMList -ErrorAction Stop

    # Install eBPF Components on the test VM.
    foreach($VM in $VMList) {
        $VMName = $VM.Name
        Install-eBPFComponentsOnVM -VMName $VMname -TestMode $TestMode -KmTracing $KmTracing -KmTraceType $KmTraceType -ErrorAction Stop
    }

    Pop-Location
}  -ArgumentList (
    $TestVMCredential,
    $TestExecutionConfig,
    $SelfHostedRunnerName,
    $TestMode,
    $LogFileName,
    $WorkingDirectory,
    $KmTracing,
    $KmTraceType)

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
            $VMList = $Config.VMMap.$SelfHostedRunnerName
            # currently one VM is used per runner.
            $TestVMName = $VMList[0].Name
            Write-Host "Setting up VM $TestVMName for Kernel Tests has timed out after one hour" -ForegroundColor Yellow
            $Timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
            $CheckpointName = "Setup-Hang-$TestVMName-Checkpoint-$Timestamp"
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
