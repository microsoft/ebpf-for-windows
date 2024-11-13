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

$SelfHostedRunnerName = "runner_host"
try {
    $TestVMCredential = Get-StoredCredential -Target $Target -ErrorAction Stop
} catch {
    Write-Host "Failed to get credentials for $Target. Using default credentials."
    $TestVMCredential = New-Credential -UserName 'Administrator' -AdminPassword 'P@ssw0rd'
}

# Load other utility modules.
Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
Import-Module .\config_test_vm.psm1 -Force -ArgumentList ($TestVMCredential.UserName, $TestVMCredential.Password, $WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue

# Read the test execution json.
$Config = Get-Content ("{0}\{1}" -f $PSScriptRoot, $TestExecutionJsonFileName) | ConvertFrom-Json
$VMList = $Config.VMMap.$SelfHostedRunnerName

# Delete old log files if any.
Remove-Item "$env:TEMP\$LogFileName" -ErrorAction SilentlyContinue
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
    $Config,
    $SelfHostedRunnerName,
    $TestMode,
    $LogFileName,
    $WorkingDirectory,
    $KmTracing,
    $KmTraceType)

# wait for the job to complete
$JobTimedOut = `
    Wait-TestJobToComplete -Job $Job `
    -Config $Config `
    -SelfHostedRunnerName $SelfHostedRunnerName `
    -TestJobTimeout $TestJobTimeout `
    -CheckpointPrefix "Setup"

# Clean up
Remove-Job -Job $Job -Force

Pop-Location

if ($JobTimedOut) {
    exit 1
}
