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

# Load other utility modules.
Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

if ($SelfHostedRunnerName -eq "1ESRunner") {
    Write-Log "Fetching the test VM credential using target: $Target"
    Get-PSExec
    $psExecPath = "$pwd\PSExec64.exe"
    $TestVMCredential = Retrieve-StoredCredential -Target $Target -PsExecPath $psExecPath
    if ($null -eq $TestVMCredential) {
        ThrowWithErrorMessage "Failed to retrieve the test VM credential."
    }
    $debugCred = $TestVMCredential.GetNetworkCredential() | Out-String
    Write-Log "Cred: $debugCred"
} else {
    $TestVMCredential = Get-StoredCredential -Target $Target -ErrorAction Stop
}

Import-Module .\config_test_vm.psm1 -Force -ArgumentList ($TestVMCredential.UserName, $TestVMCredential.Password, $WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue

# Read the test execution json.
$Config = Get-Content ("{0}\{1}" -f $PSScriptRoot, $TestExecutionJsonFileName) | ConvertFrom-Json
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
Write-Log "Finished downloading the required tools. Installing tools on the test VM."

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
    Write-Log "Starting the setup job."
    Push-Location $WorkingDirectory

    Write-Log "Importing modules."
    # Load other utility modules.
    Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
    Import-Module .\config_test_vm.psm1 -Force -ArgumentList ($TestVMCredential.UserName, $TestVMCredential.Password, $WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue

    $VMList = $Config.VMMap.$SelfHostedRunnerName

    # Get all VMs to ready state.
    Write-Log "Initializing all VMs."
    Initialize-AllVMs -VMList $VMList -ErrorAction Stop

    # Export build artifacts to the test VMs.
    Write-Log "Exporting build artifacts to VM"
    Export-BuildArtifactsToVMs -VMList $VMList -ErrorAction Stop

    # Configure network adapters on VMs.
    Write-Log "Configuring network interfaces on VMs."
    Initialize-NetworkInterfacesOnVMs $VMList -ErrorAction Stop

    # Install eBPF Components on the test VM.
    foreach($VM in $VMList) {
        $VMName = $VM.Name
        Write-Log "Installing eBPF components on VM: $VMName"
        Install-eBPFComponentsOnVM -VMName $VMname -TestMode $TestMode -KmTracing $KmTracing -KmTraceType $KmTraceType -ErrorAction Stop
    }

    # Log OS build information on the test VM.
    foreach($VM in $VMList) {
        $VMName = $VM.Name
        Write-Log "Logging OS build information on VM: $VMName"
        Log-OSBuildInformationOnVM -VMName $VMName -ErrorAction Stop
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
