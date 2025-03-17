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
    $TestVMCredential = Retrieve-StoredCredential -Target $Target
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

    if ($TestMode -eq "Performance") {
        # Disable verifier
        Disable-VerifierOnVms -VMList $VMList -UserName $TestVMCredential.UserName -AdminPassword $TestVMCredential.Password
    }

    # Export build artifacts to the test VMs. Attempt with a few retries.
    $MaxRetryCount = 5
    for ($i = 0; $i -lt $MaxRetryCount; $i += 1) {
        try {
            Export-BuildArtifactsToVMs -VMList $VMList -ErrorAction Stop
            break
        } catch {
            if ($i -eq $MaxRetryCount) {
                Write-Log "Export-BuildArtifactsToVMs failed after $MaxRetryCount attempts."
                throw
            }
            Write-Log "Export-BuildArtifactsToVMs failed. Retrying..."
        }
    }

    # Configure network adapters on VMs.
    Initialize-NetworkInterfacesOnVMs $VMList -ErrorAction Stop

    # Install eBPF Components on the test VM.
    foreach($VM in $VMList) {
        $VMName = $VM.Name
        Install-eBPFComponentsOnVM -VMName $VMname -TestMode $TestMode -KmTracing $KmTracing -KmTraceType $KmTraceType -ErrorAction Stop
    }

    # Log OS build information on the test VM.
    foreach($VM in $VMList) {
        $VMName = $VM.Name
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

# TODO - remove this
# Get physical disk information and convert size to GB
$physicalDisks = Get-PhysicalDisk | Select-Object DeviceID, MediaType, @{Name="Size(GB)";Expression={[math]::Round($_.Size / 1GB, 2)}}

# Get volume information and convert size to GB
$volumes = Get-Volume | Select-Object DriveLetter, FileSystemLabel, @{Name="Size(GB)";Expression={[math]::Round($_.Size / 1GB, 2)}}, @{Name="SizeRemaining(GB)";Expression={[math]::Round($_.SizeRemaining / 1GB, 2)}}

# Display the results
Write-Output "Physical Disks:"
$physicalDisks | Format-Table -AutoSize

Write-Output "Volumes:"
$volumes | Format-Table -AutoSize

if ($JobTimedOut) {
    exit 1
}
