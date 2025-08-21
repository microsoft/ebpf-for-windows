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
       [Parameter(Mandatory = $false)][int] $TestJobTimeout = (30*60),
       [Parameter(Mandatory = $false)][string] $EnableHVCI = "Off",
       [Parameter(Mandatory = $false)][switch] $ExecuteOnHost,
       [Parameter(Mandatory = $false)][string] $Architecture = "x64",
       [Parameter(Mandatory = $false)][switch] $VMIsRemote,
       [Parameter(Mandatory = $false)][switch] $GranularTracing
)

$ExecuteOnHost = [bool]$ExecuteOnHost
$ExecuteOnVM = (-not $ExecuteOnHost)
$VMIsRemote = [bool]$VMIsRemote

Push-Location $WorkingDirectory

# Load other utility modules.
Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

if ($ExecuteOnVM) {
    if ($SelfHostedRunnerName -eq "1ESRunner") {
        $TestVMCredential = Retrieve-StoredCredential -Target $Target
    } else {
        $TestVMCredential = Get-StoredCredential -Target $Target -ErrorAction Stop
    }

    $UserName = $TestVMCredential.UserName
    $Password = $TestVMCredential.Password
} else {
    # Username and password are not used when running on host - use empty but non-null values.
    $UserName = $env:USERNAME
    $Password = ConvertTo-SecureString -String 'empty' -AsPlainText -Force
    $TestVMCredential = New-Object System.Management.Automation.PSCredential($UserName, $Password)
}

Import-Module .\config_test_vm.psm1 -Force -ArgumentList ($UserName, $Password, $WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue

# Read the test execution json.
$Config = Get-Content ("{0}\{1}" -f $PSScriptRoot, $TestExecutionJsonFileName) | ConvertFrom-Json

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

Get-CoreNetTools -Architecture $Architecture
Get-PSExec

if ($ExecuteOnVM -and $VMIsRemote) {
    # Setup for remote machine execution.
    $VMList = $Config.VMMap.$SelfHostedRunnerName

    # Export build artifacts to the remote machine(s).
    Export-BuildArtifactsToVMs -VMList $VMList -VMIsRemote:$VMIsRemote -ErrorAction Stop

    # Configure network adapters on remote machine(s).
    Initialize-NetworkInterfaces `
        -ExecuteOnHost $false `
        -ExecuteOnVM $true `
        -VMList $VMList `
        -TestWorkingDirectory "C:\ebpf" `
        -VMIsRemote:$VMIsRemote `
        -ErrorAction Stop

    # Install eBPF Components on the remote machine(s).
    foreach($VM in $VMList) {
        $VMName = $VM.Name
        Install-eBPFComponentsOnVM -VMName $VMName -TestMode $TestMode -KmTracing $KmTracing -KmTraceType $KmTraceType -VMIsRemote:$VMIsRemote -GranularTracing:$GranularTracing -ErrorAction Stop
    }

    Pop-Location
}
elseif ($ExecuteOnVM) {
    $Job = Start-Job -ScriptBlock {
        param (
            [Parameter(Mandatory = $true)] [PSCredential] $TestVMCredential,
            [Parameter(Mandatory = $true)] [PSCustomObject] $Config,
            [Parameter(Mandatory = $true)] [string] $SelfHostedRunnerName,
            [parameter(Mandatory = $true)] [string] $TestMode,
            [parameter(Mandatory = $true)] [string] $LogFileName,
            [parameter(Mandatory = $true)] [string] $WorkingDirectory = $pwd.ToString(),
            [parameter(Mandatory = $true)] [bool] $KmTracing,
            [parameter(Mandatory = $true)] [string] $KmTraceType,
            [parameter(Mandatory = $true)] [string] $EnableHVCI,
            [parameter(Mandatory = $true)] [bool] $GranularTracing
        )
        Push-Location $WorkingDirectory

        # Load other utility modules.
        Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

        Import-Module .\config_test_vm.psm1 -Force -ArgumentList ($TestVMCredential.UserName, $TestVMCredential.Password, $WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue

        $VMList = $Config.VMMap.$SelfHostedRunnerName

        # Get all VMs to ready state.
        Initialize-AllVMs -VMList $VMList -ErrorAction Stop

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

        # Configure network adapters.
        Initialize-NetworkInterfaces `
            -ExecuteOnHost $false `
            -ExecuteOnVM $true `
            -VMList $VMList `
            -TestWorkingDirectory "C:\ebpf" `
            -ErrorAction Stop

        # Enable HVCI on the test VMs if specified.
        Write-Log "EnableHVCI: $EnableHVCI"

        if ($EnableHVCI -eq "On") {
            Write-Log "Enabling HVCI on test VMs..."
            # Enable HVCI on the test VM.
            foreach($VM in $VMList) {
                $VMName = $VM.Name
                Enable-HVCIOnVM -VMName $VMName -ErrorAction Stop
            }
        } else {
            Write-Log "HVCI is not enabled on test VMs."
        }

        # Install eBPF Components on the test VM.
        foreach($VM in $VMList) {
            $VMName = $VM.Name
            Install-eBPFComponentsOnVM -VMName $VMname -TestMode $TestMode -KmTracing $KmTracing -KmTraceType $KmTraceType -GranularTracing:$GranularTracing -ErrorAction Stop
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
        $KmTraceType,
        $EnableHVCI,
        $GranularTracing)

    # Wait for the job to complete.
    $JobTimedOut = `
        Wait-TestJobToComplete -Job $Job `
        -Config $Config `
        -SelfHostedRunnerName $SelfHostedRunnerName `
        -TestJobTimeout $TestJobTimeout `
        -CheckpointPrefix "Setup" `
        -ExecuteOnVM $true

    # Clean up.
    Remove-Job -Job $Job -Force

    Pop-Location

    if ($JobTimedOut) {
        exit 1
    }
} else {
    Initialize-NetworkInterfaces `
        -ExecuteOnHost $true `
        -ExecuteOnVM $false `
        -VMList @() `
        -TestWorkingDirectory $WorkingDirectory `
        -ErrorAction Stop

    # Install eBPF components but skip anything that requires reboot.
    # Note that installing ebpf components requires psexec which does not run in a powershell job.
    Import-Module .\install_ebpf.psm1 -Force -ArgumentList ($WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue
    Install-eBPFComponents -TestMode $TestMode -KmTracing $KmTracing -KmTraceType $KmTraceType -SkipRebootOperations -GranularTracing:$GranularTracing

    Pop-Location
}
