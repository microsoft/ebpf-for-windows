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
       [Parameter(Mandatory = $false)][string] $Architecture = "x64")

# # Normalize the working directory path to avoid issues with relative path components
# $WorkingDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($WorkingDirectory)

Push-Location $WorkingDirectory

# Load other utility modules.
Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

if (-not $ExecuteOnHost) {
    if ($SelfHostedRunnerName -eq "1ESRunner") {
        $TestVMCredential = Retrieve-StoredCredential -Target $Target
    } else {
        $TestVMCredential = Get-StoredCredential -Target $Target -ErrorAction Stop
    }

    Import-Module .\config_test_vm.psm1 -Force -ArgumentList ($TestVMCredential.UserName, $TestVMCredential.Password, $WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue
} else {
    $EmptySecureString = ConvertTo-SecureString -String 'empty' -AsPlainText -Force
    Import-Module .\config_test_vm.psm1 -Force -ArgumentList ($env:USERNAME, $EmptySecureString, $WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue
    Import-Module .\install_ebpf.psm1 -Force -ArgumentList ($WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue
}

# Read the test execution json.
$Config = Get-Content ("{0}\{1}" -f $PSScriptRoot, $TestExecutionJsonFileName) | ConvertFrom-Json

if (-not $ExecuteOnHost) {
    $VMList = $Config.VMMap.$SelfHostedRunnerName

    # Delete old log files if any.
    Remove-Item "$env:TEMP\$LogFileName" -ErrorAction SilentlyContinue
    foreach($VM in $VMList) {
        $VMName = $VM.Name
        Remove-Item $env:TEMP\$LogFileName -ErrorAction SilentlyContinue
    }
} else {
    Write-Log "ExecuteOnHost enabled - skipping VM-related setup" -ForegroundColor Yellow
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

Get-CoreNetTools -Architecture $Architecture
Get-PSExec

if (-not $ExecuteOnHost) {
    # Only run VM setup when not executing on host
    $Job = Start-Job -ScriptBlock {
        param ([Parameter(Mandatory = $True)] [PSCredential] $TestVMCredential,
               [Parameter(Mandatory = $true)] [PSCustomObject] $Config,
               [Parameter(Mandatory = $true)] [string] $SelfHostedRunnerName,
               [parameter(Mandatory = $true)] [string] $TestMode,
               [parameter(Mandatory = $true)] [string] $LogFileName,
               [parameter(Mandatory = $true)] [string] $WorkingDirectory = $pwd.ToString(),
               [parameter(Mandatory = $true)] [bool] $KmTracing,
               [parameter(Mandatory = $true)] [string] $KmTraceType,
                [parameter(Mandatory = $true)] [string] $EnableHVCI
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

        # Configure network adapters on VMs.
        Initialize-NetworkInterfacesOnVMs $VMList -ErrorAction Stop

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

    if ($JobTimedOut) {
        exit 1
    }
} else {
    # When executing on host, install necessary components directly on the host.
    Write-Log "Setting up eBPF components on host (skipping reboot-required operations)" -ForegroundColor Yellow

    Initialize-NetworkInterfacesOnHost -WorkingDirectory $WorkingDirectory -LogFileName $LogFileName

    # Install eBPF components but skip anything that requires reboot.
    Install-eBPFComponents -TestMode $TestMode -KmTracing $KmTracing -KmTraceType $KmTraceType -SkipRebootOperations
}
Pop-Location
