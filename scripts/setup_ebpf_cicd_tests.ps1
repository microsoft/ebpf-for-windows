# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ([parameter(Mandatory = $false)][string] $Target = "TEST_VM",
       [parameter(Mandatory = $false)][bool] $KmTracing = $true,
       [parameter(Mandatory = $false)][string] $KmTraceType = "file",
       [parameter(Mandatory = $false)][string] $TestMode = "CI/CD",
       [parameter(Mandatory = $false)][string] $LogFileName = "TestLog.log",
       [parameter(Mandatory = $false)][string] $WorkingDirectory = $pwd.ToString(),
       [parameter(Mandatory = $false)][string] $RegressionArtifactsVersion = "",
       [parameter(Mandatory = $false)][string] $RegressionArtifactsConfiguration = "",
       [parameter(Mandatory = $false)][string] $TestExecutionJsonFileName = "test_execution.json",
       [parameter(Mandatory = $false)][string] $SelfHostedRunnerName = [System.Net.Dns]::GetHostName(),
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

Write-Log "ExecuteOnHost: $ExecuteOnHost"
Write-Log "ExecuteOnVM: $ExecuteOnVM"
Write-Log "VMIsRemote: $VMIsRemote"
Write-Log "TestMode: $TestMode"
Write-Log "KmTracing: $KmTracing"
Write-Log "KmTraceType: $KmTraceType"
Write-Log "EnableHVCI: $EnableHVCI"
Write-Log "GranularTracing: $GranularTracing"
Write-Log "Architecture: $Architecture"

# Read the test execution json.
$Config = Get-Content ("{0}\{1}" -f $PSScriptRoot, $TestExecutionJsonFileName) | ConvertFrom-Json

if ($ExecuteOnVM) {
    if ($SelfHostedRunnerName -eq "1ESRunner") {
        $TestVMCredential = Retrieve-StoredCredential -Target $Target
    } else {
        $TestVMCredential = Get-StoredCredential -Target $Target -ErrorAction Stop
    }
} else {
    # Username and password are not used when running on host - use empty but non-null values.
    $UserName = $env:USERNAME
    $Password = ConvertTo-SecureString -String 'empty' -AsPlainText -Force
    $TestVMCredential = New-Object System.Management.Automation.PSCredential($UserName, $Password)
}

# Delete old log files if any.
Remove-Item "$env:TEMP\$LogFileName" -ErrorAction SilentlyContinue
Remove-Item ".\TestLogs" -Recurse -Confirm:$false -ErrorAction SilentlyContinue

if ($TestMode -eq "Regression") {

    # Download the release artifacts for regression tests.
    Get-RegressionTestArtifacts -ArtifactVersion $RegressionArtifactsVersion -Configuration $RegressionArtifactsConfiguration
}

Get-CoreNetTools -Architecture $Architecture
Get-PSExec

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
        [parameter(Mandatory = $true)] [bool] $ExecuteOnVM,
        [parameter(Mandatory = $true)] [bool] $VMIsRemote,
        [parameter(Mandatory = $true)] [bool] $GranularTracing
    )
    Push-Location $WorkingDirectory

    # Load other utility modules.
    Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
    Import-Module .\config_test_vm.psm1 -Force -ArgumentList ($TestVMCredential.UserName, $TestVMCredential.Password, $WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue

    if  ($ExecuteOnVM) {
        $VMList = $Config.VMMap.$SelfHostedRunnerName
        if (-not $VMIsRemote) {
            # Get all local VMs to ready state.
            Initialize-AllVMs -VMList $VMList -ErrorAction Stop
        }
    } else {
        Import-Module .\install_ebpf.psm1 -Force -ArgumentList ($WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue
        $VMList = @()
    }

    if ($ExecuteOnVM) {
        # Export build artifacts to the test VMs. Attempt with a few retries.
        $MaxRetryCount = 5
        for ($i = 0; $i -lt $MaxRetryCount; $i += 1) {
            try {
                Export-BuildArtifactsToVMs -VMList $VMList -VMIsRemote $VMIsRemote -ErrorAction Stop
                break
            } catch [System.Exception] {
                Write-Log "Export-BuildArtifactsToVMs failed: $_"
                Write-Log "Export-BuildArtifactsToVMs failed. Retrying..."
            }
        }

        # Enable HVCI on the test VMs if specified.
        if ($EnableHVCI -eq "On") {
            Write-Log "Enabling HVCI on test VMs..."
            # Enable HVCI on the test VM.
            foreach($VM in $VMList) {
                $VMName = $VM.Name
                Enable-HVCIOnVM -VMName $VMName -VMIsRemote:$VMIsRemote -ErrorAction Stop
            }
        }
    }

    # Configure network adapters on test VMs or host.
    Initialize-NetworkInterfaces `
        -ExecuteOnVM $ExecuteOnVM `
        -VMList $VMList `
        -TestWorkingDirectory $(if ($ExecuteOnVM) { "C:\ebpf" } else { $WorkingDirectory }) `
        -VMIsRemote:$VMIsRemote `
        -ErrorAction Stop

    Write-Log "Network interfaces initialized"

    $ExecuteOnHost = -not $ExecuteOnVM
    if  ($ExecuteOnHost) {
        # Install eBPF components on host, but skip anything that requires reboot.
        # Note that installing ebpf components requires psexec which does not run in a powershell job.
        Write-Log "Installing eBPF components on host"
        Install-eBPFComponents -TestMode $TestMode -KmTracing $KmTracing -KmTraceType $KmTraceType -SkipRebootOperations -GranularTracing:$GranularTracing
        return
    }

    # The rest of the script runs only if executing on VM.
    if (-not $ExecuteOnVM) {
        throw "Assertion failed: ExecuteOnVM must be true."
    }

    # Install eBPF Components on the test VM.
    foreach($VM in $VMList) {
        $VMName = $VM.Name
        Install-eBPFComponentsOnVM -VMName $VMName -TestMode $TestMode -KmTracing $KmTracing -KmTraceType $KmTraceType -VMIsRemote:$VMIsRemote -GranularTracing:$GranularTracing -ErrorAction Stop
    }

    # Log OS build information on the test VMs.
    foreach($VM in $VMList) {
        $VMName = $VM.Name
        Log-OSBuildInformationOnVM -VMName $VMName -VMIsRemote:$VMIsRemote -ErrorAction Stop
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
    $ExecuteOnVM,
    $VMIsRemote,
    $GranularTracing)

# Wait for the job to complete.
$JobTimedOut = `
    Wait-TestJobToComplete -Job $Job `
    -Config $Config `
    -SelfHostedRunnerName $SelfHostedRunnerName `
    -TestJobTimeout $TestJobTimeout `
    -CheckpointPrefix "Setup" `
    -ExecuteOnHost $ExecuteOnHost `
    -ExecuteOnVM $ExecuteOnVM `
    -AdminTestVMCredential $TestVMCredential `
    -StandardUserTestVMCredential $TestVMCredential `
    -VMIsRemote $VMIsRemote `
    -TestWorkingDirectory $(if ($ExecuteOnVM) { "C:\ebpf" } else { $WorkingDirectory }) `
    -LogFileName $LogFileName `
    -TestMode $TestMode `
    -Options @("None") `
    -TestHangTimeout (10*60) `
    -UserModeDumpFolder "C:\Dumps"

# Clean up.
Remove-Job -Job $Job -Force

Pop-Location

if ($JobTimedOut) {
    exit 1
}
