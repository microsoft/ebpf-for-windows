# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# Worker script: runs test execution logic in an isolated process.
# Invoked by execute_ebpf_cicd_tests.ps1 (the monitor).
# stdout/stderr is redirected to a file by the monitor, so Write-Host
# writes directly to a file with no pipe back-pressure.

param (
    [Parameter(Mandatory = $false)][string] $LogFileName = "TestLog.log",
    [Parameter(Mandatory = $false)][string] $WorkingDirectory = $pwd.ToString(),
    [Parameter(Mandatory = $false)][string] $TestExecutionJsonFileName = "test_execution.json",
    [Parameter(Mandatory = $false)][string] $TestMode = "CI/CD",
    [Parameter(Mandatory = $false)][string] $OptionsString = "None",
    [Parameter(Mandatory = $false)][string] $SelfHostedRunnerName = [System.Net.Dns]::GetHostName(),
    [Parameter(Mandatory = $false)][int] $TestHangTimeout = (30*60),
    [Parameter(Mandatory = $false)][string] $UserModeDumpFolder = "C:\Dumps",
    [Parameter(Mandatory = $false)][switch] $GranularTracing = $false,
    [Parameter(Mandatory = $false)][switch] $RunXdpTests,
    [Parameter(Mandatory = $false)][switch] $ExecuteOnHost,
    [Parameter(Mandatory = $false)][switch] $VMIsRemote
)

$ExecuteOnHost = [bool]$ExecuteOnHost
$ExecuteOnVM = (-not $ExecuteOnHost)
$VMIsRemote = [bool]$VMIsRemote

# Parse Options from comma-separated string (Start-Process can't pass arrays).
$Options = @($OptionsString -split ',')

Push-Location $WorkingDirectory

Import-Module $WorkingDirectory\common.psm1 -Force -ArgumentList ($LogFileName) -ErrorAction Stop

Write-Log "Worker process started (PID=$PID, TestMode=$TestMode, ExecuteOnHost=$ExecuteOnHost, ExecuteOnVM=$ExecuteOnVM, VMIsRemote=$VMIsRemote)"

# Read the test execution json.
$Config = Get-Content ("{0}\{1}" -f $PSScriptRoot, $TestExecutionJsonFileName) | ConvertFrom-Json

if ($ExecuteOnVM) {
    Write-Log "Tests will be executed on VM"
    $VMList = $Config.VMMap.$SelfHostedRunnerName
    $VMName = $VMList[0].Name
    $TestWorkingDirectory = "C:\ebpf"
} else {
    Write-Log "Executing on host"
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
        $TestWorkingDirectory,
        $LogFileName,
        $TestMode,
        $Options,
        $TestHangTimeout,
        $UserModeDumpFolder,
        $GranularTracing,
        $RunXdpTests) `
    -WarningAction SilentlyContinue

# Disable Defender real-time monitoring and add path/extension exclusions.
# These are not persisted across reboot and therefore need to be applied before test execution.
try {
    Write-Log "Configuring host Defender exclusions for $WorkingDirectory"
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath @($WorkingDirectory, $env:TEMP) -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionExtension @('.sys', '.exe', '.dll', '.etl', '.o') -ErrorAction SilentlyContinue
} catch {
    Write-Log "Warning: Failed to configure host Defender exclusions: $($_.Exception.Message)"
}

if ($ExecuteOnVM) {
    Write-Log "Configuring Defender exclusions on $VMName"
    $defenderScript = {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        $paths = @('C:\eBPF', 'C:\Dumps', 'C:\KernelDumps', 'C:\Windows\System32\drivers')
        $exts  = @('.sys', '.exe', '.dll', '.etl', '.o')
        Add-MpPreference -ExclusionPath $paths -ErrorAction SilentlyContinue
        Add-MpPreference -ExclusionExtension $exts -ErrorAction SilentlyContinue
    }
    $cred = Get-VMCredential -Username 'Administrator' -VMIsRemote $VMIsRemote
    try {
        Invoke-CommandOnVM -VMName $VMName -VMIsRemote $VMIsRemote -Credential $cred -ScriptBlock $defenderScript -TimeoutSeconds 120
        Write-Log "Defender exclusions applied on $VMName"
    } catch {
        Write-Log "Warning: Failed to configure VM Defender exclusions: $($_.Exception.Message)"
    }
}

$exitCode = 0
try {
    Write-Log "Running kernel tests"
    Run-KernelTests -Config $Config
    Write-Log "Running kernel tests completed"

    Stop-eBPFComponents -GranularTracing $GranularTracing
} catch {
    Write-Log "*** TEST FAILURE *** $($_.Exception.Message)"
    Write-Log $_.ScriptStackTrace
    if ($_.CategoryInfo.Reason -eq "TimeoutException") {
        try {
            Generate-KernelDumpOnVM
        } catch {
            Write-Log "Warning: kernel dump generation failed: $($_.Exception.Message)"
        }
    }
    $exitCode = 1
} finally {
    # Kill any remaining child processes.  Invoke-CommandOnVM uses
    # Invoke-Command -AsJob which creates in-process remoting jobs, but
    # Wait-TestJobToComplete and Generate-KernelDumpOnVM use Start-Job
    # which creates child powershell.exe processes.  If Stop-Job fails
    # (stuck PS Direct transport), these children survive and keep the
    # GitHub Actions step alive indefinitely.
    try {
        $children = Get-CimInstance Win32_Process -Filter "ParentProcessId = $PID" -ErrorAction SilentlyContinue
        if ($children) {
            Write-Log "Killing $(@($children).Count) remaining child process(es) from worker..."
            foreach ($child in $children) {
                Write-Log "  $($child.Name) PID=$($child.ProcessId)"
                & taskkill.exe /T /F /PID $child.ProcessId 2>&1 | Out-Null
            }
        }
    } catch {}
    Pop-Location
}

if ($exitCode -ne 0) {
    Write-Log "Worker exiting with failure"
    exit $exitCode
}
Write-Log "Worker process completed successfully"
