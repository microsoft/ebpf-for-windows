# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# ──────────────────────────────────────────────────────────────────────
# MONITOR SCRIPT
# ──────────────────────────────────────────────────────────────────────
# Launches the test worker as a CHILD PROCESS whose stdout/stderr is
# redirected to a file.  This completely eliminates the nested-pipe
# back-pressure deadlock that caused jobs to hang:
#
#   Old:  VM Write-Host → VMBus pipe → Start-Job pipe → stdout pipe → GitHub
#   New:  VM Write-Host → VMBus pipe → worker stdout → FILE (no back-pressure)
#
# The monitor tails the output file for GitHub log visibility and
# enforces a timeout.  On timeout it connects to the VM to generate
# crash dumps, then kills the worker with Stop-Process -Force (which
# is an OS-level kill -- always succeeds, unlike Stop-Job on a stuck
# PS Direct transport).
# ──────────────────────────────────────────────────────────────────────

param ([Parameter(Mandatory = $false)][string] $LogFileName = "TestLog.log",
       [Parameter(Mandatory = $false)][string] $WorkingDirectory = $pwd.ToString(),
       [Parameter(Mandatory = $false)][string] $TestExecutionJsonFileName = "test_execution.json",
       [Parameter(Mandatory = $false)][string] $TestMode = "CI/CD",
       [Parameter(Mandatory = $false)][string[]] $Options = @("None"),
       [Parameter(Mandatory = $false)][string] $SelfHostedRunnerName = [System.Net.Dns]::GetHostName(),
       [Parameter(Mandatory = $false)][int] $TestHangTimeout = (30*60),
       [Parameter(Mandatory = $false)][string] $UserModeDumpFolder = "C:\Dumps",
       [Parameter(Mandatory = $false)][int] $TestJobTimeout = (60*60),
       [Parameter(Mandatory = $false)][switch] $GranularTracing = $false,
       # Boolean parameter indicating if XDP tests should be run.
       [Parameter(Mandatory = $false)][bool] $RunXdpTests = $false,
       [Parameter(Mandatory = $false)][switch] $ExecuteOnHost,
       # This parameter is only used when ExecuteOnHost is false.
       [Parameter(Mandatory = $false)][switch] $VMIsRemote)

$ExecuteOnHost = [bool]$ExecuteOnHost
$ExecuteOnVM = (-not $ExecuteOnHost)
$VMIsRemote = [bool]$VMIsRemote

Push-Location $WorkingDirectory

Import-Module $WorkingDirectory\common.psm1 -Force -ArgumentList ($LogFileName) -ErrorAction Stop

Write-Log "Execute starting (TestMode=$TestMode, ExecuteOnHost=$ExecuteOnHost, ExecuteOnVM=$ExecuteOnVM, VMIsRemote=$VMIsRemote, Timeout=${TestJobTimeout}s)"

# Read the test execution json.
$Config = Get-Content ("{0}\{1}" -f $PSScriptRoot, $TestExecutionJsonFileName) | ConvertFrom-Json

# ── Phase 1: Launch the worker process ──────────────────────────────
# The worker runs in a separate powershell.exe process.  Its stdout
# and stderr are redirected to files -- no pipe, no back-pressure.
$workerScript = Join-Path $PSScriptRoot "execute_test_worker.ps1"
$outputFile = Join-Path $env:TEMP "test_worker_output_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$errorFile  = Join-Path $env:TEMP "test_worker_error_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Build argument list.  Array elements are joined by Start-Process.
$workerArgs = @(
    "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
    "-File", $workerScript,
    "-LogFileName", $LogFileName,
    "-WorkingDirectory", $WorkingDirectory,
    "-TestExecutionJsonFileName", $TestExecutionJsonFileName,
    "-TestMode", $TestMode,
    "-SelfHostedRunnerName", $SelfHostedRunnerName,
    "-TestHangTimeout", $TestHangTimeout,
    "-UserModeDumpFolder", $UserModeDumpFolder
)
if ($Options -and $Options.Count -gt 0) {
    # Pass Options as a comma-separated string (Start-Process can't pass arrays).
    $workerArgs += @("-OptionsString", ($Options -join ','))
}
if ($GranularTracing)  { $workerArgs += "-GranularTracing" }
if ($RunXdpTests)      { $workerArgs += "-RunXdpTests" }
if ($ExecuteOnHost)    { $workerArgs += "-ExecuteOnHost" }
if ($VMIsRemote)       { $workerArgs += "-VMIsRemote" }

Write-Log "Starting worker process (output → $outputFile)"
$worker = Start-Process -FilePath "powershell.exe" `
    -ArgumentList $workerArgs `
    -NoNewWindow -PassThru `
    -RedirectStandardOutput $outputFile `
    -RedirectStandardError $errorFile
# Cache the handle so we can read ExitCode after the process exits.
$workerHandle = $worker.Handle
Write-Log "Worker started (PID=$($worker.Id))"

# ── Phase 2: Poll for completion, tail output ───────────────────────
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$pollInterval = 5
$heartbeatInterval = 30
$timeSinceOutput = 0
$linesSeen = 0
$timedOut = $false

while (-not $worker.HasExited) {
    Start-Sleep -Seconds $pollInterval
    $timeSinceOutput += $pollInterval

    # Tail new lines from the output file.  Use FileStream with ReadWrite
    # sharing so we never conflict with the worker process that holds the
    # file open for writing.
    if (Test-Path $outputFile) {
        try {
            $fs = [System.IO.FileStream]::new(
                $outputFile,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
            $reader = [System.IO.StreamReader]::new($fs)
            $content = $reader.ReadToEnd()
            $reader.Close()
            $fs.Close()
            $allLines = @($content -split "`n" | ForEach-Object { $_.TrimEnd("`r") } | Where-Object { $_ -ne '' })
            if ($allLines.Count -gt $linesSeen) {
                $newCount = $allLines.Count - $linesSeen
                if ($newCount -le 20) {
                    for ($i = $linesSeen; $i -lt $allLines.Count; $i++) {
                        Write-Host $allLines[$i]
                    }
                } else {
                    Write-Host "... ($newCount new lines, showing last 10)"
                    $allLines | Select-Object -Last 10 | ForEach-Object { Write-Host $_ }
                }
                $linesSeen = $allLines.Count
                $timeSinceOutput = 0
            }
        } catch {
            # File may be locked momentarily; skip this cycle.
        }
    }

    if ($timeSinceOutput -ge $heartbeatInterval) {
        Write-Log "Execute: worker running ($([int]$sw.Elapsed.TotalSeconds)s / ${TestJobTimeout}s, PID=$($worker.Id))..."
        $timeSinceOutput = 0
    }

    # ── Timeout handling ────────────────────────────────────────────
    if ($sw.Elapsed.TotalSeconds -ge $TestJobTimeout) {
        Write-Log "*** TIMEOUT *** Worker has been running for $([int]$sw.Elapsed.TotalSeconds)s (limit: ${TestJobTimeout}s)"
        $timedOut = $true

        # Attempt to generate crash dumps on the VM before killing the worker.
        if ($ExecuteOnVM) {
            $VMList = $Config.VMMap.$SelfHostedRunnerName
            $VMName = $VMList[0].Name
            $TestWorkingDirectory = "C:\ebpf"
            Write-Log "Generating kernel dump on $VMName due to timeout..."
            try {
                Import-Module $WorkingDirectory\vm_run_tests.psm1 `
                    -Force `
                    -ArgumentList(
                        $false, $true, $VMIsRemote, $VMName, $TestWorkingDirectory,
                        $LogFileName, $TestMode, $Options, $TestHangTimeout,
                        $UserModeDumpFolder, $false, $false) `
                    -WarningAction SilentlyContinue

                # Generate-KernelDumpOnVM connects to the VM via PS Direct and
                # runs NotMyFault64.exe to trigger a bluescreen with dump.
                # The monitor process gets its own PS Direct session (separate
                # from the worker's), so this works even if the worker is stuck.
                Generate-KernelDumpOnVM -TimeoutSeconds 300
            } catch {
                Write-Log "Failed to generate kernel dump: $($_.Exception.Message)"
            }
        }

        # Kill the worker process.  Stop-Process -Force is an OS-level kill
        # that always succeeds -- unlike Stop-Job on a stuck PS Direct transport.
        Write-Log "Killing worker process (PID=$($worker.Id))..."
        try {
            Stop-Process -Id $worker.Id -Force -ErrorAction SilentlyContinue
            $worker.WaitForExit(30000) | Out-Null
        } catch {
            Write-Log "Warning: Stop-Process failed: $($_.Exception.Message)"
        }
        break
    }
}

# ── Phase 3: Collect results ────────────────────────────────────────
# Drain any final output lines.
if (Test-Path $outputFile) {
    try {
        $fs = [System.IO.FileStream]::new(
            $outputFile,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
        $reader = [System.IO.StreamReader]::new($fs)
        $content = $reader.ReadToEnd()
        $reader.Close()
        $fs.Close()
        $allLines = @($content -split "`n" | ForEach-Object { $_.TrimEnd("`r") } | Where-Object { $_ -ne '' })
        if ($allLines.Count -gt $linesSeen) {
            $remaining = $allLines.Count - $linesSeen
            if ($remaining -le 50) {
                for ($i = $linesSeen; $i -lt $allLines.Count; $i++) {
                    Write-Host $allLines[$i]
                }
            } else {
                Write-Host "... ($remaining final lines, showing last 20)"
                $allLines | Select-Object -Last 20 | ForEach-Object { Write-Host $_ }
            }
        }
    } catch {}
}

# Copy worker output logs to TestLogs for artifact upload.
$testLogsDir = Join-Path $WorkingDirectory "TestLogs"
if (-not (Test-Path $testLogsDir)) { New-Item -ItemType Directory -Path $testLogsDir -Force | Out-Null }
try {
    if (Test-Path $outputFile) {
        Copy-Item -Path $outputFile -Destination (Join-Path $testLogsDir "worker_output.log") -Force -ErrorAction SilentlyContinue
    }
    if ((Test-Path $errorFile) -and (Get-Item $errorFile).Length -gt 0) {
        Copy-Item -Path $errorFile -Destination (Join-Path $testLogsDir "worker_error.log") -Force -ErrorAction SilentlyContinue
        Write-Log "Worker stderr (first 20 lines):"
        Get-Content -Path $errorFile -TotalCount 20 -ErrorAction SilentlyContinue | ForEach-Object { Write-Log "  $_" }
    }
} catch {}

# Determine exit status.
$workerExitCode = $worker.ExitCode
Write-Log "Worker exited with code: $workerExitCode (timedOut=$timedOut)"

Pop-Location

if ($timedOut) {
    Write-Log "Exiting with error: worker timed out after ${TestJobTimeout}s"
    [Environment]::Exit(1)
}

if ($workerExitCode -ne 0) {
    Write-Log "Exiting with error: worker failed (exit code $workerExitCode)"
    [Environment]::Exit(1)
}

Write-Log "execute_ebpf_cicd_tests.ps1 completed successfully"