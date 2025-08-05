# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# This module provides utility functions for granular ETW tracing
# to enable per-test and per-operation trace collection

param(
    [Parameter(Mandatory=$true)] [string] $LogFileName,
    [Parameter(Mandatory=$true)] [string] $WorkingDirectory,
    [Parameter(Mandatory=$false)] [string] $WprpFileName = "ebpfforwindows.wprp",
    [Parameter(Mandatory=$false)] [string] $TracingProfileName = "EbpfForWindowsProvider-File"
)

Import-Module $WorkingDirectory\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

# Global variables to track tracing state
$script:TracingEnabled = $false
$script:CurrentTraceFile = $null
$script:WprpProfilePath = $null
$script:WprpFileName = $WprpFileName
$script:TracingProfileName = $TracingProfileName

<#
.SYNOPSIS
    Decodes WPR error codes to human-readable descriptions.

.PARAMETER ExitCode
    The WPR exit code to decode.

.RETURNS
    A human-readable description of the error.
#>
function Get-WPRErrorDescription {
    param([int]$ExitCode)

    switch ($ExitCode) {
        0 { return "Success" }
        1 { return "General WPR error or no recording in progress" }
        -983562752 { return "ETW session corruption or invalid state (0xC55A0000)" }
        -2147483648 { return "Severe system error or access violation (0x80000000)" }
        -1073741819 { return "Access denied (0xC0000005)" }
        -1073741502 { return "Invalid parameter (0xC0000022)" }
        -1073741515 { return "No such file or directory (0xC0000015)" }
        default { return "Unknown error (0x$($ExitCode.ToString('X')))" }
    }
}

<#
.SYNOPSIS
    Initializes the tracing utilities module.

.DESCRIPTION
    Sets up the tracing environment and locates the WPRP profile file.

.PARAMETER WorkingDirectory
    The working directory where the WPRP file is located.

.PARAMETER WprpFileName
    The name of the WPRP file to use. Defaults to "ebpfforwindows.wprp".

.PARAMETER TracingProfileName
    The name of the tracing profile to use. Defaults to "EbpfForWindowsProvider-File".
#>
function Initialize-TracingUtils {
    param(
        [Parameter(Mandatory=$true)] [string] $WorkingDirectory,
        [Parameter(Mandatory=$false)] [string] $WprpFileName = $script:WprpFileName,
        [Parameter(Mandatory=$false)] [string] $TracingProfileName = $script:TracingProfileName
    )
    
    # Update global variables if parameters are provided
    if ($WprpFileName) { $script:WprpFileName = $WprpFileName }
    if ($TracingProfileName) { $script:TracingProfileName = $TracingProfileName }

    $script:WprpProfilePath = Join-Path $WorkingDirectory $script:WprpFileName
    
    if (-not (Test-Path $script:WprpProfilePath)) {
        Write-Log "Warning: WPRP profile not found at $script:WprpProfilePath" -ForegroundColor Yellow
        return $false
    }
    
    Write-Log "Tracing utils initialized with profile: $script:WprpProfilePath using profile: $script:TracingProfileName"
    return $true
}

<#
.SYNOPSIS
    Starts ETW tracing for a specific operation.

.DESCRIPTION
    Starts ETW tracing with a unique filename based on the operation name and timestamp.

.PARAMETER OperationName
    The name of the operation being traced (e.g., "unit_tests", "setup", "cleanup").

.PARAMETER OutputDirectory
    The directory where the ETL file will be saved.

.PARAMETER TraceType
    The type of tracing to use ("file" or "memory"). Defaults to "file".

.RETURNS
    The full path to the ETL file that will be created, or $null if tracing fails to start.
#>
function Start-OperationTrace {
    param(
        [Parameter(Mandatory=$true)] [string] $OperationName,
        [Parameter(Mandatory=$true)] [string] $OutputDirectory,
        [Parameter(Mandatory=$false)] [string] $TraceType = "file"
    )
    
    # Stop any existing trace first to avoid conflicts
    if ($script:TracingEnabled) {
        Write-Log "Stopping existing trace before starting new one"
        Stop-OperationTrace
    }
    
    # Cancel any orphaned WPR sessions to avoid "profiles already running" errors
    try {
        Write-Log "Cleaning up any existing WPR sessions before starting new trace"

        # Use a timeout for the initial cleanup as well
        $cleanupJob = Start-Job -ScriptBlock {
            param($OutputDir)
            $cancelProcess = Start-Process -FilePath "wpr.exe" -ArgumentList "-cancel" -NoNewWindow -Wait -PassThru -RedirectStandardError "$OutputDir\wpr_cancel_error.txt"
            return $cancelProcess.ExitCode
        } -ArgumentList $OutputDirectory

        $cleanupCompleted = Wait-Job -Job $cleanupJob -Timeout 10

        if ($cleanupCompleted) {
            $cleanupExitCode = Receive-Job -Job $cleanupJob
            Remove-Job -Job $cleanupJob -Force

            if ($cleanupExitCode -eq 0) {
                Write-Log "Successfully canceled existing WPR sessions" -ForegroundColor Green
            } else {
                # Exit code is not 0, but this is expected if no sessions were running
                Write-Log "No existing WPR sessions to cancel (Exit code: $cleanupExitCode)" -ForegroundColor Gray
            }
        } else {
            Write-Log "WPR cleanup timed out, forcing process cleanup..." -ForegroundColor Yellow
            Remove-Job -Job $cleanupJob -Force

            # Kill any hung WPR processes from previous sessions
            try {
                $wprProcesses = Get-Process -Name "wpr" -ErrorAction SilentlyContinue
                if ($wprProcesses) {
                    Write-Log "Terminating $($wprProcesses.Count) stuck WPR process(es)..." -ForegroundColor Yellow
                    foreach ($proc in $wprProcesses) {
                        try {
                            $proc.Kill()
                            Write-Log "Terminated WPR process $($proc.Id)" -ForegroundColor Yellow
                        } catch {
                            Write-Log "Failed to kill WPR process $($proc.Id): $_" -ForegroundColor Red
                        }
                    }
                    Start-Sleep -Seconds 2
                }
            } catch {
                Write-Log "Failed to enumerate/kill WPR processes: $_" -ForegroundColor Red
            }
        }
    } catch {
        Write-Log "Warning: Failed to cancel existing WPR sessions: $_" -ForegroundColor Yellow
    }

    if (-not $script:WprpProfilePath -or -not (Test-Path $script:WprpProfilePath)) {
        Write-Log "WPRP profile not available, skipping trace start" -ForegroundColor Yellow
        return $null
    }

    # Create output directory if it doesn't exist
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    # Generate unique ETL filename
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $etlFileName = "${OperationName}_${timestamp}.etl"
    $script:CurrentTraceFile = Join-Path $OutputDirectory $etlFileName

    try {
        # Determine the profile name based on trace type and configured profile
        $baseProfileName = $script:TracingProfileName
        if ($TraceType -eq "file") {
            # If the profile name already includes the mode, use as-is, otherwise append -File
            if ($baseProfileName -match "-(File|Memory)$") {
                $profileName = $baseProfileName -replace "-(File|Memory)$", "-File"
            } else {
                $profileName = "$baseProfileName-File"
            }
            Write-Log "Starting ETW trace for '$OperationName' (file mode): $script:CurrentTraceFile" -ForegroundColor Cyan
            Write-Log "Debug: WPR command will be: wpr.exe -start `"$script:WprpProfilePath!$profileName`" -filemode" -ForegroundColor Yellow
            $arguments = "-start `"$script:WprpProfilePath!$profileName`" -filemode"
        } else {
            # If the profile name already includes the mode, use as-is, otherwise append -Memory
            if ($baseProfileName -match "-(File|Memory)$") {
                $profileName = $baseProfileName -replace "-(File|Memory)$", "-Memory"
            } else {
                $profileName = "$baseProfileName-Memory"
            }
            Write-Log "Starting ETW trace for '$OperationName' (memory mode)" -ForegroundColor Cyan
            Write-Log "Debug: WPR command will be: wpr.exe -start `"$script:WprpProfilePath!$profileName`"" -ForegroundColor Yellow
            $arguments = "-start `"$script:WprpProfilePath!$profileName`""
        }

        Write-Log "Debug: ETL file will be created at: $script:CurrentTraceFile" -ForegroundColor Yellow
        $process = Start-Process -FilePath "wpr.exe" -ArgumentList $arguments -NoNewWindow -Wait -PassThru -RedirectStandardError "$OutputDirectory\wpr_start_error.txt"

        if ($process.ExitCode -eq 0) {
            $script:TracingEnabled = $true
            Write-Log "Successfully started ETW trace for '$OperationName'" -ForegroundColor Green
            Write-Log "Debug: Trace file location confirmed: $script:CurrentTraceFile" -ForegroundColor Yellow
            return $script:CurrentTraceFile
        } else {
            $startErrorDescription = Get-WPRErrorDescription -ExitCode $process.ExitCode
            Write-Log "Failed to start ETW trace. Exit code: $($process.ExitCode) ($startErrorDescription)" -ForegroundColor Red

            if (Test-Path "$OutputDirectory\wpr_start_error.txt") {
                $errorContent = Get-Content "$OutputDirectory\wpr_start_error.txt" -Raw
                Write-Log "WPR error output: $errorContent" -ForegroundColor Red
            }

            # For any start failure, try a more aggressive cleanup and retry once
            Write-Log "Attempting recovery for WPR start failure..." -ForegroundColor Yellow
            try {
                # Force cancel any sessions
                $forceCancel = Start-Process -FilePath "wpr.exe" -ArgumentList "-cancel" -NoNewWindow -Wait -PassThru
                Write-Log "Force cancel for recovery - Exit code: $($forceCancel.ExitCode)" -ForegroundColor Yellow

                # Brief pause to let system stabilize
                Start-Sleep -Seconds 3

                # Retry the start command once
                Write-Log "Retrying WPR start after recovery..." -ForegroundColor Yellow
                $retryProcess = Start-Process -FilePath "wpr.exe" -ArgumentList $arguments -NoNewWindow -Wait -PassThru -RedirectStandardError "$OutputDirectory\wpr_start_retry_error.txt"

                if ($retryProcess.ExitCode -eq 0) {
                    $script:TracingEnabled = $true
                    Write-Log "Successfully started ETW trace after recovery for '$OperationName'" -ForegroundColor Green
                    return $script:CurrentTraceFile
                } else {
                    $retryErrorDescription = Get-WPRErrorDescription -ExitCode $retryProcess.ExitCode
                    Write-Log "Retry also failed. Exit code: $($retryProcess.ExitCode) ($retryErrorDescription)" -ForegroundColor Red
                }
            } catch {
                Write-Log "Recovery attempt failed: $_" -ForegroundColor Red
            }

            return $null
        }
    } catch {
        Write-Log "Exception starting ETW trace: $_" -ForegroundColor Red
        return $null
    }
}

<#
.SYNOPSIS
    Stops the currently active ETW trace.

.DESCRIPTION
    Stops the currently running ETW trace and saves it to the previously specified file.

.RETURNS
    The path to the saved ETL file, or $null if no trace was active or stop failed.
#>
function Stop-OperationTrace {
    if (-not $script:TracingEnabled) {
        Write-Log "No active trace to stop"
        return $null
    }

    try {
        Write-Log "Stopping ETW trace: $script:CurrentTraceFile" -ForegroundColor Cyan

        # First, check WPR status to see if there are active sessions
        try {
            Write-Log "Debug: Checking WPR status before stop..." -ForegroundColor Yellow
            $statusProcess = Start-Process -FilePath "wpr.exe" -ArgumentList "-status" -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$(Split-Path $script:CurrentTraceFile)\wpr_status.txt" -RedirectStandardError "$(Split-Path $script:CurrentTraceFile)\wpr_status_error.txt"
            if (Test-Path "$(Split-Path $script:CurrentTraceFile)\wpr_status.txt") {
                $statusContent = Get-Content "$(Split-Path $script:CurrentTraceFile)\wpr_status.txt" -Raw
                Write-Log "WPR status: $statusContent" -ForegroundColor Yellow
            }
        } catch {
            Write-Log "Warning: Could not check WPR status: $_" -ForegroundColor Yellow
        }

        Write-Log "Debug: WPR stop command will be: wpr.exe -stop `"$script:CurrentTraceFile`"" -ForegroundColor Yellow

        # Use a timeout for the WPR stop command (30 seconds)
        $job = Start-Job -ScriptBlock {
            param($TraceFile)
            $process = Start-Process -FilePath "wpr.exe" -ArgumentList "-stop `"$TraceFile`"" -NoNewWindow -Wait -PassThru -RedirectStandardError "$(Split-Path $TraceFile)\wpr_stop_error.txt"
            return $process.ExitCode
        } -ArgumentList $script:CurrentTraceFile

        $completed = Wait-Job -Job $job -Timeout 30

        if ($completed) {
            $exitCode = Receive-Job -Job $job
            Remove-Job -Job $job -Force

            if ($exitCode -eq 0) {
                Write-Log "Successfully stopped ETW trace: $script:CurrentTraceFile" -ForegroundColor Green

                # Check if file was created and report its size
                if (Test-Path $script:CurrentTraceFile) {
                    $fileSize = (Get-Item $script:CurrentTraceFile).Length / 1MB
                    Write-Log "ETL file size: $([math]::Round($fileSize, 2)) MB" -ForegroundColor Green
                    Write-Log "Debug: Final ETL file confirmed at: $script:CurrentTraceFile" -ForegroundColor Yellow
                } else {
                    Write-Log "Warning: ETL file was not created at expected location: $script:CurrentTraceFile" -ForegroundColor Yellow
                }

                $savedFile = $script:CurrentTraceFile
                $script:TracingEnabled = $false
                $script:CurrentTraceFile = $null
                return $savedFile
            } else {
                # Decode the WPR error code for better diagnostics
                $errorDescription = Get-WPRErrorDescription -ExitCode $exitCode
                Write-Log "Failed to stop ETW trace. Exit code: $exitCode ($errorDescription)" -ForegroundColor Red

                if (Test-Path "$(Split-Path $script:CurrentTraceFile)\wpr_stop_error.txt") {
                    $errorContent = Get-Content "$(Split-Path $script:CurrentTraceFile)\wpr_stop_error.txt" -Raw
                    Write-Log "WPR error output: $errorContent" -ForegroundColor Red
                }

                # For any error code, try to force a cancel and cleanup
                Write-Log "Attempting to force cancel due to WPR stop failure..." -ForegroundColor Yellow
                try {
                    $forceCancel = Start-Process -FilePath "wpr.exe" -ArgumentList "-cancel" -NoNewWindow -Wait -PassThru
                    Write-Log "Force cancel exit code: $($forceCancel.ExitCode)" -ForegroundColor Yellow
                } catch {
                    Write-Log "Failed to force cancel: $_" -ForegroundColor Red
                }

                return $null
            }
        } else {
            # Timeout occurred, kill the job and try to cancel WPR
            Write-Log "WPR stop command timed out after 30 seconds. Attempting to cancel..." -ForegroundColor Red
            Remove-Job -Job $job -Force

            # Try to cancel any running WPR sessions with timeout
            try {
                Write-Log "Attempting to cancel WPR sessions..." -ForegroundColor Yellow

                # Use a job for cancel as well to avoid hanging
                $cancelJob = Start-Job -ScriptBlock {
                    $cancelProcess = Start-Process -FilePath "wpr.exe" -ArgumentList "-cancel" -NoNewWindow -Wait -PassThru
                    return $cancelProcess.ExitCode
                }

                $cancelCompleted = Wait-Job -Job $cancelJob -Timeout 15

                if ($cancelCompleted) {
                    $cancelExitCode = Receive-Job -Job $cancelJob
                    Remove-Job -Job $cancelJob -Force
                    Write-Log "WPR cancel exit code: $cancelExitCode" -ForegroundColor Yellow

                    if ($cancelExitCode -eq 0) {
                        Write-Log "Successfully canceled WPR sessions" -ForegroundColor Green
                    } else {
                        Write-Log "WPR cancel failed with exit code: $cancelExitCode" -ForegroundColor Red
                    }
                } else {
                    Write-Log "WPR cancel also timed out. Forcing cleanup..." -ForegroundColor Red
                    Remove-Job -Job $cancelJob -Force

                    # Try one more aggressive approach - kill any wpr.exe processes
                    try {
                        $wprProcesses = Get-Process -Name "wpr" -ErrorAction SilentlyContinue
                        if ($wprProcesses) {
                            Write-Log "Found $($wprProcesses.Count) WPR process(es). Attempting to terminate..." -ForegroundColor Yellow
                            foreach ($proc in $wprProcesses) {
                                try {
                                    $proc.Kill()
                                    Write-Log "Terminated WPR process with ID: $($proc.Id)" -ForegroundColor Yellow
                                } catch {
                                    Write-Log "Failed to terminate WPR process $($proc.Id): $_" -ForegroundColor Red
                                }
                            }
                        }
                    } catch {
                        Write-Log "Failed to enumerate/kill WPR processes: $_" -ForegroundColor Red
                    }
                }
            } catch {
                Write-Log "Failed to cancel WPR sessions: $_" -ForegroundColor Red
            }

            return $null
        }
    } catch {
        Write-Log "Exception stopping ETW trace: $_" -ForegroundColor Red
        return $null
    } finally {
        $script:TracingEnabled = $false
        $script:CurrentTraceFile = $null
    }
}

<#
.SYNOPSIS
    Cancels any active ETW tracing sessions.

.DESCRIPTION
    Cancels all active WPR tracing sessions. This is useful for cleanup.
#>
function Stop-AllTraces {
    try {
        Write-Log "Canceling all active ETW traces" -ForegroundColor Cyan
        
        # Use a job with timeout for the cancel operation
        $cancelJob = Start-Job -ScriptBlock {
            $process = Start-Process -FilePath "wpr.exe" -ArgumentList "-cancel" -NoNewWindow -Wait -PassThru -RedirectStandardError "wpr_cancel_all_error.txt"
            return @{
                ExitCode = $process.ExitCode
                ErrorFile = "wpr_cancel_all_error.txt"
            }
        }

        $cancelCompleted = Wait-Job -Job $cancelJob -Timeout 15

        if ($cancelCompleted) {
            $result = Receive-Job -Job $cancelJob
            Remove-Job -Job $cancelJob -Force

            if ($result.ExitCode -eq 0) {
                Write-Log "Successfully canceled all ETW traces" -ForegroundColor Green
            } else {
                # Check if it's the "no profiles running" error
                if (Test-Path $result.ErrorFile) {
                    $errorContent = Get-Content $result.ErrorFile -Raw
                    if ($errorContent -match "no trace profiles running") {
                        Write-Log "No active ETW traces to cancel" -ForegroundColor Gray
                    } else {
                        Write-Log "Failed to cancel ETW traces. Exit code: $($result.ExitCode)" -ForegroundColor Yellow
                        Write-Log "WPR error output: $errorContent" -ForegroundColor Yellow
                    }
                } else {
                    Write-Log "Failed to cancel ETW traces. Exit code: $($result.ExitCode)" -ForegroundColor Yellow
                }
            }
        } else {
            Write-Log "WPR cancel operation timed out. Attempting to force cleanup..." -ForegroundColor Red
            Remove-Job -Job $cancelJob -Force

            # Try to kill WPR processes as last resort
            try {
                $wprProcesses = Get-Process -Name "wpr" -ErrorAction SilentlyContinue
                if ($wprProcesses) {
                    Write-Log "Found $($wprProcesses.Count) WPR process(es). Attempting to terminate..." -ForegroundColor Yellow
                    foreach ($proc in $wprProcesses) {
                        try {
                            $proc.Kill()
                            Write-Log "Terminated WPR process with ID: $($proc.Id)" -ForegroundColor Yellow
                        } catch {
                            Write-Log "Failed to terminate WPR process $($proc.Id): $_" -ForegroundColor Red
                        }
                    }
                } else {
                    Write-Log "No WPR processes found to terminate" -ForegroundColor Gray
                }
            } catch {
                Write-Log "Failed to enumerate/kill WPR processes: $_" -ForegroundColor Red
            }
        }
    } catch {
        Write-Log "Exception canceling ETW traces: $_" -ForegroundColor Red
    } finally {
        $script:TracingEnabled = $false
        $script:CurrentTraceFile = $null
    }
}

<#
.SYNOPSIS
    Checks if ETW tracing is currently active.

.RETURNS
    $true if tracing is active, $false otherwise.
#>
function Test-TracingActive {
    return $script:TracingEnabled
}

<#
.SYNOPSIS
    Gets the current trace file path.

.RETURNS
    The path to the current ETL file being written, or $null if no trace is active.
#>
function Get-CurrentTraceFile {
    return $script:CurrentTraceFile
}

<#
.SYNOPSIS
    Starts granular tracing for a script if enabled.

.DESCRIPTION
    Handles the complete initialization and startup of granular tracing for a script.
    This is a convenience function that combines module loading, initialization, and trace start.

.PARAMETER OperationName
    The name of the operation being traced (e.g., "setup_ebpf", "cleanup_ebpf").

.PARAMETER WorkingDirectory
    The working directory where the trace files will be saved and where common.psm1 is located.

.PARAMETER LogFileName
    The log file name for common.psm1.

.PARAMETER KmTraceType
    The type of tracing to use ("file" or "memory"). Defaults to "file".

.PARAMETER GranularTracing
    Whether granular tracing is enabled.

.PARAMETER KmTracing
    Whether kernel mode tracing is enabled.

.PARAMETER WprpFileName
    The name of the WPRP file to use. Defaults to "ebpfforwindows.wprp".

.PARAMETER TracingProfileName
    The name of the tracing profile to use. Defaults to "EbpfForWindowsProvider".

.RETURNS
    The full path to the ETL file that will be created, or $null if tracing is not enabled or fails.
#>
function Start-ScriptTracing {
    param(
        [Parameter(Mandatory=$true)] [string] $OperationName,
        [Parameter(Mandatory=$true)] [string] $WorkingDirectory,
        [Parameter(Mandatory=$true)] [string] $LogFileName,
        [Parameter(Mandatory=$false)] [string] $KmTraceType = "file",
        [Parameter(Mandatory=$false)] [bool] $GranularTracing = $false,
        [Parameter(Mandatory=$false)] [bool] $KmTracing = $false,
        [Parameter(Mandatory=$false)] [string] $WprpFileName = "ebpfforwindows.wprp",
        [Parameter(Mandatory=$false)] [string] $TracingProfileName = "EbpfForWindowsProvider"
    )

    if (-not ($GranularTracing -and $KmTracing)) {
        return $null
    }

    try {
        # Import common module for Write-Log function
        Import-Module "$WorkingDirectory\common.psm1" -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

        if (Initialize-TracingUtils -WorkingDirectory $WorkingDirectory -WprpFileName $WprpFileName -TracingProfileName $TracingProfileName) {
            Write-Log "Starting granular tracing for $OperationName operations"

            # Create TestLogs directory for trace files
            $traceDir = Join-Path $WorkingDirectory "TestLogs"
            if (-not (Test-Path $traceDir)) {
                New-Item -ItemType Directory -Path $traceDir -Force | Out-Null
            }

            $traceFile = Start-OperationTrace -OperationName $OperationName -OutputDirectory $traceDir -TraceType $KmTraceType
            if ($traceFile) {
                Write-Log "Started $OperationName tracing: $traceFile" -ForegroundColor Green
                return $traceFile
            }
        }
    } catch {
        Write-Log "Warning: Failed to initialize granular tracing for $OperationName`: $_" -ForegroundColor Yellow
    }

    return $null
}

<#
.SYNOPSIS
    Stops granular tracing for a script if it was started.

.DESCRIPTION
    Handles the complete shutdown of granular tracing for a script.
    This is a convenience function that stops the trace and logs the results.

.PARAMETER OperationName
    The name of the operation being traced (for logging purposes).

.PARAMETER WorkingDirectory
    The working directory where common.psm1 is located.

.PARAMETER LogFileName
    The log file name for common.psm1.

.PARAMETER TraceFile
    The trace file path returned from Start-ScriptTracing, or $null if tracing wasn't started.

.RETURNS
    The path to the saved ETL file, or $null if no trace was active or stop failed.
#>
function Stop-ScriptTracing {
    param(
        [Parameter(Mandatory=$true)] [string] $OperationName,
        [Parameter(Mandatory=$true)] [string] $WorkingDirectory,
        [Parameter(Mandatory=$true)] [string] $LogFileName,
        [Parameter(Mandatory=$false)] [string] $TraceFile = $null
    )

    if (-not $TraceFile) {
        return $null
    }

    try {
        # Import common module for Write-Log function
        Import-Module "$WorkingDirectory\common.psm1" -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

        $savedTraceFile = Stop-OperationTrace
        if ($savedTraceFile) {
            Write-Log "Stopped $OperationName tracing: $savedTraceFile" -ForegroundColor Green
            return $savedTraceFile
        }
    } catch {
        Write-Log "Warning: Failed to stop $OperationName tracing: $_" -ForegroundColor Yellow
    }

    return $null
}

<#
.SYNOPSIS
    Aggressively resets WPR sessions when they become unresponsive.

.DESCRIPTION
    This function provides a more aggressive approach to cleaning up stuck WPR sessions.
    It attempts multiple cleanup strategies including process termination and service restart.
#>
function Reset-WPRSessions {
    param(
        [Parameter(Mandatory=$false)] [string] $LogFileName = "ResetWPR.log",
        [Parameter(Mandatory=$false)] [string] $WorkingDirectory = $pwd.ToString()
    )

    try {
        # Import common module for Write-Log function
        Import-Module "$WorkingDirectory\common.psm1" -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

        Write-Log "Starting aggressive WPR session reset..." -ForegroundColor Red

        # Step 1: Kill all WPR processes
        try {
            $wprProcesses = Get-Process -Name "wpr" -ErrorAction SilentlyContinue
            if ($wprProcesses) {
                Write-Log "Found $($wprProcesses.Count) WPR process(es). Terminating..." -ForegroundColor Yellow
                foreach ($proc in $wprProcesses) {
                    try {
                        $proc.Kill()
                        Write-Log "Terminated WPR process with ID: $($proc.Id)" -ForegroundColor Yellow
                    } catch {
                        Write-Log "Failed to terminate WPR process $($proc.Id): $_" -ForegroundColor Red
                    }
                }
                Start-Sleep -Seconds 2
            }
        } catch {
            Write-Log "Failed to enumerate WPR processes: $_" -ForegroundColor Red
        }

        # Step 2: Try to restart the WPR service (Windows Performance Toolkit)
        try {
            Write-Log "Attempting to restart Windows Performance Toolkit service..." -ForegroundColor Yellow

            # Check if WinRM service is running (needed for some operations)
            $winrm = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue
            if ($winrm -and $winrm.Status -eq "Running") {
                # Try using WMI to query ETW sessions and terminate problematic ones
                try {
                    $sessions = Get-WmiObject -Class Win32_PerfRawData_Kernel_EtwSession -ErrorAction SilentlyContinue
                    if ($sessions) {
                        $ebpfSessions = $sessions | Where-Object { $_.Name -like "*ebpf*" -or $_.Name -like "*eBPF*" }
                        if ($ebpfSessions) {
                            Write-Log "Found $($ebpfSessions.Count) eBPF-related ETW session(s)" -ForegroundColor Yellow
                        }
                    }
                } catch {
                    Write-Log "Could not query ETW sessions via WMI: $_" -ForegroundColor Yellow
                }
            }
        } catch {
            Write-Log "Failed to restart WPR service: $_" -ForegroundColor Red
        }

        # Step 3: Final check - try a simple WPR status with timeout
        try {
            Write-Log "Performing final WPR status check..." -ForegroundColor Yellow
            $statusJob = Start-Job -ScriptBlock {
                try {
                    $process = Start-Process -FilePath "wpr.exe" -ArgumentList "-status" -NoNewWindow -Wait -PassThru
                    return $process.ExitCode
                } catch {
                    return -1
                }
            }

            $statusCompleted = Wait-Job -Job $statusJob -Timeout 10
            if ($statusCompleted) {
                $statusExitCode = Receive-Job -Job $statusJob
                Remove-Job -Job $statusJob -Force

                if ($statusExitCode -eq 0) {
                    Write-Log "WPR is responsive after reset" -ForegroundColor Green
                } elseif ($statusExitCode -eq 1) {
                    Write-Log "WPR is responsive - no active sessions" -ForegroundColor Green
                } else {
                    Write-Log "WPR status returned exit code: $statusExitCode" -ForegroundColor Yellow
                }
            } else {
                Write-Log "WPR status check timed out - WPR may still be unresponsive" -ForegroundColor Red
                Remove-Job -Job $statusJob -Force
            }
        } catch {
            Write-Log "Failed to perform final WPR status check: $_" -ForegroundColor Red
        }
        Write-Log "WPR session reset completed" -ForegroundColor Yellow
    } catch {
        Write-Log "Exception during WPR session reset: $_" -ForegroundColor Red
    } finally {
        $script:TracingEnabled = $false
        $script:CurrentTraceFile = $null
    }
}

# Export the public functions
Export-ModuleMember -Function Initialize-TracingUtils, Start-OperationTrace, Stop-OperationTrace, Stop-AllTraces, Test-TracingActive, Get-CurrentTraceFile, Start-ScriptTracing, Stop-ScriptTracing, Reset-WPRSessions