# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# This module provides utility functions for granular ETW tracing
# to enable per-test and per-operation trace collection

param([Parameter(Mandatory=$true)] [string] $LogFileName)

Import-Module $PSScriptRoot\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

# Global variables to track tracing state
$script:TracingEnabled = $false
$script:CurrentTraceFile = $null
$script:WprpProfilePath = $null

<#
.SYNOPSIS
    Initializes the tracing utilities module.

.DESCRIPTION
    Sets up the tracing environment and locates the WPRP profile file.

.PARAMETER WorkingDirectory
    The working directory where the ebpfforwindows.wprp file is located.
#>
function Initialize-TracingUtils {
    param(
        [Parameter(Mandatory=$true)] [string] $WorkingDirectory
    )
    
    $script:WprpProfilePath = Join-Path $WorkingDirectory "ebpfforwindows.wprp"
    
    if (-not (Test-Path $script:WprpProfilePath)) {
        Write-Log "Warning: WPRP profile not found at $script:WprpProfilePath" -ForegroundColor Yellow
        return $false
    }
    
    Write-Log "Tracing utils initialized with profile: $script:WprpProfilePath"
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
    
    # Stop any existing trace first
    if ($script:TracingEnabled) {
        Write-Log "Stopping existing trace before starting new one"
        Stop-OperationTrace
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
        if ($TraceType -eq "file") {
            Write-Log "Starting ETW trace for '$OperationName' (file mode): $script:CurrentTraceFile"
            $arguments = "-start `"$script:WprpProfilePath!EbpfForWindowsProvider-File`" -filemode"
        } else {
            Write-Log "Starting ETW trace for '$OperationName' (memory mode)"
            $arguments = "-start `"$script:WprpProfilePath!EbpfForWindowsProvider-Memory`""
        }
        
        $process = Start-Process -FilePath "wpr.exe" -ArgumentList $arguments -NoNewWindow -Wait -PassThru -RedirectStandardError "$OutputDirectory\wpr_start_error.txt"
        
        if ($process.ExitCode -eq 0) {
            $script:TracingEnabled = $true
            Write-Log "Successfully started ETW trace for '$OperationName'" -ForegroundColor Green
            return $script:CurrentTraceFile
        } else {
            Write-Log "Failed to start ETW trace. Exit code: $($process.ExitCode)" -ForegroundColor Red
            if (Test-Path "$OutputDirectory\wpr_start_error.txt") {
                $errorContent = Get-Content "$OutputDirectory\wpr_start_error.txt" -Raw
                Write-Log "WPR error output: $errorContent" -ForegroundColor Red
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
        Write-Log "Stopping ETW trace: $script:CurrentTraceFile"
        
        $process = Start-Process -FilePath "wpr.exe" -ArgumentList "-stop `"$script:CurrentTraceFile`"" -NoNewWindow -Wait -PassThru -RedirectStandardError "$(Split-Path $script:CurrentTraceFile)\wpr_stop_error.txt"
        
        if ($process.ExitCode -eq 0) {
            Write-Log "Successfully stopped ETW trace: $script:CurrentTraceFile" -ForegroundColor Green
            
            # Check if file was created and report its size
            if (Test-Path $script:CurrentTraceFile) {
                $fileSize = (Get-Item $script:CurrentTraceFile).Length / 1MB
                Write-Log "ETL file size: $([math]::Round($fileSize, 2)) MB"
            }
            
            $savedFile = $script:CurrentTraceFile
            $script:TracingEnabled = $false
            $script:CurrentTraceFile = $null
            return $savedFile
        } else {
            Write-Log "Failed to stop ETW trace. Exit code: $($process.ExitCode)" -ForegroundColor Red
            if (Test-Path "$(Split-Path $script:CurrentTraceFile)\wpr_stop_error.txt") {
                $errorContent = Get-Content "$(Split-Path $script:CurrentTraceFile)\wpr_stop_error.txt" -Raw
                Write-Log "WPR error output: $errorContent" -ForegroundColor Red
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
        Write-Log "Canceling all active ETW traces"
        $process = Start-Process -FilePath "wpr.exe" -ArgumentList "-cancel" -NoNewWindow -Wait -PassThru
        
        if ($process.ExitCode -eq 0) {
            Write-Log "Successfully canceled all ETW traces" -ForegroundColor Green
        } else {
            Write-Log "Failed to cancel ETW traces. Exit code: $($process.ExitCode)" -ForegroundColor Yellow
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

# Export the public functions
Export-ModuleMember -Function Initialize-TracingUtils, Start-OperationTrace, Stop-OperationTrace, Stop-AllTraces, Test-TracingActive, Get-CurrentTraceFile