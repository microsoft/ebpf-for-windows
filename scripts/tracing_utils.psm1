# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# Simplified module for WPR ETW tracing with automatic initialization

param(
    [Parameter(Mandatory=$true)] [string] $LogFileName,
    [Parameter(Mandatory=$true)] [string] $WorkingDirectory
)

Import-Module $WorkingDirectory\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

<#
.SYNOPSIS
    Starts WPR tracing for a specific operation.

.PARAMETER TraceType
    The type of tracing to use ("file" or "memory"). Defaults to "file".

.PARAMETER WprpFileName
    The name of the WPRP file to use. Defaults to "ebpfforwindows.wprp".

.PARAMETER TracingProfileName
    The name of the tracing profile to use. Defaults to "EbpfForWindows-Networking".
#>
function Start-WPRTrace {
    param(
        [Parameter(Mandatory=$false)] [string] $TraceType = "file",
        [Parameter(Mandatory=$false)] [string] $WprpFileName = "ebpfforwindows.wprp",
        [Parameter(Mandatory=$false)] [string] $TracingProfileName = "EbpfForWindows-Networking"
    )

    try {
        Write-Log "Start-WPRTrace called with TraceType: $TraceType, WorkingDirectory: $WorkingDirectory"

        # Quick cleanup of any orphaned sessions
        try {
            Write-Log "Attempting to cancel any existing WPR sessions..."
            $null = wpr.exe -cancel 2>&1
            Write-Log "WPR cancel completed (exit code: $LASTEXITCODE)"
        } catch {
            Write-Log "WPR cancel failed. This may be expected if no WPR session was in progress. Error: $_"
        }

        # Build profile path and check if it exists
        $wprpProfilePath = Join-Path $WorkingDirectory $WprpFileName
        Write-Log "Looking for WPRP profile at: $wprpProfilePath"
        if (-not (Test-Path $wprpProfilePath)) {
            Write-Log "Warning: WPRP profile not found at $wprpProfilePath" -ForegroundColor Yellow
        }

        Write-Log "Starting WPR trace with TraceType: $TraceType WprpFileName: $WprpFileName TracingProfileName: $TracingProfileName"
        if ($TraceType -eq "file") {
            $profileName = "$TracingProfileName-File"
            Write-Log "Executing: wpr.exe -start `"$wprpProfilePath!$profileName`" -filemode"
            wpr.exe -start "$wprpProfilePath!$profileName" -filemode
            $exitCode = $LASTEXITCODE
        } else {
            $profileName = "$TracingProfileName-Memory"
            Write-Log "Executing: wpr.exe -start `"$wprpProfilePath!$profileName`""
            wpr.exe -start "$wprpProfilePath!$profileName"
            $exitCode = $LASTEXITCODE
        }

        Write-Log "WPR command completed with exit code: $exitCode"

        if ($exitCode -ne 0) {
            throw "Failed to start trace with exit code $exitCode"
        }

        Write-Log "Successfully started trace"
    } catch {
        Write-Log "Exception starting WPR trace: $_" -ForegroundColor Red
    }
}

<#
.SYNOPSIS
    Stops the currently active WPR trace.

.PARAMETER FileName
    The base filename (without timestamp and extension) to use for the ETL file.
#>
function Stop-WPRTrace {
    param(
        [Parameter(Mandatory=$true)] [string] $FileName
    )

    try {
        # Create output directory if needed
        $outputDir = Join-Path $WorkingDirectory "TestLogs"
        if (-not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }

        # Generate unique ETL filename with timestamp
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $etlFileName = "${FileName}_${timestamp}.etl"
        $traceFile = Join-Path $outputDir $etlFileName

        Write-Log "Stopping WPR trace" -ForegroundColor Cyan

        $null = wpr.exe -stop "$traceFile" 2>&1
        $exitCode = $LASTEXITCODE

        if ($exitCode -ne 0) {
            throw "Failed to stop WPR trace with exit code $exitCode"
        }

        Write-Log "Successfully stopped WPR trace: $traceFile"
    } catch {
        Write-Log "Exception stopping WPR trace. This may be expected if no trace session was in progress. Error: $_" -ForegroundColor Red
    }
}