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
        [Parameter(Mandatory=$false)] [string] $TracingProfileName = "EbpfForWindows-Networking",
        [Parameter(Mandatory=$false)] [int] $TimeoutSeconds = 60
    )

    try {
        Write-Log "Start-WPRTrace called with TraceType: $TraceType, WorkingDirectory: $WorkingDirectory"

        # Quick cleanup of any orphaned sessions
        $exitCode = Start-ProcessWithTimeout -FilePath "wpr.exe" -ArgumentList @("-cancel") -TimeoutSeconds $TimeoutSeconds

        # Build profile path and check if it exists
        $wprpProfilePath = Join-Path $WorkingDirectory $WprpFileName
        Write-Log "Looking for WPRP profile at: $wprpProfilePath"
        if (-not (Test-Path $wprpProfilePath)) {
            Write-Log "Warning: WPRP profile not found at $wprpProfilePath" -ForegroundColor Yellow
        }

        Write-Log "Starting WPR trace with TraceType: $TraceType WprpFileName: $WprpFileName TracingProfileName: $TracingProfileName"

        # Prepare arguments
        $profileName = if ($TraceType -eq "file") { "$TracingProfileName-File" } else { "$TracingProfileName-Memory" }
        $arguments = @("-start", "$wprpProfilePath!$profileName")
        if ($TraceType -eq "file") {
            $arguments += "-filemode"
        }

        $exitCode = Start-ProcessWithTimeout -FilePath "wpr.exe" -ArgumentList $arguments -TimeoutSeconds $TimeoutSeconds
        if ($exitCode -eq 0) {
            Write-Log "Successfully started trace"
        } else {
            Write-Log "Failed to start trace with exit code $exitCode"
        }
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
        [Parameter(Mandatory=$true)] [string] $FileName,
        [Parameter(Mandatory=$false)] [int] $TimeoutSeconds = 600
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

        $exitCode = Start-ProcessWithTimeout -FilePath "wpr.exe" -ArgumentList @("-stop", "`"$traceFile`"") -TimeoutSeconds $TimeoutSeconds
        if ($exitCode -eq 0) {
            Write-Log "Successfully stopped WPR trace: $traceFile"
        } else {
            Write-Log "Failed to stop WPR trace with exit code $exitCode (This may be expected if no trace session was in progress)"
        }
    } catch {
        Write-Log "Exception stopping WPR trace. This may be expected if no trace session was in progress. Error: $_" -ForegroundColor Red
    }
}