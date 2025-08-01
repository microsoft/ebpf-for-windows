# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# This script executes the provided test command, waits for <timeout in seconds>
# and then captures a dump of the test process if it is still running. The dump
# is captured using the procdump tool from Sysinternals. The dump is saved to
# the <output folder> with the name of the test executable and the current date
# and time.
#
# Enhanced version supports per-test ETW tracing to create granular trace files
# instead of one large trace file for the entire test session.

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$OutputFolder,
    
    [Parameter(Mandatory=$true, Position=1)]
    [int]$Timeout,
    
    [Parameter(Mandatory=$true, Position=2)]
    [string]$TestCommand,
    
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$TestArguments = @(),
    
    [Parameter(Mandatory=$false)]
    [switch]$EnableTracing = $false,
    
    [Parameter(Mandatory=$false)]
    [string]$TraceOutputDirectory,
    
    [Parameter(Mandatory=$false)]
    [string]$TracingType = "file"
)

# Modifying $args directly can cause issues, so copy it to a new variable if using legacy parameter handling
if (-not $PSBoundParameters.ContainsKey('TestCommand')) {
    $arguments = $args
    
    # Check that the correct number of arguments have been provided.
    if ($arguments.Count -eq 0) {
        Write-Output "Usage: Run-Test.ps1 <output folder> <timeout in seconds> <test command> <test arguments>"
        Write-Output "   or: Run-Test.ps1 -OutputFolder <folder> -Timeout <seconds> -TestCommand <command> [-TestArguments <args>] [-EnableTracing] [-TraceOutputDirectory <dir>] [-TracingType <file|memory>]"
        exit 1
    }
    
    # Extract parameters from positional arguments for backward compatibility
    $OutputFolder = $arguments[0]
    $Timeout = [int]$arguments[1]
    $TestCommand = $arguments[2]
    if ($arguments.Count -gt 3) {
        $TestArguments = $arguments[3..($arguments.Length - 1)]
    }
} else {
    # When using named parameters, TestCommand might contain both executable and arguments
    # Parse them if TestCommand contains spaces and no separate TestArguments were provided
    if ($TestCommand.Contains(" ") -and ($TestArguments.Count -eq 0)) {
        # Split the command string into executable and arguments
        # Use proper parsing to handle quoted arguments
        $commandParts = @()
        $currentPart = ""
        $inQuotes = $false
        
        for ($i = 0; $i -lt $TestCommand.Length; $i++) {
            $char = $TestCommand[$i]
            if ($char -eq '"' -and ($i -eq 0 -or $TestCommand[$i-1] -ne '\')) {
                $inQuotes = -not $inQuotes
            } elseif ($char -eq ' ' -and -not $inQuotes) {
                if ($currentPart -ne "") {
                    $commandParts += $currentPart
                    $currentPart = ""
                }
            } else {
                $currentPart += $char
            }
        }
        if ($currentPart -ne "") {
            $commandParts += $currentPart
        }
        
        if ($commandParts.Count -gt 1) {
            $TestCommand = $commandParts[0]
            $TestArguments = $commandParts[1..($commandParts.Length - 1)]
            Write-Output "Debug: Parsed TestCommand='$TestCommand', TestArguments='$($TestArguments -join ' ')'"
        }
    }
}

# Load tracing utilities if tracing is enabled
$tracingInitialized = $false
$traceFile = $null

if ($EnableTracing) {
    # Default trace output directory to the same as test output if not specified
    if (-not $TraceOutputDirectory) {
        $TraceOutputDirectory = $OutputFolder
    }
    
    # Ensure trace output directory exists
    if (-not (Test-Path $TraceOutputDirectory)) {
        New-Item -ItemType Directory -Path $TraceOutputDirectory -Force | Out-Null
    }
    
    # Load tracing utilities
    $tracingUtilsPath = Join-Path $PSScriptRoot "tracing_utils.psm1"
    if (Test-Path $tracingUtilsPath) {
        try {
            Import-Module $tracingUtilsPath -Force -ArgumentList "Run-Test.log"
            
            if (Initialize-TracingUtils -WorkingDirectory $PWD) {
                $tracingInitialized = $true
                Write-Output "Tracing utilities initialized successfully"
            } else {
                Write-Output "Warning: Failed to initialize tracing utilities"
            }
        } catch {
            Write-Output "Warning: Failed to load tracing utilities: $_"
        }
    } else {
        Write-Output "Warning: Tracing utilities not found at $tracingUtilsPath"
    }
}

# Extract test name for tracing
$testName = [System.IO.Path]::GetFileNameWithoutExtension($TestCommand)

# Start tracing if enabled and initialized
if ($EnableTracing -and $tracingInitialized) {
    $traceFile = Start-OperationTrace -OperationName $testName -OutputDirectory $TraceOutputDirectory -TraceType $TracingType
    if ($traceFile) {
        Write-Output "Started ETW tracing for test '$testName': $traceFile"
    } else {
        Write-Output "Warning: Failed to start ETW tracing for test '$testName'"
    }
}



# Start the test process using the provided command and arguments.
# This can't use Start-Process as that doesn't save exit code and always returns 0.
$processInfo = New-Object System.Diagnostics.ProcessStartInfo
$processInfo.UseShellExecute = $false
$processInfo.FileName = $TestCommand

if ($TestArguments -and $TestArguments.Count -gt 0) {
    $processInfo.Arguments = $TestArguments -join ' '
} else {
    $processInfo.Arguments = ""
}

Write-Output "Starting test: $TestCommand $($processInfo.Arguments)"

$process = New-Object System.Diagnostics.Process
$process.StartInfo = $processInfo
$process.Start() | Out-Null

if (!$process.WaitForExit($Timeout * 1000)) {
    $dumpFileName = "$($process.ProcessName)_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').dmp"
    $dumpFilePath = Join-Path $OutputFolder $dumpFileName
    Write-Output "Capturing dump of $($process.ProcessName) to $dumpFilePath"
    Start-Process -NoNewWindow -Wait -FilePath procdump -ArgumentList "-accepteula -ma $($process.Id) $dumpFilePath"
    if (!$process.HasExited) {
        Write-Output "Killing $($process.ProcessName)"
        $process.Kill()
    }
}

# Stop tracing if it was started
if ($EnableTracing -and $tracingInitialized -and $traceFile) {
    $savedTraceFile = Stop-OperationTrace
    if ($savedTraceFile) {
        Write-Output "Stopped ETW tracing for test '$testName': $savedTraceFile"
    }
}

Write-Output "Test $($process.ProcessName) exited with code $($process.ExitCode)"
exit $process.ExitCode
