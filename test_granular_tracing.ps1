# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# Simple test script to validate the granular tracing functionality

param(
    [Parameter(Mandatory=$false)]
    [string]$WorkingDirectory = $PWD,
    
    [Parameter(Mandatory=$false)]
    [string]$TestLogDirectory = ".\TestLogs"
)

Write-Host "Testing granular ETW tracing functionality..." -ForegroundColor Cyan

# Ensure the test log directory exists
if (-not (Test-Path $TestLogDirectory)) {
    New-Item -ItemType Directory -Path $TestLogDirectory -Force | Out-Null
    Write-Host "Created test log directory: $TestLogDirectory"
}

try {
    # Test 1: Load tracing utilities
    Write-Host "`nTest 1: Loading tracing utilities module..." -ForegroundColor Yellow
    Import-Module "$WorkingDirectory\scripts\tracing_utils.psm1" -Force -ArgumentList "test_granular_tracing.log", $WorkingDirectory
    Write-Host "✓ Tracing utilities module loaded successfully" -ForegroundColor Green
    
    # Test 2: Test basic function exports
    Write-Host "`nTest 2: Testing function exports..." -ForegroundColor Yellow
    $functions = @('Start-WPRTrace', 'Stop-WPRTrace')
    $moduleCommands = Get-Command -Module tracing_utils
    
    foreach ($func in $functions) {
        if ($moduleCommands.Name -contains $func) {
            Write-Host "✓ Function $func is exported" -ForegroundColor Green
        } else {
            Write-Host "✗ Function $func is NOT exported" -ForegroundColor Red
        }
    }
    
    # Test 3: Test trace start/stop cycle
    Write-Host "`nTest 3: Testing trace start/stop cycle..." -ForegroundColor Yellow

    # Quick cleanup of any orphaned sessions
    try {
        wpr.exe -cancel | Out-Null
        Write-Host "✓ Cleaned up any existing WPR sessions" -ForegroundColor Green
    } catch {
        Write-Host "⚠ No existing WPR sessions to clean up" -ForegroundColor Yellow
    }

    # Start tracing
    $traceStarted = Start-WPRTrace -TraceType "memory"
    if ($traceStarted) {
        Write-Host "✓ WPR trace started successfully" -ForegroundColor Green

        # Stop tracing
        $traceFile = Stop-WPRTrace -FileName "test_trace"
        if ($traceFile) {
            Write-Host "✓ WPR trace stopped successfully: $traceFile" -ForegroundColor Green

            # Check if file exists
            if (Test-Path $traceFile) {
                Write-Host "✓ Trace file created successfully" -ForegroundColor Green
                $fileSize = (Get-Item $traceFile).Length
                Write-Host "  File size: $fileSize bytes" -ForegroundColor Gray
            } else {
                Write-Host "✗ Trace file was not created" -ForegroundColor Red
            }
        } else {
            Write-Host "✗ Failed to stop WPR trace" -ForegroundColor Red
        }
    } else {
        Write-Host "✗ Failed to start WPR trace (may need WPRP profile)" -ForegroundColor Red
    }

    Write-Host "`nSimplified granular tracing functionality tests completed!" -ForegroundColor Cyan
    Write-Host "Note: Tracing tests require Windows Performance Recorder (wpr.exe) and ebpfforwindows.wprp profile" -ForegroundColor Yellow

} catch {
    Write-Host "✗ Test failed with error: $_" -ForegroundColor Red
    exit 1
}