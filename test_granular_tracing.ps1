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
    
    # Test 2: Initialize tracing
    Write-Host "`nTest 2: Initializing tracing utilities..." -ForegroundColor Yellow
    $initialized = Initialize-TracingUtils -WorkingDirectory "$WorkingDirectory\scripts"
    if ($initialized) {
        Write-Host "✓ Tracing utilities initialized successfully" -ForegroundColor Green
    } else {
        Write-Host "⚠ Tracing utilities initialization returned false (WPRP profile not found)" -ForegroundColor Yellow
    }
    
    # Test 3: Check if tracing is active (should be false initially)
    Write-Host "`nTest 3: Checking initial tracing state..." -ForegroundColor Yellow
    $isActive = Test-TracingActive
    if (-not $isActive) {
        Write-Host "✓ Initial tracing state is inactive (expected)" -ForegroundColor Green
    } else {
        Write-Host "✗ Initial tracing state is active (unexpected)" -ForegroundColor Red
    }
    
    # Test 4: Test trace cancellation (cleanup any existing traces)
    Write-Host "`nTest 4: Testing trace cleanup..." -ForegroundColor Yellow
    Stop-AllTraces
    Write-Host "✓ Trace cleanup completed" -ForegroundColor Green
    
    # Test 5: Test basic function exports
    Write-Host "`nTest 5: Testing function exports..." -ForegroundColor Yellow
    $functions = @('Initialize-TracingUtils', 'Start-OperationTrace', 'Stop-OperationTrace', 'Stop-AllTraces', 'Test-TracingActive', 'Get-CurrentTraceFile')
    $moduleCommands = Get-Command -Module tracing_utils
    
    foreach ($func in $functions) {
        if ($moduleCommands.Name -contains $func) {
            Write-Host "✓ Function $func is exported" -ForegroundColor Green
        } else {
            Write-Host "✗ Function $func is NOT exported" -ForegroundColor Red
        }
    }
    
    Write-Host "`nGranular tracing functionality tests completed!" -ForegroundColor Cyan
    Write-Host "Note: Full tracing tests require Windows Performance Recorder (wpr.exe) and ebpfforwindows.wprp profile" -ForegroundColor Yellow
    
} catch {
    Write-Host "✗ Test failed with error: $_" -ForegroundColor Red
    exit 1
}