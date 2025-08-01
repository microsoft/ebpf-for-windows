# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# Backward compatibility test for Run-Test.ps1

Write-Host "Testing backward compatibility of enhanced Run-Test.ps1..." -ForegroundColor Cyan

# Create a simple test executable mock
$testDir = ".\test_compat"
if (-not (Test-Path $testDir)) {
    New-Item -ItemType Directory -Path $testDir -Force | Out-Null
}

# Create a simple test script that just exits with success
$testScript = @"
Write-Host "Mock test executable running..."
Start-Sleep -Seconds 1
Write-Host "Mock test completed successfully"
exit 0
"@

$testScriptPath = Join-Path $testDir "mock_test.ps1"
$testScript | Out-File -FilePath $testScriptPath -Encoding UTF8

try {
    # Test 1: Original positional argument format (backward compatibility)
    Write-Host "`nTest 1: Testing original positional argument format..." -ForegroundColor Yellow
    $result = & ".\scripts\Run-Test.ps1" $testDir 10 "powershell.exe" "-File" $testScriptPath
    $exitCode = $LASTEXITCODE
    
    if ($exitCode -eq 0) {
        Write-Host "✓ Backward compatibility test passed" -ForegroundColor Green
    } else {
        Write-Host "✗ Backward compatibility test failed with exit code: $exitCode" -ForegroundColor Red
        exit 1
    }
    
    # Test 2: New parameter format without tracing
    Write-Host "`nTest 2: Testing new parameter format without tracing..." -ForegroundColor Yellow
    $result = & ".\scripts\Run-Test.ps1" -OutputFolder $testDir -Timeout 10 -TestCommand "powershell.exe" -TestArguments @("-File", $testScriptPath)
    $exitCode = $LASTEXITCODE
    
    if ($exitCode -eq 0) {
        Write-Host "✓ New parameter format test passed" -ForegroundColor Green
    } else {
        Write-Host "✗ New parameter format test failed with exit code: $exitCode" -ForegroundColor Red
        exit 1
    }
    
    # Test 3: New parameter format with tracing enabled (will fail gracefully without wpr.exe)
    Write-Host "`nTest 3: Testing new parameter format with tracing enabled..." -ForegroundColor Yellow
    $result = & ".\scripts\Run-Test.ps1" -OutputFolder $testDir -Timeout 10 -TestCommand "powershell.exe" -TestArguments @("-File", $testScriptPath) -EnableTracing -TraceOutputDirectory $testDir
    $exitCode = $LASTEXITCODE
    
    if ($exitCode -eq 0) {
        Write-Host "✓ Tracing parameter test passed (graceful fallback expected)" -ForegroundColor Green
    } else {
        Write-Host "✗ Tracing parameter test failed with exit code: $exitCode" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "`nAll backward compatibility tests passed!" -ForegroundColor Green
    
} finally {
    # Cleanup
    if (Test-Path $testDir) {
        Remove-Item -Path $testDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`nBackward compatibility validation completed successfully!" -ForegroundColor Cyan