# Granular ETW Tracing for eBPF for Windows

This document describes the new granular ETW tracing functionality that enables per-test and per-operation trace collection, addressing the issue of extremely large ETL files that are not very useful for debugging.

## Problem Solved

Previously, ETW tracing was started at the beginning of a test workflow and stopped at the end, creating one massive ETL file that contained traces for all operations during the entire test session. This made debugging difficult and created storage issues.

## Solution

The new granular tracing system creates separate, focused ETL files for:
- Individual test executables
- Setup operations  
- Cleanup operations

## Usage

### 1. Per-Test Tracing with Run-Test.ps1

The enhanced `Run-Test.ps1` script now supports per-test tracing:

```powershell
# Enable tracing for a specific test
.\Run-Test.ps1 -OutputFolder "C:\Dumps" -Timeout 300 -TestCommand "unit_tests.exe" -TestArguments @("-d", "yes") -EnableTracing -TraceOutputDirectory "C:\TestLogs"

# Backward compatible usage (no tracing)
.\Run-Test.ps1 "C:\Dumps" 300 "unit_tests.exe" "-d yes"
```

**Parameters:**
- `-EnableTracing`: Enable per-test ETW tracing
- `-TraceOutputDirectory`: Directory for ETL files (defaults to OutputFolder)
- `-TracingType`: "file" or "memory" (defaults to "file")

### 2. Workflow-Level Granular Tracing

Update your test workflows to use granular tracing:

```yaml
uses: ./.github/workflows/reusable-test.yml
with:
  name: unit_tests
  test_command: .\unit_tests.exe -d yes
  build_artifact: Build-x64
  environment: '["windows-2022"]'
  capture_etw: true
  granular_etw_tracing: true  # Enable granular tracing
  code_coverage: true
  gather_dumps: true
```

### 3. Setup/Cleanup Tracing

Enable granular tracing for setup and cleanup operations:

```powershell
# Setup with granular tracing
.\setup_ebpf_cicd_tests.ps1 -KmTracing $true -KmTraceType "file" -GranularTracing

# Cleanup with granular tracing  
.\cleanup_ebpf_cicd_tests.ps1 -KmTracing $true -GranularTracing
```

## Output Files

With granular tracing enabled, you'll get separate ETL files like:

```
TestLogs/
├── setup_ebpf_20241220_143022.etl      # Setup operations
├── unit_tests_20241220_143045.etl      # Unit test execution
├── bpf2c_tests_20241220_143102.etl     # BPF2C test execution
└── cleanup_ebpf_20241220_143125.etl    # Cleanup operations
```

## Technical Details

### Tracing Utilities Module

The new `tracing_utils.psm1` module provides:

- **Initialize-TracingUtils**: Sets up tracing environment
- **Start-OperationTrace**: Starts ETW trace with unique filename
- **Stop-OperationTrace**: Stops trace and reports file size
- **Stop-AllTraces**: Emergency cleanup of all active traces
- **Test-TracingActive**: Check if tracing is currently active
- **Get-CurrentTraceFile**: Get path to current ETL file

### Backward Compatibility

All existing scripts and workflows continue to work without modification. Granular tracing is opt-in via new parameters.

### Error Handling

The tracing system includes robust error handling:
- Graceful fallback if WPRP profile is not found
- Automatic cleanup of failed trace sessions
- Non-fatal warnings for tracing initialization failures

## Migration Guide

### For GitHub Actions Workflows

Replace:
```yaml
capture_etw: true
```

With:
```yaml
capture_etw: true
granular_etw_tracing: true
```

### For Driver Tests

Add the `-GranularTracing` parameter to setup and cleanup scripts:

```yaml
pre_test: .\setup_ebpf_cicd_tests.ps1 -KmTracing $true -KmTraceType "file" -GranularTracing
post_test: .\cleanup_ebpf_cicd_tests.ps1 -KmTracing $true -GranularTracing
```

### For Custom Test Scripts

Update Run-Test.ps1 calls to use the new parameter format:

```powershell
# Old format (still works)
.\Run-Test.ps1 $dumpPath $timeout $testCommand

# New format with tracing
.\Run-Test.ps1 -OutputFolder $dumpPath -Timeout $timeout -TestCommand $testCommand -EnableTracing -TraceOutputDirectory $tracePath
```

## Benefits

1. **Reduced File Sizes**: Each ETL file contains only relevant traces for specific operations
2. **Easier Debugging**: Focused traces make it easier to identify issues in specific components
3. **Better Storage Management**: Smaller files are easier to store and transfer
4. **Parallel Analysis**: Different team members can analyze different operation traces simultaneously
5. **Historical Comparison**: Easier to compare traces between different test runs for the same operation

## Requirements

- Windows Performance Recorder (wpr.exe) must be available in PATH
- The `ebpfforwindows.wprp` profile file must be present in the working directory
- PowerShell 5.1 or later