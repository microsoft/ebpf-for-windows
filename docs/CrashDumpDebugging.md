# Crash Dump Debugging

CI workflows (especially `fault_injection_full`) upload crash dumps as artifacts named `Crash-Dumps-*`. This guide explains how to download and analyze them.

## Prerequisites

Install the Windows Debugging Tools (CDB/WinDbg) from the Windows SDK. See [Getting Started](GettingStarted.md) for general setup.

## Downloading Artifacts

```powershell
# Download crash dumps and build artifacts (PDBs) from a CI run
gh run download <run_id> -R <owner>/ebpf-for-windows -n "Crash-Dumps-<test>-x64-<config>" -D crash-dumps
gh run download <run_id> -R <owner>/ebpf-for-windows -n "Build-x64-<config>" -D build
# Extract inner build zip for PDBs (produces build\<config>\x64\<config>\ with PDBs)
Expand-Archive build\build-<config>.zip -DestinationPath build\<config>
```

## Analyzing Dumps with CDB

```powershell
$cdbPath = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
$symPath = "build\<config>\x64\<config>;SRV*C:\Symbols*https://msdl.microsoft.com/download/symbols"

# Quick triage: exception record + stack trace
& $cdbPath -z crash-dumps\unit_tests.exe.XXXX.dmp -y $symPath -lines -c ".ecxr;kP;q"

# Full automated analysis
& $cdbPath -z crash-dumps\unit_tests.exe.XXXX.dmp -y $symPath -c "!analyze -v;q"
```

## Common Patterns

- **Fault injection crashes**: Usually assert `_allocations.empty()` in `leak_detector.cpp` — a memory leak detected during teardown. Check the leak detector's `_in_memory_log` for the allocation call stack:
  ```
  # Get exception context and inspect the stack to find the leak_detector frame:
  .ecxr
  kP  # or 'k' to list frames; identify the frame index where 'this' is the leak_detector instance
  .frame <N>
  dx this->_in_memory_log
  ```
- **Crash dump artifacts**: Named `Crash-Dumps-<test_name>-<platform>-<config>` (e.g., `Crash-Dumps-fault_injection_full-x64-Debug`)
- **Build artifacts with PDBs**: Named `<build_artifact>-<config>` (for the default `build_artifact=Build-x64`, this is `Build-x64-Debug`), and contain an inner zip `build-<config>.zip`
