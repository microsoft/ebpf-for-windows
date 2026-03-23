---
name: debug-crash-dump
description: >
  Download and analyze crash dumps from CI failures using CDB/WinDbg.
  Use this skill when asked to debug crashes, analyze dump files, set up
  WinDbg/CDB, investigate fault injection failures, or start mcp-windbg.
---

# Crash Dump Debugging

Download and analyze crash dumps from CI workflow failures (especially `fault_injection_full`).

See [docs/CrashDumpDebugging.md](../../../docs/CrashDumpDebugging.md) for the full human-readable guide.

## When to Use

- User asks to debug a CI crash or test failure with a crash dump
- User asks to download crash dump artifacts from a workflow run
- User asks to set up CDB, WinDbg, or mcp-windbg
- User asks to analyze a `.dmp` file
- User asks about fault injection leak detection failures

## Agent Prerequisites

1. **Windows Debugging Tools (CDB/WinDbg)** — Install the Debugging Tools feature from the Windows SDK:
   ```powershell
   # Download the SDK online installer
   Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2272610" -OutFile winsdksetup.exe
   # Install only the debugging tools (elevated)
   Start-Process -FilePath .\winsdksetup.exe -ArgumentList "/features","OptionId.WindowsDesktopDebuggers","/quiet","/norestart" -Verb RunAs -Wait
   ```
   CDB installs to: `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe`

2. **mcp-windbg** (MCP server for AI-assisted dump analysis):
   ```powershell
   # Install Python 3.12 via NuGet (if not already available)
   nuget install python -Version 3.12.8 -OutputDirectory C:\Users\$env:USERNAME\tools
   $pyExe = (Get-ChildItem "C:\Users\$env:USERNAME\tools\python.3.12.8" -Recurse -Filter "python.exe" | Select-Object -First 1).FullName
   & $pyExe -m ensurepip --upgrade
   & $pyExe -m pip install mcp-windbg
   ```

## Downloading Artifacts

```powershell
# Download crash dumps and build artifacts (PDBs) from a CI run
gh run download <run_id> -R <owner>/ebpf-for-windows -n "Crash-Dumps-<test>-x64-<config>" -D crash-dumps
gh run download <run_id> -R <owner>/ebpf-for-windows -n "Build-x64-<config>" -D build
# Extract inner build zip for PDBs (produces build\<config>\<config>\ with PDBs)
Expand-Archive build\build-<config>.zip -DestinationPath build\<config>
```

## Analyzing Dumps with CDB

```powershell
$cdbPath = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
$symPath = "build\<config>\<config>;SRV*C:\Symbols*https://msdl.microsoft.com/download/symbols"

# Quick triage: exception record + stack trace
& $cdbPath -z crash-dumps\unit_tests.exe.XXXX.dmp -y $symPath -lines -c ".ecxr;kP;q"

# Full automated analysis
& $cdbPath -z crash-dumps\unit_tests.exe.XXXX.dmp -y $symPath -c "!analyze -v;q"
```

## Running mcp-windbg Server

```powershell
$pyExe = (Get-ChildItem "C:\Users\$env:USERNAME\tools\python.3.12.8" -Recurse -Filter "python.exe" | Select-Object -First 1).FullName
$cdbPath = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
$symPath = "build\<config>\<config>;SRV*C:\Symbols*https://msdl.microsoft.com/download/symbols"

& $pyExe -m mcp_windbg --cdb-path $cdbPath --symbols-path $symPath --transport streamable-http --port 8765
# MCP endpoint: http://127.0.0.1:8765/mcp
```

## Common Patterns

- **Fault injection crashes**: Usually assert `_allocations.empty()` in `leak_detector.cpp` — a memory leak detected during teardown. Check the leak detector's `_in_memory_log` for the allocation call stack:
  ```
  $$ Get exception context and inspect the stack to find the leak_detector frame:
  .ecxr
  kP
  $$ Identify the frame index where 'this' is the leak_detector instance
  .frame <N>
  dx this->_in_memory_log
  ```
- **Crash dump artifacts**: Named `Crash-Dumps-<test_name>-<platform>-<config>` (e.g., `Crash-Dumps-fault_injection_full-x64-Debug`)
- **Build artifacts with PDBs**: Named `<build_artifact>-<config>` (for the default `build_artifact=Build-x64`, this is `Build-x64-Debug`), and contain an inner zip `build-<config>.zip`
