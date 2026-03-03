# eBPF for Windows - Copilot Instructions

This project brings eBPF (extended Berkeley Packet Filter) to Windows, enabling programmable OS kernel extensions for use cases like network filtering and observability.

## Quick Reference

| Task | Command |
|------|---------|
| Build | `msbuild /m /p:Configuration=Debug /p:Platform=x64 ebpf-for-windows.sln` |
| Build (native only) | `msbuild /m /p:Configuration=NativeOnlyDebug /p:Platform=x64 ebpf-for-windows.sln` |
| Format code | `./scripts/format-code --staged` |
| Run unit tests | `unit_tests.exe` (from `x64\Debug`) |
| Run single test | `unit_tests.exe "test name"` |
| List tests | `unit_tests.exe -l` |

See [docs/GettingStarted.md](../docs/GettingStarted.md) for prerequisites, build options, and detailed setup.
See [docs/AutomatedTests.md](../docs/AutomatedTests.md) for test categories and descriptions.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        User Space                                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐ │
│  │ bpftool  │  │  netsh   │  │   Apps   │  │  ebpfsvc.exe         │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  │  (JIT/verification)  │ │
│       └─────────────┴─────────────┘        └──────────┬───────────┘ │
│                      │                                │             │
│              ┌───────▼───────┐                        │             │
│              │  ebpfapi.dll  │◄───────────────────────┘             │
│              │  (libbpf API) │                                      │
└──────────────┴───────┬───────┴──────────────────────────────────────┘
                       │ IOCTLs
┌──────────────────────▼──────────────────────────────────────────────┐
│                        Kernel Space                                 │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    ebpfcore.sys                              │   │
│  │              (eBPF execution context)                        │   │
│  │   • Program loading/unloading    • Map management            │   │
│  │   • Interpreter (debug only)     • Native driver execution   │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │ NMR (Network Module Registrar)       │
│  ┌───────────────────────────▼──────────────────────────────────┐   │
│  │  Extension Drivers (Hook Providers)                          │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌───────────────────────┐ │   │
│  │  │netebpfext.sys│ │sample_ext.sys│ │ (custom extensions)  │ │   │
│  │  │ (WFP hooks) │  │  (testing)  │  │                       │ │   │
│  │  └─────────────┘  └─────────────┘  └───────────────────────┘ │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| **ebpfcore.sys** | `libs/execution_context/`, `ebpfcore/` | Kernel execution context for eBPF programs |
| **ebpfapi.dll** | `libs/api/`, `ebpfapi/` | User-mode library exposing libbpf-compatible APIs |
| **ebpfsvc.exe** | `libs/service/`, `ebpfsvc/` | Service handling JIT compilation and verification |
| **netebpfext.sys** | `netebpfext/` | Network extension providing WFP hooks |
| **bpf2c** | `tools/bpf2c/` | Converts eBPF bytecode to C for native compilation |

### External Dependencies (in `external/`)

- **ebpf-verifier** (PREVAIL): Validates eBPF program safety
- **ubpf**: JIT compiler and interpreter
- **usersim**: User-mode simulation of kernel APIs for testing
- **Catch2**: Test framework

### Program Execution Modes

1. **Native** (preferred): eBPF → bpf2c → C → Windows driver (.sys)
2. **JIT**: eBPF bytecode → native code at runtime via ubpf
3. **Interpreter**: Direct bytecode execution (debug builds only)

## Code Conventions

See [docs/DevelopmentGuide.md](../docs/DevelopmentGuide.md) for full details. Key points:

- **Naming**: `lower_snake_case` for functions/variables, `UPPER_SNAKE_CASE` for macros, `ebpf_` prefix for global names
- **Structs**: `typedef struct _ebpf_widget { ... } ebpf_widget_t;`
- **Types**: Use `stdint.h` fixed-width types (`uint32_t`, not `int`)
- **Headers**: `#pragma once`, local includes before system includes, alphabetized
- **Formatting**: clang-format 18.1.8, 120-char limit, braces required on single-line blocks
- **License header** (required):
  ```c
  // Copyright (c) eBPF for Windows contributors
  // SPDX-License-Identifier: MIT
  ```

## Extension Development

eBPF extensions are kernel drivers providing hooks/helpers via NMR. See [docs/eBpfExtensions.md](../docs/eBpfExtensions.md).

## Crash Dump Debugging

CI workflows (especially `fault_injection_full`) upload crash dumps as artifacts named `Crash-Dumps-*`. To analyze them:

### Prerequisites

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

### Downloading Artifacts

```powershell
# Download crash dumps and build artifacts (PDBs) from a CI run
gh run download <run_id> -R <owner>/ebpf-for-windows -n "Crash-Dumps-<test>-x64-<config>" -D crash-dumps
gh run download <run_id> -R <owner>/ebpf-for-windows -n "Build-x64-<config>" -D build
# Extract inner build zip for PDBs
Expand-Archive build\build-<config>.zip -DestinationPath build\<config>
```

### Analyzing Dumps with CDB

```powershell
$cdbPath = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
$symPath = "path\to\build\Debug;SRV*C:\Symbols*https://msdl.microsoft.com/download/symbols"

# Quick triage: exception record + stack trace
& $cdbPath -z crash-dumps\unit_tests.exe.XXXX.dmp -y $symPath -lines -c ".ecxr;kP;q"

# Full automated analysis
& $cdbPath -z crash-dumps\unit_tests.exe.XXXX.dmp -y $symPath -c "!analyze -v;q"
```

### Running mcp-windbg Server

```powershell
& $pyExe -m mcp_windbg --cdb-path $cdbPath --symbols-path $symPath --transport streamable-http --port 8765
# MCP endpoint: http://127.0.0.1:8765/mcp
```

### Common Patterns

- **Fault injection crashes**: Usually assert `_allocations.empty()` in `leak_detector.cpp` — a memory leak detected during teardown. Check the leak detector's `_in_memory_log` for the allocation call stack:
  ```
  .ecxr; .frame 0n10; dx this->_in_memory_log
  ```
- **Crash dump artifacts**: Named `Crash-Dumps-<test_name>-<platform>-<config>` (e.g., `Crash-Dumps-fault_injection_full-x64-Debug`)
- **Build artifacts with PDBs**: Named `Build-<platform>-<config>` (e.g., `Build-x64-Debug`), contain an inner zip `build-<config>.zip`

## Tracing

See "Using tracing" section in [docs/GettingStarted.md](../docs/GettingStarted.md). Quick reference:
```cmd
tracelog -start MyTrace -guid ebpf-printk.guid -rt
tracefmt -rt MyTrace -displayonly -jsonMeta 0
```
