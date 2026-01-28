# eBPF for Windows - Copilot Instructions

This project brings eBPF (extended Berkeley Packet Filter) to Windows, enabling programmable OS kernel extensions for use cases like network filtering and observability.

## Build Commands

**Prerequisites**: Visual Studio 2022 (v17.4.2+), Clang 18.1.8, Git. Run `scripts\initialize_ebpf_repo.ps1` once after cloning.

```cmd
# Build (from Developer Command Prompt for VS 2022)
msbuild /m /p:Configuration=Debug /p:Platform=x64 ebpf-for-windows.sln

# Build without JIT/Interpreter (native mode only)
msbuild /m /p:Configuration=NativeOnlyDebug /p:Platform=x64 ebpf-for-windows.sln
```

**Format code** (run before committing):
```bash
./scripts/format-code           # Format all C/C++ files
./scripts/format-code --staged  # Format only staged files
```

**Check license headers**:
```bash
./scripts/check-license.sh
```

## Test Commands

Tests use the [Catch2](https://github.com/catchorg/Catch2) framework. Run from the build output directory (`x64\Debug` or `x64\Release`).

```cmd
# User-mode unit tests (no drivers required)
unit_tests.exe
bpf2c_tests.exe
netebpfext_unit.exe

# Run a single test by name
unit_tests.exe "test name here"

# List all tests
unit_tests.exe -l

# Kernel tests (require drivers loaded and eBPFSvc running)
api_test.exe
socket_tests.exe
connect_redirect_tests.exe
```

Useful Catch2 flags: `-s` (show passing tests), `-b` (break on failure), `~[tag]` (exclude tagged tests).

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

### Naming
- `lower_snake_case` for variables, functions, fields
- `UPPER_SNAKE_CASE` for macros and constants
- Prefix with `ebpf_` for eBPF-specific names in global namespace
- Prefix with `_` for file-local static functions/variables
- Structs: `typedef struct _ebpf_widget { ... } ebpf_widget_t;`

### Types
- Use `stdint.h` fixed-width types (`uint32_t`, `int64_t`) instead of `int`, `long`
- Use `const` and `static` to limit scope

### Headers
- Use `#pragma once` (not include guards)
- Include local headers (`""`) before system headers (`<>`)
- Alphabetize includes within groups

### Formatting
- **clang-format 18.1.8** with `.clang-format` config (LLVM-based)
- 120-character line limit
- Single-line if/else/loop blocks must use braces
- Run `./scripts/format-code --staged` before committing

### License Header (required on all new source files)
```c
// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
```

### Doxygen
Use doxygen comments with `\[in,out\]` direction annotations for public API headers.

## Extension Development

eBPF extensions are Windows kernel drivers that provide hooks or helper functions via NMR (Network Module Registrar):

1. **Program Information NPI Provider**: Defines program type ABI (context structure, available helpers)
2. **Hook NPI Provider**: Invokes eBPF programs when OS events occur

See `docs/eBpfExtensions.md` for detailed extension authoring guide.

## Testing Guidelines

- Unit tests link against static libraries with mocked kernel APIs (run entirely in user mode)
- Kernel tests require actual driver installation and eBPFSvc running
- Address sanitization is enabled for unit tests
- Fault injection tests verify behavior under failure conditions

## Tracing

eBPF for Windows uses ETW. Capture traces with:
```cmd
wpr.exe -start "%ProgramFiles%\ebpf-for-windows\ebpfforwindows.wprp" -filemode
# ... run scenario ...
wpr.exe -stop ebpfforwindows.etl
netsh trace convert ebpfforwindows.etl
```

View `bpf_printk()` output in real-time:
```cmd
tracelog -start MyTrace -guid ebpf-printk.guid -rt
tracefmt -rt MyTrace -displayonly -jsonMeta 0
```
