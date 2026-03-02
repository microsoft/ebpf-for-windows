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
| Build MCP server | `msbuild /m /p:Configuration=Debug /p:Platform=x64 /t:tools\ebpf_mcp` |

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
| **ebpf_mcp** | `tools/ebpf_mcp/` | MCP server exposing PREVAIL verifier analysis to LLM agents |

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

## Tracing

See "Using tracing" section in [docs/GettingStarted.md](../docs/GettingStarted.md). Quick reference:
```cmd
tracelog -start MyTrace -guid ebpf-printk.guid -rt
tracefmt -rt MyTrace -displayonly -jsonMeta 0
```
