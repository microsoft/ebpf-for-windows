---
name: verify-bpf
description: >
  Build and verify eBPF programs for the ebpf-for-windows project.
  Use this skill when asked to compile a .c BPF source to .o, verify a .o ELF file
  with bpf2c, or diagnose verification failures. Covers the full clang→bpf2c pipeline.
---

# Build & Verify eBPF Programs (ebpf-for-windows)

Compile eBPF C source to ELF bytecode with clang, then verify (and optionally generate
native code) with bpf2c. On verification failure, diagnose using the PREVAIL reference.

## When to Use

- User asks to compile/build a `.c` eBPF program to `.o`
- User asks to verify a `.o` ELF file or check if it passes the verifier
- User asks to debug or fix a verification failure from bpf2c output
- User mentions bpf2c, clang+bpf, or PREVAIL verification in the ebpf-for-windows context

## Quick Reference

### 1. Compile: C → ELF (.o)

Run from the **solution root directory**:

```powershell
# Standard sample programs
& 'C:\Program Files\LLVM\bin\clang.exe' -g -target bpf -O2 -Werror `
  -Iinclude -Iexternal\bpftool `
  -Itests\xdp -Itests\socket `
  -Itests\sample\ext\inc -Itests\include `
  -c <SOURCE>.c -o <OUTPUT>.o
```

For **undocked** programs (`tests\sample\undocked\*.c`), also add:
- `-Itests\sample`
- `-Iundocked\tests\sample\ext\inc`

> **Note:** The examples use `C:\Program Files\LLVM\bin\clang.exe`, the default
> LLVM install location. Adjust the path if LLVM is installed elsewhere.

### 2. Verify: ELF (.o) → native C (via bpf2c)

```powershell
.\x64\Debug\bpf2c.exe --bpf <FILE>.o --sys <OUTPUT_DIR>\<name>_driver.c
```

Add **`--verbose`** to get detailed verifier output (pre/post invariants at each instruction)
on failure.

### bpf2c Options

| Flag | Purpose |
|------|---------|
| `--bpf <file>` | Input ELF file containing BPF bytecode |
| `--sys <file>` | Generate Windows kernel driver C wrapper |
| `--dll <file>` | Generate Windows DLL C wrapper |
| `--raw <file>` | Generate C code without platform wrapper |
| `--verbose` | Show detailed verifier failure info (invariants) |
| `--type <str>` | Override eBPF program type string |
| `--hash <alg>` | Algorithm used to hash ELF file |

## Workflow

### Step 1: Identify the Source

Determine the `.c` source file and where the `.o` should go. Common patterns:

| Source Location | Include Flags |
|----------------|---------------|
| `tests\sample\*.c` | `-Iinclude -Iexternal\bpftool -Itests\xdp -Itests\socket -Itests\sample\ext\inc -Itests\include` |
| `tests\sample\undocked\*.c` | Same as above, plus `-Itests\sample -Iundocked\tests\sample\ext\inc` |
| User-provided file | Start with the standard sample flags; add more `-I` paths as needed |

### Step 2: Compile with Clang

Run clang. If it fails, fix compiler errors in the C source (standard C/clang diagnostics).

### Step 3: Verify with bpf2c

Run bpf2c with `--sys` (or `--dll`/`--raw`). Two outcomes:

- **Success** → bpf2c generates the output C file. Verification passed.
- **Failure** → bpf2c prints verifier errors. Proceed to diagnosis.

### Step 4: Diagnose Failures

On verification failure:

1. **Re-run with `--verbose`** if not already used, to get full invariant output.
2. **Read `external/ebpf-verifier/docs/llm-context.md`** — the authoritative PREVAIL diagnostic reference.
3. Follow the diagnosis protocol in that document (identify error → check pre-invariant →
   trace root cause → recommend fix).

## Example: Full Pipeline

```powershell
# Compile (undocked program — needs full include paths)
& 'C:\Program Files\LLVM\bin\clang.exe' -g -target bpf -O2 -Werror `
  -Iinclude -Iexternal\bpftool `
  -Itests\xdp -Itests\socket -Itests\sample\ext\inc -Itests\include `
  -Itests\sample -Iundocked\tests\sample\ext\inc `
  -c tests\sample\undocked\perf_event_burst.c `
  -o x64\Debug\perf_event_burst.o

# Verify + generate driver
.\x64\Debug\bpf2c.exe --bpf x64\Debug\perf_event_burst.o `
  --sys .\x64\Debug\perf_event_burst_km\perf_event_burst_driver.c

# If verification fails, re-run with --verbose for diagnosis
.\x64\Debug\bpf2c.exe --bpf x64\Debug\perf_event_burst.o `
  --sys .\x64\Debug\perf_event_burst_km\perf_event_burst_driver.c `
  --verbose
```
