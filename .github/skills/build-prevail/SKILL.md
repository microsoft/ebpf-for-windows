---
name: build-prevail
description: >
  Build and test the PREVAIL verifier (external/ebpf-verifier) standalone.
  Use this skill when asked to build, test, or iterate on the PREVAIL verifier,
  run YAML verification tests, or work with the verifier's cmake build system.
---

# Build and Test PREVAIL Verifier

Build and test the PREVAIL eBPF verifier (`external/ebpf-verifier`) independently from the main eBPF for Windows solution.

## When to Use

- Working on verifier changes in `external/ebpf-verifier/`
- Running or debugging YAML verification tests
- Building `run_yaml.exe` or `tests.exe` for the verifier
- Iterating on verifier fixes with faster feedback than full MSBuild

## Prerequisites

The verifier's cmake build directory must exist. If `external/ebpf-verifier/build/` is missing, run from the solution root:

```powershell
.\scripts\initialize_ebpf_repo.ps1
```

This generates cmake projects for the verifier (and other submodules). You only need to do this once, or after resetting submodules.

## Building Standalone

```powershell
cd external\ebpf-verifier

# Build the YAML test runner (most common during development)
cmake --build build --config Release --target run_yaml

# Build the full Catch2 test binary
cmake --build build --config Release --target tests

# Clean build (rebuild everything from scratch)
cmake --build build --config Release --clean-first
```

### Enabling Standalone Tests

When built as a submodule, `prevail_ENABLE_TESTS` defaults to OFF. To enable standalone tests:

```powershell
cmake -B build -Dprevail_ENABLE_TESTS=ON
cmake --build build --config Release
```

**Note:** The `initialize_ebpf_repo.ps1` script does NOT enable tests. You need to reconfigure with `-Dprevail_ENABLE_TESTS=ON` if you want to build `tests.exe` standalone.

## Running YAML Tests

YAML test files are in `external/ebpf-verifier/test-data/*.yaml`. Each file is a test suite with individual tests separated by `---`.

```powershell
cd external\ebpf-verifier

# Run all tests in a suite
.\bin\run_yaml.exe test-data\loop.yaml

# Run tests matching a substring
.\bin\run_yaml.exe test-data\loop.yaml "while loop with"

# Run a specific test by exact name
.\bin\run_yaml.exe test-data\bitop.yaml "AND with 0xFF preserves relations when value fits"
```

### Exit codes
- `0` — all tests passed
- `1` — one or more tests failed

### Discovering postconditions for new tests

When writing new YAML tests, use placeholder postconditions and run the test to discover actual values:

```yaml
post:
  - placeholder
messages:
  - placeholder
```

The failure output shows "Unexpected properties" (actual values) and "Unseen properties" (your placeholders). Copy the actual values into your test.

### Available test suites

| Suite | Description |
|-------|-------------|
| `loop.yaml` | Bounded loop verification (termination checking) |
| `bitop.yaml` | Bitwise operations (AND, OR, XOR) |
| `movsx.yaml` | Sign extension (MOVSX) operations |
| `sext.yaml` | Sign/zero extension relational tests |
| `jump.yaml` | Conditional jumps and branching |
| `packet.yaml` | Packet access safety |
| `pointer.yaml` | Pointer arithmetic and safety |
| `stack.yaml` | Stack access verification |
| `call.yaml` | Helper function calls |
| `calllocal.yaml` | Local (subprogram) calls |
| `assign.yaml` | Register assignment |
| `add.yaml` / `subtract.yaml` | Arithmetic operations |
| `muldiv.yaml` / `sdivmod.yaml` / `udivmod.yaml` | Multiplication, division, modulo |
| `shift.yaml` | Shift operations |
| `atomic.yaml` | Atomic operations |
| `full64.yaml` | 64-bit comparison operations |
| `unsigned.yaml` | Unsigned comparison operations |
| `unop.yaml` | Unary operations (neg, swap) |
| `observe.yaml` | Observation/assertion tests |
| `uninit.yaml` | Uninitialized variable detection |
| `map.yaml` | Map operations |
| `parse.yaml` | YAML parsing tests |
| `callx.yaml` | Indirect calls |

## Running the Full Catch2 Test Binary

```powershell
cd external\ebpf-verifier

# Run all tests
.\bin\tests.exe

# Run with compact reporter
.\bin\tests.exe --reporter compact

# Abort on first failure
.\bin\tests.exe --abort --reporter compact

# Run specific test sections
.\bin\tests.exe "YAML suite: test-data/loop.yaml"
```

The `tests.exe` binary includes YAML tests, ELF verification tests, conformance tests, and unit tests.

## YAML Test Format

```yaml
---
test-case: descriptive test name
options: ["termination"]    # optional; enables loop termination checking

pre: ["r1.type=number", "r1.svalue=[0, 100]", "r1.uvalue=r1.svalue"]

code:
  <start>: |
    r0 = 0
  <loop>: |
    r0 += 1
    if r1 > r0 goto <loop>
  <out>: |
    exit

post:
  - r0.type=number
  - r0.svalue=[1, 100]

messages: []    # expected verifier messages; omit for no messages
```

### Key conventions
- `r` prefix for 64-bit registers, `w` prefix for 32-bit
- `w2 = r2` generates a 32-bit self-MOV (SHL 32 + RSH 32 truncation pattern)
- `r2 &= 255` generates 64-bit AND with immediate
- `svalue` = signed value, `uvalue` = unsigned value
- `r2.svalue=r1.svalue` means relational constraint (r2 tracks r1)
- `r1.svalue=[0, 100]` means interval [0, 100]
- `pc[N]` refers to the loop counter at instruction N
- `post:` must list ALL expected properties — unlisted ones cause "Unexpected properties" failure
- `messages:` field is optional (defaults to empty)

## Building via MSBuild (within the main solution)

When you need to build the verifier as part of the main solution (e.g., to build bpf2c which depends on it):

```powershell
# From solution root
msbuild ebpf-for-windows.sln /m /p:Configuration=Debug /p:Platform=x64 /t:"tools\bpf2c" /v:q /nologo
```

The MSBuild target for the verifier library is `libs\user\prevail` (for Debug/Release configs).
The `ubpf_fuzzer\ebpfverifier` target is a separate copy used only in `FuzzerDebug` configuration.

## Submodule Notes

- The verifier lives at `external/ebpf-verifier/` as a git submodule
- `git stash` in the parent repo does NOT affect the submodule working tree — stash separately in the submodule if needed
- To reset to the committed pointer: `git submodule update --init --recursive` (from the parent repo root)
- After resetting submodules, re-run `.\scripts\initialize_ebpf_repo.ps1` to regenerate cmake projects
