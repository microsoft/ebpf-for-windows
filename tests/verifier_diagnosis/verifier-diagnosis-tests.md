# Verifier Diagnosis Test Cases (ebpf-for-windows)

This file contains test cases for validating that the `verify-bpf` and `prevail-mcp`
skills can accurately diagnose PREVAIL verification failures on the Windows eBPF
platform.

Each test case is a minimal eBPF program compiled for `g_ebpf_platform_windows` with
a deliberate verification bug. The diagnostic reference is
`external/ebpf-verifier/docs/llm-context.md`.

## Prerequisites

Source files are in `tests/verifier_diagnosis/`. Pre-built ELFs are in
`tests/verifier_diagnosis/build/`.

To rebuild from source:

```powershell
$clang = "C:\Program Files\LLVM\bin\clang.exe"  # or packages\llvm.tools\clang.exe
Get-ChildItem tests\verifier_diagnosis\*.c | ForEach-Object {
    & $clang -g -target bpf -O2 -Werror `
        -Iinclude -Iexternal\bpftool -Itests\include `
        -c $_.FullName -o "tests\verifier_diagnosis\build\$($_.BaseName).o"
}
```

Tools required:

- **bpf2c.exe** (`x64\Debug\bpf2c.exe`) — used by the `verify-bpf` skill
- **ebpf_mcp.exe** (`x64\Debug\ebpf_mcp.exe`) — MCP server used by the `prevail-mcp` skill

## How to Test

### Single Test — verify-bpf skill

```text
Using the verify-bpf skill, verify tests/verifier_diagnosis/build/nullmapref.o
and diagnose the failure.
```

### Single Test — prevail-mcp skill

```text
Using the prevail-mcp skill, diagnose the verification failure in
tests/verifier_diagnosis/build/nullmapref.o.
```

### Single Test — either skill

```text
Verify tests/verifier_diagnosis/build/nullmapref.o and diagnose the failure.
```

The LLM should:
1. Identify the correct failure pattern from `external/ebpf-verifier/docs/llm-context.md`
2. Explain the root cause by reading the pre-invariant
3. Suggest the correct fix

## Automated Regression Prompts

### Run All Tests with verify-bpf

```text
Read external/ebpf-verifier/docs/llm-context.md for diagnostic patterns. Then for
each test case in tests/verifier_diagnosis/verifier-diagnosis-tests.md, run bpf2c
--verbose on the ELF and diagnose the failure.

For each test case:
1. Run: .\x64\Debug\bpf2c.exe --bpf <elf_path> --verbose
2. Identify the §4.X pattern from llm-context.md that matches the error
3. Read the pre-invariant at the failing instruction to confirm the root cause
4. Compare your diagnosis against the expected pattern and key invariant

Report results as a table:
| Test | Expected Pattern | Actual Pattern | Key Invariant Found | PASS/FAIL |

A test PASSES when:
- The correct §4.X pattern is identified
- The key invariant from the expected values is present in the output
- The root cause explanation is consistent with the expected fix

Skip tests marked as NEEDS-FLAG.
```

### Run All Tests with prevail-mcp

```text
Read external/ebpf-verifier/docs/llm-context.md for diagnostic patterns. Then for
each test case in tests/verifier_diagnosis/verifier-diagnosis-tests.md, use the
ebpf-verifier MCP tools to diagnose the failure.

For each test case:
1. Call get_slice on the ELF file with trace_depth=10
2. Identify the §4.X pattern from llm-context.md that matches the error
3. Read the pre-invariant from the MCP output to confirm the root cause
4. Compare your diagnosis against the expected pattern and key invariant

Report results as a table:
| Test | Expected Pattern | Actual Pattern | Key Invariant Found | PASS/FAIL |

A test PASSES when:
- The correct §4.X pattern is identified
- The key invariant from the expected values is present in the output
- The root cause explanation is consistent with the expected fix

Skip tests marked as NEEDS-FLAG.
```

### Head-to-Head Comparison

```text
Read external/ebpf-verifier/docs/llm-context.md for diagnostic patterns. Then for
each test case in tests/verifier_diagnosis/verifier-diagnosis-tests.md (skip
NEEDS-FLAG tests), diagnose the failure using BOTH approaches:

Approach A (verify-bpf): Run .\x64\Debug\bpf2c.exe --bpf <elf_path> --verbose
Approach B (prevail-mcp): Call get_slice with trace_depth=10

For each test case, compare the two diagnoses and report:
| Test | Pattern (bpf2c) | Pattern (MCP) | Match? | Key Invariant |

Then summarize:
- Number of tests where both approaches agree on the pattern
- Any tests where the approaches diverge
- Which approach required more tool output to reach the same diagnosis
```

---

## Test Cases

### Test 1: Null Pointer After Map Lookup

**Source**: `tests/verifier_diagnosis/nullmapref.c`

```powershell
.\x64\Debug\bpf2c.exe --bpf tests\verifier_diagnosis\build\nullmapref.o --verbose
```

**Expected error**: `Possible null access (valid_access(r0.offset, width=4) for write)`
**Pattern**: §4.4 — Null Pointer After Map Lookup
**Key invariant**: `r0.svalue=[0, 2147418112]` — lower bound of 0 means NULL is possible
**Fix**: Add `if (value == NULL) return 0;` after `bpf_map_lookup_elem`

---

### Test 2: Unbounded Packet Access

**Source**: `tests/verifier_diagnosis/packet_overflow.c`

```powershell
.\x64\Debug\bpf2c.exe --bpf tests\verifier_diagnosis\build\packet_overflow.o --verbose
```

**Expected error**: `Upper bound must be at most packet_size (valid_access(r2.offset, width=4) for read)`
**Pattern**: §4.2 — Unbounded Packet Access
**Key invariant**: `packet_size=0` — bounds check does not establish minimum packet size
**Fix**: Change guard to `if (data + sizeof(int) > data_end) return XDP_DROP;`

---

### Test 3: Uninitialized Stack Memory

**Source**: `tests/verifier_diagnosis/ringbuf_uninit.c`

```powershell
.\x64\Debug\bpf2c.exe --bpf tests\verifier_diagnosis\build\ringbuf_uninit.o --verbose
```

**Expected error**: `Stack content is not numeric (valid_access(r2.offset, width=r3) for read)`
**Pattern**: §4.13 — Non-Numeric Stack Content
**Key invariant**: `Stack: Numbers -> {}` — no stack bytes marked as numeric
**Fix**: Initialize the buffer before passing to helper: `__builtin_memset(&test, 0, sizeof(test));`

---

### Test 4: Pointer Exposure to Map (Value)

**Source**: `tests/verifier_diagnosis/exposeptr.c`

```powershell
.\x64\Debug\bpf2c.exe --bpf tests\verifier_diagnosis\build\exposeptr.o --verbose
```

**Expected error**: `Illegal map update with a non-numerical value [4088-4096) (within(r3:value_size(r1)))`
**Pattern**: §4.9 — Map Key/Value Non-Numeric (pointer exposure)
**Key invariant**: `s[4088...4095].type=ctx` — context pointer stored on stack, passed as map value
**Fix**: Store numeric data only in maps; never store pointers

---

### Test 5: Nonzero Context Offset

**Source**: `tests/verifier_diagnosis/ctxoffset.c`

```powershell
.\x64\Debug\bpf2c.exe --bpf tests\verifier_diagnosis\build\ctxoffset.o --verbose
```

**Expected error**: `Nonzero context offset (r1.ctx_offset == 0)`
**Pattern**: §4.10 — Context Field Bounds Violation
**Key invariant**: `r1.ctx_offset=8` — context pointer was modified before helper call
**Fix**: Pass the original unmodified context pointer to helpers

---

### Test 6: Map Value Overrun

**Source**: `tests/verifier_diagnosis/mapvalue_overrun.c`

```powershell
.\x64\Debug\bpf2c.exe --bpf tests\verifier_diagnosis\build\mapvalue_overrun.o --verbose
```

**Expected error**: `Upper bound must be at most r1.shared_region_size (valid_access(r1.offset, width=8) for read)`
**Pattern**: §4.9 — Map Key/Value Size Mismatch
**Key invariant**: `r1.shared_region_size=4` — map value is 4 bytes, but reading 8
**Fix**: Match read width to map value size, or increase map value size

---

### Test 7: Pointer Arithmetic with Non-Number

**Source**: `tests/verifier_diagnosis/ptr_arith.c`

```powershell
.\x64\Debug\bpf2c.exe --bpf tests\verifier_diagnosis\build\ptr_arith.o --verbose
```

**Expected error**: `Only numbers can be added to pointers (r2.type in {ctx, stack, packet, shared} -> r1.type == number)`
**Pattern**: §4.6 — Type Mismatch (pointer + pointer)
**Key invariant**: Both `r1.type=packet` and `r2.type=packet` — adding two pointers is illegal
**Fix**: Only add/subtract numeric values to/from pointers

---

### Test 8: Division by Zero (NEEDS-FLAG)

**Source**: `tests/verifier_diagnosis/divzero.c`

```powershell
.\x64\Debug\bpf2c.exe --bpf tests\verifier_diagnosis\build\divzero.o --verbose
```

**Expected error**: `Possible division by zero`
**Pattern**: §4.8 — Division by Zero
**Key invariant**: Divisor register has `svalue=[0, ...]` — lower bound includes 0
**Fix**: Add `if (divisor != 0)` check before division
**Note**: NEEDS-FLAG — passes with default settings. The verifier allows division by
zero by default; this test requires a `--no-division-by-zero` flag to enable the check.
Neither bpf2c nor the MCP server currently expose this flag.

---

### Test 9: Infinite Loop (NEEDS-FLAG)

**Source**: `tests/verifier_diagnosis/infinite_loop.c`

```powershell
.\x64\Debug\bpf2c.exe --bpf tests\verifier_diagnosis\build\infinite_loop.o --verbose
```

**Expected error**: `Could not prove termination` or loop counter shows `[1, +oo]`
**Pattern**: §4.7 — Infinite Loop / Termination Failure
**Key invariant**: Loop bound comes from map value with unbounded range `[0, UINT32_MAX]`
**Fix**: Use compile-time constant bounds or restructure loop
**Note**: NEEDS-FLAG — passes with default settings. The MCP server enables termination
checking by default, but this test still passes because the loop bound from a map value
is not checked by the loop-counter mechanism (only widened). bpf2c also passes this test.

---

### Test 10: Bounded Loop (Compiler Transformation)

**Source**: `tests/verifier_diagnosis/bounded_loop.c`

```powershell
.\x64\Debug\bpf2c.exe --bpf tests\verifier_diagnosis\build\bounded_loop.o --verbose
```

**Expected error**: `Loop counter is too large (pc[7] < 100000)`
**Pattern**: §4.7 — Infinite Loop / Termination Failure (compiler transformation)
**Key invariant**: `pc[7]=[0, +oo]` — loop counter widened to infinity; clang transforms `i < 1000` to `i != 1000` which the verifier cannot prove terminates
**Fix**: Verifier limitation; the loop is actually bounded but unprovable

---

### Test 11: Bad Map Pointer Type

**Source**: `tests/verifier_diagnosis/badmapptr.c`

```powershell
.\x64\Debug\bpf2c.exe --bpf tests\verifier_diagnosis\build\badmapptr.o --verbose
```

**Expected error**: `Invalid type (r1.type in {number, ctx, stack, packet, shared})`
**Pattern**: §4.6 — Type Mismatch (arithmetic on map_fd)
**Key invariant**: `r1.type=map_fd` — a map file descriptor was used in arithmetic (`map + 1`), which is not permitted
**Fix**: Pass the map pointer directly to `bpf_map_lookup_elem` without arithmetic

---

### Test 12: Stack Out-of-Bounds Access

**Source**: `tests/verifier_diagnosis/badhelpercall.c`

```powershell
.\x64\Debug\bpf2c.exe --bpf tests\verifier_diagnosis\build\badhelpercall.o --verbose
```

**Expected error**: `Upper bound must be at most EBPF_TOTAL_STACK_SIZE (valid_access(r1.offset, width=8) for write)`
**Pattern**: §4.3 — Stack Out-of-Bounds Access
**Key invariant**: `r1.stack_offset=4095` with width 8 — writing 8 bytes at offset 4095 spans [4095, 4103), exceeding EBPF_TOTAL_STACK_SIZE (4096)
**Fix**: Ensure stack pointer + access width stays within the stack frame

---

### Test 13: Lost Correlations (Dependent Read)

**Source**: `tests/verifier_diagnosis/dependent_read.c`

```powershell
.\x64\Debug\bpf2c.exe --bpf tests\verifier_diagnosis\build\dependent_read.o --verbose
```

**Expected error**: `Upper bound must be at most packet_size (valid_access(r1.offset, width=4) for read)`
**Pattern**: §4.11 — Lost Correlations in Computed Branches
**Key invariant**: `packet_size=1` at the read but needs ≥ 4. The bounds check (`data + 4 > data_end`) stores its result in flag `r5`. The verifier joins the checked and unchecked paths, weakening `packet_size`, and cannot recover the correlation when branching on `r5 != 0`.
**Fix**: Use a direct `if (data + 4 > data_end)` check immediately before the read instead of a cached flag

---

### Test 14: Pointer Exposure to Map (Key)

**Source**: `tests/verifier_diagnosis/exposeptr2.c`

```powershell
.\x64\Debug\bpf2c.exe --bpf tests\verifier_diagnosis\build\exposeptr2.o --verbose
```

**Expected error**: `Illegal map update with a non-numerical value [4088-4096) (within(r2:key_size(r1)))`
**Pattern**: §4.9 — Map Key/Value Non-Numeric (pointer in key)
**Key invariant**: `s[4088...4095].type=ctx` — context pointer stored on stack, passed as map key
**Fix**: Store only numeric data in map keys; never use pointers as keys

---

### Test 15: Stale Packet Pointer After Reallocation

**Source**: `tests/verifier_diagnosis/packet_reallocate.c`

```powershell
.\x64\Debug\bpf2c.exe --bpf tests\verifier_diagnosis\build\packet_reallocate.o --verbose
```

**Expected error**: `Invalid type (r6.type in {ctx, stack, packet, shared})`
**Pattern**: §4.12 — Stale Pointer After Reallocation
**Key invariant**: r6 is absent from the type domain — `bpf_xdp_adjust_head` invalidated all packet pointers; r6 held a packet pointer before the call but was scrubbed after
**Fix**: Re-derive packet pointers from `ctx->data` / `ctx->data_end` after any helper that may resize the packet

---

### Test 16: Wrong Map Type for Tail Call

**Source**: `tests/verifier_diagnosis/tail_call_bad.c`

```powershell
.\x64\Debug\bpf2c.exe --bpf tests\verifier_diagnosis\build\tail_call_bad.o --verbose
```

**Expected error**: `Invalid type (r2.type == map_fd_programs)`
**Pattern**: §4.6 — Type Mismatch (map_fd vs map_fd_programs)
**Key invariant**: `r2.type=map_fd` but `bpf_tail_call` requires `r2.type=map_fd_programs` — a regular `BPF_MAP_TYPE_ARRAY` was passed instead of `BPF_MAP_TYPE_PROG_ARRAY`
**Fix**: Use `BPF_MAP_TYPE_PROG_ARRAY` for tail call maps

---

## Pattern Coverage

| Pattern | Tests |
|---------|-------|
| §4.2 — Unbounded Packet Access | 2 |
| §4.3 — Stack Out-of-Bounds Access | 12 |
| §4.4 — Null Pointer After Map Lookup | 1 |
| §4.6 — Type Mismatch | 7, 11, 16 |
| §4.7 — Infinite Loop / Termination | 9 (NEEDS-FLAG), 10 |
| §4.8 — Division by Zero | 8 (NEEDS-FLAG) |
| §4.9 — Map Key/Value Non-Numeric | 4, 6, 14 |
| §4.10 — Context Field Bounds Violation | 5 |
| §4.11 — Lost Correlations | 13 |
| §4.12 — Stale Pointer After Reallocation | 15 |
| §4.13 — Non-Numeric Stack Content | 3 |

**Coverage**: 11 of 12 documented patterns. Missing: §4.1 (Uninitialized Register) — this
pattern is difficult to trigger from C source because clang initializes registers.

## Results Summary

All 14 active test cases (excluding NEEDS-FLAG tests 8 and 9) produce the expected
verification errors when run against bpf2c or queried via the prevail-verifier MCP tools.

### Validated Results (Phase 1 Comparison)

Both the `verify-bpf` skill (bpf2c --verbose) and the `prevail-mcp` skill (MCP
get_slice) were tested on all 14 active test cases with fresh agent
contexts. Results:

| Metric | verify-bpf | prevail-mcp |
|--------|-----------|-------------|
| Accuracy | 14/14 (100%) | 14/14 (100%) |
| Pattern agreement | 14/14 | 14/14 |
| Avg time per test | 10.8s | 8.3s |
| Total time (14 tests) | 151s | 116s |
| Relative speed | 1.0× | 1.3× faster |

Both approaches produce identical diagnoses for all test cases. The prevail-mcp
approach is ~23% faster due to targeted structured output vs full-program text dumps.

### How to Reproduce the Comparison

```text
For each test case in tests/verifier_diagnosis/verifier-diagnosis-tests.md
(skip NEEDS-FLAG tests), run TWO independent diagnoses:

1. verify-bpf: Run bpf2c --verbose and diagnose
2. prevail-mcp: Call get_slice and diagnose

Compare: Do both identify the same §4.X pattern and root cause?

Expected result: 100% agreement on all 14 active tests.
```

## Skill-Specific Notes

### verify-bpf (bpf2c --verbose)

- Outputs the **full program** with pre/post invariants at every instruction
- Token-heavy: 4–14K chars for 7–29 instruction programs
- Provides complete context — no follow-up queries needed
- Best for: understanding the full abstract state evolution

### prevail-mcp (MCP tools)

- `get_slice`: returns error + failure slice (targeted, 1.5–3K chars)
- `verify_program`: quick pass/fail check with error summary
- `get_invariant`: query specific PCs for detailed state
- `check_constraint`: test hypotheses about the verifier's knowledge
- Best for: targeted diagnosis with minimal token consumption

### Key Differences

| Aspect | verify-bpf | prevail-mcp |
|--------|-----------|-------------|
| Output per diagnosis | 4–14K chars | 1.5–3K chars |
| Follow-up queries | Not needed | Available (get_invariant, check_constraint) |
| Source mapping | Embedded in text | Structured (get_source_mapping) |
| CFG navigation | Manual from text | Structured (get_cfg) |
| Hypothesis testing | Not available | check_constraint tool |

## Build Reference

```powershell
# Build bpf2c
msbuild ebpf-for-windows.sln /m /p:Configuration=Debug /p:Platform=x64 /t:tools\bpf2c

# Build MCP server
msbuild ebpf-for-windows.sln /m /p:Configuration=Debug /p:Platform=x64 /t:tools\prevail_mcp

# Compile test programs
$clang = "C:\Program Files\LLVM\bin\clang.exe"
Get-ChildItem tests\verifier_diagnosis\*.c | ForEach-Object {
    & $clang -g -target bpf -O2 -Werror `
        -Iinclude -Iexternal\bpftool -Itests\include `
        -c $_.FullName -o "tests\verifier_diagnosis\build\$($_.BaseName).o"
}

# Quick-verify a single test
.\x64\Debug\bpf2c.exe --bpf tests\verifier_diagnosis\build\nullmapref.o --verbose
```
