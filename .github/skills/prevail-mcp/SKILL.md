---
name: prevail-mcp
description: >
  Query PREVAIL verifier analysis results via the MCP server. Use this skill when
  asked to diagnose verification failures using structured verifier data (invariants,
  constraints, CFG, source mapping) rather than text output from bpf2c --verbose.
---

# Query PREVAIL Verifier via MCP

Use the `ebpf-verifier` MCP tools to query PREVAIL's analysis of eBPF programs.

## When to Use

- Diagnose verification failures with structured invariant data.
- Understand what the verifier proves at specific instructions.
- Trace register state, constraints, or data flow through a program.
- Test hypotheses about the verifier's abstract state.
- Map between C source lines and BPF assembly instructions.

## When NOT to Use

- User just wants to compile and verify (use `verify-bpf` skill).
- User wants to fix C source from a bpf2c error message (use `verify-bpf` skill).
- User is working with the standalone PREVAIL repo (use `verify-prevail` skill).

## Prerequisites

- **ebpf_mcp.exe** must be built: `msbuild /m /p:Configuration=Debug /p:Platform=x64 /t:tools/ebpf_mcp`
- **export_program_info.exe** must have been run to populate the eBPF program type registry.

## Diagnostic Workflow

Read [external/ebpf-verifier/docs/llm-context.md](../../external/ebpf-verifier/docs/llm-context.md)
for the full diagnostic protocol, error patterns (§4), and invariant format (§3).

### 1. Start with `get_slice`

Call `get_slice` first — it returns the error, pre-invariant, assertions, source
line, and a backward failure slice in one call. **Often sufficient for diagnosis.**

Read the pre-invariant at the error:
- Register **listed** with constraints → verifier has proven facts about it.
- Register **absent** → invalidated (e.g., by a helper that may reallocate buffers; §4.12).
- `r0.svalue=[0, ...]` → includes NULL, missing null check (§4.4).
- `packet_size=0` → missing bounds check (§4.2).

### 2. Deep dive with `get_instruction` (if needed)

Compare pre vs post invariants across a helper call to see which registers were
invalidated. Only needed when the failure slice doesn't show the full picture.

### 3. Test hypotheses with `check_constraint` (if needed)

Use `proven` mode to confirm the verifier guarantees a constraint.
Use `consistent` mode to test if a constraint is possible (not contradicted).

**IMPORTANT**: `consistent` mode returns `ok=true` for variables absent from the
invariant (vacuously true). Always check the `invariant` field in the response
to confirm the variable is actually tracked. Use `proven` mode to get definitive
answers.

### 4. Understand structure with `get_cfg` and `get_source_mapping`

Use when you need to understand branch/join points or map C lines to BPF PCs.

## Verification Options

`verify_program` and `get_slice` accept optional overrides. **Do not change these
unless the user explicitly requests it** — defaults match the platform:

| Option | Default (Windows) | Default (PREVAIL) | Effect |
|--------|-------------------|-------------------|--------|
| `check_termination` | true | false | Verify loop bounds |
| `allow_division_by_zero` | true | true | Allow BPF ISA div-by-zero |
| `strict` | false | false | Additional runtime checks |

## Important Notes

- Results match bpf2c exactly (same platform, same verifier).
- Source mapping requires ELF compiled with `-g` (BTF debug info).
- Constraint strings use PREVAIL's format (documented in llm-context.md §3):
  `r1.type=ctx`, `r1.svalue=[0, 42]`, `packet_size=0`, `s[4088...4095].type=number`.
