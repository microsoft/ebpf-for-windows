---
name: prevail-mcp
description: >
  Query PREVAIL verifier analysis results via the MCP server. Use this skill when
  asked to diagnose verification failures using structured verifier data (invariants,
  constraints, CFG, source mapping) rather than text output from bpf2c --verbose.
---

# Query PREVAIL Verifier via MCP (prevail_mcp)

Use the `prevail-verifier` MCP server to query PREVAIL's analysis of eBPF programs.
The server exposes structured access to verification results — invariants, errors,
control flow, source mapping, and constraint checking — for diagnosing bpf2c
verification failures.

## When to Use

- User asks to diagnose a verification failure and you need structured invariant data.
- User asks what the verifier proves at a specific instruction.
- User asks why a specific register has a certain type or value range.
- User asks to trace how constraints evolve through the program.
- User wants to test a hypothesis about the verifier's state ("is r1.type=packet possible at PC 5?").
- User asks to map between C source lines and BPF assembly instructions.
- You need to understand the CFG structure of a verified program.

## When NOT to Use

- User just wants to compile and verify (use `verify-bpf` skill instead).
- User wants to fix the C source code based on a bpf2c error message (use `verify-bpf` skill).
- User is working with the standalone PREVAIL repo (use `verify-prevail` skill).

## Prerequisites

- **prevail_mcp.exe** must be built: `msbuild /m /p:Configuration=Debug /p:Platform=x64 /t:tools\prevail_mcp`
- **export_program_info.exe** must have been run to populate the eBPF program type registry.
- The MCP server is configured in `.vscode/mcp.json` and starts automatically.

## Diagnostic Workflow

Follow the [PREVAIL LLM diagnostic protocol](../../external/ebpf-verifier/docs/llm-context.md):

### Step 1: Get Error Context (Start Here — Often Sufficient)

Call `get_error_context` first. It returns the error, pre-invariant, assertions,
source line, AND a backward trace — all in one call.

**In most cases, this single call is all you need for diagnosis.** Read the
pre-invariant directly: if a register's type or constraint is listed, it is proven.
If a register mentioned in the error is absent, it was invalidated.

```
get_error_context: { "elf_path": "x64/Debug/myprogram.o", "trace_depth": 10 }
```

If you need an overview first (e.g., to check if verification passes or count
errors), use `verify_program`:

```
verify_program: { "elf_path": "x64/Debug/myprogram.o" }
```

### Step 2: Read the Pre-Invariant

The pre-invariant at the failing instruction tells you what the verifier knows.
Look for the register(s) named in the error message and check their constraints.
Common patterns:

- **Register absent** from the invariant → it was invalidated (e.g., by a helper
  call that may reallocate buffers). See §4.12.
- **Register has wrong type** (e.g., `r1.type=map_fd` where `number` is needed)
  → type mismatch. See §4.6.
- **Value range includes unsafe values** (e.g., `r0.svalue=[0, ...]` includes NULL)
  → missing null check. See §4.4.
- **`packet_size=0`** or too small → missing or insufficient bounds check. See §4.2.

The backward trace shows **post-invariants** at each preceding instruction, so you
can see exactly where a register acquired its current type or where a constraint
was lost.

### Step 3: Compare Pre/Post Invariants (If Needed)

Only needed when you suspect a register lost its type across a single instruction
(e.g., a helper call). Use `get_instruction` to see both pre and post invariants:

```
get_instruction: { "elf_path": "x64/Debug/myprogram.o", "pcs": [9, 10, 11] }
```

Compare the pre-invariant and post-invariant at the helper call. Registers present
in the pre but absent in the post were **invalidated** by the helper (e.g.,
`bpf_xdp_adjust_head` scrubs all packet-derived pointers).

### Step 4: Test Hypotheses with check_constraint (If Needed)

Only use `check_constraint` when you need formal confirmation beyond what the
pre-invariant already tells you, or when testing non-obvious implications.

Use `check_constraint` to test whether a constraint is consistent with the
verifier's state at a specific instruction.

```
check_constraint: {
  "elf_path": "x64/Debug/myprogram.o",
  "pc": 5,
  "constraints": ["r1.type=packet", "packet_size=[8, 65534]"],
  "mode": "consistent"
}
```

The response includes the invariant at that point, so you can see what the verifier
actually knows:

```json
{
  "ok": true,
  "message": "",
  "invariant": ["r1.type=packet", "r1.packet_offset=0", "packet_size=[0, 65534]", ...]
}
```

#### Modes

- `consistent`: Is the constraint **possible** (not contradicted by the invariant)?
- `proven`: Does the verifier **guarantee** the constraint? (invariant implies observation)
- `entailed`: Is the observation a sub-state of the invariant (rarely needed)?

#### How to Use Each Mode

**`consistent`** — "Could this be true?"
```
check_constraint: { "constraints": ["r1.type=packet"], "mode": "consistent" }
→ { "ok": true }   ← r1 MIGHT be a packet pointer (not ruled out)
→ { "ok": false }  ← r1 CANNOT be a packet pointer (contradicted)
```

**`proven`** — "Is this definitely true?"
```
check_constraint: { "constraints": ["r1.type=ctx"], "mode": "proven" }
→ { "ok": true }   ← the verifier GUARANTEES r1 is ctx
→ { "ok": false }  ← NOT proven (r1 could be something else, or is unconstrained)
```

Use `proven` to confirm the verifier's knowledge. For example, after a map lookup:
```
check_constraint: { "pc": 7, "constraints": ["r0.svalue=[0, 2147418112]"], "mode": "proven" }
→ { "ok": true }  ← verifier proves r0 could be NULL (svalue includes 0)
```

#### IMPORTANT: Interpreting "consistent" Results

A `consistent` check answers: "does this constraint contradict the invariant?"
If the invariant says **nothing** about a variable, then no constraint on it can
contradict the invariant, so `ok` will always be `true`.

**Always check the `invariant` field in the response.** If the variable you're
asking about is absent from the invariant, the `ok: true` result is vacuous —
it means the verifier has no information about that variable, not that the
constraint is proven.

**To prove the verifier knows `r1.type=ctx`, use `proven` mode:**
```
check_constraint: { "constraints": ["r1.type=ctx"], "mode": "proven" }
→ { "ok": true }   ← proven: the invariant guarantees r1 is ctx
→ { "ok": false }  ← NOT proven: r1 may be unconstrained or have other types
```

**Example — stale pointer after helper call:**
```
check_constraint at PC 11: { "constraints": ["r6.type=packet"] }
→ { "ok": true, "invariant": ["r0.type=number", "r10.type=stack"] }
```
`ok: true` but r6 is NOT in the invariant — it was scrubbed by a preceding
helper call. The result is vacuously true, not a proof that r6 is a packet pointer.

#### Batch Mode

Test multiple hypotheses in a single call (runs analysis once):

```
check_constraint: {
  "elf_path": "x64/Debug/myprogram.o",
  "checks": [
    { "pc": 9, "constraints": ["r6.type=packet"], "mode": "proven" },
    { "pc": 11, "constraints": ["r6.type=packet"], "mode": "proven" },
    { "pc": 11, "constraints": ["r6.type=packet"], "mode": "consistent" }
  ]
}
```

Returns an array of results, one per check. Each check can have its own `pc`,
`constraints`, `mode`, and `point` — only `elf_path` is shared. This is faster
than multiple single calls because analysis runs once and the live session is
cached for reuse.

### Step 5: Understand Program Structure

Use `get_cfg` for the control-flow graph and `get_source_mapping` for
C source ↔ BPF instruction mapping.

```
get_cfg:            { "elf_path": "x64/Debug/myprogram.o", "format": "json" }
get_source_mapping: { "elf_path": "x64/Debug/myprogram.o", "source_line": 42 }
```

`get_source_mapping` supports substring matching on `source_file`, so you can
pass just the filename (e.g., `"source_file": "myprogram.c"`) rather than the
full path.

## Common Diagnosis Patterns

### Stale pointer after helper (§4.12)

1. `get_error_context` shows a register not in the pre-invariant
2. `get_instruction` at the preceding helper call shows the register WAS in the
   pre-invariant but is ABSENT from the post-invariant
3. Fix: re-derive the pointer from context after the helper call

### Lost correlation at join (§4.11)

1. `get_error_context` backward trace shows a branch where the constraint was
   established, but the pre-invariant at the error lost it
2. Look for a join point where checked and unchecked paths merge — the verifier's
   path-insensitive analysis takes the weaker constraint
3. Fix: restructure so the bounds check directly guards the access

### Loop termination failure (§4.7)

1. Error is at a `(counter)` pseudo-instruction with `pc[N]=[0, +oo]`
2. The verifier's widening pushed the loop counter to infinity
3. Use `get_cfg` to understand the loop structure (find back-edges)
4. Fix: ensure compiler generates a provably bounded loop exit condition

## Tool Quick-Reference

| Question | Tool | Notes |
|----------|------|-------|
| Does it pass? How many errors? | `verify_program` | Start here if unsure about pass/fail |
| What went wrong? (first call for failures) | `get_error_context` | Returns error + invariant + backward trace in one call |
| All errors at once | `get_errors` | Use for multi-error programs |
| What's proven at PC N? | `get_invariant` | `pcs: [N]` for one, `pcs: [N,M,...]` for many |
| Full instruction detail (pre/post invariants) | `get_instruction` | `pcs: [N]` for one, `pcs: [N,M,...]` for many |
| Is constraint X possible at PC N? | `check_constraint` | mode=consistent; **check invariant field** |
| Does the verifier prove X at PC N? | `check_constraint` | mode=proven |
| Multiple hypothesis tests | `check_constraint` | Use `checks` array for batch (single analysis) |
| Program structure / basic blocks | `get_cfg` | JSON or DOT format |
| Which C line = which PC? | `get_source_mapping` | Requires `-g` debug info; supports filename substring |
| Full instruction listing | `get_disassembly` | Use `from_pc`/`to_pc` to limit range |

## Tool Reference

| Tool | Purpose | Key Parameters |
|------|---------|----------------|
| `list_programs` | List programs in ELF | `elf_path` |
| `verify_program` | Run verification | `elf_path`, `section`, `program`, `program_type` |
| `get_errors` | All errors + unreachable code | `elf_path` |
| `get_error_context` | Error or any-PC + backward trace | `elf_path`, `error_index` or `pc`, `trace_depth` |
| `get_disassembly` | Instruction listing with source | `elf_path`, `from_pc`, `to_pc` |
| `get_invariant` | Abstract state at instruction(s) | `elf_path`, `pcs`, `point` (pre/post) |
| `get_instruction` | Full instruction detail | `elf_path`, `pcs` |
| `get_cfg` | Control-flow graph | `elf_path`, `format` (json/dot) |
| `get_source_mapping` | C ↔ BPF mapping | `elf_path`, `pc` or `source_line` + `source_file` |
| `check_constraint` | Test hypothesis | `elf_path`, `pc`, `constraints`, `mode` |

All tools that accept `section`/`program` also accept `program_type` to override
the program type inferred from the ELF section name (e.g., `"program_type": "xdp"`).

## Constraint String Format

Constraint strings use the same format as PREVAIL's verbose output
(documented in `external/ebpf-verifier/docs/llm-context.md`):

- `r1.type=ctx` — Register type.
- `r1.svalue=[1, 2147418112]` — Signed value interval.
- `r1.packet_offset=0` — Offset within memory region.
- `packet_size=[0, 65534]` — Global constraint.
- `s[4088...4095].type=number` — Stack byte range type.

## Important Notes

- The MCP server uses `g_ebpf_platform_windows` (same as bpf2c). Results match bpf2c exactly.
- Source mapping requires ELF compiled with `-g` (BTF debug info).
- `check_constraint` re-runs analysis for each call (TLS-dependent). Other tools use cached results.
- `get_instruction` returns structured error entries for invalid PCs (e.g., gap PCs in LDDW instructions) instead of failing the request.
- Always read `external/ebpf-verifier/docs/llm-context.md` for the full diagnostic reference.
