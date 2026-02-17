---
name: verify-prevail
description: >
  Diagnose eBPF program verification failures from the PREVAIL verifier.
  Use this skill for linux-compatible eBPF programs verified in the standalone
  PREVAIL repo (external/ebpf-verifier). For programs using Windows-specific
  features (bpf2c pipeline, Windows helpers, ebpf-for-windows headers), use the
  'verify-bpf' skill instead.
---

# Diagnose PREVAIL Verification Failures (Linux-Compatible Programs)

Diagnose eBPF program verification failures using the standalone PREVAIL verifier
(`external/ebpf-verifier`). This skill covers **linux-compatible** eBPF programs
that can be verified directly with the PREVAIL `check` or `run_yaml` tools.

## When to Use

- User shares a PREVAIL verifier error or log and asks why verification failed
- User asks to diagnose, debug, or explain an eBPF verification failure **in the
  PREVAIL repo** (`external/ebpf-verifier`)
- User asks to debug PREVAIL YAML test failures or abstract-interpretation issues
- User is working on verifier internals (abstract domains, widening, transformers)
- User mentions "verifier", "verification", "PREVAIL", or "abstract interpretation" errors
  **for linux-compatible BPF programs**

## When NOT to Use

- Program uses **Windows-specific helpers or headers** (e.g., `ebpf_helpers.h`,
  `sample_ext_helpers.h`, WFP hook types) → use **`verify-bpf`** instead
- User wants to run the **bpf2c pipeline** (clang → bpf2c → native driver) → use
  **`verify-bpf`** instead
- User needs to **compile** a `.c` BPF source to `.o` for ebpf-for-windows → use
  **`verify-bpf`** instead

## Reference Document

Read the full PREVAIL diagnostic reference before diagnosing:

```
external/ebpf-verifier/docs/llm-context.md
```

This document contains:
- How to interpret PREVAIL log output (register state, stack state, invariants)
- Glossary of log terms, types, type groups, and assertions
- Common failure patterns with symptoms, causes, and fixes
- Advanced topics (widening, path-insensitivity, pointer provenance)
- A step-by-step reasoning protocol for diagnosis

**Always read this file first** — it is the authoritative reference for PREVAIL diagnostics.

## Diagnosis Instructions

### Step 1: Read the Reference

Read `external/ebpf-verifier/docs/llm-context.md` to load the full diagnostic context.

### Step 2: Gather the Error

Ask the user to provide (if not already given):
1. The **verifier error message** (the line with `<pc>: <message> (<assertion>)`)
2. The **pre-invariant** at the failing instruction
3. The **3–5 instructions** leading up to the failure
4. The **source code** of the eBPF program (or the relevant section)
5. Any **map or context definitions** (for map/context-related errors)

### Step 3: Identify the Failure Pattern

Using the reference document, match the error to one of the common failure patterns:

| Pattern | Key Symptom |
|---------|-------------|
| Uninitialized register | `Invalid type (r<N>.type in {...})` |
| Unbounded packet access | `Upper bound must be at most packet_size` |
| Stack out-of-bounds | `Lower bound must be at least r10.stack_offset - EBPF_SUBPROGRAM_STACK_SIZE` |
| Null pointer (map lookup) | `Possible null access` |
| Type mismatch | `Only pointers can be dereferenced` |
| Pointer arithmetic error | `Only numbers can be added to pointers` |
| Infinite loop | `Loop counter is too large (pc[N] < 100000)` |
| Division by zero | `Possible division by zero` |
| Map key/value mismatch | `Illegal map update with a non-numerical value` |
| Context bounds violation | `Nonzero context offset` or context `Upper bound` error |
| Lost correlation (verifier limitation) | Bounds check present but verifier can't prove safety |

### Step 4: Trace the Root Cause

Follow the reasoning protocol from the reference:
1. **Check the pre-invariant** — what types and constraints do the relevant registers have?
2. **Identify missing constraints** — what constraint would make the assertion pass?
3. **Trace backwards** — where was the constraint lost or never established?
4. **Check for verifier limitations** — is this a code bug or a verifier precision issue?

### Step 5: Recommend a Fix

Provide:
1. A clear explanation of **why** verification failed
2. The **specific constraint** that is missing or violated
3. A **concrete code fix** (with before/after examples when possible)
4. If it's a verifier limitation, suggest **workarounds** (direct pointer comparisons, restructured control flow, etc.)

## Important Notes

- PREVAIL is **more conservative** than the Linux kernel verifier — code accepted by Linux may be rejected by PREVAIL.
- PREVAIL is **path-insensitive** — it uses a single abstract state per program point, so correlated conditions across branches may be lost.
- **Widening** at loop headers can destroy constraints — if a loop-related failure occurs, check whether widening eliminated a needed bound.
- Never assume a register has a type or constraint unless it appears in the pre-invariant.
