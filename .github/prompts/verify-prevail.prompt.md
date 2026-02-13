---
mode: agent
description: >
  Diagnose eBPF program verification failures from the PREVAIL verifier for
  linux-compatible programs. For Windows-specific BPF programs (bpf2c pipeline,
  Windows helpers), use the 'verify-bpf' skill instead.
---

## Tools

- `run_in_terminal`: Execute PREVAIL `check` or `run_yaml` tools to verify programs
- `read_file`: Examine BPF source files, YAML test data, verifier output, and diagnostic reference
- `replace_string_in_file`: Make targeted fixes to BPF C source or YAML test cases
- `grep_search`: Search for error patterns, register states, and type definitions
- `list_dir`: Navigate project structure when needed

## Scope

This skill is for **linux-compatible** eBPF programs verified in the standalone PREVAIL
repo (`external/ebpf-verifier`). It covers:
- PREVAIL YAML test failures and abstract-interpretation debugging
- Verifier internal issues (abstract domains, widening, transformers)
- Linux-compatible BPF programs that don't use Windows-specific features

For **Windows-specific** BPF programs that use the bpf2c pipeline, Windows helpers,
or ebpf-for-windows headers, use the **`verify-bpf`** skill instead.

## Instructions

Read the full diagnostic reference before proceeding:

```
.github/skills/verify-prevail/SKILL.md
```

Follow the instructions in that file for gathering verifier errors, identifying failure patterns, tracing root causes, and recommending fixes. That file is the authoritative reference for PREVAIL verification diagnosis.
