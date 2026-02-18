---
mode: agent
description: >
  Build and verify eBPF programs for the ebpf-for-windows project.
  Use when asked to compile a .c BPF source to .o, verify a .o ELF file
  with bpf2c, or diagnose verification failures.
---

## Tools

- `run_in_terminal`: Execute clang and bpf2c commands and capture output
- `get_errors`: Retrieve compilation errors and warnings from VS Code
- `read_file`: Examine BPF source files, verifier output, and diagnostic reference
- `replace_string_in_file`: Make targeted fixes to BPF C source
- `grep_search`: Search for error patterns, helper definitions, and type information
- `list_dir`: Navigate project structure when needed

## Instructions

Read the full build and verification reference before proceeding:

```
.github/skills/verify-bpf/SKILL.md
```

Follow the instructions in that file for compiling BPF programs with clang, verifying with bpf2c, and diagnosing verification failures. That file is the authoritative reference for the clang→bpf2c pipeline.
