---
mode: agent
description: "Build and test the PREVAIL verifier standalone. Use when asked to build, test, or iterate on the PREVAIL verifier or run YAML verification tests."
---

## Tools

- `run_in_terminal`: Execute cmake build and test commands
- `get_errors`: Retrieve compilation errors and warnings from VS Code
- `read_file`: Examine verifier source files, YAML tests, and test output
- `replace_string_in_file`: Make targeted fixes to verifier code or YAML tests
- `grep_search`: Search for test patterns, verifier logic, and error messages
- `list_dir`: Navigate external/ebpf-verifier/ directory structure

## Instructions

Read the full build and test reference before proceeding:

```
.github/skills/build-prevail/SKILL.md
```

Follow the instructions in that file for building with cmake, running YAML tests, and iterating on verifier changes. That file is the authoritative reference for standalone PREVAIL verifier development.
