<!-- Copyright (c) eBPF for Windows contributors -->
<!-- SPDX-License-Identifier: MIT -->

# Copilot Workflows

This directory contains structured workflows for use with GitHub Copilot
(or any LLM agent with tool access). Each workflow is a self-contained
prompt that defines an identity, reasoning protocols, and a multi-phase
task for the agent to execute interactively.

## How to Use

Ask the agent to read and execute the workflow file:

```
Read and execute the spec-extraction-workflow in the workflows directory.
```

The workflows are interactive — they include human review gates and will
pause for confirmation before advancing between phases.

## Available Workflows

| Workflow | When to Use |
|----------|------------|
| **spec-extraction-workflow.md** | Bootstrapping specs for a module that has code but no formal requirements, design, or validation documents. Extracts structured specs from the codebase. |
| **engineering-workflow.md** | Making changes to a module that already has specs. Guides incremental development from requirements through implementation with audit gates. |
| **maintenance-workflow.md** | Periodic health checks. Detects drift between specs and implementation, classifies findings, and generates corrective patches. |

## Typical Order

1. **spec-extraction** — run first on a module to create the initial baseline.
2. **engineering** — run when making changes to a module with existing specs.
3. **maintenance** — run periodically to catch spec/code drift.
