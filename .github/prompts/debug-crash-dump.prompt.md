---
mode: agent
description: "Download and analyze crash dumps from CI failures using CDB/WinDbg. Use when asked to debug crashes, analyze dump files, or investigate fault injection failures."
---

## Tools

- `run_in_terminal`: Execute gh, CDB, and mcp-windbg commands
- `read_file`: Examine dump analysis output and build configuration
- `list_dir`: Navigate crash dump and build artifact directories

## Instructions

Read the full crash dump debugging reference before proceeding:

```
.github/skills/debug-crash-dump/SKILL.md
```

Follow the instructions in that file for downloading artifacts, setting up CDB, analyzing dumps, and running mcp-windbg. That file is the authoritative reference for all crash dump debugging operations.
