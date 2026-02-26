# prevail_mcp — PREVAIL Verifier MCP Server

An MCP (Model Context Protocol) server that exposes the PREVAIL eBPF verifier's analysis results as structured, queryable tools for LLM agents.

## Prerequisites

- Build the ebpf-for-windows solution (Debug or Release configuration)
- Run `export_program_info.exe` to populate the eBPF program type registry (same requirement as bpf2c)
- ELF files to analyze (compiled with `clang -g -target bpf`)

## Building

```powershell
msbuild ebpf-for-windows.sln /m /p:Configuration=Debug /p:Platform=x64 /t:tools\prevail_mcp
```

Output: `x64\Debug\prevail_mcp.exe`

## VS Code Integration

The server is configured in `.vscode/mcp.json`. It starts automatically when VS Code/Copilot needs it.

## Copilot CLI Integration

Copilot CLI uses a user-level config file to discover MCP servers. Add the
`prevail-verifier` server to `~/.copilot/mcp-config.json`:

```json
{
  "mcpServers": {
    "prevail-verifier": {
      "type": "stdio",
      "command": "C:/path/to/ebpf-for-windows/x64/Debug/prevail_mcp.exe",
      "args": []
    }
  }
}
```

Replace the path with the absolute path to your built `prevail_mcp.exe`. Use
forward slashes in the path.

After editing the config, restart Copilot CLI (`ghcs` or reopen the terminal).
The `prevail-verifier` tools will then be available in all sessions.

> **Note**: There is currently no way to have Copilot CLI automatically pick up
> MCP server configs from a repo-level file (like `.vscode/mcp.json`). The
> user-level `~/.copilot/mcp-config.json` is required.

## Tools

| Tool | Description |
|------|-------------|
| `list_programs` | List all eBPF programs (sections/functions) in an ELF file |
| `verify_program` | Run verification, get pass/fail summary with error count and stats |
| `get_invariant` | Get pre/post abstract state (register types, value ranges, constraints) at a specific instruction |
| `get_instruction` | Full detail for one instruction: text, assertions, invariants, source mapping, CFG neighbors |
| `get_errors` | All verification errors with pre-invariants, source lines, and unreachable code |
| `get_cfg` | Control-flow graph as JSON basic blocks or Graphviz DOT |
| `get_source_mapping` | Bidirectional C source ↔ BPF instruction mapping (requires `-g` compilation) |
| `check_constraint` | Test if constraints are consistent with or entailed by the verifier's state |
| `get_error_context` | Error or instruction with backward trace showing preceding instructions and constraint evolution |
| `get_disassembly` | Disassembly listing for a range of instructions with source lines |

### Diagnostic Workflow

These tools map directly to the [PREVAIL LLM diagnostic protocol](../../external/ebpf-verifier/docs/llm-context.md):

| Protocol Step | Tool |
|---|---|
| 1. Identify error | `verify_program` or `get_errors` |
| 2. Pre-invariant at error | `get_error_context` |
| 3. Trace the register | Read pre-invariant constraints from `get_error_context` |
| 4. Identify missing constraints | Agent reasons; `check_constraint` to test hypotheses |
| 5. Trace backwards | `get_error_context` backward trace; `get_instruction` for deeper dives |
| 6. Formulate fix | Agent reasoning + source from `get_source_mapping` |

## Architecture

```
src/core/        ← Core MCP server and verification logic
  mcp_transport  — JSON-RPC 2.0 over stdio
  mcp_server     — Tool registry and dispatch
  analysis_engine — PREVAIL pipeline runner with LRU cache
  json_serializers — PREVAIL types → JSON (delegates to operator<< / to_set())
  tools          — All 10 tool implementations
src/windows/     ← Platform layer (Windows-specific)
  main.cpp       — Entry point, g_ebpf_platform_windows setup
```
