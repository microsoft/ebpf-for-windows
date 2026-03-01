# ebpf_mcp — eBPF Verifier MCP Server

An [MCP](https://modelcontextprotocol.io/) (Model Context Protocol) server that
exposes the PREVAIL eBPF verifier's analysis results as structured, queryable
tools for LLM agents. Works with both passing and failing programs — agents can
diagnose verification errors, inspect invariants, trace register state evolution,
and formally verify safety properties.

## Prerequisites

- Build the ebpf-for-windows solution (Debug or Release configuration)
- Run `export_program_info.exe` to populate the eBPF program type registry (same requirement as bpf2c)
- ELF files to analyze (compiled with `clang -g -target bpf` for source mapping)

## Building

```powershell
msbuild ebpf-for-windows.sln /m /p:Configuration=Debug /p:Platform=x64 /t:tools\prevail_mcp
```

Output: `x64\Debug\ebpf_mcp.exe`

## VS Code Integration

The server is configured in `.vscode/mcp.json`. It starts automatically when VS Code/Copilot needs it.

## Copilot CLI Integration

Copilot CLI uses a user-level config file to discover MCP servers. Add the
`ebpf-verifier` server to `~/.copilot/mcp-config.json`:

```json
{
  "mcpServers": {
    "ebpf-verifier": {
      "type": "stdio",
      "command": "C:/path/to/ebpf-for-windows/x64/Debug/ebpf_mcp.exe",
      "args": []
    }
  }
}
```

Replace the path with the absolute path to your built `ebpf_mcp.exe`. Use
forward slashes in the path.

After editing the config, restart Copilot CLI (`ghcs` or reopen the terminal).
The `ebpf-verifier` tools will then be available in all sessions.

> **Note**: There is currently no way to have Copilot CLI automatically pick up
> MCP server configs from a repo-level file (like `.vscode/mcp.json`). The
> user-level `~/.copilot/mcp-config.json` is required.

## Tools

| Tool | Description |
|------|-------------|
| `list_programs` | List all eBPF programs (sections/functions) in an ELF file |
| `verify_program` | Run verification — pass/fail, error count, exit value range, stats |
| `get_slice` | Backward slice from error or any PC with register relevance, pre-invariant, assertions, source line |
| `get_errors` | All verification errors with pre-invariants and unreachable code |
| `get_invariant` | Pre/post abstract state at one or more instructions |
| `get_instruction` | Full detail: text, assertions, pre/post invariants, source, CFG neighbors |
| `get_disassembly` | Instruction listing with source annotations (supports PC range) |
| `get_cfg` | Control-flow graph (JSON basic blocks or Graphviz DOT) |
| `get_source_mapping` | Bidirectional C source ↔ BPF instruction mapping |
| `check_constraint` | Test hypotheses: consistent, proven, or entailed modes; batch support |

### Common Parameters

All tools that accept `section` and `program` also accept `program_type` to
override the type inferred from the ELF section name (e.g., `"program_type": "xdp"`).
This matches bpf2c's `--type` flag.

### Diagnostic Workflow

For failure diagnosis, `get_slice` with `trace_depth=10` is usually
sufficient in a single call. It returns the error message, pre-invariant,
assertions, source line, and a failure slice showing how each register reached
its current state.

These tools map to the [PREVAIL LLM diagnostic protocol](../../external/ebpf-verifier/docs/llm-context.md):

| Protocol Step | Tool |
|---|---|
| 1. Identify error | `verify_program` or `get_errors` |
| 2. Pre-invariant at error | `get_slice` (includes failure slice) |
| 3. Trace the register | Read pre-invariant constraints from `get_slice` |
| 4. Test hypotheses | `check_constraint` with `mode="proven"` or `mode="consistent"` |
| 5. Compare states | `get_instruction` or `get_invariant` at multiple PCs |
| 6. Formulate fix | Agent reasoning + source from `get_source_mapping` |

### check_constraint Modes

| Mode | Question | Semantics |
|------|----------|-----------|
| `consistent` | Could this be true? | `A ∩ C ≠ ⊥` — not contradicted by the invariant |
| `proven` | Is this definitely true? | `A ⊆ C` — the invariant guarantees the constraint |
| `entailed` | Is this a sub-state? | `C ⊆ A` — rarely needed outside testing |

The response always includes the invariant at the queried point, so agents can
see exactly what the verifier knows.

**Batch mode**: Pass a `checks` array to test multiple hypotheses in a single call
(runs analysis once):

```json
{
  "elf_path": "x64/Debug/myprogram.o",
  "checks": [
    { "pc": 9,  "constraints": ["r6.type=packet"], "mode": "proven" },
    { "pc": 11, "constraints": ["r6.type=packet"], "mode": "proven" }
  ]
}
```

### Caching

- **Serialized sessions**: An LRU cache (8 entries) stores the serialized
  analysis result for each ELF/section/program/type combination. Tools like
  `get_invariant`, `get_instruction`, `get_errors`, etc. reuse cached sessions.
- **Live session**: `check_constraint` keeps the most recent `AnalysisResult`
  alive with its thread-local state, so consecutive constraint checks on the
  same program skip re-analysis entirely.

## Examples

See [mcp_query_examples.md](mcp_query_examples.md) for natural-language queries
with responses, and [mcp_tool_examples.md](mcp_tool_examples.md) for raw tool
call examples with JSON output.

## Architecture

```
external/ebpf-verifier/src/main/mcp/  ← Core MCP server (from PREVAIL submodule)
  mcp_transport  — JSON-RPC 2.0 over stdio
  mcp_server     — Tool registry and dispatch
  analysis_engine — PREVAIL pipeline runner with LRU + live session cache
  json_serializers — PREVAIL types → JSON
  tools          — All 10 tool implementations
  platform_ops   — Abstract platform interface
src/windows/     ← Platform layer (Windows-specific)
  main.cpp       — Entry point, g_ebpf_platform_windows setup
  platform_ops_windows — Windows PlatformOps implementation
```

The server uses `g_ebpf_platform_windows` (same as bpf2c), so verification
results match bpf2c exactly. The `proven` check mode is implemented in the MCP
layer using `EbpfDomain::operator<=` against the live analysis result.
