# eBPF Latency MCP Server

An **MCP (Model Context Protocol)** server that ingests eBPF latency ETL trace files and exposes structured query tools via **JSON-RPC 2.0 over stdin/stdout**. Designed to be used with VS Code Copilot (or any MCP client) for interactive latency analysis.

## Overview

Instead of using `netsh ebpf show latencytrace` to get a static text report, this MCP server loads the ETL file into memory, builds indexes, and lets Copilot query the data conversationally:

- "Show me the latency summary for this trace"
- "What's the P99.9 latency for program 3?"
- "Find the P99 invocation of program 7 and show me all the map operations it did"
- "List all programs in this trace"

## Building

```powershell
# From the tools/mcp-latency-server directory
cl /EHsc /std:c++17 /O2 ebpf_latency_mcp_server.cpp /link tdh.lib advapi32.lib
```

Or add the project to the Visual Studio solution.

## VS Code Configuration

Add to your workspace `.vscode/mcp.json`:

```json
{
    "servers": {
        "ebpf-latency": {
            "type": "stdio",
            "command": "path/to/ebpf_latency_mcp_server.exe",
            "args": []
        }
    }
}
```

## Tools Exposed

### 1. `load_etl` — Ingest an ETL file

Loads and indexes all eBPF latency events from an ETL file. Must be called before any queries.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | string | Yes | Absolute path to the `.etl` file |

**Returns:** Load summary (event counts, trace duration, unique programs).

---

### 2. `unload` — Release a loaded trace

Frees the in-memory data for a previously loaded trace.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | string | Yes | Path of the loaded `.etl` file |

---

### 3. `list_programs` — List all programs in the trace

Returns all program IDs, names, invocation counts, and helper event counts.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | string | Yes | Path of the loaded `.etl` file |

---

### 4. `get_summary` — Full trace summary (equivalent to `netsh ebpf show latencytrace`)

Returns the same information as the netsh table report: per-program invocation statistics (count, avg, P50, P90, P95, P99, P99.9, max) and per-helper statistics grouped by program.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | string | Yes | Path of the loaded `.etl` file |

**Example query:** "Show me the latency summary for this trace"

---

### 5. `get_program_summary` — Detailed stats for one program

Returns all percentile statistics for a specific program ID, plus its helper function breakdown.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | string | Yes | Path of the loaded `.etl` file |
| `program_id` | integer | Yes | The eBPF program ID to query |

**Example query:** "What are the latency numbers for program 3?"

---

### 6. `get_helper_summary` — Map helper stats for a program

Returns latency statistics for map helper functions, optionally filtered to a specific helper.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | string | Yes | Path of the loaded `.etl` file |
| `program_id` | integer | Yes | The eBPF program ID |
| `helper_function_id` | integer | No | Filter to a specific BPF_FUNC_xxx ID |

---

### 7. `get_percentile_instance` — Find the invocation at a percentile

Finds the **specific program invocation event** at a given latency percentile (e.g., P99, P99.9). Returns the full event record including timestamps, thread ID, CPU, and duration.

Use the returned `start_time` and `end_time` with `get_correlated_map_helpers` to drill down into what map operations contributed to that invocation's latency.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | string | Yes | Path of the loaded `.etl` file |
| `program_id` | integer | Yes | The eBPF program ID |
| `percentile` | number | Yes | Percentile value (0-100), e.g. 99 for P99, 99.9 for P99.9 |

**Example query:** "Find the P99 invocation of program 3"

---

### 8. `get_program_events` — Browse raw invocation events

Lists program invocation events with pagination and sorting. Useful for finding outliers or browsing raw data.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | string | Yes | Path of the loaded `.etl` file |
| `program_id` | integer | Yes | The eBPF program ID |
| `sort_by` | string | No | `"duration"` or `"time"` (default: `"time"`) |
| `order` | string | No | `"asc"` or `"desc"` (default: `"asc"`) |
| `offset` | integer | No | Pagination offset (default: 0) |
| `limit` | integer | No | Max events to return, up to 1000 (default: 100) |

**Example query:** "Show me the top 10 slowest invocations of program 7"

---

### 9. `get_correlated_map_helpers` — Find map helpers within an invocation

Given a program invocation's time window (`start_time`, `end_time`) and `program_id`, finds all map helper calls that executed within that invocation. This is the key drill-down tool: start from a percentile instance, then see exactly which map operations ran.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | string | Yes | Path of the loaded `.etl` file |
| `program_id` | integer | Yes | The eBPF program ID |
| `start_time` | integer | Yes | Program invocation `start_time` (from event record) |
| `end_time` | integer | Yes | Program invocation `end_time` (from event record) |
| `thread_id` | integer | No | Optional: filter to a specific thread ID for exact matching |

**Returns:** List of correlated helper events, total helper duration, and comparison with program duration.

**Example query:** "Find the map operations for the P99 invocation of program 3"

## Example Conversation

```
User: Load the trace file c:\traces\ebpf_latency.etl

Copilot: [calls load_etl with file_path="c:\traces\ebpf_latency.etl"]
  Loaded 1,423,891 events (847,291 program invocations, 576,600 map helpers)
  across 2 programs over 30.2 seconds.

User: What are the latency numbers?

Copilot: [calls get_summary]
  Program 3 ("xdp_filter"): 847,291 invocations
    Avg: 2,340 ns | P50: 2,100 ns | P99: 5,200 ns | P99.9: 8,400 ns | Max: 12,400 ns

  Program 7 ("socket_filter"): 112,456 invocations
    Avg: 1,890 ns | P50: 1,750 ns | P99: 4,100 ns | P99.9: 6,800 ns | Max: 9,800 ns

User: Find the P99 invocation of program 3 and show me what map ops it did

Copilot: [calls get_percentile_instance with program_id=3, percentile=99]
  The P99 invocation (rank 838,818 of 847,291):
    Duration: 5,200 ns | Thread: 4812 | CPU: 3
    StartTime: 1823847291000 | EndTime: 1823847343200

  [calls get_correlated_map_helpers with program_id=3, start_time=..., end_time=...]
  This invocation made 3 map helper calls:
    1. map_lookup_elem on "conn_table": 1,100 ns
    2. map_lookup_elem on "policy_map": 800 ns
    3. map_update_elem on "stats_map": 1,500 ns
  Total helper time: 3,400 ns (65% of invocation)

User: What about P99.9?

Copilot: [calls get_percentile_instance with program_id=3, percentile=99.9]
  ...
```

## Usage with VS Code Copilot

### Prerequisites

1. **Build the MCP server** (see [Building](#building) above).
2. **Capture an ETL trace** with eBPF latency events enabled:

```powershell
# Enable latency tracking (all programs, program + map helpers)
netsh ebpf set latency mode=all

# Or filter to specific programs
netsh ebpf set latency mode=all programs=3,7

# Start the ETW trace session
netsh ebpf start latencytrace file=c:\traces\ebpf_latency.etl buffersize=256

# ... run your workload ...

# Stop the trace
netsh ebpf stop latencytrace

# Disable latency tracking
netsh ebpf set latency mode=off
```

### Step 1: Register the MCP Server in VS Code

Add the server to your workspace's `.vscode/mcp.json` (create the file if it doesn't exist):

```json
{
    "servers": {
        "ebpf-latency": {
            "type": "stdio",
            "command": "d:/git/github/ebpf-for-windows/x64/Debug/ebpf_latency_mcp_server.exe",
            "args": []
        }
    }
}
```

Adjust the path to point to wherever you built the executable. VS Code will automatically start the MCP server process when Copilot needs it.

### Step 2: Chat with Copilot

Open **GitHub Copilot Chat** (Ctrl+Shift+I or the Copilot sidebar) and use **Agent mode** (`@workspace` is not needed — MCP tools are available automatically in Agent mode). You can ask natural-language questions and Copilot will call the appropriate MCP tools behind the scenes.

### Step 3: Example Conversations

**Loading a trace and getting an overview:**

> **You:** Load the trace file `c:\traces\ebpf_latency.etl` and give me a summary.
>
> **Copilot:** *(calls `load_etl` → then `get_summary`)*
> Loaded 1,423,891 events across 2 programs over 30.2 seconds.
>
> | Program ID | Invocations | Avg (ns) | P50 (ns) | P99 (ns) | P99.9 (ns) | Max (ns) |
> |------------|-------------|----------|----------|----------|------------|----------|
> | 3          | 847,291     | 2,340    | 2,100    | 5,200    | 8,400      | 12,400   |
> | 7          | 112,456     | 1,890    | 1,750    | 4,100    | 6,800      | 9,800    |

**Drilling into a specific program:**

> **You:** What's the P99.9 latency for program 3? Show me the details.
>
> **Copilot:** *(calls `get_program_summary` with program_id=3)*
> Program 3 has 847,291 invocations. The P99.9 latency is **8,400 ns**.
> Its map helper breakdown shows `map_lookup_elem` averaging 680 ns and `map_update_elem` averaging 920 ns.

**Finding and analyzing a tail-latency invocation:**

> **You:** Find the P99 invocation of program 3 and show me what map operations it did.
>
> **Copilot:** *(calls `get_percentile_instance` with program_id=3, percentile=99)*
> The P99 invocation (rank 838,818 of 847,291):
> - Duration: 5,200 ns
> - Thread: 4812, CPU: 3
> - StartTime: 1823847291000, EndTime: 1823847343200
>
> *(calls `get_correlated_map_helpers` with the start/end times)*
> This invocation made 3 map helper calls:
> 1. `map_lookup_elem` on "conn_table": 1,100 ns
> 2. `map_lookup_elem` on "policy_map": 800 ns
> 3. `map_update_elem` on "stats_map": 1,500 ns
>
> Total helper time: 3,400 ns (65% of invocation duration).

**Browsing raw events:**

> **You:** Show me the top 10 slowest invocations of program 7.
>
> **Copilot:** *(calls `get_program_events` with program_id=7, sort_by="duration", order="desc", limit=10)*
> *(displays a table of the 10 slowest invocations with timestamps, durations, thread/CPU info)*

### Tips

- **Start with `load_etl`**: The server keeps trace data in memory. Always load the ETL file first before querying.
- **Multiple traces**: You can load multiple ETL files simultaneously and query them independently by specifying different `file_path` values.
- **Tool chaining**: Copilot automatically chains tools together. Ask high-level questions like *"Why is the P99.9 so high for program 3?"* and Copilot will call `get_percentile_instance` followed by `get_correlated_map_helpers` to give you the full picture.
- **Unload when done**: Call `unload` (or just ask *"unload the trace"*) to free memory when you're finished analyzing a trace.
- **Stderr diagnostics**: The MCP server logs diagnostic messages to stderr, visible in the VS Code Output panel under the MCP server entry.

---

## Protocol Details

- **Transport:** stdin/stdout, newline-delimited JSON-RPC 2.0
- **MCP Version:** 2024-11-05
- **Capabilities:** tools (listChanged: false)
- **Diagnostics:** Logged to stderr
