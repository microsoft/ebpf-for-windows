# eBPF for Windows sock_addr Bind Hook

## Contents

- [eBPF for Windows sock\_addr Bind Hook](#ebpf-for-windows-sock_addr-bind-hook)
  - [Contents](#contents)
  - [Purpose](#purpose)
  - [Relationship to the Legacy Bind Hook](#relationship-to-the-legacy-bind-hook)
  - [Design Rationale](#design-rationale)
  - [eBPF Design](#ebpf-design)
    - [Program Type](#program-type)
    - [Attach Types](#attach-types)
    - [Context Structure](#context-structure)
    - [Return Values](#return-values)
  - [Architecture](#architecture)
    - [Hook Integration and Flow](#hook-integration-and-flow)
    - [WFP Layer Integration](#wfp-layer-integration)
    - [Coexistence with the Legacy Bind Hook](#coexistence-with-the-legacy-bind-hook)
  - [Helper Function Support](#helper-function-support)
  - [Example eBPF Program](#example-ebpf-program)
  - [Linux Compatibility](#linux-compatibility)
    - [Aligned](#aligned)
    - [Divergences](#divergences)

---

## Purpose

Provide a cross-platform eBPF interface for intercepting socket `bind()` operations on
Windows that mirrors Linux's `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` with `BPF_CGROUP_INET4_BIND`
/ `BPF_CGROUP_INET6_BIND` attach types. This enables eBPF programs written for Linux
(using `cgroup/bind4` / `cgroup/bind6` ELF section names and the `bpf_sock_addr` context)
to run on Windows without source modifications.

Programs attached to these hooks can:

- Inspect the local address, port, protocol, compartment, and interface for each bind
- Allow or deny the bind operation
- Retrieve process and user information via helper functions

This addresses [issue #333](https://github.com/microsoft/ebpf-for-windows/issues/333) and
the multi-attach requirement from [issue #5180](https://github.com/microsoft/ebpf-for-windows/issues/5180).

## Relationship to the Legacy Bind Hook

eBPF for Windows continues to support the legacy `EBPF_PROGRAM_TYPE_BIND` /
`EBPF_ATTACH_TYPE_BIND` hook with the Windows-specific `bind_md_t` context. Existing
programs that use the legacy hook continue to work without changes — the legacy hook
and the new sock_addr-aligned bind hook coexist at the same WFP layers.

| Aspect | Legacy bind hook | New sock_addr bind hook |
|---|---|---|
| Program type | `BPF_PROG_TYPE_BIND` | `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` |
| Attach type | `BPF_ATTACH_TYPE_BIND` (one) | `BPF_CGROUP_INET4_BIND` / `BPF_CGROUP_INET6_BIND` |
| Context | `bind_md_t` (Windows-specific) | `bpf_sock_addr_t` (Linux-compatible) |
| ELF section | n/a (Windows-only) | `cgroup/bind4` / `cgroup/bind6` |
| Multi-attach | No (single attach) | Yes (`MULTI_ATTACH_WITH_WILDCARD`) |
| Verdicts | `bind_action_t` (PERMIT_SOFT/HARD, DENY, REDIRECT) | `ebpf_sock_addr_verdict_t` (PROCEED_SOFT/HARD, REJECT) |
| Address modification | Declared via `BIND_REDIRECT` but not actually enforced by WFP | Not supported |
| Release / unbind notifications | Yes (`BIND_OPERATION_UNBIND`) | No |

Choose the legacy hook when you need release/unbind notifications or are extending an
existing Windows-specific program. Choose the new sock_addr-aligned hook for any new
work, especially when cross-platform compatibility with Linux is desired.

## Design Rationale

Linux exposes bind operations through `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` with
`BPF_CGROUP_INET4_BIND` / `BPF_CGROUP_INET6_BIND` attach types. This work adds the
matching attach types to the existing `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` implementation
on Windows, following the same pattern used for connect, recv_accept, and
connect_authorization.

## eBPF Design

### Program Type

The bind hook uses the existing **`BPF_PROG_TYPE_CGROUP_SOCK_ADDR`** program type.

### Attach Types

Two attach types are added to the `bpf_attach_type` enum:

```c
// Added to bpf_attach_type enum:
BPF_CGROUP_INET4_BIND,  ///< IPv4 socket bind operations
BPF_CGROUP_INET6_BIND,  ///< IPv6 socket bind operations
```

Each attach type has a corresponding GUID identifier:

```c
#define EBPF_ATTACH_TYPE_CGROUP_INET4_BIND_GUID                                        \
    {                                                                                  \
        0x0d7ce21a, 0x7773, 0x405c, { 0x93, 0xb6, 0xd5, 0xbf, 0xb9, 0x2e, 0x74, 0xbc } \
    }
__declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_CGROUP_INET4_BIND =
    EBPF_ATTACH_TYPE_CGROUP_INET4_BIND_GUID;

#define EBPF_ATTACH_TYPE_CGROUP_INET6_BIND_GUID                                        \
    {                                                                                  \
        0x81de64c0, 0x2973, 0x468d, { 0x83, 0x82, 0x67, 0x69, 0xf0, 0x33, 0xd7, 0x59 } \
    }
__declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_CGROUP_INET6_BIND =
    EBPF_ATTACH_TYPE_CGROUP_INET6_BIND_GUID;
```

Programs are loaded by section name using the standard Linux conventions:

- `SEC("cgroup/bind4")` → `BPF_CGROUP_INET4_BIND`
- `SEC("cgroup/bind6")` → `BPF_CGROUP_INET6_BIND`

### Context Structure

The bind hook uses the existing `bpf_sock_addr_t` context (unchanged):

```c
typedef struct bpf_sock_addr
{
    uint32_t family;         ///< IP address family (AF_INET or AF_INET6).
    struct {
        union { uint32_t msg_src_ip4; uint32_t msg_src_ip6[4]; };
        uint16_t msg_src_port;
    };
    struct {
        union { uint32_t user_ip4; uint32_t user_ip6[4]; };
        uint16_t user_port;
    };
    uint32_t protocol;
    uint32_t compartment_id;
    uint64_t interface_luid;
} bpf_sock_addr_t;
```

For bind operations, fields are populated as follows:

| Field | Value for bind |
|---|---|
| `family` | `AF_INET` (v4) or `AF_INET6` (v6) |
| `user_ip4` / `user_ip6` | Local IP being bound to (network byte order) |
| `user_port` | Local port being bound to (network byte order) |
| `msg_src_ip4` / `msg_src_ip6` | `0` — no remote endpoint at bind layer |
| `msg_src_port` | `0` — no remote endpoint at bind layer |
| `protocol` | IP protocol (e.g., `IPPROTO_TCP`, `IPPROTO_UDP`) |
| `compartment_id` | Network compartment ID |
| `interface_luid` | Local interface LUID |

### Return Values

The bind hook uses the existing `ebpf_sock_addr_verdict_t` return values:

```c
typedef enum _ebpf_sock_addr_verdict
{
    BPF_SOCK_ADDR_VERDICT_REJECT = 0,       ///< Block the bind operation.
    BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT = 1, ///< Allow with soft permit (can be overridden).
    BPF_SOCK_ADDR_VERDICT_PROCEED_HARD = 2  ///< Allow with hard permit (cannot be overridden).
} ebpf_sock_addr_verdict_t;
```

When multiple bind programs are attached, the verdicts are combined: if any program
rejects, the bind is blocked.

## Architecture

### Hook Integration and Flow

1. **Application bind request**: Application calls `bind()` on a socket
2. **WFP interception**: WFP `ALE_RESOURCE_ASSIGNMENT` layer intercepts the operation
3. **eBPF invocation**: Registered eBPF programs are invoked with the `bpf_sock_addr_t` context
4. **Program execution**: Each program inspects the context and returns a verdict
5. **Action processing**: WFP processes the verdict and allows or blocks the bind

```
Application
    |
    | bind()
    v
Windows Socket Layer
    |
    | WFP ALE_RESOURCE_ASSIGNMENT callout
    v
sock_addr Bind Hook (this hook)         Legacy Bind Hook (independent)
    |                                           |
    | bpf_sock_addr_t context                   | bind_md_t context
    v                                           v
CGROUP_SOCK_ADDR eBPF Program(s)         EBPF_PROGRAM_TYPE_BIND program (single)
    |                                           |
    | BPF_SOCK_ADDR_VERDICT_*                   | bind_action_t
    v                                           v
        WFP Action Processing (both verdicts must allow for bind to succeed)
    |
    | Allow / Block
    v
Socket Operation Result
```

### WFP Layer Integration

The sock_addr bind hook integrates with the WFP ALE Resource Assignment layers:

- **`FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4`** — IPv4 bind operations
- **`FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6`** — IPv6 bind operations

### Coexistence with the Legacy Bind Hook

Both hooks register filters at the same `ALE_RESOURCE_ASSIGNMENT` layers but use
distinct WFP callout GUIDs, so WFP invokes each filter's bound callout independently.
If both a legacy bind program and a sock_addr bind program are attached, both run for
each bind, and the bind succeeds only if both allow it.

## Helper Function Support

Bind programs can use the following helpers in addition to standard map and
control-flow helpers:

| Helper | Behavior at bind |
|---|---|
| `bpf_get_current_pid_tgid` | Returns the bind caller's PID/TID |
| `bpf_get_current_logon_id` | Returns the logon session ID |
| `bpf_is_current_admin` | Returns whether the caller has Administrator privileges |
| `bpf_get_socket_cookie` | Returns a socket cookie |
| `bpf_sock_addr_get_network_context` | Returns interface metadata; `interface_type` and `tunnel_type` are available; `next_hop_interface_luid` and `sub_interface_index` are not available at the bind layer and are returned as their unspecified defaults |
| `bpf_sock_addr_set_redirect_context` | **Not supported** at the bind layer — returns `-1` |

## Example eBPF Program

```c
// SPDX-License-Identifier: MIT
#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

typedef struct _bind_deny_key
{
    uint16_t port;
    uint8_t  protocol;
    uint8_t  pad;
} bind_deny_key_t;

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, bind_deny_key_t);
    __type(value, uint32_t);
    __uint(max_entries, 256);
} bind_deny_map SEC(".maps");

__inline int
authorize_bind(bpf_sock_addr_t* ctx)
{
    bind_deny_key_t key = {0};
    key.port = (uint16_t)ctx->user_port;
    key.protocol = (uint8_t)ctx->protocol;

    uint32_t* deny = bpf_map_lookup_elem(&bind_deny_map, &key);
    if (deny != NULL && *deny != 0) {
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }
    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}

SEC("cgroup/bind4")
int authorize_bind4(bpf_sock_addr_t* ctx) { return authorize_bind(ctx); }

SEC("cgroup/bind6")
int authorize_bind6(bpf_sock_addr_t* ctx) { return authorize_bind(ctx); }
```

A complete working sample is available at `tests/sample/cgroup_sock_addr_bind.c`.

## Linux Compatibility

This section documents alignment with and divergences from the Linux
`BPF_CGROUP_INET4_BIND` / `BPF_CGROUP_INET6_BIND` implementation.

### Aligned

| Aspect | Details |
|---|---|
| Program type | `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` (same as Linux) |
| Attach type names | `BPF_CGROUP_INET4_BIND` / `BPF_CGROUP_INET6_BIND` (same as Linux) |
| Context structure | `bpf_sock_addr` / `bpf_sock_addr_t` with same field names |
| Field semantics | `user_*` contains the local bind address/port (matches Linux) |
| ELF section names | `cgroup/bind4` / `cgroup/bind6` |

### Divergences

The following divergences are pre-existing characteristics of the Windows `bpf_sock_addr`
shared by all sock_addr hooks; they are not specific to the bind hook.

| Aspect | Linux | Windows | Reason |
|---|---|---|---|
| Port field type | `__u32` | `uint16_t` | Pre-existing Windows design choice |
| `type` field | Present (`SOCK_STREAM`, etc.) | Absent | Not available from WFP |
| `sk` field | Present (socket pointer) | Absent | Kernel-internal, not exposed |
| `compartment_id` | Absent | Present | Windows networking concept |
| `interface_luid` | Absent | Present | Windows networking concept |
| `msg_src_*` for bind | Mirrors local address | Zero | Bind has no remote endpoint; zeroing is unambiguous |
| Return values | `0` (deny) / `1` (allow) | 3-value verdict enum (`PROCEED_SOFT`, `PROCEED_HARD`, `REJECT`) | Pre-existing Windows design choice |
| Address rewriting | Supported (program may modify `user_*`) | Not supported (modifications are silently ignored) | WFP `ALE_RESOURCE_ASSIGNMENT` rewrite not implemented |

Programs that access `user_ip4`, `user_port`, `family`, and `protocol` and return only
allow/deny verdicts are portable between Linux and Windows bind hooks.
