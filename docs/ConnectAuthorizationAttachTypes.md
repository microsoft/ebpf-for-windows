# CONNECT_AUTHORIZATION Attach Types

## Overview

This document explains the purpose and rationale behind the `BPF_CGROUP_INET4_CONNECT_AUTHORIZATION` and `BPF_CGROUP_INET6_CONNECT_AUTHORIZATION` attach types that were added to eBPF for Windows.

## Background

eBPF for Windows already supports several attach types for socket address operations:

- `BPF_CGROUP_INET4_CONNECT` / `BPF_CGROUP_INET6_CONNECT` - Inspect outbound connections, with the capability to modify the destination address or port (redirection). Invoked at the redirect layer before route selection.
- `BPF_CGROUP_INET4_RECV_ACCEPT` / `BPF_CGROUP_INET6_RECV_ACCEPT` - Inspect inbound connections on receive/accept and allow or reject them.

However, there was a gap in functionality that required the addition of new attach points.

**Implementation Note:** CONNECT and CONNECT_AUTHORIZATION attach types are implemented as WFP callouts in the connect-redirect and auth_connect layers, respectively, providing deep integration with the Windows Filtering Platform.

## Problem Statement

The existing `BPF_CGROUP_INET4_CONNECT` and `BPF_CGROUP_INET6_CONNECT` attach types operate at the **redirect layer** in the Windows Filtering Platform (WFP). This layer occurs **before route selection** in the network stack processing pipeline.

### Limitations of the Redirect Layer

At the redirect layer, certain critical outbound connection properties are not yet available, including:

- **Interface information** - Which network interface will be used for the outbound connection.
- **Tunnel type** - Whether the outbound connection will use tunneling protocols.
- **Route-dependent metadata** - Information that depends on the selected route.

Additionally, the redirect layer is **not invoked during WFP reauthorization (reauth) events**. When WFP triggers a reauth cycle for an existing connection (e.g., due to policy changes, network transitions, or security updates), the redirect-layer eBPF programs are bypassed. This means:

- Programs cannot re-evaluate or re-redirect established connections during reauth
- Authorization decisions made at the redirect layer are not re-evaluated on reauth
- **Reauth support is required** for eBPF-based solutions to handle policy enforcement across connection lifecycle events

### Use Cases Requiring Route Information

eBPF programs that need to make authorization decisions based on these properties cannot function properly with the existing CONNECT attach types. Examples include:

1. **Interface-based policies** - Allowing or denying outbound connections based on which network interface will be used
2. **Tunnel-aware security** - Different policies for tunneled vs. non-tunneled traffic
3. **Route-dependent access control** - Authorization decisions that depend on the network path

## Solution: CONNECT_AUTHORIZATION Attach Types

The new `BPF_CGROUP_INET4_CONNECT_AUTHORIZATION` and `BPF_CGROUP_INET6_CONNECT_AUTHORIZATION` attach types address this limitation by operating at the **authorization layer** in WFP.

### Key Characteristics

- **Timing**: Invoked **after route selection** but **before outbound connection authorization**
- **Coverage**: Invoked for both initial connection establishment and WFP reauthorization (reauth) cycles
- **Available Information**: Full outbound connection context including interface and tunnel information
- **Purpose**: Authorization decisions based on complete outbound connection metadata
- **Limitation**: **No redirection support** - outbound connections cannot be redirected at this layer since route selection has already occurred

### WFP Layer Mapping

- `BPF_CGROUP_INET4_CONNECT_AUTHORIZATION` → `FWPM_LAYER_ALE_AUTH_CONNECT_V4`
- `BPF_CGROUP_INET6_CONNECT_AUTHORIZATION` → `FWPM_LAYER_ALE_AUTH_CONNECT_V6`

## When to Use Each Attach Type

### Use CONNECT Attach Types When:
- Program needs to **redirect** outbound connections to different destinations (**redirection is only supported at these layers**).
- Program only needs basic outbound connection information (source/destination IP/port).
- Interface and route information is not relevant to the program's use case.

### Use CONNECT_AUTHORIZATION Attach Types When:
- Program needs **interface information** for authorization decisions via `bpf_sock_addr_get_network_context()` (field: `interface_type`).
- Program needs **tunnel type** information via `bpf_sock_addr_get_network_context()` (field: `tunnel_type`).
- Program needs **next-hop interface** details via `bpf_sock_addr_get_network_context()` (field: `next_hop_interface_luid`).
- Program needs **sub-interface** granularity via `bpf_sock_addr_get_network_context()` (field: `sub_interface_index`).
- Program wants to **authorize or deny** outbound connections based on complete network context (**no redirection support**).
- Program policy depends on route-dependent metadata.

## Implementation Details

### Program Type
Both CONNECT_AUTHORIZATION attach types use the `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` program type, sharing the same context structure and helper functions as other sock_addr programs.

### Attach Parameters and Wildcards

The CONNECT and CONNECT_AUTHORIZATION sock_addr hooks support an optional attach parameter: a Windows network compartment ID.

- If a specific compartment ID is provided, the program is only invoked for outbound connections in that compartment.
- If no attach parameters are provided, or if the compartment ID is set to `UNSPECIFIED_COMPARTMENT_ID`, the attachment is treated as a **wildcard** and matches outbound connections in any compartment.

When both specific and wildcard programs are attached:

- Programs attached for a specific compartment are invoked before wildcard programs, regardless of the order they were attached.
- If multiple programs are attached for the same compartment ID (including wildcard), they are invoked in attach order.

### Verdict Handling
CONNECT_AUTHORIZATION programs return values from the existing `BPF_SOCK_ADDR_VERDICT` enum. This proposal does not redefine verdict semantics; see `ebpf_nethooks.h` for details.

### Context Modification Restrictions

The `bpf_sock_addr` context is **read-only** for CONNECT_AUTHORIZATION attach types. Programs must not attempt to modify the source or destination IP address and port fields at this layer.

**Expected Behavior:**
If a program attached to CONNECT_AUTHORIZATION modifies the sock_addr context, the extension overrides the verdict returned by the program and always blocks the connection. Writes that leave the fields unchanged (for example, writing back the same value) are effectively no-ops, but are discouraged; programs should treat the context as read-only and avoid writes entirely.

**Rationale:**
- Route selection has already completed at the authorization layer, making any IP/port modifications ineffective
- Context modifications would violate the semantic contract of read-only authorization at this layer
- Silently ignoring modifications would lead to confusing program behavior and difficult-to-diagnose bugs

**Contrast with CONNECT Layer:**
Unlike CONNECT_AUTHORIZATION, the CONNECT layer (operating at the redirect layer) fully supports `bpf_sock_addr` context modifications for redirection purposes, since route selection has not yet occurred.

### Additional Helper Functions

CONNECT_AUTHORIZATION and RECV_ACCEPT attach types provide access to additional network layer properties through a single versioned helper function that returns a struct containing all relevant network context information.

#### `int bpf_sock_addr_get_network_context()`

Returns a struct containing network layer information for the connection. This is a versioned helper that supports future extensibility.

**Parameters:**
- `ctx` - The socket address context
- `context_ptr` - Pointer to the `bpf_sock_addr_network_context_t` struct to be filled
- `context_size` - Size of the struct (used for version management)

**Returns:** 
- 0 on success
- A negative value on error. Currently this helper returns `-1` as a generic error when network context is unavailable at the current attach layer. Callers should treat any value `< 0` as an error to remain forward compatible with potential errno-style codes (for example, `-EINVAL`, `-ENOTSUP`).

**Struct Definition:**
```c
// Version 1 of the network context struct
typedef struct {
    __u32 version;                    // Struct version (currently 1)
    __u32 interface_type;             // IANA interface type, or UINT32_MAX (0xFFFFFFFF) if not available.
    __u32 tunnel_type;                // IANA tunnel type value; 0 if not a tunnel, or UINT32_MAX (0xFFFFFFFF) if not available.
    __u64 next_hop_interface_luid;    // Next-hop interface LUID, or UINT64_MAX (0xFFFFFFFFFFFFFFFF) if not available. This is the same as `NET_LUID` defined in `ifdef.h`.
    __u32 sub_interface_index;        // Sub-interface index, or UINT32_MAX (0xFFFFFFFF) if not available.
} bpf_sock_addr_network_context_t;
```

Note on sentinel values: The fields above are unsigned types and use a "not available" sentinel represented by casting -1 to the corresponding width (for example, `(uint32_t)-1` or `(uint64_t)-1`). For clarity, this equals `UINT32_MAX` (0xFFFFFFFF) for 32-bit fields and `UINT64_MAX` (0xFFFFFFFFFFFFFFFF) for 64-bit fields. When checking these values in C, compare against the correctly sized constant or use an explicit cast to match the field width.

**Availability:**
- `interface_type` - Available for CONNECT_AUTHORIZATION (BPF_CGROUP_INET4_CONNECT_AUTHORIZATION / BPF_CGROUP_INET6_CONNECT_AUTHORIZATION) and RECV_ACCEPT (BPF_CGROUP_INET4_RECV_ACCEPT / BPF_CGROUP_INET6_RECV_ACCEPT) hooks
- `tunnel_type` - Available for CONNECT_AUTHORIZATION (BPF_CGROUP_INET4_CONNECT_AUTHORIZATION / BPF_CGROUP_INET6_CONNECT_AUTHORIZATION) and RECV_ACCEPT (BPF_CGROUP_INET4_RECV_ACCEPT / BPF_CGROUP_INET6_RECV_ACCEPT) hooks
- `next_hop_interface_luid` - Available for CONNECT_AUTHORIZATION (BPF_CGROUP_INET4_CONNECT_AUTHORIZATION / BPF_CGROUP_INET6_CONNECT_AUTHORIZATION) hooks only
- `sub_interface_index` - Available for CONNECT_AUTHORIZATION (BPF_CGROUP_INET4_CONNECT_AUTHORIZATION / BPF_CGROUP_INET6_CONNECT_AUTHORIZATION) and RECV_ACCEPT (BPF_CGROUP_INET4_RECV_ACCEPT / BPF_CGROUP_INET6_RECV_ACCEPT) hooks

**Benefits of Versioned Struct Approach:**
- **Single helper call** - Reduces overhead of multiple helper invocations
- **Forward compatible** - New fields can be added in future versions without breaking existing programs
- **Version awareness** - Programs can check the `version` field to know which fields are populated
- **Extensible** - Future versions (e.g., version 2) can add new fields while maintaining backward compatibility

**Usage Example:**
```c
SEC("cgroup/connect_authorization4")
int interface_aware_authorization(struct bpf_sock_addr *ctx)
{
    bpf_sock_addr_network_context_t net_ctx = {};
    
    // Retrieve network context.
    if (bpf_sock_addr_get_network_context(ctx, &net_ctx, sizeof(net_ctx)) < 0) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }
    
    // Use the retrieved information.
    if (net_ctx.interface_type == IF_TYPE_IEEE80211) { // IEEE 802.11 (WiFi).
        // Apply WiFi-specific policy.
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }
    
    if (net_ctx.tunnel_type != 0) {
        // Handle tunneled traffic.
        return BPF_SOCK_ADDR_VERDICT_PROCEED_HARD;
    }
    
    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}
```

**Reference Notes:**
- Interface type values are assigned by IANA as defined in the [Interface Types (ifType) registry](https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib). Common values include `IF_TYPE_ETHERNET_CSMACD` (6), `IF_TYPE_IEEE80211` (71), `IF_TYPE_TUNNEL` (131), etc. These constants are defined in `ipifcons.h`.
- Tunnel type values are also assigned by IANA in the same registry. Common values include `3` (gre), `19` (ipsectunnelmode), `5` (l2tp), etc. defined in `ifdef.h`.

### Note on VPN Detection

**VPNs do not have a single, reliable interface type.** Depending on the VPN implementation, the interface may appear as `IF_TYPE_PPP`, `IF_TYPE_VIRTUAL_INTERFACE`, Ethernet, or other types.

To identify VPN traffic in your programs, you may need to:
- Correlate with `tunnel_type` information (IPSec, L2TP, etc.)
- Use other connection context signals available in the network context
- Maintain a database of known VPN application behaviors

Do not rely solely on `interface_type` to detect VPNs.



## Program Interaction: CONNECT and CONNECT_AUTHORIZATION Together

When both CONNECT and CONNECT_AUTHORIZATION programs are attached to the same cgroup, they operate in a coordinated sequence that provides comprehensive outbound connection control:

### Execution Order
1. **CONNECT Layer** (`BPF_CGROUP_INET4_CONNECT`/`BPF_CGROUP_INET6_CONNECT`)
   - Executes first at the **redirect layer** (before route selection)
   - Can **redirect** outbound connections to different destinations
   - Has access to basic outbound connection information (source/dest IP/port)
   - Produces a verdict that affects subsequent processing

2. **CONNECT_AUTHORIZATION Layer** (`BPF_CGROUP_INET4_CONNECT_AUTHORIZATION`/`BPF_CGROUP_INET6_CONNECT_AUTHORIZATION`)
   - Executes second at the **authorization layer** (after route selection)
   - **Cannot redirect** outbound connections (route already selected)
   - Has access to enhanced network context (interface type, tunnel info, routing details)
   - Makes final authorization decision

### Verdict Flow and Interaction

CONNECT and CONNECT_AUTHORIZATION programs are invoked at different points in the stack, but their decisions apply to the same outbound connection attempt.

The CONNECT verdict does **not** prevent CONNECT_AUTHORIZATION programs from running (including for `PROCEED_HARD`). CONNECT_AUTHORIZATION exists specifically so that a later-stage program can make the final decision using route-dependent metadata.

When both are present, the effective decision is:

- If any stage returns **`BPF_SOCK_ADDR_VERDICT_REJECT`**, the connection is blocked.
- Otherwise, a **`BPF_SOCK_ADDR_VERDICT_PROCEED_HARD`** decision may be used to produce a hard-permit (terminating) decision in WFP.
- Otherwise, the connection proceeds as a soft-permit.

#### Behavior When No CONNECT Program Is Attached

If no CONNECT program is attached for a given cgroup, outbound connections that reach the authorization layer will still invoke any attached CONNECT_AUTHORIZATION programs. For the purposes of determining whether CONNECT_AUTHORIZATION runs, the absence of a CONNECT program is equivalent to the CONNECT layer returning `BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT`.

### Use Case: Layered Security Policy

```c
// CONNECT layer program - handles redirection and basic filtering.
SEC("cgroup/connect4")
int redirect_and_basic_filter(struct bpf_sock_addr *ctx)
{
    // Example uses IPv4 (`connect4`). Adapt to IPv6 with the appropriate attach
    // type and IP fields (for example, `user_ip6`).
    // Block known malicious destinations immediately.
    if (is_blacklisted_destination(ctx->user_ip4)) {
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    // Redirect to local proxy for inspection.
    if (needs_proxy_inspection(ctx->user_ip4)) {
        // In CONNECT programs, the context is writable; use a helper to update
        // the destination for redirection. `redirect_to_proxy` is a placeholder
        // wrapper around the helper logic. Replace `PROXY_SERVER_IP` and
        // `PROXY_SERVER_PORT` with real values or configuration.
        redirect_to_proxy(ctx, PROXY_SERVER_IP, PROXY_SERVER_PORT);
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    // High-trust destinations can skip additional authorization.
    if (is_highly_trusted_destination(ctx->user_ip4)) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_HARD;
    }

    // Default: allow but require additional authorization.
    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}
```
```c
// CONNECT_AUTHORIZATION layer program - handles interface-aware authorization.
SEC("cgroup/connect_authorization4")
int interface_aware_authorization(struct bpf_sock_addr *ctx)
{
    // Note: In CONNECT_AUTHORIZATION programs, the bpf_sock_addr context is read-only.
    // Programs must not modify destination/source IP/port fields at this layer.
    // The extension is expected to reject such modifications (reject the verdict and block the connection).

    bpf_sock_addr_network_context_t net_ctx = {};
    if (bpf_sock_addr_get_network_context(ctx, &net_ctx, sizeof(net_ctx)) < 0) {
        // If network context is unavailable, conservatively reject.
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    // Block outbound connections on public WiFi to sensitive destinations.
    if (net_ctx.interface_type == IF_TYPE_IEEE80211 && is_sensitive_destination(ctx->user_ip4)) { // IEEE 802.11 (WiFi).
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    // Require VPN for external outbound connections.
    if (!is_internal_network(ctx->user_ip4) && net_ctx.tunnel_type == 0) {
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}
```

> Note: The example functions `is_blacklisted_destination()`, `needs_proxy_inspection()`, `is_highly_trusted_destination()`, `is_sensitive_destination()`, `is_internal_network()`, `is_approved_interface()`, `is_restricted_sub_interface()`, `is_high_bandwidth_destination()`, and `validate_tunnel_route()` are illustrative placeholders and are not eBPF helper functions. Program authors should implement equivalent logic using appropriate data structures and policies (for example, BPF maps, configuration maps, and policy engines).

## See Also

- [eBPF Extensions Documentation](eBpfExtensions.md)
