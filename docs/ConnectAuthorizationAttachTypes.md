# CONNECT_AUTHORIZATION Attach Types

## Overview

This document explains the purpose and rationale behind the `BPF_CGROUP_INET4_CONNECT_AUTHORIZATION` and `BPF_CGROUP_INET6_CONNECT_AUTHORIZATION` attach types that were added to eBPF for Windows.

## Background

eBPF for Windows already supports several attach types for socket address operations:

- `BPF_CGROUP_INET4_CONNECT` / `BPF_CGROUP_INET6_CONNECT` - Inspect outbound connections, with the capability to modify the destination address or port (redirection). Invoked at the redirect layer before route selection.
- `BPF_CGROUP_INET4_RECV_ACCEPT` / `BPF_CGROUP_INET6_RECV_ACCEPT` - For incoming connections

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

The CONNECT_AUTHORIZATION attach types are invoked during both initial connection establishment **and** reauth cycles, providing comprehensive authorization coverage throughout the connection lifecycle.

### Use Cases Requiring Route Information

eBPF programs that need to make authorization decisions based on these properties cannot function properly with the existing CONNECT attach types. Examples include:

1. **Interface-based policies** - Allowing or denying outbound connections based on which network interface will be used
2. **Tunnel-aware security** - Different policies for tunneled vs. non-tunneled traffic
3. **Route-dependent access control** - Authorization decisions that depend on the network path

## Solution: CONNECT_AUTHORIZATION Attach Types

The new `BPF_CGROUP_INET4_CONNECT_AUTHORIZATION` and `BPF_CGROUP_INET6_CONNECT_AUTHORIZATION` attach types address this limitation by operating at the **authorization layer** in WFP.

### Key Characteristics

- **Timing**: Invoked **after route selection** but **before outbound connection authorization**
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

### Verdict Handling
CONNECT_AUTHORIZATION programs can return:
- `BPF_SOCK_ADDR_VERDICT_PROCEED_HARD` - Allow the outbound connection. Maps to hard permit in WFP.
- `BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT` - Allow the outbound connection. Maps to soft permit in WFP.
- `BPF_SOCK_ADDR_VERDICT_REJECT` - Deny the outbound connection.

**Important Details:**

`PROCEED_HARD` will tell WFP it does not need to verify any more filters **at this sublayer**. It will still process the outbound request at other sublayers. Additionally, `PROCEED_HARD` will override soft-block settings (e.g., default Windows Firewall allow/block settings are soft-block settings; this will allow the connection even if the Windows Firewall policy is to block by default).

`PROCEED_SOFT` allows the outbound connection while respecting soft-block settings and continuing evaluations.

For detailed information on how WFP evaluates and arbitrates filters across multiple layers and callouts, see [Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration).

**Important:** Redirect functionality is **not supported** at the CONNECT_AUTHORIZATION layer since route selection has already occurred. Outbound connection redirection can only be performed at the `BPF_CGROUP_INET4_CONNECT` and `BPF_CGROUP_INET6_CONNECT` layers.

### Context Modification Restrictions

The `bpf_sock_addr` context is **read-only** for CONNECT_AUTHORIZATION attach types. Programs must not attempt to modify the source or destination IP address and port fields at this layer.

**Rationale:**
- Route selection has already completed at the authorization layer, making any IP/port modifications ineffective
- Context modifications would violate the semantic contract of read-only authorization at this layer
- Silently ignoring modifications would lead to confusing program behavior and difficult-to-diagnose bugs

**Expected Behavior:**
The extension will **reject** the verdict of a program at this attach layer that changed the sock_addr context by modifying the source or destination IP/port. Programs that modify these fields will have their verdict rejected and the outbound connection will be blocked for security.

**Contrast with CONNECT Layer:**
Unlike CONNECT_AUTHORIZATION, the CONNECT layer (operating at the redirect layer) fully supports `bpf_sock_addr` context modifications for redirection purposes, since route selection has not yet occurred.

### Additional Helper Functions

CONNECT_AUTHORIZATION and RECV_ACCEPT attach types provide access to additional network layer properties through a single versioned helper function that returns a struct containing all relevant network context information.

#### `int bpf_sock_addr_get_network_context(ctx, context_ptr, context_size)`

Returns a struct containing network layer information for the connection. This is a versioned helper that supports future extensibility.

**Parameters:**
- `ctx` - The socket address context
- `context_ptr` - Pointer to the `bpf_sock_addr_network_context_t` struct to be filled
- `context_size` - Size of the struct (used for version management)

**Returns:** 
- 0 on success
- -1 on error (e.g., not available at this attach layer)

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

The verdict from the CONNECT layer determines whether CONNECT_AUTHORIZATION programs are invoked:

- **`BPF_SOCK_ADDR_VERDICT_REJECT`** from CONNECT → Outbound connection blocked, CONNECT_AUTHORIZATION programs **not invoked**
- **`BPF_SOCK_ADDR_VERDICT_PROCEED_HARD`** from CONNECT → Outbound connection authorized, CONNECT_AUTHORIZATION programs **not invoked** (optimization)
- **`BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT`** from CONNECT → CONNECT_AUTHORIZATION programs **are invoked** for additional authorization

### Use Case: Layered Security Policy

```c
// CONNECT layer program - handles redirection and basic filtering.
SEC("cgroup/connect4")
int redirect_and_basic_filter(struct bpf_sock_addr *ctx)
{
    // Block known malicious destinations immediately.
    if (is_blacklisted_destination(ctx->user_ip4)) {
        return BPF_SOCK_ADDR_VERDICT_REJECT; // CONNECT_AUTHORIZATION will NOT run.
    }

    // Redirect to local proxy for inspection.
    if (needs_proxy_inspection(ctx->user_ip4)) {
        // In CONNECT programs, the context is writable; use a helper to update
        // the destination for redirection.
        redirect_to_proxy(ctx, PROXY_SERVER_IP, PROXY_SERVER_PORT);
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT; // CONNECT_AUTHORIZATION WILL run.
    }

    // High-trust destinations can skip additional authorization.
    if (is_highly_trusted_destination(ctx->user_ip4)) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_HARD; // CONNECT_AUTHORIZATION will NOT run.
    }

    // Default: allow but require additional authorization.
    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT; // CONNECT_AUTHORIZATION WILL run.
}
```
```c
// CONNECT_AUTHORIZATION layer program - handles interface-aware authorization.
SEC("cgroup/connect_authorization4")
int interface_aware_authorization(struct bpf_sock_addr *ctx)
{
    // This program only runs for PROCEED_SOFT verdicts from CONNECT layer.

    bpf_sock_addr_network_context_t net_ctx = {};
    if (bpf_sock_addr_get_network_context(ctx, &net_ctx, sizeof(net_ctx)) < 0) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
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

## Example Scenarios

The following are reference implementations demonstrating eBPF-based CONNECT_AUTHORIZATION programs. Sample test programs can cover these scenarios in the actual test suite.

Note: Helper functions like `is_blacklisted_destination()`, `needs_proxy_inspection()`, `is_highly_trusted_destination()`, `is_sensitive_destination()`, `is_internal_network()`, `is_approved_interface()`, `is_restricted_sub_interface()`, `is_high_bandwidth_destination()`, and `validate_tunnel_route()` are illustrative placeholders to show policy logic. They are not eBPF helper functions and should be implemented by program authors using appropriate data structures (for example, BPF maps), configuration, or external policy logic.

### Scenario 1: Interface-Based Access Control
```c
SEC("cgroup/connect_authorization4")
int connect_authorization_interface_policy(struct bpf_sock_addr *ctx)
{
    // Get network context using helper function.
    bpf_sock_addr_network_context_t net_ctx = {};
    if (bpf_sock_addr_get_network_context(ctx, &net_ctx, sizeof(net_ctx)) < 0) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    // Apply interface-specific policy with appropriate verdict types.
    if (net_ctx.interface_type == IF_TYPE_TUNNEL) { // tunnel(131) - IPv6/IPv4 tunnels (IPHTTPS, Teredo, 6to4, etc.).
        // VPN connections are highly trusted - skip additional authorization.
        return BPF_SOCK_ADDR_VERDICT_PROCEED_HARD;
    } else if (net_ctx.interface_type == IF_TYPE_IEEE80211) { // ieee80211(71) - WiFi interfaces.
        // Block outbound connections on public WiFi for sensitive applications.
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    } else if (net_ctx.interface_type == IF_TYPE_ETHERNET_CSMACD) { // ethernetCsmacd(6) - Ethernet interfaces.
        // Corporate wired network - allow but continue with normal authorization flow.
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    // Default: allow with normal authorization checks.
    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}
```

### Scenario 2: Tunnel-Aware Security
```c
SEC("cgroup/connect_authorization4")
int connect_authorization_tunnel_policy(struct bpf_sock_addr *ctx)
{
    // Check if outbound connection will use tunneling.
    bpf_sock_addr_network_context_t net_ctx = {};
    if (bpf_sock_addr_get_network_context(ctx, &net_ctx, sizeof(net_ctx)) < 0) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    if (net_ctx.tunnel_type != 0) {
        // This is a tunneled outbound connection.
        // Apply tunnel-specific security policy.
        if (net_ctx.tunnel_type == 19) { // ipsectunnelmode(19) - IPSec tunnel mode.
            return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
        } else if (net_ctx.tunnel_type == 3) { // gre(3) - GRE encapsulation.
            return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
        } else {
            // Unknown or unsupported tunnel type.
            return BPF_SOCK_ADDR_VERDICT_REJECT;
        }
    }

    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}
```

### Scenario 3: Route-Dependent Authorization
```c
SEC("cgroup/connect_authorization4")
int connect_authorization_route_policy(struct bpf_sock_addr *ctx)
{
    // Get network context for route information.
    bpf_sock_addr_network_context_t net_ctx = {};
    if (bpf_sock_addr_get_network_context(ctx, &net_ctx, sizeof(net_ctx)) < 0) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    if (net_ctx.next_hop_interface_luid != (uint64_t)-1) {
        // Check if the next-hop interface is approved for this type of traffic.
        if (!is_approved_interface(net_ctx.next_hop_interface_luid)) {
            return BPF_SOCK_ADDR_VERDICT_REJECT;
        }
    }

    // Get sub-interface details for fine-grained control.
    if (net_ctx.sub_interface_index != (uint32_t)-1 && is_restricted_sub_interface(net_ctx.sub_interface_index)) {
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}
```

### Scenario 4: Verdict Type Demonstration
```c
SEC("cgroup/connect_authorization4")
int connect_authorization_verdict_demo(struct bpf_sock_addr *ctx)
{
    uint32_t dest_ip = ctx->user_ip4;
    bpf_sock_addr_network_context_t net_ctx = {};
    if (bpf_sock_addr_get_network_context(ctx, &net_ctx, sizeof(net_ctx)) < 0) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    // Trusted internal network with VPN - maximum trust.
    if (is_internal_network(dest_ip) && net_ctx.tunnel_type == 19) { // ipsectunnelmode(19).
        // Skip all further authorization checks for performance.
        return BPF_SOCK_ADDR_VERDICT_PROCEED_HARD;
    }

    // Known malicious destination - immediate block.
    if (is_blacklisted_destination(dest_ip)) {
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    // Corporate wired network - allow but let other filters validate.
    if (net_ctx.interface_type == IF_TYPE_ETHERNET_CSMACD) { // ethernetCsmacd(6) - Ethernet interfaces.
        // Continue with normal authorization flow.
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    // External destinations on public WiFi networks - proceed with caution.
    if (net_ctx.interface_type == IF_TYPE_IEEE80211) { // ieee80211(71) - WiFi.
        // Allow but ensure other security mechanisms evaluate this.
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    // Default case - standard proceed.
    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}
```

### Scenario 5: Combined Network Context Analysis
```c
SEC("cgroup/connect_authorization4")
int connect_authorization_comprehensive_policy(struct bpf_sock_addr *ctx)
{
    // Gather all available network context.
    bpf_sock_addr_network_context_t net_ctx = {};
    if (bpf_sock_addr_get_network_context(ctx, &net_ctx, sizeof(net_ctx)) < 0) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    // Create a comprehensive security decision based on all available context.
    if (net_ctx.interface_type == IF_TYPE_WWANPP && net_ctx.tunnel_type == 0) { // WWANPP(243) - cellular without tunnel.
        // On cellular without tunnel - apply data usage restrictions.
        if (is_high_bandwidth_destination(ctx->user_ip4)) {
            return BPF_SOCK_ADDR_VERDICT_REJECT;
        }
        // Allow low-bandwidth destinations but continue with authorization checks.
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    if (net_ctx.tunnel_type != 0 && net_ctx.next_hop_interface_luid != (uint64_t)-1) {
        // Tunneled traffic with specific next-hop - enhanced validation.
        if (!validate_tunnel_route(net_ctx.tunnel_type, net_ctx.next_hop_interface_luid)) {
            return BPF_SOCK_ADDR_VERDICT_REJECT;
        }
        // Validated tunnel outbound connections can skip additional checks.
        return BPF_SOCK_ADDR_VERDICT_PROCEED_HARD;
    }

    // Default: allow with normal authorization flow.
    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}
```

### Important Note on VPN Detection

**VPNs do not have a specific interface type.** Sadly, VPNs don't have an iftype. Some will use type `IF_TYPE_PPP`, some type `IF_TYPE_VIRTUAL_INTERFACE`, and some will just be type Ethernet.

To identify VPN traffic in your programs, you may need to:
- Correlate with `tunnel_type` information (IPSec, L2TP, etc.)
- Use other connection context signals available in the network context
- Maintain a database of known VPN application behaviors

Do not rely solely on `interface_type` to detect VPNs.

## Migration Considerations

### Existing Programs
Existing programs using `BPF_CGROUP_INET4_CONNECT` and `BPF_CGROUP_INET6_CONNECT` will continue to work unchanged. The new CONNECT_AUTHORIZATION attach types are additional, not replacements.

### Choosing the Right Attach Type
When developing new programs, consider whether you need:
- Redirection capability → Use CONNECT attach types
- Enhanced network context information → Use CONNECT_AUTHORIZATION attach types

### Backward Compatibility
The new helper functions are designed to be backward compatible:
- They return -1 when information is not available
- Existing programs that don't use these helpers continue to function normally
- The `bpf_sock_addr_t` context structure remains unchanged to maintain ABI compatibility

## See Also

- [eBPF Extensions Documentation](eBpfExtensions.md)
- [Windows Filtering Platform (WFP) Layer Reference](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/filtering-layer-identifiers)