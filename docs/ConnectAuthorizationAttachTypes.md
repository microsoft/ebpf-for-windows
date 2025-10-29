# CONNECT_AUTHORIZATION Attach Types

## Overview

This document explains the purpose and rationale behind the `BPF_CGROUP_INET4_CONNECT_AUTHORIZATION` and `BPF_CGROUP_INET6_CONNECT_AUTHORIZATION` attach types that were added to eBPF for Windows.

## Background

eBPF for Windows already supports several attach types for socket address operations:

- `BPF_CGROUP_INET4_CONNECT` / `BPF_CGROUP_INET6_CONNECT` - Invoked at the redirect layer for outbound connections
- `BPF_CGROUP_INET4_RECV_ACCEPT` / `BPF_CGROUP_INET6_RECV_ACCEPT` - For incoming connections

However, there was a gap in functionality that required the addition of new attach points.

## Problem Statement

The existing `BPF_CGROUP_INET4_CONNECT` and `BPF_CGROUP_INET6_CONNECT` attach types operate at the **redirect layer** in the Windows Filtering Platform (WFP). This layer occurs **before route selection** in the network stack processing pipeline.

### Limitations of the Redirect Layer

At the redirect layer, certain critical outbound connection properties are not yet available, including:

- **Interface information** - Which network interface will be used for the outbound connection
- **Tunnel type** - Whether the outbound connection will use tunneling protocols
- **Route-dependent metadata** - Information that depends on the selected route

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
- You need to **redirect** outbound connections to different destinations (**redirection is only supported at these layers**)
- You only need basic outbound connection information (source/destination IP/port)
- Interface and route information is not relevant to your use case

### Use CONNECT_AUTHORIZATION Attach Types When:
- You need **interface information** for authorization decisions (via `bpf_sock_addr_get_interface_type()`)
- You need **tunnel type** information (via `bpf_sock_addr_get_tunnel_type()`)
- You need **next-hop interface** details (via `bpf_sock_addr_get_next_hop_interface_luid()`)
- You need **sub-interface** granularity (via `bpf_sock_addr_get_sub_interface_index()`)
- You want to **authorize or deny** outbound connections based on complete network context (**no redirection support**)
- Your policy depends on route-dependent metadata

## Implementation Details

### Program Type
Both CONNECT_AUTHORIZATION attach types use the `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` program type, sharing the same context structure and helper functions as other sock_addr programs.

### Verdict Handling
CONNECT_AUTHORIZATION programs can return:
- `BPF_SOCK_ADDR_VERDICT_PROCEED_HARD` - Allow the outbound connection and skip further authorization checks
- `BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT` - Allow the outbound connection but continue with additional authorization checks
- `BPF_SOCK_ADDR_VERDICT_REJECT` - Deny the outbound connection

#### Verdict Types Explained

**PROCEED_HARD vs PROCEED_SOFT:**
- `PROCEED_HARD` provides an optimization by signaling to the WFP layer that no further authorization checks are needed for this outbound connection, potentially improving performance for trusted outbound connections
- `PROCEED_SOFT` allows the outbound connection but ensures that other WFP filters and authorization mechanisms continue to evaluate the outbound connection normally
- `PROCEED` (standard) behaves the same as `PROCEED_SOFT` - allows the outbound connection with normal authorization flow

**Use Cases:**
- Use `PROCEED_HARD` for outbound connections that have been thoroughly validated and are known to be safe, where bypassing additional checks improves performance
- Use `PROCEED_SOFT` or `PROCEED` for outbound connections that should be allowed but may still need evaluation by other security mechanisms
- Use `REJECT` to block outbound connections that violate security policies

**Important:** Redirect functionality is **not supported** at the CONNECT_AUTHORIZATION layer since route selection has already occurred. Outbound connection redirection can only be performed at the `BPF_CGROUP_INET4_CONNECT` and `BPF_CGROUP_INET6_CONNECT` layers.

### Additional Helper Functions
CONNECT_AUTHORIZATION and AUTH_RECV_ACCEPT attach types provide access to additional network layer properties through specialized helper functions:

#### `bpf_sock_addr_get_interface_type(ctx)`
Returns the network interface type for the connection. Available for CONNECT_AUTHORIZATION and AUTH_RECV_ACCEPT hooks.
- **Returns**: Interface type value, or -1 if not available
- **Use case**: Distinguish between different interface types (e.g., Ethernet, WiFi, VPN)
- **Note**: Interface type values are assigned by IANA as defined in the [Interface Types (ifType) registry](https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib). Common values include `6` (ethernetCsmacd), `71` (ieee80211 for WiFi), `131` (tunnel), etc.

#### `bpf_sock_addr_get_tunnel_type(ctx)`
Returns the tunnel type information for the connection. Available for CONNECT_AUTHORIZATION and AUTH_RECV_ACCEPT hooks.
- **Returns**: Tunnel type value, 0 if not a tunnel, or -1 if not available
- **Use case**: Apply different policies for tunneled vs. non-tunneled traffic
- **Note**: Tunnel type values are also assigned by IANA in the same registry. Common values include `3` (gre), `19` (ipsectunnelmode), `5` (l2tp), etc.

#### `bpf_sock_addr_get_next_hop_interface_luid(ctx)`
Returns the next-hop interface LUID for the outbound connection. Available for CONNECT_AUTHORIZATION hooks only.
- **Returns**: Next-hop interface LUID, or -1 if not available
- **Use case**: Route-dependent access control decisions

#### `bpf_sock_addr_get_sub_interface_index(ctx)`
Returns the sub-interface index for the connection. Available for CONNECT_AUTHORIZATION and AUTH_RECV_ACCEPT hooks.
- **Returns**: Sub-interface index, or -1 if not available
- **Use case**: Granular interface-based policies

### Selective Program Invocation
The implementation includes a filtering mechanism to ensure that:
- CONNECT_AUTHORIZATION programs are only invoked for CONNECT_AUTHORIZATION attach points
- CONNECT programs are only invoked for CONNECT attach points

This prevents cross-invocation and ensures programs run at the appropriate layer.

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
        ctx->user_ip4 = PROXY_SERVER_IP;
        ctx->user_port = PROXY_SERVER_PORT;
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT; // CONNECT_AUTHORIZATION WILL run.
    }

    // High-trust destinations can skip additional authorization.
    if (is_highly_trusted_destination(ctx->user_ip4)) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_HARD; // CONNECT_AUTHORIZATION will NOT run.
    }

    // Default: allow but require additional authorization.
    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT; // CONNECT_AUTHORIZATION WILL run.
}

// CONNECT_AUTHORIZATION layer program - handles interface-aware authorization.
SEC("cgroup/connect_authorization4")
int interface_aware_authorization(struct bpf_sock_addr *ctx)
{
    // This program only runs for PROCEED_SOFT verdicts from CONNECT layer.

    uint32_t interface_type = bpf_sock_addr_get_interface_type(ctx);
    uint32_t tunnel_type = bpf_sock_addr_get_tunnel_type(ctx);

    // Block outbound connections on public WiFi to sensitive destinations.
    if (interface_type == 71 && is_sensitive_destination(ctx->user_ip4)) { // ieee80211.
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    // Require VPN for external outbound connections.
    if (!is_internal_network(ctx->user_ip4) && tunnel_type == 0) {
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    return BPF_SOCK_ADDR_VERDICT_PROCEED;
}
```

### Benefits of Layered Approach

1. **Performance Optimization**: PROCEED_HARD verdicts skip unnecessary CONNECT_AUTHORIZATION processing for trusted outbound connections
2. **Comprehensive Control**: CONNECT handles redirection + basic filtering, CONNECT_AUTHORIZATION adds interface-aware policies
3. **Separation of Concerns**: Network topology changes (CONNECT) vs. authorization policies (CONNECT_AUTHORIZATION)
4. **Flexibility**: Each layer can be independently updated without affecting the other

### Important Considerations

- **Redirection must happen at CONNECT layer**: Once CONNECT_AUTHORIZATION runs, route selection is complete
- **Context preservation**: Outbound connection context from CONNECT layer is available to CONNECT_AUTHORIZATION programs
- **Verdict precedence**: REJECT verdicts are final; PROCEED_HARD optimizes by skipping CONNECT_AUTHORIZATION
- **Error handling**: Failures in either layer result in outbound connection blocking for security

## Example Scenarios

### Scenario 1: Interface-Based Access Control
```c
SEC("cgroup/connect_authorization4")
int connect_authorization_interface_policy(struct bpf_sock_addr *ctx)
{
    // Get interface type using helper function.
    uint32_t interface_type = bpf_sock_addr_get_interface_type(ctx);

    // Apply interface-specific policy with appropriate verdict types.
    if (interface_type == 131) { // tunnel(131) - VPN/tunnel interfaces.
        // VPN connections are highly trusted - skip additional authorization.
        return BPF_SOCK_ADDR_VERDICT_PROCEED_HARD;
    } else if (interface_type == 71) { // ieee80211(71) - WiFi interfaces.
        // Block outbound connections on public WiFi for sensitive applications.
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    } else if (interface_type == 6) { // ethernetCsmacd(6) - Ethernet interfaces.
        // Corporate wired network - allow but continue with normal authorization flow.
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    // Default: allow with normal authorization checks.
    return BPF_SOCK_ADDR_VERDICT_PROCEED;
}
```

### Scenario 2: Tunnel-Aware Security
```c
SEC("cgroup/connect_authorization4")
int connect_authorization_tunnel_policy(struct bpf_sock_addr *ctx)
{
    // Check if outbound connection will use tunneling.
    uint32_t tunnel_type = bpf_sock_addr_get_tunnel_type(ctx);

    if (tunnel_type != 0) {
        // This is a tunneled outbound connection.
        // Apply tunnel-specific security policy.
        if (tunnel_type == 19) { // ipsectunnelmode(19) - IPSec tunnel mode.
            return BPF_SOCK_ADDR_VERDICT_PROCEED;
        } else if (tunnel_type == 3) { // gre(3) - GRE encapsulation.
            return BPF_SOCK_ADDR_VERDICT_PROCEED;
        } else {
            // Unknown or unsupported tunnel type.
            return BPF_SOCK_ADDR_VERDICT_REJECT;
        }
    }

    return BPF_SOCK_ADDR_VERDICT_PROCEED;
}
```

### Scenario 3: Route-Dependent Authorization
```c
SEC("cgroup/connect_authorization4")
int connect_authorization_route_policy(struct bpf_sock_addr *ctx)
{
    // Get next-hop interface information.
    uint64_t next_hop_interface = bpf_sock_addr_get_next_hop_interface_luid(ctx);

    if (next_hop_interface != 0) {
        // Check if the next-hop interface is approved for this type of traffic.
        if (!is_approved_interface(next_hop_interface)) {
            return BPF_SOCK_ADDR_VERDICT_REJECT;
        }
    }

    // Get sub-interface details for fine-grained control.
    uint32_t sub_interface = bpf_sock_addr_get_sub_interface_index(ctx);
    if (sub_interface != 0 && is_restricted_sub_interface(sub_interface)) {
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    return BPF_SOCK_ADDR_VERDICT_PROCEED;
}
```

### Scenario 4: Verdict Type Demonstration
```c
SEC("cgroup/connect_authorization4")
int connect_authorization_verdict_demo(struct bpf_sock_addr *ctx)
{
    uint32_t dest_ip = ctx->user_ip4;
    uint32_t interface_type = bpf_sock_addr_get_interface_type(ctx);
    uint32_t tunnel_type = bpf_sock_addr_get_tunnel_type(ctx);

    // Trusted internal network with VPN - maximum trust.
    if (is_internal_network(dest_ip) && tunnel_type == 19) { // ipsectunnelmode(19).
        // Skip all further authorization checks for performance.
        return BPF_SOCK_ADDR_VERDICT_PROCEED_HARD;
    }

    // Known malicious destination - immediate block.
    if (is_blacklisted_destination(dest_ip)) {
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    // Corporate wired network - allow but let other filters validate.
    if (interface_type == 6) { // ethernetCsmacd(6) - Ethernet.
        // Continue with normal authorization flow.
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    // External destinations on public WiFi networks - proceed with caution.
    if (interface_type == 71) { // ieee80211(71) - WiFi.
        // Allow but ensure other security mechanisms evaluate this.
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    // Default case - standard proceed.
    return BPF_SOCK_ADDR_VERDICT_PROCEED;
}
```

### Scenario 5: Combined Network Context Analysis
```c
SEC("cgroup/connect_authorization4")
int connect_authorization_comprehensive_policy(struct bpf_sock_addr *ctx)
{
    // Gather all available network context.
    uint32_t interface_type = bpf_sock_addr_get_interface_type(ctx);
    uint32_t tunnel_type = bpf_sock_addr_get_tunnel_type(ctx);
    uint64_t next_hop_interface = bpf_sock_addr_get_next_hop_interface_luid(ctx);
    uint32_t sub_interface = bpf_sock_addr_get_sub_interface_index(ctx);

    // Create a comprehensive security decision based on all available context.
    if (interface_type == 187 && tunnel_type == 0) { // aal2(187) - cellular without tunnel.
        // On cellular without tunnel - apply data usage restrictions.
        if (is_high_bandwidth_destination(ctx->user_ip4)) {
            return BPF_SOCK_ADDR_VERDICT_REJECT;
        }
        // Allow low-bandwidth destinations but continue with authorization checks.
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    if (tunnel_type != 0 && next_hop_interface != 0) {
        // Tunneled traffic with specific next-hop - enhanced validation.
        if (!validate_tunnel_route(tunnel_type, next_hop_interface)) {
            return BPF_SOCK_ADDR_VERDICT_REJECT;
        }
        // Validated tunnel outbound connections can skip additional checks.
        return BPF_SOCK_ADDR_VERDICT_PROCEED_HARD;
    }

    // Default: allow with normal authorization flow.
    return BPF_SOCK_ADDR_VERDICT_PROCEED;
}
```

## Migration Considerations

### Existing Programs
Existing programs using `BPF_CGROUP_INET4_CONNECT` and `BPF_CGROUP_INET6_CONNECT` will continue to work unchanged. The new CONNECT_AUTHORIZATION attach types are additional, not replacements.

### Choosing the Right Attach Type
When developing new programs, consider:

1. **Do you need to redirect outbound connections?** → Use CONNECT attach types
2. **Do you need enhanced network context (interface type, tunnel info, routing details)?** → Use CONNECT_AUTHORIZATION attach types with the new helper functions
3. **Do you only need basic outbound connection info for authorization?** → Either type works, but CONNECT_AUTHORIZATION provides significantly more context

### Backward Compatibility
The new helper functions are designed to be backward compatible:
- They return -1 when information is not available (e.g., on CONNECT_REDIRECT layers)
- Existing programs that don't use these helpers continue to function normally
- The `bpf_sock_addr_t` context structure remains unchanged to maintain ABI compatibility

## See Also

- [eBPF Extensions Documentation](eBpfExtensions.md)
- [Windows Filtering Platform (WFP) Layer Reference](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/filtering-layer-identifiers)