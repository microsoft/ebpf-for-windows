# AUTH_CONNECT Attach Types

## Overview

This document explains the purpose and rationale behind the `BPF_CGROUP_INET4_AUTH_CONNECT` and `BPF_CGROUP_INET6_AUTH_CONNECT` attach types that were added to eBPF for Windows.

## Background

eBPF for Windows already supports several attach types for socket address operations:

- `BPF_CGROUP_INET4_CONNECT` / `BPF_CGROUP_INET6_CONNECT` - Invoked at the redirect layer
- `BPF_CGROUP_INET4_RECV_ACCEPT` / `BPF_CGROUP_INET6_RECV_ACCEPT` - For incoming connections

However, there was a gap in functionality that required the addition of new attach points.

## Problem Statement

The existing `BPF_CGROUP_INET4_CONNECT` and `BPF_CGROUP_INET6_CONNECT` attach types operate at the **redirect layer** in the Windows Filtering Platform (WFP). This layer occurs **before route selection** in the network stack processing pipeline.

### Limitations of the Redirect Layer

At the redirect layer, certain critical connection properties are not yet available, including:

- **Interface information** - Which network interface will be used for the connection
- **Tunnel type** - Whether the connection will use tunneling protocols
- **Route-dependent metadata** - Information that depends on the selected route

### Use Cases Requiring Route Information

eBPF programs that need to make authorization decisions based on these properties cannot function properly with the existing CONNECT attach types. Examples include:

1. **Interface-based policies** - Allowing or denying connections based on which network interface will be used
2. **Tunnel-aware security** - Different policies for tunneled vs. non-tunneled traffic
3. **Route-dependent access control** - Authorization decisions that depend on the network path

## Solution: AUTH_CONNECT Attach Types

The new `BPF_CGROUP_INET4_AUTH_CONNECT` and `BPF_CGROUP_INET6_AUTH_CONNECT` attach types address this limitation by operating at the **authorization layer** in WFP.

### Key Characteristics

- **Timing**: Invoked **after route selection** but **before connection authorization**
- **Available Information**: Full connection context including interface and tunnel information
- **Purpose**: Authorization decisions based on complete connection metadata

### WFP Layer Mapping

- `BPF_CGROUP_INET4_AUTH_CONNECT` → `FWPM_LAYER_ALE_AUTH_CONNECT_V4`
- `BPF_CGROUP_INET6_AUTH_CONNECT` → `FWPM_LAYER_ALE_AUTH_CONNECT_V6`

## When to Use Each Attach Type

### Use CONNECT Attach Types When:
- You need to **redirect** connections to different destinations
- You only need basic connection information (source/destination IP/port)
- Interface and route information is not relevant to your use case

### Use AUTH_CONNECT Attach Types When:
- You need **interface information** for authorization decisions (via `bpf_sock_addr_get_interface_type()`)
- You need **tunnel type** information (via `bpf_sock_addr_get_tunnel_type()`)
- You need **next-hop interface** details (via `bpf_sock_addr_get_nexthop_interface_luid()`)
- You need **sub-interface** granularity (via `bpf_sock_addr_get_sub_interface_index()`)
- You want to **authorize or deny** connections based on complete network context
- Your policy depends on route-dependent metadata

## Implementation Details

### Program Type
Both AUTH_CONNECT attach types use the `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` program type, sharing the same context structure and helper functions as other sock_addr programs.

### Verdict Handling
AUTH_CONNECT programs can return:
- `BPF_SOCK_ADDR_VERDICT_PROCEED` - Allow the connection
- `BPF_SOCK_ADDR_VERDICT_REJECT` - Deny the connection

Note: Redirect functionality is not supported at the AUTH_CONNECT layer since route selection has already occurred.

### Additional Helper Functions
AUTH_CONNECT and AUTH_RECV_ACCEPT attach types provide access to additional network layer properties through specialized helper functions:

#### `bpf_sock_addr_get_interface_type(ctx)`
Returns the network interface type for the connection. Available for AUTH_CONNECT and AUTH_RECV_ACCEPT hooks.
- **Returns**: Interface type value, or 0 if not available
- **Use case**: Distinguish between different interface types (e.g., Ethernet, WiFi, VPN)

#### `bpf_sock_addr_get_tunnel_type(ctx)`
Returns the tunnel type information for the connection. Available for AUTH_CONNECT and AUTH_RECV_ACCEPT hooks.
- **Returns**: Tunnel type value, or 0 if not a tunnel or not available
- **Use case**: Apply different policies for tunneled vs. non-tunneled traffic

#### `bpf_sock_addr_get_nexthop_interface_luid(ctx)`
Returns the next-hop interface LUID for the connection. Available for AUTH_CONNECT hooks only.
- **Returns**: Next-hop interface LUID, or 0 if not available
- **Use case**: Route-dependent access control decisions

#### `bpf_sock_addr_get_sub_interface_index(ctx)`
Returns the sub-interface index for the connection. Available for AUTH_CONNECT and AUTH_RECV_ACCEPT hooks.
- **Returns**: Sub-interface index, or 0 if not available
- **Use case**: Granular interface-based policies

### Selective Program Invocation
The implementation includes a filtering mechanism to ensure that:
- AUTH_CONNECT programs are only invoked for AUTH_CONNECT attach points
- CONNECT programs are only invoked for CONNECT attach points

This prevents cross-invocation and ensures programs run at the appropriate layer.

## Example Scenarios

### Scenario 1: Interface-Based Access Control
```c
SEC("cgroup/auth_connect4")
int auth_connect_interface_policy(struct bpf_sock_addr *ctx)
{
    // Get interface type using helper function
    uint32_t interface_type = bpf_sock_addr_get_interface_type(ctx);

    // Apply interface-specific policy
    if (interface_type == INTERFACE_TYPE_VPN) {
        // Allow VPN connections
        return BPF_SOCK_ADDR_VERDICT_PROCEED;
    } else if (interface_type == INTERFACE_TYPE_PUBLIC_WIFI) {
        // Block connections on public WiFi for sensitive applications
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    return BPF_SOCK_ADDR_VERDICT_PROCEED;
}
```

### Scenario 2: Tunnel-Aware Security
```c
SEC("cgroup/auth_connect4")
int auth_connect_tunnel_policy(struct bpf_sock_addr *ctx)
{
    // Check if connection will use tunneling
    uint32_t tunnel_type = bpf_sock_addr_get_tunnel_type(ctx);

    if (tunnel_type != 0) {
        // This is a tunneled connection
        // Apply tunnel-specific security policy
        if (tunnel_type == TUNNEL_TYPE_IPSEC) {
            return BPF_SOCK_ADDR_VERDICT_PROCEED;
        } else {
            // Unknown or unsupported tunnel type
            return BPF_SOCK_ADDR_VERDICT_REJECT;
        }
    }

    return BPF_SOCK_ADDR_VERDICT_PROCEED;
}
```

### Scenario 3: Route-Dependent Authorization
```c
SEC("cgroup/auth_connect4")
int auth_connect_route_policy(struct bpf_sock_addr *ctx)
{
    // Get next-hop interface information
    uint64_t nexthop_interface = bpf_sock_addr_get_nexthop_interface_luid(ctx);

    if (nexthop_interface != 0) {
        // Check if the next-hop interface is approved for this type of traffic
        if (!is_approved_interface(nexthop_interface)) {
            return BPF_SOCK_ADDR_VERDICT_REJECT;
        }
    }

    // Get sub-interface details for fine-grained control
    uint32_t sub_interface = bpf_sock_addr_get_sub_interface_index(ctx);
    if (sub_interface != 0 && is_restricted_sub_interface(sub_interface)) {
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    return BPF_SOCK_ADDR_VERDICT_PROCEED;
}
```

### Scenario 4: Combined Network Context Analysis
```c
SEC("cgroup/auth_connect4")
int auth_connect_comprehensive_policy(struct bpf_sock_addr *ctx)
{
    // Gather all available network context
    uint32_t interface_type = bpf_sock_addr_get_interface_type(ctx);
    uint32_t tunnel_type = bpf_sock_addr_get_tunnel_type(ctx);
    uint64_t nexthop_interface = bpf_sock_addr_get_nexthop_interface_luid(ctx);
    uint32_t sub_interface = bpf_sock_addr_get_sub_interface_index(ctx);

    // Create a comprehensive security decision based on all available context
    if (interface_type == INTERFACE_TYPE_CELLULAR && tunnel_type == 0) {
        // On cellular without tunnel - apply data usage restrictions
        if (is_high_bandwidth_destination(ctx->user_ip4)) {
            return BPF_SOCK_ADDR_VERDICT_REJECT;
        }
    }

    if (tunnel_type != 0 && nexthop_interface != 0) {
        // Tunneled traffic with specific next-hop - enhanced validation
        if (!validate_tunnel_route(tunnel_type, nexthop_interface)) {
            return BPF_SOCK_ADDR_VERDICT_REJECT;
        }
    }

    return BPF_SOCK_ADDR_VERDICT_PROCEED;
}
```

## Migration Considerations

### Existing Programs
Existing programs using `BPF_CGROUP_INET4_CONNECT` and `BPF_CGROUP_INET6_CONNECT` will continue to work unchanged. The new AUTH_CONNECT attach types are additional, not replacements.

### Choosing the Right Attach Type
When developing new programs, consider:

1. **Do you need to redirect connections?** → Use CONNECT attach types
2. **Do you need enhanced network context (interface type, tunnel info, routing details)?** → Use AUTH_CONNECT attach types with the new helper functions
3. **Do you only need basic connection info for authorization?** → Either type works, but AUTH_CONNECT provides significantly more context

### Backward Compatibility
The new helper functions are designed to be backward compatible:
- They return 0 when information is not available (e.g., on CONNECT_REDIRECT layers)
- Existing programs that don't use these helpers continue to function normally
- The `bpf_sock_addr_t` context structure remains unchanged to maintain ABI compatibility

## See Also

- [eBPF Extensions Documentation](eBpfExtensions.md)
- [Windows Filtering Platform (WFP) Layer Reference](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/filtering-layer-identifiers)