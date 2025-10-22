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
- You need **interface information** for authorization decisions
- You need **tunnel type** information
- You want to **authorize or deny** connections (not redirect them)
- Your policy depends on route-dependent metadata

## Implementation Details

### Program Type
Both AUTH_CONNECT attach types use the `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` program type, sharing the same context structure and helper functions as other sock_addr programs.

### Verdict Handling
AUTH_CONNECT programs can return:
- `BPF_SOCK_ADDR_VERDICT_PROCEED` - Allow the connection
- `BPF_SOCK_ADDR_VERDICT_REJECT` - Deny the connection

Note: Redirect functionality is not supported at the AUTH_CONNECT layer since route selection has already occurred.

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
    // Get interface information (available at auth layer)
    uint32_t interface_index = ctx->interface_index;

    // Apply interface-specific policy
    if (is_restricted_interface(interface_index)) {
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
    if (ctx->tunnel_type != TUNNEL_TYPE_NONE) {
        // Apply tunnel-specific security policy
        return apply_tunnel_policy(ctx);
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
2. **Do you need interface/tunnel information?** → Use AUTH_CONNECT attach types
3. **Do you only need basic connection info for authorization?** → Either type works, but AUTH_CONNECT provides more context

## See Also

- [eBPF Extensions Documentation](eBpfExtensions.md)
- [Windows Filtering Platform (WFP) Layer Reference](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/filtering-layer-identifiers)