# eBPF for Windows Listen Hook

## Contents

- [eBPF for Windows Listen Hook](#ebpf-for-windows-listen-hook)
  - [Contents](#contents)
  - [Purpose](#purpose)
  - [Requirements](#requirements)
  - [Design Rationale](#design-rationale)
  - [eBPF Design](#ebpf-design)
    - [Program Type](#program-type)
    - [Attach Types](#attach-types)
    - [Context Structure](#context-structure)
    - [Return Values](#return-values)
  - [Architecture](#architecture)
    - [Hook Integration and Flow](#hook-integration-and-flow)
    - [WFP Layer Integration](#wfp-layer-integration)
  - [WFP Implementation Details](#wfp-implementation-details)
    - [Supported WFP Fields](#supported-wfp-fields)
    - [Filter Configuration](#filter-configuration)
  - [Use Cases](#use-cases)
    - [Security and Access Control](#security-and-access-control)
    - [Monitoring and Auditing](#monitoring-and-auditing)
    - [Resource Management](#resource-management)
    - [Example eBPF Program](#example-ebpf-program)
  - [Performance Considerations](#performance-considerations)
    - [Optimization Strategies](#optimization-strategies)
    - [Expected Performance Impact](#expected-performance-impact)
    - [Benchmarking Metrics](#benchmarking-metrics)
  - [Implementation Plan](#implementation-plan)
    - [Phase 1: Core Infrastructure](#phase-1-core-infrastructure)
    - [Phase 2: Context Population](#phase-2-context-population)
    - [Phase 3: Testing and Validation](#phase-3-testing-and-validation)
    - [Phase 4: Documentation and Samples](#phase-4-documentation-and-samples)

---

## Purpose

Support an eBPF interface for intercepting and controlling socket listen operations on Windows by hooking into the Windows Filtering Platform (WFP) ALE (Application Layer Enforcement) Authorization Listen layers. This enables security and monitoring solutions to inspect, allow, or block listen operations before they are established.

The new hooks will support:
- Security solutions that need to control which applications can listen on specific ports
- Network monitoring and auditing solutions
- Process-based network access control

## Requirements

- Hook that allows intercepting socket listen operations for both IPv4 and IPv6
- Access to key socket and process information during listen authorization
- Ability to allow or block listen operations
- Support for multiple eBPF programs attached to the same hook
- Minimal performance impact on non-monitored traffic
- Integration with existing eBPF for Windows infrastructure

## Design Rationale

Linux does not currently provide `BPF_CGROUP_INET4_LISTEN` or `BPF_CGROUP_INET6_LISTEN` attach types. Listen interception in Linux is typically done via LSM hooks (`security_socket_listen`). However, eBPF for Windows follows the `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` pattern for socket operations, which provides a consistent programming model.

This design adds new listen attach types to the existing `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` program type, following the same pattern used for:
- `BPF_CGROUP_INET4_CONNECT` / `BPF_CGROUP_INET6_CONNECT`
- `BPF_CGROUP_INET4_RECV_ACCEPT` / `BPF_CGROUP_INET6_RECV_ACCEPT`

Key considerations:
- Reusing the existing program type and context structure provides consistency and reduces implementation complexity
- The `bpf_sock_addr_t` context already contains all fields needed for listen operations (local address, port, protocol, compartment_id, interface_luid)
- Existing helper functions (e.g., `bpf_get_current_pid_tgid()`) are automatically available

## eBPF Design

The listen hook extends the existing `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` program type with new attach types for intercepting socket listen operations through the Windows Filtering Platform ALE Authorization Listen layers. This approach follows the same pattern used for connect and recv_accept hooks.

### Program Type

The listen hook reuses the existing **BPF_PROG_TYPE_CGROUP_SOCK_ADDR** program type, which is already used for:
- `BPF_CGROUP_INET4_CONNECT` / `BPF_CGROUP_INET6_CONNECT`
- `BPF_CGROUP_INET4_RECV_ACCEPT` / `BPF_CGROUP_INET6_RECV_ACCEPT`

This provides consistency with existing socket address hooks and allows programs to share helper functions and infrastructure.

### Attach Types

Two new attach types are added to the standard `bpf_attach_type` enum to support IPv4 and IPv6 listen operations:

```c
// Added to bpf_attach_type enum:
BPF_CGROUP_INET4_LISTEN,  ///< IPv4 socket listen operations
BPF_CGROUP_INET6_LISTEN,  ///< IPv6 socket listen operations
```

Each attach type has a corresponding GUID identifier:

```c
#define EBPF_ATTACH_TYPE_CGROUP_INET4_LISTEN_GUID                                      \
    {                                                                                  \
        0xe1b0cb3d, 0xd70c, 0x4ee2, { 0xb2, 0x3a, 0x07, 0x42, 0xbe, 0xdb, 0x06, 0xd6 } \
    }
/** @brief Attach type for handling IPv4 socket listen operations.
 *
 * Program type: \ref BPF_PROG_TYPE_CGROUP_SOCK_ADDR
 */
__declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_CGROUP_INET4_LISTEN =
    EBPF_ATTACH_TYPE_CGROUP_INET4_LISTEN_GUID;

#define EBPF_ATTACH_TYPE_CGROUP_INET6_LISTEN_GUID                                      \
    {                                                                                  \
        0x4e72f92e, 0x5ed0, 0x4fe5, { 0xb8, 0x51, 0xb1, 0x24, 0xfe, 0x14, 0x07, 0x4d } \
    }
/** @brief Attach type for handling IPv6 socket listen operations.
 *
 * Program type: \ref BPF_PROG_TYPE_CGROUP_SOCK_ADDR
 */
__declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_CGROUP_INET6_LISTEN =
    EBPF_ATTACH_TYPE_CGROUP_INET6_LISTEN_GUID;
```

### Context Structure

The listen hook uses the existing `bpf_sock_addr_t` context structure:

```c
/**
 * @brief Data structure used as context for BPF_PROG_TYPE_CGROUP_SOCK_ADDR program type.
 */
typedef struct bpf_sock_addr
{
    uint32_t family;         ///< IP address family (AF_INET or AF_INET6).
    struct
    {
        /**
         * @brief Source IP address in network byte order.
         * For listen operations, this contains the local address.
         */
        union
        {
            uint32_t msg_src_ip4;
            uint32_t msg_src_ip6[4];
        };
        uint16_t msg_src_port; ///< Source port in network byte order.
    };
    struct
    {
        /**
         * @brief Destination IP address in network byte order.
         * For listen operations, this is unused (set to zero).
         */
        union
        {
            uint32_t user_ip4;
            uint32_t user_ip6[4];
        };
        uint16_t user_port;  ///< Destination port (unused for listen).
    };
    uint32_t protocol;       ///< IP protocol (typically IPPROTO_TCP).
    uint32_t compartment_id; ///< Network compartment ID.
    uint64_t interface_luid; ///< Interface LUID.
} bpf_sock_addr_t;
```

For listen operations:
- `msg_src_ip4`/`msg_src_ip6` and `msg_src_port` contain the local address and port the socket is listening on
- `user_ip4`/`user_ip6` and `user_port` are unused (set to zero)
- Process ID can be obtained via the `bpf_get_current_pid_tgid()` helper

### Return Values

The listen hook uses the existing `ebpf_sock_addr_verdict_t` return values:

```c
typedef enum _ebpf_sock_addr_verdict
{
    BPF_SOCK_ADDR_VERDICT_REJECT = 0,       ///< Block the listen operation.
    BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT = 1, ///< Allow with soft permit (can be overridden).
    BPF_SOCK_ADDR_VERDICT_PROCEED_HARD = 2  ///< Allow with hard permit (cannot be overridden).
} ebpf_sock_addr_verdict_t;
```

## Architecture

### Hook Integration and Flow

1. **Application Listen Request**: Application calls `bind()` and `listen()` on a socket
2. **WFP Interception**: WFP ALE_AUTH_LISTEN layer intercepts the operation
3. **eBPF Invocation**: Registered eBPF programs are invoked with listen context
4. **Program Execution**: Each program inspects the context and returns a verdict
5. **Action Processing**: WFP processes the verdict and allows/blocks the operation

```
Application
    |
    | bind()/listen()
    v
Windows Socket Layer
    |
    | WFP ALE_AUTH_LISTEN callout
    v
eBPF Listen Hook
    |
    | bpf_sock_addr_t context
    v
eBPF Program(s)
    |
    | BPF_SOCK_ADDR_VERDICT_*
    v
WFP Action Processing
    |
    | Allow/Block
    v
Socket Operation Result
```

### WFP Layer Integration

The listen hook integrates with two specific WFP layers:

- **FWPM_LAYER_ALE_AUTH_LISTEN_V4**: IPv4 socket listen authorization
- **FWPM_LAYER_ALE_AUTH_LISTEN_V6**: IPv6 socket listen authorization

These layers provide access to comprehensive information about the listen operation including process context, socket details, and network parameters.

## WFP Implementation Details

### Supported WFP Fields

The following WFP fields from the ALE_AUTH_LISTEN layers are made available to eBPF programs through the `bpf_sock_addr_t` context:

| WFP Field Identifier | Description | Context Field |
|---------------------|-------------|---------------|
| FWPM_CONDITION_IP_LOCAL_ADDRESS | Local IP address | msg_src_ip4/msg_src_ip6 |
| FWPM_CONDITION_IP_LOCAL_PORT | Local port | msg_src_port |
| FWPM_CONDITION_IP_PROTOCOL | IP protocol | protocol |
| FWPM_CONDITION_COMPARTMENT_ID | Compartment ID | compartment_id |
| FWPM_CONDITION_IP_LOCAL_INTERFACE | Interface LUID | interface_luid |

Process ID can be obtained via the `bpf_get_current_pid_tgid()` helper function.

### Filter Configuration

WFP filters will be configured for each attach type:

```c
// IPv4 Listen Hook Filter Configuration
net_ebpf_extension_wfp_filter_parameters_t _cgroup_inet4_listen_filter_parameters[] = {
    {&FWPM_LAYER_ALE_AUTH_LISTEN_V4,
     NULL, // Default sublayer
     &EBPF_HOOK_ALE_AUTH_LISTEN_V4_CALLOUT,
     L"net eBPF listen hook",
     L"net eBPF listen hook WFP filter"}
};

// IPv6 Listen Hook Filter Configuration
net_ebpf_extension_wfp_filter_parameters_t _cgroup_inet6_listen_filter_parameters[] = {
    {&FWPM_LAYER_ALE_AUTH_LISTEN_V6,
     NULL, // Default sublayer
     &EBPF_HOOK_ALE_AUTH_LISTEN_V6_CALLOUT,
     L"net eBPF listen hook",
     L"net eBPF listen hook WFP filter"}
};
```

## Use Cases

### Security and Access Control

- **Port Access Control**: Restrict which processes can listen on privileged ports (< 1024)
- **Process Whitelisting**: Only allow authorized applications to open network listeners
- **User-based Restrictions**: Prevent certain users from opening network services

### Monitoring and Auditing

- **Network Service Discovery**: Track all network services started on the system
- **Compliance Monitoring**: Ensure network services comply with organizational policies
- **Threat Detection**: Detect unauthorized network listeners (potential malware)

### Resource Management

- **Service Conflict Prevention**: Prevent multiple services from conflicting on the same port
- **Resource Quotas**: Limit the number of listening sockets per process/user

### Example eBPF Program

```c
#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

SEC("cgroup/inet4_listen")
int monitor_listen_operations(bpf_sock_addr_t* ctx)
{
    // Only monitor TCP listeners
    if (ctx->protocol != IPPROTO_TCP) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    // Block privileged ports
    uint16_t port = bpf_ntohs(ctx->msg_src_port);
    if (port < 1024) {
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    // Log the listen operation
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = pid_tgid >> 32;
    bpf_printk("Process %u listening on port %u\n", pid, port);

    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}

char _license[] SEC("license") = "GPL";
```

## Performance Considerations

### Optimization Strategies

1. **Selective Filtering**: Only attach to relevant traffic using WFP filter conditions
2. **Early Exit**: Return quickly for uninteresting traffic
3. **Minimal Context**: Only populate necessary fields in the context structure
4. **Efficient Verdict Processing**: Fast-path for common allow/block decisions

### Expected Performance Impact

- **Minimal Overhead**: WFP callouts add ~1-5 microseconds per operation
- **Scalable Design**: Per-operation cost doesn't increase with number of active listeners
- **Efficient Memory Usage**: Context structure designed to minimize memory allocations

### Benchmarking Metrics

The implementation should be benchmarked against:
- Listen operation latency without hooks
- Listen operation latency with hooks (no programs attached)
- Listen operation latency with simple allow/block programs
- System throughput under high listener creation/destruction rates

---

## Implementation Plan

### Phase 1: Core Infrastructure
- Generate unique GUIDs for EBPF_ATTACH_TYPE_CGROUP_INET4_LISTEN and EBPF_ATTACH_TYPE_CGROUP_INET6_LISTEN
- Add attach type definitions to ebpf_program_attach_type_guids.h
- Register new attach types with the existing BPF_PROG_TYPE_CGROUP_SOCK_ADDR program type
- Extend netebpfext with ALE_AUTH_LISTEN layer support
- Implement WFP callout registration for listen layers

### Phase 2: Context Population
- Populate bpf_sock_addr_t context from WFP ALE_AUTH_LISTEN classify parameters
- Ensure existing helper functions work with the new attach types

### Phase 3: Testing and Validation
- Unit tests for WFP integration
- End-to-end tests with sample eBPF programs
- Performance benchmarking and optimization
- Security and stability testing

### Phase 4: Documentation and Samples
- Complete API documentation
- Sample programs for common use cases
- Integration guide for security products
- Best practices documentation

This listen hook implementation extends the existing sock_addr infrastructure to provide listen interception capabilities, enabling powerful control over socket listen operations while maintaining consistency with other sock_addr hooks.