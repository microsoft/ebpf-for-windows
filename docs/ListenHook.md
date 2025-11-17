# eBPF for Windows Listen Hook

## Contents

- [eBPF for Windows Listen Hook](#ebpf-for-windows-listen-hook)
  - [Contents](#contents)
  - [Purpose](#purpose)
  - [Requirements](#requirements)
  - [Alternative - Using existing Linux hooks](#alternative---using-existing-linux-hooks)
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
    - [Phase 2: Context and Helpers](#phase-2-context-and-helpers)
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

## Alternative - Using existing Linux hooks

Linux provides several eBPF program types that can be used for similar functionality:

- **BPF_PROG_TYPE_CGROUP_SOCK**: Socket creation and binding control at the cgroup level
- **BPF_PROG_TYPE_CGROUP_SOCK_ADDR**: Socket address operations including bind operations
- **LSM hooks**: Linux Security Module hooks for socket operations

However, these approaches have limitations:
- Linux hooks operate at different abstraction levels than Windows WFP
- Different network stack architecture between Linux and Windows
- Linux cgroup model doesn't directly map to Windows process/session model
- WFP provides more granular control and integration with Windows security model

## eBPF Design

The listen hook extension introduces a new eBPF program type for intercepting socket listen operations through the Windows Filtering Platform ALE Authorization Listen layers.

### Program Type

- **BPF_PROG_TYPE_SOCK_LISTEN**: A new program type specifically for socket listen operations. This program type is dedicated to intercepting and controlling socket listen operations through the WFP ALE Authorization Listen layers.

The program type will have a corresponding GUID identifier:

```c
#define EBPF_PROGRAM_TYPE_SOCK_LISTEN_GUID                                             \
    {                                                                                  \
        0x577a6a4d, 0x386d, 0x4238, { 0xab, 0xc6, 0x0a, 0xce, 0x9a, 0x94, 0x00, 0x95 } \
    }

/** @brief Program type for handling socket listen operations.
 *
 * eBPF program prototype: \ref listen_hook_t
 *
 * Attach type(s):
 *  \ref EBPF_ATTACH_TYPE_CGROUP_INET4_LISTEN
 *  \ref EBPF_ATTACH_TYPE_CGROUP_INET6_LISTEN
 *
 * Helpers available: see bpf_helpers.h
 */
__declspec(selectany) ebpf_program_type_t EBPF_PROGRAM_TYPE_SOCK_LISTEN = EBPF_PROGRAM_TYPE_SOCK_LISTEN_GUID;
```

### Attach Types

Two new attach types will be added to the standard `bpf_attach_type` enum to support IPv4 and IPv6 listen operations:

```c
// Added to bpf_attach_type enum:
BPF_CGROUP_INET4_LISTEN,  ///< IPv4 socket listen operations
BPF_CGROUP_INET6_LISTEN,  ///< IPv6 socket listen operations
```

Each attach type will have corresponding GUID identifiers:

```c
#define EBPF_ATTACH_TYPE_CGROUP_INET4_LISTEN_GUID                                      \
    {                                                                                  \
        0xe1b0cb3d, 0xd70c, 0x4ee2, { 0xb2, 0x3a, 0x07, 0x42, 0xbe, 0xdb, 0x06, 0xd6 } \
    }
/** @brief Attach type for handling IPv4 socket listen operations.
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_SOCK_LISTEN
 */
__declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_CGROUP_INET4_LISTEN =
    EBPF_ATTACH_TYPE_CGROUP_INET4_LISTEN_GUID;

#define EBPF_ATTACH_TYPE_CGROUP_INET6_LISTEN_GUID                                      \
    {                                                                                  \
        0x4e72f92e, 0x5ed0, 0x4fe5, { 0xb8, 0x51, 0xb1, 0x24, 0xfe, 0x14, 0x07, 0x4d } \
    }
/** @brief Attach type for handling IPv6 socket listen operations.
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_SOCK_LISTEN
 */
__declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_CGROUP_INET6_LISTEN =
    EBPF_ATTACH_TYPE_CGROUP_INET6_LISTEN_GUID;
```

### Context Structure

The listen hook will use an extended version of the existing `bpf_sock_addr_t` structure with additional fields relevant to listen operations:

```c
/**
 * @brief Context structure for listen hook operations.
 * Extends bpf_sock_addr_t with listen-specific fields.
 */
typedef struct bpf_sock_addr_listen
{
    uint32_t family;         ///< IP address family (AF_INET or AF_INET6).

    struct
    {
        /**
         * @brief Local IP address in network byte order.
         * The address the socket is attempting to bind/listen on.
         */
        union
        {
            uint32_t local_ip4;
            uint32_t local_ip6[4];
        };
        uint16_t local_port;     ///< Local port in network byte order.
    };

    uint32_t protocol;           ///< IP protocol (IPPROTO_TCP, IPPROTO_UDP, etc.).
    uint32_t compartment_id;     ///< Network compartment ID.
    uint64_t interface_luid;     ///< Interface LUID.

    // Listen-specific fields from WFP ALE_AUTH_LISTEN layers
    uint64_t process_id;         ///< Process ID of the listening application.
    uint32_t flags;              ///< ALE authorization flags.
    uint32_t socket_type;        ///< Socket type (SOCK_STREAM, SOCK_DGRAM, etc.).
    uint32_t interface_type;     ///< Interface type.
    uint32_t tunnel_type;        ///< Tunnel type.
} bpf_sock_addr_listen_t;
```

### Return Values

The listen hook will use a dedicated verdict system for listen operations:

```c
/**
 * @brief Return values for listen hook programs.
 */
typedef enum _ebpf_listen_verdict
{
    BPF_LISTEN_VERDICT_REJECT = 0,        ///< Block the listen operation.
    BPF_LISTEN_VERDICT_PROCEED_SOFT = 1,  ///< Allow with soft permit (can be overridden).
    BPF_LISTEN_VERDICT_PROCEED_HARD = 2   ///< Allow with hard permit (cannot be overridden).
} ebpf_listen_verdict_t;
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
    | bpf_sock_addr_listen_t context
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

The following WFP fields from the ALE_AUTH_LISTEN layers will be made available to eBPF programs:

| WFP Field Identifier | Description | Context Field |
|---------------------|-------------|---------------|
| FWPM_CONDITION_IP_LOCAL_ADDRESS | Local IP address | local_ip4/local_ip6 |
| FWPM_CONDITION_IP_LOCAL_PORT | Local port | local_port |
| FWPM_CONDITION_IP_PROTOCOL | IP protocol | protocol |
| FWPM_CONDITION_ALE_PROCESS_ID | Process ID | process_id |
| FWPM_CONDITION_COMPARTMENT_ID | Compartment ID | compartment_id |
| FWPM_CONDITION_IP_LOCAL_INTERFACE | Interface LUID | interface_luid |
| FWPM_CONDITION_FLAGS | ALE flags | flags |
| FWPM_CONDITION_INTERFACE_TYPE | Interface type | interface_type |
| FWPM_CONDITION_TUNNEL_TYPE | Tunnel type | tunnel_type |

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

SEC("listen")
int monitor_listen_operations(bpf_sock_addr_listen_t* ctx)
{
    // Only monitor TCP listeners
    if (ctx->protocol != IPPROTO_TCP) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    // Block privileged ports for non-privileged processes
    uint16_t port = bpf_ntohs(ctx->local_port);
    if (port < 1024) {
        // Block all privileged port access
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    // Log the listen operation
    bpf_printk("Process %llu listening on port %u\n",
               ctx->process_id, port);

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
- Generate unique GUIDs for EBPF_PROGRAM_TYPE_SOCK_LISTEN and EBPF_ATTACH_TYPE_CGROUP_INET*_LISTEN
- Add program type and attach type definitions to ebpf_program_attach_type_guids.h
- Extend netebpfext with ALE_AUTH_LISTEN layer support
- Implement basic WFP callout registration
- Add new attach types to eBPF infrastructure
- Add multi-instance capability for isolated program execution

### Phase 2: Context and Helpers
- Implement bpf_sock_listen_t context population
- Integrate with existing helper infrastructure for the new program type

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

This listen hook implementation provides a comprehensive foundation for network security and monitoring capabilities in eBPF for Windows, enabling powerful control over socket listen operations while maintaining the performance and reliability expected from the Windows networking stack.