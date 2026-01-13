# Proposal: BPF Socket Operations Flow ID Access

## Summary

This proposal introduces a new helper function `bpf_sock_ops_get_flow_id()` that will allow eBPF
socket operations (sock_ops) programs to access a unique flow identifier associated with network
connections. This enhancement enables eBPF programs to correlate network events with flow tracking
for advanced network monitoring, security analysis, and troubleshooting scenarios.

Unlike the 5-tuple (source IP, source port, destination IP, destination port, protocol) which can 
be reused as connections end and are recycled, this flow identifier guarantees uniqueness throughout 
the flow's lifetime. Additionally, this identifier is used internally by the Windows networking stack 
for operations like direct connection termination (via FwpsFlowAbort), making it essential for full 
integration with Windows network management APIs.

## Background

Network connections in Windows are managed by the Windows Filtering Platform (WFP), which assigns 
unique flow identifiers to each network connection. These identifiers are fundamental to the Windows 
networking stack and are used for operations such as:

- Direct connection termination via `FwpsFlowAbort()`
- Flow statistics and telemetry collection
- Network policy enforcement and filtering
- Connection tracking across multiple layers of the networking stack

Currently, eBPF socket operations programs can observe connection events and extract connection 
metadata (IP addresses, ports, protocol, etc.), but they cannot access the flow identifier. This 
limitation prevents eBPF programs from integrating with Windows network management tools such as:

- Network diagnostic and troubleshooting utilities
- Performance monitoring and analytics platforms
- Security analysis and intrusion detection systems
- Network policy compliance and enforcement tools
- Connection-level QoS and bandwidth management applications

Without access to the flow identifier, eBPF programs cannot:

- Correlate eBPF events with other Windows networking tools and infrastructure
- Implement flow-based tracking that integrates with system networking operations
- Perform operations requiring the flow identifier (like direct connection termination)
- Enable user-space applications to act on flow-specific information discovered by eBPF programs

## Proposed Changes

### 1. New Helper Function

A new program-type specific helper function will be introduced for sock_ops programs:

```c
/**
 * @brief Get the flow ID associated with the current sock_ops context.
 *
 * @param[in] ctx Pointer to bpf_sock_ops_t context.
 *
 * @return The flow ID as a 64-bit unsigned integer, or 0 if not available.
 */
EBPF_HELPER(uint64_t, bpf_sock_ops_get_flow_id, (bpf_sock_ops_t * ctx));
```

**Key characteristics:**
- **Function ID**: `BPF_FUNC_sock_ops_get_flow_id` (0x10000)
- **Program Type**: Exclusive to `BPF_PROG_TYPE_SOCK_OPS`
- **Return Value**: 64-bit flow identifier (implementation may use the WFP flow ID)
- **Context**: Requires valid `bpf_sock_ops_t` context pointer

**Flow identifier semantics:**
- The helper returns an opaque 64-bit value that uniquely identifies the flow for its lifetime.
- The current implementation will derive this value from the WFP flow handle to allow interoperability
    with APIs such as `FwpsFlowAbort()`, but callers should treat it as an opaque identifier rather
    than a raw WFP handle.

### 2. Context Enhancement

The internal sock_ops context structure will be extended to store the WFP flow ID:

```c
typedef struct _net_ebpf_bpf_sock_ops
{
    EBPF_CONTEXT_HEADER;
    bpf_sock_ops_t context;
    uint64_t process_id;
    uint64_t flow_id; ///< Flow identifier (implemented using the WFP flow handle).
} net_ebpf_sock_ops_t;
```

**Note:** This shows the proposed structure to be implemented. The `flow_id` field does not currently exist.
The flow ID will be populated during the flow establishment phase when WFP metadata is available.

### 3. Helper Function Registration

The helper function will be registered as a program-type specific helper:

```c
enum _sock_ops_program_specific_helper_functions
{
    // Function ID reserved for bpf_sock_ops_get_flow_id() helper.
    SOCK_OPS_PROGRAM_SPECIFIC_HELPER_GET_FLOW_ID = 0x10000,
};
```

This ensures the helper will only be available to sock_ops programs and maintains proper isolation between program types.

## Use Cases

The flow identifier will enable several important scenarios:

1. **Network Security Monitoring** - Correlate eBPF-observed connection events with other security 
tools for comprehensive threat detection and response.

2. **Performance Analysis** - Track connections across multiple observation points to diagnose 
network performance issues and bottlenecks.

3. **Policy Compliance Monitoring** - Verify that connections follow organizational policies and 
enable enforcement of network policies at the connection level.

4. **Connection Termination** - Enable user-space applications to terminate specific connections 
using the flow ID with system APIs like `FwpsFlowAbort()`.

5. **Advanced Network Analytics** - Correlate eBPF-collected data with flow-level information for 
sophisticated network analysis and anomaly detection.

## Implementation Details

### Files Modified

1. **Core API Changes (planned):**
    - `include/ebpf_nethooks.h`: Helper function declaration and ID definition
    - `netebpfext/net_ebpf_ext_program_info.h`: Helper function registration
    - `netebpfext/net_ebpf_ext_sock_ops.c`: Helper function implementation and context enhancement

2. **Testing Infrastructure (planned additions):**
    - `tests/sample/sockops_flow_id.c`: Proposed comprehensive test program demonstrating usage
    - `tests/socket/socket_tests.cpp`: Integration tests for flow ID functionality
    - `tests/end_to_end/helpers.h`: Proposed test helper utilities

### Technical Implementation

**Flow ID Storage (planned):**
- The WFP flow ID will be captured from the existing `incoming_metadata_values->flowHandle` metadata field during the `net_ebpf_extension_sock_ops_flow_established_classify` function
- The flow ID will be read from this existing field (no new WFP metadata fields are introduced by this proposal) and copied to the sock_ops context
- The flow ID will remain valid for the lifetime of the network connection

**Helper Function Implementation (proposed):**
```c
static uint64_t
_ebpf_sock_ops_get_flow_id(
    uint64_t dummy_param1,
    uint64_t dummy_param2,
    uint64_t dummy_param3,
    uint64_t dummy_param4,
    uint64_t dummy_param5,
    _In_ const bpf_sock_ops_t* ctx)
{
    // Use CONTAINING_RECORD (Windows macro similar to Linux container_of)
    // to get the extended context from the public context pointer.
    const net_ebpf_sock_ops_t* sock_ops_ctx = CONTAINING_RECORD(ctx, net_ebpf_sock_ops_t, context);
    return sock_ops_ctx->flow_id;
}
```

**Implementation Notes:**
- The five dummy parameters are part of the internal eBPF helper function dispatch mechanism, which reserves slots for up to 5 arguments before the context parameter
- The public API (line 58) shows the logical single-parameter interface that programs use
- `CONTAINING_RECORD` is a Windows macro (similar to Linux `container_of`) used to retrieve the extended context structure from the embedded public context
**Program-Type Specificity:**
- The helper will be registered as program-type specific with ID `0x10000`
- This will prevent other program types from accessing sock_ops specific functionality
- This will maintain the eBPF security model and program isolation

### Error Handling

The implementation will provide robust error handling:
- **Invalid Context**: The helper will validate the context pointer before accessing flow ID
- **Uninitialized Flow**: Will return 0 for connections without associated WFP flows
- **Memory Safety**: Will use proper container macros to access the extended context safely

### Backward Compatibility

- The change will be fully backward compatible with existing sock_ops programs
- Programs not using the new helper function will continue to work unchanged
- The additional context field will not affect existing functionality
- A new helper function ID will be allocated from the program-specific range to avoid conflicts

## Testing Strategy

The implementation will include comprehensive test coverage:

### 1. Unit Tests
- Helper function registration and invocation
- Context structure validation
- Flow ID storage and retrieval
- Error condition handling

### 2. Integration Tests
- End-to-end flow ID tracking through connection lifecycle
- Tests will support both IPv4 and IPv6 connections
- Multiple connection types (TCP, UDP where applicable)
- Process correlation validation

### 3. Functional Tests
- Real network connection flow ID validation
- Ring buffer event correlation
- Map storage and retrieval operations
- Flow establishment and deletion tracking

### Test Program Structure
The proposed test program (`sockops_flow_id.c`) will demonstrate:
- Flow ID extraction during different sock_ops events
- Storage in hash maps for later verification
- Ring buffer logging for event correlation
- Support for both IPv4 and IPv6 connections

## Security Considerations

### Access Control

- Flow IDs will only be accessible to sock_ops programs running in kernel context
- The helper function will validate the program context before returning flow information
- No sensitive information beyond the flow ID will be exposed

### Information Disclosure

- WFP flow IDs are system-internal identifiers and do not expose sensitive user data
- Flow IDs can be used for correlation but do not reveal packet contents or user credentials
- The information available through this helper is already accessible through other WFP APIs

### Privilege Requirements

- Programs using this helper will need the same privileges as other sock_ops programs
- No additional permissions or capabilities will be required
- Standard eBPF program loading and verification will apply

## Performance Impact

### Runtime Performance
- **Helper Call Overhead**: Minimal—simple memory access to a pre-stored flow ID
- **Context Storage**: 8 additional bytes per sock_ops context (negligible impact)
- **Flow Establishment**: No additional overhead—flow ID will be captured from existing WFP metadata

### Memory Impact
- **Context Size**: Increased by 8 bytes per active sock_ops context
- **Helper Registration**: Minimal static memory for helper function tables
- **No Dynamic Allocation**: All changes will use existing memory allocation patterns

### Scalability
- Flow ID access will scale linearly with connection volume
- No new global locks or shared resources will be introduced
- Performance characteristics will remain aligned with other sock_ops helpers

## Future Enhancements

This foundation enables several potential future improvements:

### 1. Extended WFP Metadata Access
- Additional WFP properties (layer information, callout data)
- Flow classification results
- QoS and bandwidth management information

### 2. Cross-Program Communication
- Flow ID-based communication between different eBPF program types
- Shared flow tracking across XDP, TC, and sock_ops programs
- Integration with other Windows networking APIs

### 3. Advanced Analytics
- Historical flow tracking and analysis
- ML-based anomaly detection using flow correlation
- Integration with Windows Event Tracing (ETW)

### 4. Policy Integration
- Dynamic policy updates based on flow analysis
- Real-time threat response using flow correlation
- Integration with Windows Defender and security frameworks

## Conclusion

The BPF socket operations flow ID access feature will provide essential correlation capabilities
between eBPF programs and the Windows Filtering Platform. This enhancement will enable sophisticated
network monitoring, security analysis, and troubleshooting scenarios while maintaining the
performance and security characteristics of the eBPF for Windows platform.

The implementation will be minimal, efficient, and well-tested, providing value for network
monitoring applications while establishing a foundation for future WFP integration enhancements.
The program-type specific helper approach will ensure proper isolation and security while maximizing
utility for sock_ops programs.

This feature will bridge a critical gap between eBPF observability and Windows networking
infrastructure, and will enable new classes of network analysis and security applications on the Windows
platform.