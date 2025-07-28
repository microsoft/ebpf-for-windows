
# EBPF for Windows Stream Inspection Hook

## Purpose

Support an eBPF interface to support inspecting TCP stream data and then based on that allowing/blocking the connection.

On linux today, this can be done, but there is no simple or well constrained way to support this.

The new stream hooks are designed to enhance the data processing capabilities of the system by providing efficient, scalable, and secure mechanisms for handling data streams. These hooks will be integrated into the existing infrastructure to support real-time data processing and analytics.

## eBPF Design

The proposed stream inspection extension introduces a new eBPF program type for stream-layer flow classification, with three distinct hooks to enable fine-grained, stateful inspection and control of TCP connections:

### Program Type

- **EBPF_PROGRAM_TYPE_FLOW_CLASSIFY**: A new program type for stream-layer flow classification. Programs of this type can be attached to one or more of the hooks described below.

### Hooks

1. **new_flow_classify**
   - **Invocation:** Invoked when a new TCP flow is established (at the WFP flow established layer).
   - **Purpose:** Allows the eBPF program to make an initial classification decision based on connection metadata (addresses, ports, process, etc.) before any stream data is seen.
   - **Return values:**
     - `FLOW_CLASSIFY_ALLOW`: The flow is permitted and will not be further inspected at the stream layer; no additional hook invocations for this flow.
     - `FLOW_CLASSIFY_NEED_MORE_DATA`: The flow requires further inspection at the stream layer; subsequent TCP segments will trigger `stream_flow_classify` invocations.
   - **Notes:** This avoids unnecessary stream processing for flows that do not require data inspection at the stream layer.

2. **stream_flow_classify**
   - **Invocation:** Called for each TCP segment on flows that were marked as needing more data by `new_flow_classify`.
   - **Purpose:** Allows the eBPF program to inspect stream data and make allow/block decisions, or request more data if the classification is not yet possible.
   - **Return values:**
     - `FLOW_CLASSIFY_ALLOW`: The flow is permitted; no further stream inspection for this flow.
     - `FLOW_CLASSIFY_BLOCK`: The flow is blocked; all further data is dropped (WFP ABSORB), and the connection will be terminated or time out.
     - `FLOW_CLASSIFY_NEED_MORE_DATA`: The current segment is allowed, but the program will be invoked again for subsequent segments until a final decision is made.
   - **Notes:** This enables stateful, multi-segment inspection and supports protocols that require parsing multiple segments before a decision can be made.

3. **flow_deleted**
   - **Invocation:** Called when a flow is deleted (e.g., connection teardown) and the last action for the flow was `FLOW_CLASSIFY_NEED_MORE_DATA` (i.e., the program never returned a final allow/block decision).
   - **Purpose:** Allows the eBPF program to perform cleanup of any per-flow state (e.g., in maps) that was allocated during inspection.
   - **Return value:**
     - Ignored
   - **Notes:** This hook is only invoked for flows that were being actively classified and not for those that were allowed immediately.


```c
typedef enum _flow_classify_action
{
    FLOW_CLASSIFY_ALLOW,
    FLOW_CLASSIFY_BLOCK,
    FLOW_CLASSIFY_NEED_MORE_DATA,
} flow_classify_action_t;

typedef enum _flow_direction
{
    FLOW_DIRECTION_INBOUND,
    FLOW_DIRECTION_OUTBOUND,
} flow_direction_t;

typedef enum _flow_state
{
    FLOW_STATE_NEW,
    FLOW_STATE_ESTABLISHED,
    FLOW_STATE_DELETED,
    FLOW_STATE_INVALID,
} flow_state_t;

// typedef bpf_sock_ops_t bpf_flow_classify_t; // FIXME: temporary hack

typedef struct _bpf_flow_classify
{
    uint32_t family; ///< IP address family.
    struct
    {
        union
        {
            uint32_t local_ip4;
            uint32_t local_ip6[4];
        }; ///< Local IP address.
        uint32_t local_port;
    }; ///< Local IP address and port stored in network byte order.
    struct
    {
        union
        {
            uint32_t remote_ip4;
            uint32_t remote_ip6[4];
        }; ///< Remote IP address.
        uint32_t remote_port;
    }; ///< Remote IP address and port stored in network byte order.
    uint8_t protocol;        ///< IP protocol.
    uint32_t compartment_id; ///< Network compartment Id.
    uint64_t interface_luid; ///< Interface LUID.
    uint8_t direction;       ///< 0 = inbound, 1 = outbound
    uint64_t flow_id;        ///< WFP flow handle
    uint32_t state;          ///< State of the flow.
    uint8_t* data_start;     ///< Pointer to start of stream segment data
    uint8_t* data_end;       ///< Pointer to end of stream segment data
} bpf_flow_classify_t;

/*
 * @brief Select flows for stream layer classification
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_FLOW_CLASSIFY
 *
 * Attach type(s):
 * \ref EBPF_ATTACH_TYPE_FLOW_CLASSIFY
 *
 * @param[in] context \ref bpf_flow_classify_t
 * @return ALLOW to ignore(allow) this flow, NEED_MORE_DATA for stream layer classification.
 */
typedef flow_classify_action_t
new_flow_classify_hook_t(bpf_flow_classify_t* context);

/*
 * @brief Handle flow classification (stream inspection).
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_FLOW_CLASSIFY
 *
 * Attach type(s):
 * \ref EBPF_ATTACH_TYPE_FLOW_CLASSIFY
 *
 * @param[in] context \ref bpf_flow_classify_t
 * @return classification decision (allow, block, or need more data to decide).
 */
typedef flow_classify_action_t
stream_flow_classify_hook_t(bpf_flow_classify_t* context);

/*
 * @brief Handle deletion of a flow that is still being classified
 *
 * Called for flows where the last return value was NEED_MORE_DATA
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_FLOW_CLASSIFY
 *
 * Attach type(s):
 * \ref EBPF_ATTACH_TYPE_FLOW_CLASSIFY
 *
 * @param[in] context \ref bpf_flow_classify_t
 * @return classification decision (allow, block, or need more data to decide).
 */
typedef flow_classify_action_t
flow_deleted_hook_t(bpf_flow_classify_t* context);

```

### Hook Integration and Flow

- The extension uses the Windows Filtering Platform (WFP) to register callouts at both the flow established and stream layers.
- When a new TCP flow is established, the extension initializes a per-flow context and invokes the `new_flow_classify` hook.
- The program can return ALLOW/NEED_MORE_DATA to ignore the flow or classify the flow at the stream layer.
- If further inspection is needed, the extension associates the context with the WFP stream layer and enables conditional stream callouts for this flow only (using the WFP `CONDITIONAL_ON_FLOW` flag).
- For each TCP segment, the extension invokes the `stream_flow_classify` hook, passing the current segment data and flow metadata. The program can allow, block, or request more data as needed.
- If the program returns `FLOW_CLASSIFY_ALLOW` or `FLOW_CLASSIFY_BLOCK`, the extension disables further stream callouts for this flow and releases the context.
- If the flow is deleted while still in the `NEED_MORE_DATA` state (i.e., no final decision was made), the extension invokes the `flow_deleted` hook for cleanup.