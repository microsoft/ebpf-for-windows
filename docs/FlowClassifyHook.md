
# EBPF for Windows Stream Inspection Hook


## Contents

1. [Purpose](#purpose)
2. [Requirements](#requirements)
3. [Alternative - Using existing Linux hooks](#alternative---using-existing-linux-hooks)
4. [eBPF Design](#ebpf-design)
    - [Program Type](#program-type)
    - [Hooks](#hooks)
5. [Architecture](#architecture)
    - [Hook Integration and Flow](#hook-integration-and-flow)
    - [Stream Hook Lifecycle](#stream-hook-lifecycle)


---

## Purpose

Support an eBPF interface to support inspecting TCP stream data and then based on that allowing/blocking the connection.

The new hooks will support security and observability related solutions that require parsing TCP stream data
without incurring overhead for flows that can be ignored.

## Requirements

- Hook that allows choosing whether to classify a newly established TCP connection at the stream layer.
- Hook that receives each stream layer data segment in-order for both ingress and egress traffic.
  - 3 possible actions:
    - Allow the connection and stop being invoked for this flow.
    - Block the connection (no further invocations for this flow).
    - Allow the segment but keep getting invoked for further data segments (need more data to classify).
- Hook that supports cleanup of flows that were closed while still being classified.
- No eBPF programs should be invoked for segments on flows not needing stream layer classification.
- After a flow is allowed/block, there should be no further stream layer eBPF program invocations for the flow.
- We do not currently need any stream mutation support for these hooks -- only inspect/allow/block.

## Alternative - Using existing Linux hooks

Linux provides several eBPF program types, including:

- XDP: High-speed packet filtering and processing at the link layer.
- TC (Traffic Control): Packet shaping and filtering at the network and transport layers.
- SOCK_FILTER: Stream-layer filtering based on socket-level data, enabling payload inspection and application-specific processing.
- BPF_PROG_TYPE_SK_MSG: Socket-level filtering of outgoing messages being sent by attaching an SK_MSG program to an eBPF socket map.
- BPF_PROG_TYPE_SK_SKB: Socket parsing and filtering for incoming packets based on socket maps.
  - SK_SKB_STREAM_PARSER: L4 layer message parser for L7 protocol.
  - SK_SKB_STREAM_VERDICT: Pass/drop "messages" from stream.
  - SK_SKB_VERDICT: Pass/drop segments from TCP stream.

On linux today, the required functionality can be implemented using the above program types with socket maps, but there is no simple or well constrained way to support this.

- Requires multiple programs at multiple layers (and/or packet header parsing and TCP reassembly at a low network layer).
- There are no hooks for an eBPF program to classify _flows_ by inspecting _stream-layer_ data.
  - There are only hooks for classifying new flows and for classifying stream-layer messages.
  - Existing stream data classifying hooks only allow/drop individual packets/segments/messages.
  - Blocking connection requires injecting TCP RST, blocking individual packets/messages until timeout, or redirecting flows to a dummy socket.
- Most hooks only receive traffic in one direction.

## eBPF Design

The proposed stream inspection extension introduces a new eBPF program type for stream-layer flow classification, with three distinct hooks to enable fine-grained, stateful inspection and classification of TCP connections:

### Program Type

- **EBPF_PROGRAM_TYPE_FLOW_CLASSIFY**: A new program type for stream-layer flow classification. Programs of this type can be attached to one or more of the hooks described below.

_Note:_ Using a single program type for all 3 hooks enables tail calls between programs attached to the 3 hooks
to simplify flow classification designs.

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
```

### Hooks

1. **new_flow_classify**
   - **Invocation:** Invoked when a new TCP flow is established (at the WFP flow established layer).
   - **Purpose:** Allows the eBPF program to make an initial classification decision based on connection metadata (addresses, ports, process, etc.) before any stream data is seen.
   - **Return values:**
     - `FLOW_CLASSIFY_ALLOW`: The flow is permitted and will not be further inspected at the stream layer; no additional hook invocations for this flow.
     - `FLOW_CLASSIFY_NEED_MORE_DATA`: The flow requires inspection at the stream layer; subsequent TCP segments will trigger `stream_flow_classify` invocations.
   - **Notes:** This avoids unnecessary stream processing for flows that do not require data inspection at the stream layer.

2. **stream_flow_classify**
   - **Invocation:** Called for each TCP segment on flows that were marked as needing more data by `new_flow_classify`.
   - **Purpose:** Allows the eBPF program to inspect stream data and allow/block the connection, or request more data if classification is not yet possible.
   - **Return values:**
     - `FLOW_CLASSIFY_ALLOW`: The flow is permitted; no further stream inspection for this flow.
     - `FLOW_CLASSIFY_BLOCK`: The flow is blocked; all further data is dropped (using WFP ABSORB), and the connection will be terminated or time out.
     - `FLOW_CLASSIFY_NEED_MORE_DATA`: The current segment is allowed, but the program will be invoked again for subsequent segments until a final decision is made.
   - **Notes:** This is only invoked for each flow segment until allow/block are returned.

3. **flow_deleted**
   - **Invocation:** Called when a flow is deleted (e.g., connection teardown) and the last action for the flow was `FLOW_CLASSIFY_NEED_MORE_DATA` (i.e., the program never returned a final allow/block decision).
   - **Purpose:** Allows the eBPF program to perform cleanup of any per-flow state (e.g., in maps) that was maintained during inspection.
   - **Return value:**
     - Ignored
   - **Notes:** This hook is only invoked for flows that were still being actively classified and not for those that were allowed immediately.

```c
/*
 * @brief Select flows for stream layer classification
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_FLOW_CLASSIFY
 *
 * Attach type(s):
 * \ref EBPF_ATTACH_TYPE_NEW_FLOW_CLASSIFY
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
 * \ref EBPF_ATTACH_TYPE_STREAM_FLOW_CLASSIFY
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
 * \ref EBPF_ATTACH_TYPE_FLOW_DELETED
 *
 * @param[in] context \ref bpf_flow_classify_t
 * @return classification decision (allow, block, or need more data to decide).
 */
typedef flow_classify_action_t
flow_deleted_hook_t(bpf_flow_classify_t* context);
```
## Architecture

### Hook Integration and Flow

The extension uses the Windows Filtering Platform (WFP) to register callouts at both the flow established and stream layers.

1. When a new TCP flow is established, the extension initializes a per-flow context and invokes the `new_flow_classify` hook.
2. The program can return ALLOW/NEED_MORE_DATA to ignore the flow or classify the flow at the stream layer.

    b. If no stream-layer inspection is needed, the bpf program context is freed immediately.

    a. If further inspection is needed, the extension associates the context with the WFP stream layer callout to enable conditional callouts for this flow (using the WFP `CONDITIONAL_ON_FLOW` flag).
3. For each TCP segment, the extension invokes the `stream_flow_classify` hook, passing the current segment data and flow metadata. The program can allow/block the flow or request more data as needed.

    a. If the program returns `FLOW_CLASSIFY_ALLOW` or `FLOW_CLASSIFY_BLOCK` the context is freed and there will be no further invocations for this flow.

    b. If `FLOW_CLASSIFY_NEED_MORE_DATA` is returned, the current segment is allowed but the context is not freed.
4. If the flow is deleted while still in the NEED_MORE_DATA state (i.e., no final decision was made), the extension invokes the `flow_deleted` hook for cleanup.

### Stream Hook Lifecycle

1. **Load and Attach**
    - The lifecycle begins with the setup of WFP filters. These filters are configured to be called at flow established for all TCP flows, and at the stream layer only for flows with the wfp context still set.
2. **Flow Established Callback and Invocation**
    - Extension initializes bpf program context and invokes the `new_flow_classify` hook to decide whether to classify this flow at the stream layer.
    - Context is immediately freed if no classification is needed for this flow.
    - If classification is needed, the context is stored in the WFP stream layer callout context.
2. **Stream Callback and Invocation**
    - When stream data arrives, WFP triggers the extension through a callout. This callback serves as the starting point for invoking the eBPF `stream_flow_classify` programs.
    - The stream layer callout is only invoked for flows still requiring invocation (using WFP CONDITIONAL_ON_FLOW).
3. **eBPF Program Invocation**
    - The extension invokes eBPF filter programs in the order they were attached.
    - On each invocation, the eBPF program will be presented with the data for the current segment.
    - Classify programs inspect the stream segment data and classify the connection using return codes:
        - **Allow**: The connection is deemed safe and permitted to proceed without further inspection.
        - **Block**: Terminates the connection immediately.
        - **Need More Data**: Indicates the need for additional data for a conclusive decision. The extension allows the current segment and will invoke the program again for the next segment.
4. **Stream Inspection**
    - The eBPF program performs parsing/inspection tasks on the stream.
    - If the “Need More Data” return code is used, the inspection until a definitive decision is returned.
6. **Connection Termination or Continuation**
    - Once a decision other than "Need More Data" is reached (Allow or Block), the lifecycle for that connection ends within the context of the filter program.
    - For “Block,” the connection is terminated.
    - For “Allow,” the connection proceeds without further filtering.
    - If a connection is terminated while still being classified, the `flow_deleted` hook is invoked.

_Notes:_

- The [Windows Stream Inspection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/stream-inspection)
API is used for inspecting the stream-layer data via WFP callouts.
- the WFP `CONDITIONAL_ON_FLOW` flag means the stream-layer callout will only run for flows where the stream-layer WFP context (containing the bpf program context) is set.
  - The context is freed immediately if the flow is allowed at the flow established layer.
  - Otherwise the context is freed when an allow/block decision is made or the flow is deleted.
- When returning NEED_MORE_DATA, the current data segment is allowed (but the hook will keep getting invoked).
- Multiple eBPF programs can be invoked for a single stream, but the decision is finalized based on the first conclusive return code.
- No stream mutation is supported through these hooks (only inspection and allow/block).