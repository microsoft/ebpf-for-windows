
# EBPF for Windows Stream Inspection Hook


## Contents

1. [Purpose](#purpose)
2. [Requirements](#requirements)
3. [Alternative - Using existing Linux hooks](#alternative---using-existing-linux-hooks)
4. [eBPF Design](#ebpf-design)
    - [Program Type](#program-type)
    - [Attach Types](#attach-types)
    - [Hooks](#hooks)
5. [Architecture](#architecture)
    - [Hook Integration and Flow](#hook-integration-and-flow)
    - [Stream Hook Lifecycle](#stream-hook-lifecycle)
6. [WFP Implementation Details](#wfp-implementation-details)


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
- Multiple programs can be attached to the stream layer classify hooks at once.
  - Each program will be invoked in attached order until the flow is blocked or the program has allowed the flow.
- After a flow is allowed/block, there should be no further invocations of that program for the flow.
  - If the flow is blocked, no further stream-layer eBPF programs will be invoked for the flow.
  - If the flow is allowed, other stream layer programs that are still classifying the flow will continue to be invoked.
- We do not currently need any stream mutation support for these hooks -- only inline inspect/allow/block.

## Alternative - Using existing Linux hooks

Linux provides several eBPF program types, including:

- XDP: High-speed packet filtering and processing at the link layer.
- TC (Traffic Control): Packet shaping and filtering at the network and transport layers.
- SOCK_FILTER: Stream-layer filtering based on socket-level data, enabling payload inspection and application-specific processing.
- BPF_PROG_TYPE_SK_MSG: Socket-level filtering of outgoing messages being sent by attaching an SK_MSG program to an eBPF socket map.
- BPF_PROG_TYPE_SK_SKB: Socket parsing and filtering for incoming packets based on socket maps.
  - SK_SKB_STREAM_PARSER: L4 message parser for L7 protocol.
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
typedef enum _ebpf_flow_classify_action
{
    EBPF_FLOW_CLASSIFY_ALLOW,
    EBPF_FLOW_CLASSIFY_BLOCK,
    EBPF_FLOW_CLASSIFY_NEED_MORE_DATA,
} ebpf_flow_classify_action_t;

typedef enum _ebpf_flow_direction
{
    EBPF_FLOW_DIRECTION_INBOUND,
    EBPF_FLOW_DIRECTION_OUTBOUND,
} ebpf_flow_direction_t;

typedef enum _ebpf_flow_state
{
    EBPF_FLOW_STATE_NEW,
    EBPF_FLOW_STATE_ESTABLISHED,
    EBPF_FLOW_STATE_DELETED,
    EBPF_FLOW_STATE_INVALID,
} ebpf_flow_state_t;

typedef struct _ebpf_flow_classify
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
} ebpf_flow_classify_t;
```

### Hook

1. **EBPF_ATTACH_TYPE_STREAM_FLOW_CLASSIFY**
   - **Invocation:** Called when new streams are established, for each TCP segment on flows that were classified as needing more data, and on flow deletion for unclassified flows.
   - **Purpose:** Allows the eBPF program to inspect stream data and allow/block the connection, or request more data if classification is not yet possible.
   - **Return values:**
     - `EBPF_FLOW_CLASSIFY_ALLOW`: The flow is permitted; the program requires no further stream inspection for this flow.
     - `EBPF_FLOW_CLASSIFY_BLOCK`: The flow is blocked; all further data is dropped (using WFP ABSORB), and the connection will be terminated or time out.
       - _Note_: WFP does not support blocking a flow at the flow-established layer, so if block is returned for
         a new flow the extension will remember the decision and block the flow on the first stream-layer WFP callout.
     - `EBPF_FLOW_CLASSIFY_NEED_MORE_DATA`: The current segment is allowed, but the program will be invoked again for subsequent segments until a final decision is made.
       - _Note_: If the flow is deleted before classification by an attached program, that program will be invoked
         one final time for cleanup (with the return value ignored).
   - **Notes:** This is only invoked for each flow segment until allow/block are returned (and only if NEED_MORE_DATA was returned when the flow was established).

```c
/*
 * @brief Handle flow classification (stream inspection).
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_FLOW_CLASSIFY
 *
 * Attach type(s):
 * \ref EBPF_ATTACH_TYPE_STREAM_FLOW_CLASSIFY
 *
 * Has different behavior based on ctx->state.
 *   EBPF_FLOW_STATE_NEW - Invoked when new flow is established.
 *     - ALLOW - No stream-layer classification of this flow needed by this program.
 *     - BLOCK - Block flow. No further program invocations for this flow.
 *     - NEED_MORE_DATA - invoke this program for each stream segment until classification.
 *   EBPF_FLOW_STATE_ESTABLISHED - Invoked for each segment of established flows still needing classification.
 *     - ALLOW - Allow flow. No further invocations of this program for this flow.
 *       Other programs still classifying will get a final flow deleted invocation.
 *     - BLOCK - Block flow. No further invocations for this flow for this program
 *     - NEED_MORE_DATA - invoke this program for each stream segment until classification.
 *   EBPF_FLOW_STATE_DELETED - Invoked for each program that was still classifying the flow when it was deleted.
 *     - Return value ignored.
 *
 * @param[in] context \ref bpf_flow_classify_t
 * @retval FLOW_CLASSIFY_ALLOW The flow is permitted; no further stream inspection by this program for this flow.
 * @retval FLOW_CLASSIFY_BLOCK The flow is blocked; no further stream inspection for this flow.
 * @retval FLOW_CLASSIFY_NEED_MORE_DATA Allow current segment but continue inspection of subsequent segments.
 */
typedef flow_classify_action_t
stream_flow_classify_hook_t(bpf_flow_classify_t* context);
```

## Architecture

### Hook Integration and Flow

The extension uses the Windows Filtering Platform (WFP) to register callouts at both the flow established and stream layers.

1. When a new TCP flow is established, the extension initializes a per-flow context and invokes each program attached to the hook.
  a. Each program can return ALLOW/BLOCK/NEED_MORE_DATA to allow/block the new flow or classify the flow at the stream layer.

    b. If no stream-layer inspection is needed, the bpf program context is freed immediately.
    c. If any program returns `EBPF_FLOW_CLASSIFY_NEED_MORE_DATA`, the extension associates the context with the WFP stream layer callout to enable conditional callouts for this flow (using the WFP `CONDITIONAL_ON_FLOW` flag).
3. For each TCP segment, the extension invokes the `stream_flow_classify` hook, passing the current segment data and flow metadata. Each program can allow/block the flow or request more data as needed.

    a. If a program returns `FLOW_CLASSIFY_BLOCK` the context is freed and there will be no further invocations for this flow.

       - programs that previously returned `NEED_MORE_DATA` will be invoked a final time for this flow with the `state` set to `EBPF_FLOW_STATE_DELETED`.

    b. If `FLOW_CLASSIFY_NEED_MORE_DATA` is returned, the current segment is allowed but the context is not freed.
4. If the flow is deleted while still in the NEED_MORE_DATA state (i.e., no final decision was made),
   each program that most recently returned NEED_MORE_DATA will be invoked a final timeto notify them.

### Stream Hook Lifecycle

1. **Load and Attach**
    - The lifecycle begins with the setup of WFP filters. These filters are configured to be called at flow established for all TCP flows, and at the stream layer only for flows with the wfp context still set.
2. **Flow Established Callback and Invocation**
    - Extension initializes bpf program context and invokes the hook programs to decide whether to classify this flow at the stream layer.
    - Context is immediately freed if no classification is needed for this flow.
    - If classification is needed, the context is stored in the WFP stream layer callout context.
3. **Stream Callback and Invocation**
    - When stream data arrives, WFP triggers the extension through a callout. This callback serves as the starting point for stream-layer flow classification.
    - The stream layer callout is only invoked for flows still requiring invocation (using WFP CONDITIONAL_ON_FLOW).
4. **eBPF Program Invocation**
    - The extension invokes eBPF filter programs in the order they were attached.
    - On each invocation, the eBPF program will be presented with the data for the current segment.
    - Classify programs inspect the stream segment data and classify the connection using return codes:
        - **Allow**: The connection is deemed safe and permitted to proceed without further inspection.
        - **Block**: Terminates the connection immediately.
        - **Need More Data**: Indicates the need for additional data for a conclusive decision. The extension allows the current segment and will invoke the program again for the next segment.
5. **Stream Inspection**
    - The eBPF program performs parsing/inspection tasks on the stream.
    - If the “Need More Data” return code is used, the inspection until a definitive decision is returned.
6. **Connection Termination or Continuation**
    - Once a decision other than "Need More Data" is reached (Allow or Block), the lifecycle for that connection ends within the context of the filter program.
    - For “Block,” the connection is terminated.
    - For “Allow,” the connection proceeds without further filtering.
    - If a connection is terminated while still being classified by a program, the program is invoked a final time with `EBPF_FLOW_STATE_DELETED`.

_Notes:_

- The [Windows Stream Inspection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/stream-inspection)
API is used for inspecting the stream-layer data via WFP callouts.
- the WFP `CONDITIONAL_ON_FLOW` flag means the stream-layer callout will only run for flows where the stream-layer WFP context (containing the bpf program context) is set.
  - The context is freed immediately if the flow is allowed at the flow established layer.
  - Otherwise the context is freed when an allow/block decision is made or the flow is deleted.
- When returning NEED_MORE_DATA, the current data segment is allowed (but the hook will keep getting invoked).
- Multiple eBPF programs can be invoked for a single stream, but the decision is finalized based on the first conclusive return code.
- No stream mutation is supported through these hooks (only inspection and allow/block).

### WFP Implementation Details

The stream inspection extension integrates with the Windows Filtering Platform (WFP)
at the flow_established layer to indicate flows for classification and at the stream layer to
classify flows.

Currently only inline stream classification will be supported.

#### WFP Action Mapping

The hook implementation maps eBPF program return values to specific WFP actions:

- **FLOW_CLASSIFY_ALLOW**: Returns `FWP_ACTION_PERMIT` and deletes the WFP flow context. This allows the current segment and terminates further classification for this flow by removing the flow context.

- **FLOW_CLASSIFY_BLOCK**: Returns `FWP_ACTION_BLOCK` with the `FWPS_CLASSIFY_OUT_FLAG_ABSORB` flag set. This blocks the current segment and terminates the connection by blocking all subsequent segments.

- **FLOW_CLASSIFY_NEED_MORE_DATA**: Returns `FWP_ACTION_PERMIT`. This allows the current segment to proceed while maintaining the flow context for continued classification of subsequent segments.
  - The initial stream-layer hook only supports passive inspection until an allow/block decision is made.
    - This avoids withholding data that higher level protocols need to proceed (which could stall/deadlock the flow).

#### Stream Inspection Model

The implementation supports **inline stream inspection only**, meaning:

- All classification decisions are made in the WFP callout
  - No out-of-band or deferred processing is supported
- Stream data is processed segment-by-segment as it arrives
- No reassembly or reordering of TCP segments is performed by the hook (this is handled by the TCP stack before reaching the stream layer).
- Data is allowed through when `FLOW_CLASSIFY_NEED_MORE_DATA` is returned.
  - **Note**: The WFP `countBytesEnforced` field is not modified by these hooks,
    which currently only allow stream inspection and allow/block of flows.

#### Stream Data Handling

The hook provides direct access to stream segment data through the context's `data_start` and `data_end` pointers:

- **Contiguous Data**: When possible, pointers reference the original NET_BUFFER data directly for zero-copy access.
- **Non-contiguous Data**: For fragmented NET_BUFFERs, data is copied into a temporary buffer using `FwpsCopyStreamDataToBuffer0` to provide contiguous access to eBPF programs.
- **Data Lifetime**: Stream data pointers are only valid during the program invocation and must not be accessed after the program returns.

#### Resource Management

WFP resource management:

- **Conditional Callouts**: Stream layer callouts use the `FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW` flag to ensure they are only invoked for flows requiring classification.
- **Context Cleanup**: Flow contexts are immediately free'd by the extension when the flow is allowed/blocked.
  For flows that terminate while still being classified, the extension will free them after invoking the program(s) in the flow deleted callout.
- **Memory Management**: Temporary buffers for non-contiguous data are allocated from non-paged pool and freed immediately after program execution.
