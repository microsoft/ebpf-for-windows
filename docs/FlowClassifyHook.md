# eBPF for Windows Flow Classification Hook Design

## Contents

1. [Status](#status)
2. [Purpose](#purpose)
3. [Design overview](#design-overview)
4. [Relationship to Linux](#relationship-to-linux)
5. [eBPF interface](#ebpf-interface)
   - [Program and attach types](#program-and-attach-types)
   - [Flow map](#flow-map)
   - [Program attachment](#program-attachment)
   - [Flow enrollment](#flow-enrollment)
   - [Classification context](#classification-context)
   - [Payload access](#payload-access)
   - [Actions and classifier composition](#actions-and-classifier-composition)
6. [Lifecycle](#lifecycle)
7. [Stream and datagram behavior](#stream-and-datagram-behavior)
8. [WFP integration](#wfp-integration)
9. [Pending flows](#pending-flows)
10. [Security and resource management](#security-and-resource-management)
11. [Verifier, ABI, and versioning](#verifier-abi-and-versioning)
12. [Validation](#validation)
13. [Implementation phases](#implementation-phases)

## Status

This is a design proposal. The authoritative behavioral requirements are in
[FlowClassifyHookRequirements.md](FlowClassifyHookRequirements.md).

This design covers TCP stream data, UDP datagrams, and non-error ICMP and ICMPv6 messages. Implementation is staged:
TCP stream classification precedes datagram classification.

`PEND` withholds the current payload for an external decision. Its implementation is deferred to a separate phase.

Payload mutation, raw IP datagrams, reauthorization, and redirect are out of scope. ICMP error-layer classification is
not defined by this proposal and requires requirements clarification before the design is finalized.

All type and function declarations below are proposed and non-final.

## Purpose

The flow classification hook lets eBPF programs inspect transport payload and contribute to a flow-level policy
decision to allow or block the associated network flow.

A **network flow** is traffic with common endpoint and protocol metadata tracked under one stable identifier and
lifecycle. TCP flows are connections. Related UDP datagrams and ICMP or ICMPv6 messages are grouped under the same flow
identifier.

**Flow classification** is a whole-flow decision informed by metadata and payload inspection. `ALLOW` and `BLOCK` are
terminal decisions for a classifier or flow, not per-packet verdicts. A classifier can return `NEED_MORE_DATA` to
permit the current payload and continue observing future payload.

## Design overview

The design follows the Linux sockmap principle that map membership drives inspection:

1. A flow-classify program attaches to a **flow map**.
2. An existing `sock_ops` program runs at flow establishment and decides whether the current flow needs payload
   inspection.
3. The `sock_ops` program calls `bpf_flow_map_track()` for each classifier map that should inspect the flow's payload.
4. Membership in a flow map activates that map's classifier for the flow.
5. On each applicable payload indication, the extension invokes active classifiers in global program-attachment order.
   Each classifier returns an action.
6. The extension applies each returned action. `ALLOW` finalizes only the returning classifier.
   `NEED_MORE_DATA` keeps that classifier active. `BLOCK` is terminal for the flow.
7. Finalized classifiers receive cleanup before their memberships are removed. When no active classifier remains,
   payload inspection is disarmed unless the flow must retain blocked or out-of-band enforcement state.

```text
 flow established                           payload indication
       |                                            |
       v                                            v
 [sock_ops program]                         [extension flow state]
       | bpf_flow_map_track()                       |
       v                                            v
 [flow map membership] ---- activates ----> [classifiers in attach order]
                                                    |
                                       ALLOW / BLOCK / NEED_MORE_DATA
```

One flow may be tracked by multiple flow maps so an enrollment policy can compose independent classifiers. Each flow
map supports at most one program per flow-classification attach type.

## Relationship to Linux

Linux combines `BPF_PROG_TYPE_SOCK_OPS` enrollment with programs attached to `BPF_MAP_TYPE_SOCKMAP` or
`BPF_MAP_TYPE_SOCKHASH`. Sockets inserted into the map inherit its parser or verdict programs.

This design adopts:

- `sock_ops` enrollment at flow establishment;
- program attachment to a map FD;
- membership-driven payload inspection;
- direct payload access with lazy linearization.

It deliberately differs from Linux:

- the map key is a Windows flow ID rather than a caller-selected socket lookup key;
- verdicts classify a whole flow rather than one message;
- one flow may be tracked by multiple classifier maps;
- flow direction selection is explicit rather than implied by program type;
- asynchronous pending uses Windows-specific payload retention and reinjection.

## eBPF interface

### Program and attach types

The design reuses `EBPF_PROGRAM_TYPE_SOCK_OPS` for enrollment and adds:

- `EBPF_PROGRAM_TYPE_FLOW_CLASSIFY`
- `EBPF_ATTACH_TYPE_STREAM_FLOW_CLASSIFY`
- `EBPF_ATTACH_TYPE_DATAGRAM_FLOW_CLASSIFY`

Flow-classify programs use these ELF section names:

- `flow_classify/stream` for `EBPF_ATTACH_TYPE_STREAM_FLOW_CLASSIFY`; and
- `flow_classify/datagram` for `EBPF_ATTACH_TYPE_DATAGRAM_FLOW_CLASSIFY`.

The context and flow-map value contain fields used by both stream and datagram classification. The TCP phase registers
the stream attach type and section. The datagram phase registers the datagram attach type and section. Until then, the
datagram data-path value and ICMP-specific metadata are reserved and are not produced.

### Flow map

`BPF_MAP_TYPE_FLOW_MAP` is a new custom map type provided by `netebpfext` and backed by a hash map.

Map creation requires a `uint64_t` key and the exact fixed metadata value size for the negotiated ABI. `max_entries`
uses the semantics described below.

#### Key

The key is the stable `uint64_t flow_id` exposed by `bpf_sock_ops_get_flow_id()`.

#### Value

The value is fixed-size, extension-owned metadata. A proposed shape is:

```c
/**
 * @brief Identifies the payload path used to classify a flow.
 */
typedef enum _ebpf_flow_classify_data_path
{
    EBPF_FLOW_CLASSIFY_DATA_PATH_STREAM,   /**< TCP stream payload. */
    EBPF_FLOW_CLASSIFY_DATA_PATH_DATAGRAM, /**< UDP, ICMP, or ICMPv6 message payload. */
} ebpf_flow_classify_data_path_t;

/**
 * @brief Indicates which optional flow metadata fields are valid.
 */
typedef enum _ebpf_flow_metadata_flag
{
    EBPF_FLOW_METADATA_PORTS_VALID = 1 << 0, /**< The TCP or UDP ports are valid. */
    EBPF_FLOW_METADATA_ICMP_TYPE_CODE_VALID = 1 << 1, /**< The ICMP type and code are valid. */
    EBPF_FLOW_METADATA_PROCESS_ID_VALID = 1 << 2, /**< The process identifier is valid. */
    EBPF_FLOW_METADATA_LOGON_ID_VALID = 1 << 3, /**< The logon identifier is valid. */
    EBPF_FLOW_METADATA_ADMIN_VALID = 1 << 4, /**< The administrator status is valid. */
} ebpf_flow_metadata_flag_t;

/**
 * @brief Identifies one or both payload directions.
 */
typedef enum _ebpf_flow_direction
{
    EBPF_FLOW_DIRECTION_UNSPECIFIED = 0,  /**< No payload direction is associated with the event. */
    EBPF_FLOW_DIRECTION_INBOUND = 1 << 0,  /**< Inbound payload. */
    EBPF_FLOW_DIRECTION_OUTBOUND = 1 << 1, /**< Outbound payload. */
    EBPF_FLOW_DIRECTION_BOTH = 0x3,        /**< Inbound and outbound payload. */
} ebpf_flow_direction_t;

/**
 * @brief Contains extension-owned metadata for one tracked flow.
 *
 * User mode can read this value, but neither user mode nor eBPF programs can modify it through standard map
 * operations.
 */
typedef struct _ebpf_flow_map_value
{
    uint64_t flow_id; /**< Stable flow identifier and flow-map key. */
    uint32_t family;  /**< IP address family selecting the valid member in both address unions. */
    union
    {
        uint32_t local_ip4;    /**< Local IPv4 address in network byte order. */
        uint32_t local_ip6[4]; /**< Local IPv6 address in network byte order. */
    };
    union
    {
        uint32_t remote_ip4;    /**< Remote IPv4 address in network byte order. */
        uint32_t remote_ip6[4]; /**< Remote IPv6 address in network byte order. */
    };
    uint32_t protocol;       /**< IP protocol number. */
    uint32_t data_path;      /**< One ebpf_flow_classify_data_path_t value. */
    uint32_t metadata_flags; /**< Bitmask of ebpf_flow_metadata_flag_t values. */
    union
    {
        struct
        {
            uint16_t local_port;  /**< Local TCP or UDP port in network byte order. */
            uint16_t remote_port; /**< Remote TCP or UDP port in network byte order. */
        } ports;                   /**< Port metadata when EBPF_FLOW_METADATA_PORTS_VALID is set. */
        struct
        {
            uint8_t type; /**< ICMP or ICMPv6 message type. */
            uint8_t code; /**< ICMP or ICMPv6 message code. */
        } icmp;           /**< ICMP metadata when EBPF_FLOW_METADATA_ICMP_TYPE_CODE_VALID is set. */
    } transport; /**< Protocol-specific transport metadata. */
    uint32_t compartment_id;  /**< Network compartment identifier. */
    uint64_t interface_luid;  /**< Local interface LUID. */
    uint64_t process_id;      /**< Initiating process identifier, if valid. */
    uint64_t logon_id;        /**< Initiating logon identifier, if valid. */
    int32_t is_admin;         /**< 1 for an administrator, 0 otherwise, or -1 when unavailable. */
    uint32_t armed_directions; /**< Bitmask of ebpf_flow_direction_t values selected for this membership. */
} ebpf_flow_map_value_t;
```

The value does not contain a verdict, pending state, retained payload, writable scratch, or WFP pointers. Classifiers
store mutable parser or policy state in ordinary program maps keyed by `flow_id`.

An eBPF program declares a flow map using the normal BTF map syntax:

```c
#define MAX_TRACKED_FLOWS 1024

struct
{
    __uint(type, BPF_MAP_TYPE_FLOW_MAP);
    __uint(max_entries, MAX_TRACKED_FLOWS);
    __type(key, uint64_t);
    __type(value, ebpf_flow_map_value_t);
} flow_map SEC(".maps");
```

The program sets `max_entries` to the desired aggregate limit on active stream and datagram memberships. A value of
zero specifies no map-specific membership limit. Allocation and system resource limits still apply.

#### Operations

- User mode can enumerate keys and look up copied metadata values. Enumeration is weakly consistent with concurrent
  membership changes.
- User-mode update and delete fail with an operation-not-supported error.
- eBPF map lookup, update, and delete helpers are rejected for this map type.
- Membership is created only by `bpf_flow_map_track()`.
- Membership is removed only by classifier verdict or lifecycle processing.

### Program attachment

A flow-classify program attaches to a flow-map FD through a link-returning API:

```c
/**
 * @brief Attaches a flow-classify program to a flow map.
 *
 * @param[in] program Flow-classify program to attach.
 * @param[in] flow_map_fd File descriptor for the target flow map.
 * @param[in] attach_type Stream or datagram flow-classify attach type.
 *
 * @return A link that owns the attachment, or NULL with errno set on failure.
 */
struct bpf_link*
bpf_program__attach_flow_classify(
    const struct bpf_program* program, int flow_map_fd, enum bpf_attach_type attach_type);
```

The returned link owns the attachment and retains the flow map. The caller retains or pins the link for the desired
attachment lifetime.

A flow map supports:

- zero or one stream classifier; and
- zero or one datagram classifier.

A second program for an occupied attach type is rejected. Multiple classifiers of the same type use separate flow
maps. Applicable classifiers run in successful attachment order; reattaching places the new link at the end.

A classifier must be attached before a flow can be tracked for its protocol. No dormant memberships exist. A
classifier can run concurrently for different flows tracked in its map. Detaching it prevents new invocations, waits
for all in-flight invocations to finish, removes only memberships governed by that attach type, and disarms inspection
on an ordinary active flow only when no other classifier map still requires it.

Closing the map FD or removing a pin does not destroy the map while another reference remains.

### Flow enrollment

The enrollment program must have the metadata required to select a flow before it calls the tracking helper. The
existing `bpf_sock_ops_t` prefix remains unchanged and gains this appended, versioned member:

```c
/**
 * @brief Contains optional stable metadata available during flow enrollment.
 */
typedef struct _ebpf_sock_ops_flow_metadata
{
    uint32_t metadata_flags; /**< Bitmask of ebpf_flow_metadata_flag_t values. */
    uint8_t icmp_type;       /**< ICMP or ICMPv6 type, if valid. */
    uint8_t icmp_code;       /**< ICMP or ICMPv6 code, if valid. */
    uint16_t reserved;       /**< Reserved; set to zero. */
    uint64_t process_id;     /**< Initiating process identifier, if valid. */
    uint64_t logon_id;       /**< Initiating logon identifier, if valid. */
    int32_t is_admin;        /**< 1 for an administrator, 0 otherwise, or -1 when unavailable. */
    uint32_t reserved2;      /**< Reserved; set to zero. */
} ebpf_sock_ops_flow_metadata_t;
```

The appended `bpf_sock_ops_t` member `flow_metadata` contains this structure. Existing endpoint, port, protocol,
compartment, interface, and operation fields remain unchanged. Program information versioning preserves compatibility
with programs compiled against the existing context prefix. Optional fields use the same validity semantics during
enrollment, map lookup, and classification.

`bpf_flow_map_track()` is a BTF-resolved function callable only from an active or passive establishment `sock_ops`
invocation:

```c
/**
 * @brief Tracks the current flow in a flow map and activates the map's classifier for that flow.
 *
 * The helper derives the flow identifier and stable metadata from the supplied sock_ops context.
 *
 * @param[in] context Current sock_ops context identifying the flow to track.
 * @param[in] flow_map Flow map whose applicable classifier will inspect the flow.
 * @param[in] flags Direction-selection flags from ebpf_flow_map_track_flag_t.
 *
 * @retval 0 The flow was tracked, or an identical membership already existed.
 * @retval -ENOTSUP The requested direction-selection mode is not implemented.
 * @retval <0 The operation failed for another reason.
 */
long
bpf_flow_map_track(bpf_sock_ops_t* context, struct bpf_map* flow_map, uint64_t flags);
```

The `flags` argument selects inbound payload, outbound payload, or both for this membership:

```c
/**
 * @brief Selects the payload directions to activate for one flow-map membership.
 */
typedef enum _ebpf_flow_map_track_flag
{
    EBPF_FLOW_MAP_TRACK_DEFAULT = 0, /**< Uses the default behavior, which activates both directions. */
    EBPF_FLOW_MAP_TRACK_INBOUND =
        EBPF_FLOW_DIRECTION_INBOUND, /**< Requests inbound-only classification. */
    EBPF_FLOW_MAP_TRACK_OUTBOUND =
        EBPF_FLOW_DIRECTION_OUTBOUND, /**< Requests outbound-only classification. */
    EBPF_FLOW_MAP_TRACK_BOTH = EBPF_FLOW_DIRECTION_BOTH, /**< Requests classification in both directions. */
    EBPF_FLOW_MAP_TRACK_DIRECTION_MASK =
        EBPF_FLOW_DIRECTION_BOTH, /**< Mask containing all direction-selection bits. */
} ebpf_flow_map_track_flag_t;
```

The helper normalizes `DEFAULT` to `BOTH`. The TCP phase accepts only that normalized `BOTH` value; `INBOUND` and
`OUTBOUND` return `-ENOTSUP`. Programs still receive the current direction in the classification context and can
self-filter. The direction-selection phase enables single-direction invocation suppression.

A repeated track operation with the same normalized flags is idempotent. Any different flags for an existing flow/map
membership fail explicitly. Membership configuration is immutable for its lifetime.

Tracking fails without creating a membership when the context is not an establishment event, the map has no applicable
classifier, the configured membership limit is reached, resources cannot be allocated, required protocol metadata is
unavailable, or the arguments or flags are invalid.

### Classification context

Stream and datagram programs share one context:

```c
/**
 * @brief Identifies the lifecycle event represented by a flow-classify invocation.
 */
typedef enum _ebpf_flow_classify_event
{
    EBPF_FLOW_CLASSIFY_EVENT_DATA,    /**< Payload is available for classification. */
    EBPF_FLOW_CLASSIFY_EVENT_DELETED, /**< The classifier membership is being cleaned up. */
} ebpf_flow_classify_event_t;

/**
 * @brief Contains stable flow metadata and the payload for one flow-classify invocation.
 *
 * The verifier enforces read-only access to metadata and payload. Payload pointers are valid only for the duration of
 * the current invocation and can be invalidated by bpf_flow_classify_pull_data().
 */
typedef struct _ebpf_flow_classify
{
    uint64_t flow_id; /**< Stable flow identifier. */
    uint32_t family;  /**< IP address family selecting the valid member in both address unions. */
    union
    {
        uint32_t local_ip4;    /**< Local IPv4 address in network byte order. */
        uint32_t local_ip6[4]; /**< Local IPv6 address in network byte order. */
    };
    union
    {
        uint32_t remote_ip4;    /**< Remote IPv4 address in network byte order. */
        uint32_t remote_ip6[4]; /**< Remote IPv6 address in network byte order. */
    };
    uint32_t protocol;       /**< IP protocol number. */
    uint32_t compartment_id; /**< Network compartment identifier. */
    uint64_t interface_luid; /**< Local interface LUID. */
    uint64_t process_id;     /**< Initiating process identifier, if valid. */
    uint64_t logon_id;       /**< Initiating logon identifier, if valid. */
    int32_t is_admin;        /**< 1 for an administrator, 0 otherwise, or -1 when unavailable. */

    uint32_t event;            /**< One ebpf_flow_classify_event_t value. */
    uint32_t data_path;        /**< One ebpf_flow_classify_data_path_t value. */
    uint32_t metadata_flags;   /**< Bitmask of ebpf_flow_metadata_flag_t values. */
    uint32_t direction;        /**< Current payload direction, or UNSPECIFIED for a deletion event. */
    uint32_t armed_directions; /**< Directions selected for this classifier membership. */

    union
    {
        struct
        {
            uint16_t local_port;  /**< Local TCP or UDP port in network byte order. */
            uint16_t remote_port; /**< Remote TCP or UDP port in network byte order. */
        } ports;                   /**< Port metadata when EBPF_FLOW_METADATA_PORTS_VALID is set. */
        struct
        {
            uint8_t type; /**< ICMP or ICMPv6 message type. */
            uint8_t code; /**< ICMP or ICMPv6 message code. */
        } icmp;           /**< ICMP metadata when EBPF_FLOW_METADATA_ICMP_TYPE_CODE_VALID is set. */
    } transport; /**< Protocol-specific transport metadata. */

    uint64_t data_length; /**< Total logical payload length for this invocation. */
    uint64_t missed_bytes; /**< Stream bytes not delivered to this classifier before the current payload. */
    uint8_t* data_start;   /**< Start of the directly accessible payload span. */
    uint8_t* data_end;     /**< End of the directly accessible payload span. */
} ebpf_flow_classify_t;
```

The concrete layout is non-final. Its contract is:

- `event` distinguishes payload delivery from final cleanup.
- `data_path` and `protocol` identify stream, UDP, ICMP, or ICMPv6.
- `metadata_flags` identifies valid transport and identity fields.
- `direction` is the current payload direction.
- `armed_directions` reports the membership's requested directions. It is `BOTH` during the TCP phase.
- `data_length` and `missed_bytes` preserve the full WFP-native length without 32-bit truncation.
- `data_start..data_end` is the directly accessible first span and is valid only for this invocation.
- `missed_bytes` reports a gap before the current stream payload. Each classifier handles the gap in its program logic
  by resetting its parser state, returning `BLOCK`, or continuing inspection.

Field validity depends on `event`:

- For `DATA`, stable metadata is valid according to `metadata_flags`; `direction` is `INBOUND` or `OUTBOUND`; the
  payload fields describe the current payload; and `missed_bytes` is valid only for stream data.
- For `DELETED`, stable captured metadata, `data_path`, `metadata_flags`, and `armed_directions` remain valid;
  `direction` is `UNSPECIFIED`; `data_length` and `missed_bytes` are zero; and the payload pointers are `NULL`.

Flow establishment is represented by the existing `sock_ops` enrollment invocation. Flow-classify programs receive
only payload and membership-deletion events.

When a flow is tracked, the extension captures the available `process_id`, `logon_id`, and tri-state `is_admin` values
and keeps them stable for the flow lifetime. Unavailable optional fields clear their validity flags and do not fail
enrollment.

`bpf_get_current_logon_id(context)` and `bpf_is_current_admin(context)` are available to flow-classify programs and
return the captured values for source compatibility with `sock_addr`.

The initial identity summary supports logon-session and administrator-based policy. Support for richer token claims
requires a separately versioned identity extension.

### Payload access

For each payload event, `data_start..data_end` exposes the first contiguous payload span without a helper call, and
`data_length` reports the total logical payload length. The exposed span is valid only for the current invocation. A
classifier calls `bpf_flow_classify_pull_data()` only when it needs a longer prefix than the exposed span:

```c
/**
 * @brief Makes a requested prefix of the current payload directly accessible to the program.
 *
 * A successful call can relocate payload storage and invalidates all payload-derived pointers previously checked by
 * the verifier.
 *
 * @param[in,out] context Current flow-classify context. The helper can update data_start and data_end.
 * @param[in] length Number of bytes to make directly accessible, or 0 to request the whole payload.
 *
 * @retval 0 The requested payload prefix is directly accessible.
 * @retval -E2BIG The requested prefix exceeds the configured linearization limit.
 * @retval <0 The request is invalid or the payload could not be made directly accessible.
 */
long
bpf_flow_classify_pull_data(ebpf_flow_classify_t* context, uint64_t length);
```

- `length` requests that many bytes from the start of the current logical payload.
- `length == 0` requests the whole payload.
- a length larger than `data_length` fails;
- a request larger than the configured linearization limit fails with `-E2BIG`;
- copying or linearization occurs only when needed;
- success preserves the payload contents and exposes at least the requested prefix, including the prior span, but can
  relocate storage and invalidate prior payload-derived pointers; and
- the program must reload `data_start` and `data_end` and repeat bounds checks.

This helper affects only the current invocation. It is independent of `NEED_MORE_DATA`, which permits the current
payload and asks to observe future payload.

### Actions and classifier composition

The synchronous action set is:

```c
/**
 * @brief Specifies a synchronous whole-flow classification action.
 */
typedef enum _ebpf_flow_classify_action
{
    EBPF_FLOW_CLASSIFY_ALLOW, /**< Allows the current payload and finalizes the returning classifier. */
    EBPF_FLOW_CLASSIFY_BLOCK, /**< Blocks the flow and terminates classification for every classifier. */
    EBPF_FLOW_CLASSIFY_NEED_MORE_DATA, /**< Allows the current payload and keeps the classifier active. */
} ebpf_flow_classify_action_t;

/**
 * @brief Classifies payload for a tracked network flow.
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_FLOW_CLASSIFY
 *
 * Attach types:
 * \ref EBPF_ATTACH_TYPE_STREAM_FLOW_CLASSIFY
 * \ref EBPF_ATTACH_TYPE_DATAGRAM_FLOW_CLASSIFY
 *
 * @param[in] context Flow metadata and the current payload or cleanup event.
 *
 * Return values are ignored for EBPF_FLOW_CLASSIFY_EVENT_DELETED.
 *
 * @retval EBPF_FLOW_CLASSIFY_ALLOW Allow the current payload and finalize this classifier.
 * @retval EBPF_FLOW_CLASSIFY_BLOCK Block the flow and terminate all classifiers.
 * @retval EBPF_FLOW_CLASSIFY_NEED_MORE_DATA Allow the current payload and keep this classifier active.
 */
typedef ebpf_flow_classify_action_t
flow_classify_hook_t(ebpf_flow_classify_t* context);
```

Any return value that is not enabled by the negotiated action ABI is treated as `BLOCK` and logged as an invalid
classifier result.

For each payload, the extension snapshots applicable active classifier attachments and invokes them in global
attachment order.

- **ALLOW**
  - permits the current payload unless another classifier blocks it;
  - finalizes only the returning classifier; and
  - gives it one final `DELETED` cleanup invocation after its in-flight invocations drain, then removes its membership.
- **NEED_MORE_DATA**
  - permits the current payload unless another classifier blocks it;
  - keeps only the returning classifier active for future payload; and
  - does not hold, accumulate, replay, or partially permit the current payload.
- **BLOCK**
  - stops the classifier chain immediately;
  - is terminal for the flow and blocks current and future payload;
  - gives every active classifier one final `DELETED` cleanup invocation after in-flight invocations drain; and
  - removes all memberships after cleanup but retains minimal enforcement state until WFP deletes the flow.

Direction controls whether a classifier is invoked, not the scope of its verdict. A classifier armed only for ingress
can still block the whole flow.

Programs release mutable per-flow state from the final `DELETED` invocation. Its return value is ignored.

When no active classifier remains on an ordinary flow, payload inspection is disarmed. Blocked and out-of-band flows
retain their required enforcement state.

## Lifecycle

### Enrollment

At ALE flow establishment, the extension captures stable flow metadata. The `sock_ops` enrollment program can track the
flow in one or more classifier maps. If no membership is created, payload inspection is not armed.

TCP flows require the map's stream classifier. UDP and non-error ICMP/ICMPv6 flows require its datagram classifier.
Connectionless grouping follows the WFP flow identifier and lifetime represented by the associated flow context.

### Concurrency and cleanup

The extension does not hold a lock while an eBPF program runs. One payload indication invokes classifiers serially in
attachment order, but WFP can concurrently invoke the same flow for the opposite direction or for separate datagrams.
Programs synchronize mutable per-flow state stored in ordinary maps. TCP byte ranges remain ordered within each
direction according to the WFP stream contract.

Terminal membership and flow decisions are committed between program invocations. Once a classifier or flow begins
finalizing, no new invocation starts for that scope. Cleanup runs exactly once after its in-flight invocations drain.

### Payload delivery

For each payload indication:

1. Snapshot applicable active classifiers in global attachment order.
2. Invoke every classifier in the snapshot unless one returns `BLOCK`.
3. Finalize a classifier's membership when it returns `ALLOW`; keep it active for `NEED_MORE_DATA`. Commit each action
   before invoking the next classifier.
4. Recheck the flow decision before permitting the payload so a concurrent `BLOCK` remains flow-terminal.
5. Drain and clean finalized memberships, then disarm ordinary inspection when none remain.

### Flow deletion

WFP `flowDeleteFn` is the data-layer context-removal callback. It can result from natural flow teardown or explicit
context removal after disarming. Natural deletion prevents new classifier invocations and gives each still-active
classifier one `DELETED` event after in-flight invocations drain. Explicit removal does not repeat cleanup already
performed while disarming.

Classifiers already removed after `ALLOW` or `BLOCK` are not called again. A blocked flow retains enforcement state
until natural deletion.

WFP does not expose a UDP "conversation ended" event. Connectionless cleanup occurs when WFP deletes the associated
flow context, such as after endpoint closure or implementation-defined flow timeout.

### Link or map deletion

Deleting a classifier link prevents new invocations, drains in-flight invocations, cleans that classifier's active
memberships, and removes them. It does not fabricate flow deletion for classifiers in other maps.

A flow map remains valid while file descriptors, pins, links, memberships, or pending operations reference it.

## Stream and datagram behavior

### TCP stream

- An invocation represents an ordered stream-byte range in one direction.
- WFP stream indications define the byte-range boundaries independently of TCP packet, TCP segment, and
  application-message boundaries.
- Every active classifier receives the same logical range.
- `data_length` is the total range length; direct access exposes its first contiguous span, which may be shorter than
  the full range.
- `missed_bytes` reports a stream discontinuity as the number of bytes not observed by this classifier before the
  current range.
- `NEED_MORE_DATA` does not use WFP's accumulate-more-data action.

### UDP and ICMP/ICMPv6

Datagram classification covers UDP and non-error ICMP/ICMPv6. Raw IP datagrams and WFP's separate ICMP error layers
are out of scope.

- one invocation receives one logical UDP datagram or ICMP/ICMPv6 message;
- inbound and outbound offsets are normalized to one direction-independent payload contract;
- UDP payload begins after the UDP header;
- proposed ICMP payload begins after the base ICMP/ICMPv6 header, with type and code in metadata;
- the extension delivers one logical message after any required IP fragment reassembly; and
- the datagram callout does not advertise `FWP_CALLOUT_FLAG_ALLOW_USO` or `FWP_CALLOUT_FLAG_ALLOW_URO`, preserving
  logical datagram boundaries.

**Open question:** Whether ICMP payload should instead begin at the base ICMP/ICMPv6 header.

USO/URO normalization is outside this design. Its performance impact should be measured during datagram implementation.

## WFP integration

The eBPF contract maps to:

- `ALE_FLOW_ESTABLISHED_V4/V6` for `sock_ops` enrollment and identity capture;
- `STREAM_V4/V6` for TCP byte ranges; and
- `DATAGRAM_DATA_V4/V6` for UDP and non-error ICMP/ICMPv6.

The stream path uses one stream callout per address family. The datagram path uses one datagram callout per address
family. Flow context is associated with the applicable data-layer callout, and
`FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW` prevents invocation for flows with no associated context.

WFP's waterfall model orders separate callouts at a filtering layer. The global attachment sequence described by this
design orders eBPF classifiers multiplexed inside the single `netebpfext` callout.

[TCP stream implementation (Phase 1B)](#phase-1b-tcp-stream-implementation) supports only bidirectional arming and
delivers both directions to tracked stream classifiers. Programs can inspect `direction` and self-filter during this
phase. [Direction selection (Phase 1C)](#phase-1c-direction-selection) persists and enforces the direction flags so
classifiers are not invoked for unarmed directions. Direction-specific WFP callouts are outside this design.

Stream and datagram payload can be scatter/gather. The extension derives total logical length and the first contiguous
span without unconditionally flattening data. `bpf_flow_classify_pull_data()` copies only the requested range.

After `BLOCK`, the stream callout uses `FWPS_STREAM_ACTION_DROP_CONNECTION`, while the datagram callout blocks every
later indication associated with the retained flow context. The design does not promise a particular on-wire TCP
signal. Connectionless traffic can later create a new WFP flow and be evaluated again.

## Pending flows

`EBPF_FLOW_CLASSIFY_PEND` means withhold the current logical payload for an external decision. It is not equivalent to
`NEED_MORE_DATA`. Pending is implemented in a separate phase.

The pending phase adds `PEND` to `ebpf_flow_classify_action_t` and must:

- allow at most one outstanding external decision per flow;
- identify each decision with an opaque value that only the owning completion channel can complete;
- freeze the classifier chain at the pending classifier;
- retain the current payload and later payload in both directions;
- expose total payload length and a bounded copied prefix without requiring `bpf_flow_classify_pull_data()`;
- complete with `ALLOW`, `BLOCK`, or `NEED_MORE_DATA`; and
- provide bounded retention, timeout, stale/duplicate rejection, and exactly-once cleanup.

Completion actions retain their synchronous semantics. `ALLOW` and `NEED_MORE_DATA` resume the held payload after the
pending classifier, while `BLOCK` discards retained payload and terminates the flow. Timeout, notification failure,
quota exhaustion, or loss of the completion subscriber fail closed as `BLOCK`.

TCP pending requires WFP out-of-band stream processing. WFP requires pending stream data to be cloned and absorbed and
warns that mixing synchronous and asynchronous processing for one flow is undefined. The pending phase must define
when a pending-capable flow enters out-of-band mode and how long it remains there.

Exact APIs, notification structures, queueing, teardown, and reinjection mechanics are outside the scope of this
document and are deferred to the pending phase. They must align with the lifetime, authorization, cancellation, and
exactly-once completion principles in [Asynchronous Processing](AsyncProcessing.md).

## Security and resource management

- Only the current `sock_ops` context can authorize tracking its flow.
- The fixed map key is the context-derived WFP flow ID.
- Flow metadata and identity are extension-owned and read-only.
- A flow-map handle grants metadata observation and classifier-attachment authority; link handles control detach.
- eBPF programs cannot use standard map CRUD on flow maps.
- Classifier attachments retain their maps and scope membership ownership.
- Token-derived identity is copied or derived at enrollment; no raw token pointer is exposed or retained.
- A nonzero `max_entries` bounds map membership. Allocation, system flow state, payload linearization, and pending
  retention remain bounded and fail explicitly.
- Pending payload and identity are disclosed only to the owning completion-map subscriber.

## Verifier, ABI, and versioning

- New helpers use BTF-resolved functions.
- `ebpf_flow_classify_t` is a fixed, verifier-described context whose metadata and direct payload region are read-only.
- `bpf_flow_classify_pull_data()` invalidates payload-derived pointer proofs, requiring programs to reload the context
  pointers and repeat bounds checks.
- The context and flow-map value use one layout for stream and datagram classification.
- Appended `sock_ops` enrollment metadata preserves the existing context prefix.
- The TCP phase registers the stream attach type. The datagram phase registers the datagram attach type.
- Metadata validity uses append-only bit flags with reserved bits.
- Unsupported single-direction modes fail explicitly until the direction-selection phase.
- The synchronous action enum contains only implemented actions. `PEND` is added with the pending phase.
- Pending notification and completion structures are independently versioned.
- The flow-map entry contains no pending control fields, retained payload, or writable program state.
- Public structures use fixed-width fields and compile-time layout assertions. ABI changes are version-gated.

## Validation

### Local

- custom-map creation, lookup/enumeration, rejected mutation, and program-type association;
- map-target program attach, map/link lifetime, and one-program-per-attach-type enforcement;
- enrollment metadata, helper validation, idempotency, unsupported direction flags, and nonzero or zero `max_entries`
  behavior;
- verifier acceptance of the context and actions and rejection of metadata or direct-payload writes;
- verifier invalidation of payload pointers after `bpf_flow_classify_pull_data()`;
- invalid-action handling, 64-bit payload lengths, action aggregation, and cleanup races.

### VM / live network stack

- TCP enrollment, ordered stream delivery, discontinuity, lazy payload access, allow, block, and need-more-data;
- multiple classifier maps and deterministic attachment order;
- concurrent invocation without holding a lock across eBPF execution;
- persistent whole-flow blocking for stream and datagram traffic;
- natural flow deletion, explicit context removal, link detach, and map deletion cleanup;
- process/logon/admin identity validity and stability;
- direction reporting and program-side filtering;
- stress with many flows, high data rates, attach/detach churn, and with or without a map-specific membership limit;
- resource limits and failure behavior; and
- observed on-wire behavior when `BLOCK` aborts a stream flow.

The datagram phase adds UDP and ICMP/ICMPv6 boundary, metadata, cleanup, action, offload, and performance tests. The
pending phase adds out-of-band processing, retention, reinjection, timeout, quota, race, and cancellation tests.

## Implementation phases

### Phase 1A: common interface and core plumbing

- add the flow-classify program type, stream attach type and section, flow-map type and declaration, entry-point
  signature, shared contexts and map-value layout, synchronous action enum, direction and metadata enums, and helper
  prototypes;
- add map-target link attachment with resolved map lifetime;
- register the BTF-resolved enrollment and payload-access functions and their verifier metadata;
- add read-only context and direct-payload verifier enforcement; and
- add user-mode/libbpf attach support.

Phase 1B is the first supported implementation of the interfaces introduced by Phase 1A. Datagram and pending
interfaces are added with their implementation phases.

### Phase 1B: TCP stream implementation

- enable the stream program, map, link, enrollment, metadata, and payload-access ABI for applications;
- capture identity and create internal per-flow state at ALE flow establishment;
- implement the stream-backed behavior for flow-map tracking and payload access;
- implement bidirectional arming only;
- register conditional stream callouts;
- implement stream payload access, classifier ordering, actions, and cleanup; and
- validate and harden the TCP path.

Phase 1B is an intermediate implementation. Direction selection, datagram classification, and pending are completed by
later phases.

### Phase 1C: direction selection

- enable the ingress-only and egress-only flag values already defined in Phase 1A;
- persist per-membership direction masks; and
- suppress eBPF invocation for unarmed directions.

### Phase 1D: datagram implementation

- register and publish the datagram attach type and section;
- implement UDP and non-error ICMP/ICMPv6 normalization and callouts;
- finalize the ICMP payload boundary;
- validate that the extension receives or constructs one reassembled logical message;
- omit `FWP_CALLOUT_FLAG_ALLOW_USO` and `FWP_CALLOUT_FLAG_ALLOW_URO`; and
- validate correctness and measure performance.

### Phase 2: asynchronous pending

- finalize and implement the pending APIs and completion channel;
- process pending-capable TCP flows out of band from their first payload indication;
- retain and reinject datagram payload while a decision is outstanding;
- enforce queue, quota, timeout, and cancellation rules; and
- add fault, race, stress, and restart testing.
