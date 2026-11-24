# eBPF for Windows Flow Classification Hook Design

## Contents

1. [Status](#status)
2. [Purpose](#purpose)
3. [Definitions](#definitions)
4. [High-level process overview](#high-level-process-overview)
5. [Relationship to Linux](#relationship-to-linux)
6. [eBPF interface](#ebpf-interface)
   - [Program and attach types](#program-and-attach-types)
   - [Flow map](#flow-map)
   - [Program attachment](#program-attachment)
   - [Flow enrollment](#flow-enrollment)
   - [Classification context](#classification-context)
   - [Payload access](#payload-access)
   - [Actions and classifier composition](#actions-and-classifier-composition)
7. [Lifecycle](#lifecycle)
8. [Stream and datagram behavior](#stream-and-datagram-behavior)
9. [Pending flows](#pending-flows)
10. [Security and resource management](#security-and-resource-management)
11. [Verifier, ABI, and versioning](#verifier-abi-and-versioning)
12. [Windows Filtering Platform implementation](#windows-filtering-platform-implementation)
13. [Validation](#validation)

## Status

The [flow-classification requirements](FlowClassifyHookRequirements.md) define the required behavior.

This design covers TCP stream data, UDP datagrams, non-error ICMP and ICMPv6 messages, and asynchronous `PEND`.
Support for payload mutation, raw IP datagrams, WFP reauthorization, and redirect is not currently planned.

## Purpose

The hook lets one or more eBPF classifiers inspect a flow over time and return actions that compose into a whole-flow
policy decision. `ALLOW` and `NEED_MORE_DATA` are nonblocking results; `PEND` retains the current indication; and
`BLOCK` stops the current indication and future traffic but cannot retract payload already released.

## Definitions

- **Network flow:** Traffic grouped under one stable flow identifier and lifecycle. A TCP flow is one connection; UDP
  and non-error ICMP/ICMPv6 traffic follows the WFP flow identifier and lifetime.
- **Flow classification:** A whole-flow decision informed by metadata and payload inspection rather than a per-packet
  verdict.
- **Classifier:** A flow-classify program attached to a flow map.
- **Flow map:** A map whose memberships select flows for its attached stream or datagram classifier.
- **Flow-map membership:** The relationship between one flow and one flow map, including its direction and pending
  flags. The membership activates the applicable classifier.
- **Payload indication:** One classification unit: an ordered stream-byte range or one logical datagram.
- **Logical datagram:** One UDP or non-error ICMP/ICMPv6 message presented as a single classification unit.
- **Pending (`PEND`):** Retaining the current indication until an external decision provider completes the decision.
- **Windows Filtering Platform (WFP):** The Windows network filtering framework used to receive flow and payload
  indications.
- **Application Layer Enforcement (ALE):** WFP layers that report flow establishment and lifecycle events.
- **Callout:** A kernel callback registered at a WFP filtering layer.
- **Flow context:** Extension-owned state associated with a WFP flow and callout.
- **Waterfall:** WFP's higher-to-lower ordering of stream callouts. Injected replacement data is available only to
  lower-weight sublayers.
- **USO / URO:** UDP Segmentation Offload and UDP Receive Offload.
- **BTF-resolved function:** An extension function resolved by name and BPF Type Format metadata rather than a fixed
  helper identifier.
- **LUID:** A locally unique identifier, used by this design for interface and logon-session identity.

## High-level process overview

Flow-map membership activates payload inspection:

1. A flow-classify program attaches to a flow map.
2. At flow establishment, `sock_ops` enrolls the flow in each classifier map selected for inspection.
3. For each indication, the extension invokes applicable classifiers in successful attachment order.
4. `ALLOW` finalizes only the returning classifier; `NEED_MORE_DATA` keeps it active; `PEND` retains the indication and
   pauses the chain; and `BLOCK` is terminal for the flow.
5. A finalized classifier receives one cleanup invocation after in-flight calls drain, then its membership is removed.

```text
 flow established                           payload indication
       |                                            |
       v                                            v
 [sock_ops program]                         [extension flow state]
       | ebpf_flow_map_track()                      |
       v                                            v
 [flow map membership] ---- activates ----> [classifiers in attach order]
                                                    |
                                  ALLOW / BLOCK / NEED_MORE_DATA / PEND
```

A flow may belong to multiple flow maps, allowing independent classifiers to compose.

## Relationship to Linux

Linux combines `BPF_PROG_TYPE_SOCK_OPS` enrollment with programs attached to `BPF_MAP_TYPE_SOCKMAP` or
`BPF_MAP_TYPE_SOCKHASH`; sockets in a map are processed by programs attached to that map. This design retains
`sock_ops` enrollment, program attachment to a map FD, membership-driven inspection, and direct payload access with lazy
linearization.

Unlike Linux sockmap/sockhash:

- the map key is a Windows flow ID rather than a caller-selected socket lookup key;
- policy is whole-flow, and one flow can compose multiple classifier maps;
- each membership explicitly selects inbound, outbound, or both directions; and
- `PEND` adds asynchronous decisions using Windows payload retention.

## eBPF interface

### Program and attach types

The design reuses `EBPF_PROGRAM_TYPE_SOCK_OPS` for enrollment and adds these libbpf and GUID identifier mappings:

| Role | libbpf identifier | GUID identifier |
| --- | --- | --- |
| Program type | `BPF_PROG_TYPE_FLOW_CLASSIFY` | `EBPF_PROGRAM_TYPE_FLOW_CLASSIFY` |
| Stream attach type | `BPF_ATTACH_TYPE_STREAM_FLOW_CLASSIFY` | `EBPF_ATTACH_TYPE_STREAM_FLOW_CLASSIFY` |
| Datagram attach type | `BPF_ATTACH_TYPE_DATAGRAM_FLOW_CLASSIFY` | `EBPF_ATTACH_TYPE_DATAGRAM_FLOW_CLASSIFY` |

These ELF section names automatically select the program and expected attach type:

- `flow_classify/stream` for `BPF_ATTACH_TYPE_STREAM_FLOW_CLASSIFY`, mapped to
  `EBPF_ATTACH_TYPE_STREAM_FLOW_CLASSIFY`; and
- `flow_classify/datagram` for `BPF_ATTACH_TYPE_DATAGRAM_FLOW_CLASSIFY`, mapped to
  `EBPF_ATTACH_TYPE_DATAGRAM_FLOW_CLASSIFY`.

The names are optional. The program type can be supplied explicitly, and attachment can select either attach type.
Native generation preserves the selected expected attach type in the program metadata.

The context and flow-map value contain fields used by both stream and datagram classification. Datagram data-path
values and ICMP-specific metadata are produced only for datagram classification.

### Flow map

`BPF_MAP_TYPE_FLOW_MAP` is a new custom map type provided by `netebpfext` and backed by a hash map.

Map creation requires a `uint64_t` key, the published `ebpf_flow_map_value_t` size, and a nonzero `max_entries`.

#### Key

The key is the `uint64_t flow_id` exposed by `bpf_sock_ops_get_flow_id()`. It is opaque and unique among live
extension flow contexts during the current boot. It is not reused until all invocations, cleanup, and pending
completions for the prior flow are impossible.

#### Value

The value is fixed-size, extension-owned metadata with this layout:

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
    EBPF_FLOW_METADATA_PROCESS_ID_VALID = 1 << 1, /**< The process identifier is valid. */
    EBPF_FLOW_METADATA_LOGON_ID_VALID = 1 << 2, /**< The logon identifier is valid. */
    EBPF_FLOW_METADATA_ADMIN_VALID = 1 << 3, /**< The administrator status is valid. */
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
 * @brief Contains stable metadata for one flow.
 */
typedef struct _ebpf_flow_metadata
{
    uint64_t flow_id;       /**< Stable flow identifier and flow-map key. */
    uint64_t process_id;    /**< Initiating process identifier, if valid. */
    uint64_t logon_id;      /**< Initiating token AuthenticationId LUID, encoded as uint64_t, if valid. */
    uint64_t interface_luid; /**< Local interface LUID. */

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

    uint32_t family;         /**< IP address family selecting the valid member in both address unions. */
    uint32_t compartment_id; /**< Network compartment identifier. */
    uint32_t data_path;      /**< One ebpf_flow_classify_data_path_t value. */
    uint32_t metadata_flags; /**< Bitmask of ebpf_flow_metadata_flag_t values. */

    uint16_t local_port;   /**< Local TCP or UDP port in network byte order, if valid. */
    uint16_t remote_port;  /**< Remote TCP or UDP port in network byte order, if valid. */
    uint8_t protocol;      /**< IP protocol number. */
    uint8_t is_admin;      /**< 1 if the initiating token is an administrator, otherwise 0, if valid. */
    uint8_t reserved[2];   /**< Reserved; set to zero. */
} ebpf_flow_metadata_t;

/**
 * @brief Contains extension-owned metadata for one tracked flow-map membership.
 *
 * User mode can read this value, but neither user mode nor eBPF programs can modify it through standard map
 * operations.
 */
typedef struct _ebpf_flow_map_value
{
    ebpf_flow_metadata_t metadata; /**< Stable flow metadata. */
    uint64_t track_flags;          /**< Normalized ebpf_flow_map_track_flag_t values for this membership. */
} ebpf_flow_map_value_t;
```

The field ordering groups identifiers, addresses, fixed-width flow attributes, and compact transport and identity
fields while preserving natural alignment. The layout is not packed.

The value does not contain a verdict, pending state, retained payload, writable scratch, or WFP pointers. Classifiers
store mutable parser or policy state in ordinary program maps keyed by `flow_id`. ICMP type and code are per-message
metadata and appear only in the classification context.

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

`max_entries` is the hard aggregate limit on active stream and datagram memberships in the map. Tracking a new
membership fails when the limit is reached.

#### Operations

- User mode can enumerate keys and look up copied metadata values. Enumeration is weakly consistent with concurrent
  membership changes.
- User-mode update and delete fail with an operation-not-supported error.
- eBPF map lookup, update, and delete helpers are rejected for this map type.
- Membership is created only by `ebpf_flow_map_track()`.
- Membership is removed only by classifier verdict or lifecycle processing.

### Program attachment

Flow-classify programs attach to a flow-map FD. The link-returning API is:

```c
/**
 * @brief Configures flow-classify attachment.
 */
struct bpf_flow_classify_attach_opts
{
    size_t sz;                        /**< Size of this structure. */
    enum bpf_attach_type attach_type; /**< Attach type, or BPF_ATTACH_TYPE_UNSPEC to use the program's expected type. */
};

/**
 * @brief Attaches a flow-classify program to a flow map and returns a link.
 *
 * @param[in] program Flow-classify program to attach.
 * @param[in] flow_map_fd File descriptor for the target flow map.
 * @param[in] opts Optional attachment options.
 * @return A link that owns the attachment, or NULL with errno set on failure.
 */
struct bpf_link*
bpf_program__attach_flow_classify(
    const struct bpf_program* program, int flow_map_fd, const struct bpf_flow_classify_attach_opts* opts);
```

`opts == NULL` or `BPF_ATTACH_TYPE_UNSPEC` uses the program's expected attach type. An explicit stream or datagram type
selects that slot even when it differs from the expected type; any other type is rejected.

The same program can attach through `bpf_prog_attach()` using the flow-map FD, an explicit stream or datagram attach
type, and zero flags. `bpf_prog_detach2()` removes the matching attachment.

A returned link retains the program and flow map until the link is detached or destroyed. An attachment created by
`bpf_prog_attach()` is owned by the map and retains the program until detached or the map is destroyed.

A flow map supports:

- zero or one stream classifier; and
- zero or one datagram classifier.

A second attachment for an occupied attach type is rejected, regardless of API. Multiple classifiers of the same type
use separate flow maps. Applicable classifiers run in successful attachment order; reattaching places the new
attachment at the end.

A classifier must be attached before a flow can be tracked for its protocol. No dormant memberships exist. A
classifier can run concurrently for different flows tracked in its map. Detaching it prevents new invocations, waits
for all in-flight invocations to finish, removes only memberships governed by that attach type, and disarms inspection
on an ordinary active flow only when no other classifier map still requires it.

Closing the map FD or removing a pin does not destroy the map while another reference remains.

### Flow enrollment

Before invoking the enrollment program, the extension captures the stable flow metadata and available flow-owner
identity. The enrollment program uses the `sock_ops` context and existing helpers to select classifier maps:

- the process-ID component of `bpf_get_current_pid_tgid()` reports the captured initiating process;
- `bpf_get_current_logon_id(context)` reports the captured initiating token's `AuthenticationId`; and
- `bpf_is_current_admin(context)` evaluates the captured initiating token.

Unavailable identity uses the existing helper failure values. Tracking copies the same captured values and validity
into the flow's stable metadata, so map selection and later classification use one identity snapshot.

`ebpf_flow_map_track()` is a BTF-resolved function callable only from an active or passive establishment `sock_ops`
invocation:

```c
/**
 * @brief Tracks the current flow in a flow map and activates the map's classifier for that flow.
 *
 * The function uses the current flow identified by the supplied sock_ops context and captures its stable metadata.
 *
 * @param[in] context Current sock_ops context identifying the flow to track.
 * @param[in] flow_map Flow map whose applicable classifier will inspect the flow.
 * @param[in] flags Membership flags from ebpf_flow_map_track_flag_t.
 *
 * @retval 0 The membership was prepared, or an identical membership already existed.
 * @retval -ENOTSUP A requested membership capability is not implemented.
 * @retval <0 The operation failed for another reason.
 */
long
ebpf_flow_map_track(bpf_sock_ops_t* context, struct bpf_map* flow_map, uint64_t flags);
```

The direction bits in `flags` select inbound payload, outbound payload, or both for this membership:

```c
/**
 * @brief Configures one flow-map membership.
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
    EBPF_FLOW_MAP_TRACK_ALLOW_PEND = 1 << 2, /**< Allows this membership to return PEND. */
    EBPF_FLOW_MAP_TRACK_FLAG_MASK =
        EBPF_FLOW_MAP_TRACK_DIRECTION_MASK | EBPF_FLOW_MAP_TRACK_ALLOW_PEND, /**< Mask containing all valid bits. */
} ebpf_flow_map_track_flag_t;
```

The function normalizes `DEFAULT` to `BOTH`. `ALLOW_PEND` is protocol-independent and declares during enrollment that
the membership can return `PEND`. If any TCP membership declares it, the extension selects out-of-band stream
processing before the first payload. Datagram processing remains inline until a classifier actually returns `PEND`.

A repeated track operation with the same normalized flags is idempotent. Any different flags for an existing flow/map
membership fail explicitly. Membership configuration is immutable for its lifetime.

Tracking fails without creating a membership when the context is not an establishment event, the map has no applicable
classifier, the membership limit is reached, resources cannot be allocated, required protocol metadata is unavailable,
or the arguments or flags are invalid.

A successful call reserves the required resources and retains the selected classifier attachment. The prepared
membership remains inactive until the enrollment program returns. A failed call creates no membership and does not
affect earlier successful calls.

After enrollment returns, the extension activates all prepared memberships together and arms payload inspection.
Activation cannot fail. Racing attachment removal discards that attachment's prepared memberships, and a replacement
attachment does not inherit them. Otherwise, the first payload includes every successfully tracked membership.

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
 * @brief Indicates which optional invocation-specific metadata fields are valid.
 */
typedef enum _ebpf_flow_classify_metadata_flag
{
    EBPF_FLOW_CLASSIFY_METADATA_ICMP_TYPE_CODE_VALID = 1 << 0, /**< The ICMP type and code are valid. */
} ebpf_flow_classify_metadata_flag_t;

/**
 * @brief Contains stable flow metadata and the payload for one flow-classify invocation.
 *
 * The verifier enforces read-only access to metadata and payload. Payload pointers are valid only for the duration of
 * the current invocation and can be invalidated by ebpf_flow_classify_pull_data().
 */
typedef struct _ebpf_flow_classify
{
    ebpf_flow_metadata_t metadata; /**< Stable flow metadata. */
    uint64_t track_flags;          /**< Normalized ebpf_flow_map_track_flag_t values for this membership. */

    uint32_t event;                   /**< One ebpf_flow_classify_event_t value. */
    uint32_t direction;               /**< Current payload direction, or UNSPECIFIED for a deletion event. */
    uint32_t classify_metadata_flags; /**< Bitmask of ebpf_flow_classify_metadata_flag_t values. */
    uint8_t icmp_type;                /**< ICMP or ICMPv6 message type, if valid. */
    uint8_t icmp_code;                /**< ICMP or ICMPv6 message code, if valid. */
    uint8_t reserved[2];              /**< Reserved; set to zero. */

    uint64_t data_length;  /**< Total logical payload length for this invocation. */
    uint64_t missed_bytes; /**< Stream bytes hidden by higher-weight filters since the previous invocation. */
    uint8_t* data_start;   /**< Start of the directly accessible payload span. */
    uint8_t* data_end;     /**< End of the directly accessible payload span. */
} ebpf_flow_classify_t;
```

Field validity is:

| Field group | `DATA` | `DELETED` |
| --- | --- | --- |
| Stable metadata and `track_flags` | Valid according to `metadata.metadata_flags` | Same captured values |
| `direction` | `INBOUND` or `OUTBOUND` | `UNSPECIFIED` |
| ICMP metadata | Valid only when its classify flag is set | Zero |
| Payload | `0 <= data_end - data_start <= data_length` | Lengths are zero and pointers are `NULL` |
| `missed_bytes` | WFP stream-gap count; zero for datagrams | Zero |

Flow establishment uses the existing `sock_ops` invocation. Flow-classify programs receive `DATA` and
membership-deletion events. A deletion event occurs exactly once per membership after its in-flight calls drain.

The context contains the same `process_id`, `logon_id`, and `is_admin` snapshot used during enrollment. Unavailable
optional fields clear their validity flags and remain zero. `logon_id` is the initiating token's `AuthenticationId`
LUID encoded as a `uint64_t`; it is not a token handle.

`bpf_get_current_logon_id(context)` and `bpf_is_current_admin(context)` return the captured values to enrollment and
flow-classify programs consistently with `sock_addr`. The former returns zero when the logon ID is unavailable; the
latter returns a negative value when administrator status is unavailable.

The identity metadata supports logon-session and administrator-based policy. Richer token claims are not included.

### Payload access

For each payload event, `data_start..data_end` exposes the first contiguous payload span without a helper call, and
`data_length` reports the total logical payload length. The exposed span is valid only for the current invocation. A
classifier calls `ebpf_flow_classify_pull_data()` only when it needs a longer prefix than the exposed span:

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
ebpf_flow_classify_pull_data(ebpf_flow_classify_t* context, uint64_t length);
```

- `length` requests that many bytes from the start of the current logical payload.
- `length == 0` requests the whole payload.
- a length larger than `data_length` fails;
- a request larger than the configured linearization limit fails with `-E2BIG`;
- copying or linearization occurs only when needed;
- success preserves the payload contents and exposes at least the requested prefix, including the prior span, but can
  relocate storage and invalidate prior payload-derived pointers; and
- the program must reload `data_start` and `data_end` and repeat bounds checks.

For example, a program that needs a prefix spanning multiple backing buffers uses:

```c
uint8_t* data = context->data_start;
uint8_t* data_end = context->data_end;

if (data + HEADER_LENGTH > data_end) {
    if (ebpf_flow_classify_pull_data(context, HEADER_LENGTH) < 0) {
        return EBPF_FLOW_CLASSIFY_BLOCK;
    }

    data = context->data_start;
    data_end = context->data_end;
    if (data + HEADER_LENGTH > data_end) {
        return EBPF_FLOW_CLASSIFY_BLOCK;
    }
}

// Parse HEADER_LENGTH bytes starting at data.
```

This helper affects only the current invocation. It is independent of `NEED_MORE_DATA`, which permits the current
payload and asks to observe future payload.

### Actions and classifier composition

The action set is:

```c
/**
 * @brief Specifies a whole-flow classification action.
 */
typedef enum _ebpf_flow_classify_action
{
    EBPF_FLOW_CLASSIFY_ALLOW, /**< Allows the current payload and finalizes the returning classifier. */
    EBPF_FLOW_CLASSIFY_BLOCK, /**< Blocks the flow and terminates classification for every classifier. */
    EBPF_FLOW_CLASSIFY_NEED_MORE_DATA, /**< Allows the current payload and keeps the classifier active. */
    EBPF_FLOW_CLASSIFY_PEND, /**< Withholds the current payload for an external decision. */
} ebpf_flow_classify_action_t;

/**
 * @brief Classifies payload for a tracked network flow.
 *
 * Program type: \ref BPF_PROG_TYPE_FLOW_CLASSIFY, mapped to \ref EBPF_PROGRAM_TYPE_FLOW_CLASSIFY
 *
 * Attach types:
 * \ref BPF_ATTACH_TYPE_STREAM_FLOW_CLASSIFY, mapped to \ref EBPF_ATTACH_TYPE_STREAM_FLOW_CLASSIFY
 * \ref BPF_ATTACH_TYPE_DATAGRAM_FLOW_CLASSIFY, mapped to \ref EBPF_ATTACH_TYPE_DATAGRAM_FLOW_CLASSIFY
 *
 * @param[in] context Flow metadata and the current payload or cleanup event.
 *
 * Return values are ignored for EBPF_FLOW_CLASSIFY_EVENT_DELETED.
 *
 * @retval EBPF_FLOW_CLASSIFY_ALLOW Allow the current payload and finalize this classifier.
 * @retval EBPF_FLOW_CLASSIFY_BLOCK Block the flow and terminate all classifiers.
 * @retval EBPF_FLOW_CLASSIFY_NEED_MORE_DATA Allow the current payload and keep this classifier active.
 * @retval EBPF_FLOW_CLASSIFY_PEND Withhold the current payload for an external decision.
 */
typedef ebpf_flow_classify_action_t
flow_classify_hook_t(ebpf_flow_classify_t* context);
```

Returning `PEND` without `EBPF_FLOW_MAP_TRACK_ALLOW_PEND`, or returning any undefined action, is treated as `BLOCK` and
logged as an invalid classifier result.

For each payload, the extension snapshots applicable active classifier attachments and invokes them in global
attachment order.

- **ALLOW**
  - finalizes only the returning classifier; and
  - gives it one final `DELETED` cleanup invocation after its in-flight invocations drain, then removes its membership.
- **NEED_MORE_DATA**
  - keeps only the returning classifier active for future payload; and
  - does not hold, accumulate, replay, or partially permit the current payload.
- **PEND**
  - stops the classifier chain after the returning classifier; and
  - retains the indication for the external-decision workflow described in [Pending flows](#pending-flows).
- **BLOCK**
  - stops the classifier chain immediately;
  - is terminal for the flow and blocks current and future payload;
  - gives every active classifier one final `DELETED` cleanup invocation after in-flight invocations drain; and
  - removes all memberships after cleanup but retains minimal enforcement state until WFP deletes the flow.

`ALLOW` and `NEED_MORE_DATA` are nonblocking classifier results, not immediate WFP verdicts. The extension releases or
reinjects the indication only after the classifier chain completes and the flow remains neither pending nor blocked.

Direction controls whether a classifier is invoked, not the scope of its verdict. A classifier armed only for ingress
can still block the whole flow.

Programs release mutable per-flow state from the final `DELETED` invocation. Its return value is ignored.

When no active classifier remains on an ordinary flow, payload inspection is disarmed. Blocked and out-of-band flows
retain their required enforcement state.

## Lifecycle

### Enrollment

At ALE flow establishment, the extension captures stable flow metadata and runs the enrollment process described in
[Flow enrollment](#flow-enrollment). If no membership is activated, payload inspection is not armed.

TCP flows require the map's stream classifier. UDP and non-error ICMP/ICMPv6 flows require its datagram classifier.
Connectionless grouping follows the WFP flow identifier and lifetime represented by the associated flow context.

### Concurrency and cleanup

The extension does not hold a lock while an eBPF program runs. One payload indication invokes classifiers serially in
attachment order, but WFP can concurrently invoke the same flow for the opposite direction or for separate datagrams.
Programs synchronize mutable per-flow state stored in ordinary maps. TCP byte ranges remain ordered within each
direction according to the WFP stream contract.

If any membership has `ALLOW_PEND`, the extension serializes payload indications for that flow across both directions.
This ensures that only one classifier chain can enter the pending state.

Terminal membership and flow decisions are committed between program invocations. Once a classifier or flow begins
finalizing, no new invocation starts for that scope. Cleanup runs exactly once after its in-flight invocations drain.

### Payload delivery

For each payload indication:

1. Snapshot applicable active classifiers in global attachment order. The snapshot retains their lifetime.
2. Before each invocation, recheck that the membership is active; skip it otherwise. Stop when the chain completes or
   one classifier returns `PEND` or `BLOCK`.
3. Finalize a classifier's membership when it returns `ALLOW`; keep it active for `NEED_MORE_DATA`. Commit each action
   before invoking the next classifier.
4. Recheck the flow state, then release or retain the indication according to the aggregate result.
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

### Attachment or map deletion

Removing a classifier attachment prevents new tracking and payload invocations, discards its prepared memberships,
drains in-flight invocations, and cleans its active memberships. Reattachment does not inherit the removed
memberships. Other classifier maps are unaffected.

A flow map remains valid while file descriptors, pins, links, memberships, or pending operations reference it.

## Stream and datagram behavior

### TCP stream

- An invocation represents an ordered stream-byte range in one direction.
- WFP stream indications define the byte-range boundaries independently of TCP packet, TCP segment, and
  application-message boundaries.
- Every classifier reached before `PEND` or `BLOCK` receives the same range.
- `data_length` is the total range length; direct access exposes its first contiguous span, which may be shorter than
  the full range.
- `NEED_MORE_DATA` releases the current range and does not request WFP buffering or replay. Programs retain any parser
  carry-over in their own maps.
- `missed_bytes` is the WFP callout-level gap count before the current range. A nonzero value means stream continuity
  was lost; it does not identify the missing bytes or an absolute stream position.

### UDP and ICMP/ICMPv6

Datagram classification covers UDP and non-error ICMP/ICMPv6. Support for raw IP datagram classification is not
currently planned. ICMP error-layer classification is not defined pending requirements clarification.

- one invocation receives one logical UDP datagram or ICMP/ICMPv6 message;
- inbound and outbound offsets are normalized to one direction-independent payload contract;
- UDP payload begins after the UDP header;
- ICMP payload begins after the base ICMP/ICMPv6 header, with type and code in metadata;
- WFP provides the complete transport-layer message; the extension does not perform IP fragment reassembly.

**Open question:** Whether ICMP payload should instead begin at the base ICMP/ICMPv6 header.

When supported by the running Windows version, the datagram callout advertises USO/URO support. Offload is transparent
to classifiers: they receive ordered logical datagrams, and membership changes apply between them. WFP receives one
verdict for the underlying indication, so `BLOCK` or `PEND` applies to the complete indication. If all synchronous
results are nonblocking, the original offloaded indication passes unchanged.

Datagram payload reinjected by this extension bypasses repeat classification.

## Pending flows

`EBPF_FLOW_CLASSIFY_PEND` means withhold the current logical payload for an external decision. It is not equivalent to
`NEED_MORE_DATA`. A membership declares this capability during enrollment with `EBPF_FLOW_MAP_TRACK_ALLOW_PEND`.

When a classifier returns `PEND`:

1. The extension atomically marks the flow pending, stops the chain after that classifier, and retains the current and
   later indications in both directions. At most one decision is outstanding for a flow.
2. The owning completion channel receives an opaque decision identifier, flow metadata, payload direction and type,
   total payload length, and a bounded copied prefix.
3. The channel completes the decision with `ALLOW`, `NEED_MORE_DATA`, or `BLOCK`.
4. Exactly one valid completion is accepted. `ALLOW` finalizes the pending classifier; `NEED_MORE_DATA` keeps it active
   for future indications. Both resume the current chain at the next active classifier without rerunning earlier
   classifiers. `BLOCK` discards retained payload and terminates the flow.

Timeout, retention or notification failure, quota exhaustion, and loss of the completion channel fail closed as
`BLOCK`. Duplicate, stale, or unauthorized completions are rejected. Flow deletion cancels the decision, discards
retained payload, and makes its identifier stale.

The pending classifier remains referenced until completion or timeout; detaching it prevents new invocations and waits
for the pending operation to finish.

TCP selects out-of-band stream processing before the first payload when any membership has `ALLOW_PEND`. It remains
out of band while a classifier is active or data is retained or being injected. Once none of those conditions remains,
the extension disarms inspection rather than switching the flow back to inline processing. The external component is
not notified for synchronous classifier results.

Datagram classification remains inline until `PEND` is returned. It then retains the current and later logical
datagrams while the decision is outstanding.

If a logical datagram within an offloaded indication returns `PEND`, the extension retains the complete indication.
Completion resumes at the pending datagram and processes the remaining datagrams in order.

WFP prohibits cloning and reinjecting an inbound URO indication. Until a compatible retention mechanism is defined,
returning `PEND` for inbound URO is treated as `BLOCK`.

This document defines the required pending behavior. Notification structures, queueing, teardown, and reinjection
mechanics are specified separately and must follow the lifetime, authorization, cancellation, and exactly-once
completion principles in [Asynchronous Processing](AsyncProcessing.md).

## Security and resource management

- Only the current `sock_ops` context can authorize tracking its flow.
- The fixed map key is the context-derived WFP flow ID.
- Flow metadata and identity are extension-owned and read-only.
- A flow-map handle grants metadata observation and classifier-attachment authority.
- eBPF programs cannot use standard map CRUD on flow maps.
- Link attachments retain their maps; every attachment retains its program and owns its memberships.
- Token-derived identity is captured before enrollment, used by the enrollment helpers, and copied into stable flow
  metadata; no raw token pointer is exposed or retained.
- `max_entries` bounds map membership. Allocation, system flow state, payload linearization, and pending retention
  remain separately bounded and fail explicitly.
- Pending payload and identity are disclosed only to the owning completion channel.

## Verifier, ABI, and versioning

- New extension functions use the BTF-resolved function mechanism. Its metadata restricts each function to its
  supported program type and marks payload-access functions that invalidate verifier pointer proofs.
- `ebpf_flow_classify_t` is a fixed, verifier-described context whose metadata and direct payload region are read-only.
- `ebpf_flow_classify_pull_data()` invalidates payload-derived pointer proofs, requiring programs to reload the context
  pointers and repeat bounds checks.
- The internal flow context, classifier context, and flow-map value embed the same pointer-free
  `ebpf_flow_metadata_t` layout by value.
- Metadata validity uses append-only bit flags with reserved bits.
- Pending notification and completion structures are independently versioned.
- The flow-map entry contains no pending control fields, retained payload, or writable program state.
- The extension zero-initializes public contexts and map values before populating valid fields. Reserved and inactive
  union storage remain zero.
- Public structures use fixed-width fields and compile-time layout assertions.

## Windows Filtering Platform implementation

### Layers and callouts

| Purpose | WFP layer |
| --- | --- |
| Flow enrollment and stable metadata capture | `ALE_FLOW_ESTABLISHED_V4/V6` |
| TCP payload classification | `STREAM_V4/V6` |
| UDP and non-error ICMP/ICMPv6 classification | `DATAGRAM_DATA_V4/V6` |

`netebpfext` registers one runtime callout per address family and data path. The stream and datagram callouts use
`FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW`, so WFP invokes them only when the extension has associated a context with the
flow.

Enrollment runs at ALE flow establishment. The extension associates the shared flow state through
`FwpsFlowAssociateContext()`, but data-layer callouts do not invoke classifiers until the prepared memberships are
activated. `FwpsFlowRemoveContext()` disarms an ordinary flow when no classifier remains.

### Action mapping

| eBPF action | Inline TCP | Pending-capable TCP | Datagram |
| --- | --- | --- | --- |
| `ALLOW` | Permit; finalize | Reinject; finalize | Permit; finalize |
| `NEED_MORE_DATA` | Permit; retain | Reinject; retain | Permit; retain |
| `BLOCK` | Drop connection | Discard; drop connection | Block; retain flow state |
| `PEND` | Invalid | Retain; notify | Retain; notify |

After the classifier chain produces a final nonblocking result, inline TCP uses `FWPS_STREAM_ACTION_NONE`, sets
`countBytesEnforced` to the complete indicated length, and returns `FWP_ACTION_PERMIT`. It does not use
`FWPS_STREAM_ACTION_NEED_MORE_DATA`. `BLOCK` uses `FWPS_STREAM_ACTION_DROP_CONNECTION`; the stream filter therefore
uses `FWP_ACTION_CALLOUT_UNKNOWN`.

A pending-capable TCP flow remains on the clone/block/reinject path while a classifier is active or data is retained or
being injected. Only `PEND` notifies the external component. Datagram processing remains inline until `PEND`; that
indication and later indications are then blocked and retained.

### Payload handling and ordering

WFP orders stream callouts through its waterfall. Replacement data injected by a callout in a higher-weight sublayer
is visible to flow classification; modifications made afterward are not reindicated to it. Bytes a higher-weight filter
prevents the hook from processing contribute to `missed_bytes`.

The stream callout receives `FWPS_STREAM_CALLOUT_IO_PACKET`; its `missedBytes` value is exposed as `missed_bytes`.
WFP's `streamDataOffset` is reserved for system use, so the extension does not expose an absolute stream offset.
`ebpf_flow_classify_pull_data()` materializes only the requested prefix from chained payload storage.

The datagram callout normalizes inbound and outbound payload offsets. On supported Windows versions, it advertises
`FWP_CALLOUT_FLAG_ALLOW_USO` and `FWP_CALLOUT_FLAG_ALLOW_URO`. For an offloaded indication, it uses the offload metadata
to invoke classifiers once for each logical datagram. Synchronous classification returns one verdict for the original
indication without splitting or reinjecting it.

The callout uses a flow-classification-specific injection handle with `FwpsQueryPacketInjectionState()` to bypass its
own reinjected payload. Third-party reinjected datagrams can be classified as new indications.

Flow-classify programs are multiplexed inside one `netebpfext` callout and run in successful attachment order,
independent of WFP callout order.

For pending-capable TCP flows, the extension clones the indicated data and returns `FWP_ACTION_BLOCK` for the complete
original indication. It reinjects synchronously approved data with `FwpsStreamInjectAsync()`, retains data when a
classifier returns `PEND`, and discards retained data on `BLOCK`.

For ordinary datagrams, `PEND` blocks and retains the indication for later WFP transport injection or discard.
Offloaded indications follow the behavior described in [Pending flows](#pending-flows).

### Teardown

WFP invokes `flowDeleteFn` when an associated flow ends. The extension stops new classifier invocations, drains
in-flight calls, sends final deletion events, removes memberships, and releases the flow context. Attachment removal
removes only that attachment's memberships. A blocked flow retains enough state to reject later payload until WFP
deletes it.

## Validation

### Local

- custom-map creation, lookup/enumeration, rejected mutation, and program-type association;
- BPF-to-GUID mappings, automatic and explicit attach-type selection, both attachment APIs, their lifetimes, and
  one-program-per-attach-type enforcement;
- enrollment helper validation, captured flow-owner identity, idempotency, unsupported flags, and capacity limits;
- atomic activation, per-call failure, and detach races before the first payload;
- verifier acceptance of the context and actions and rejection of metadata or direct-payload writes;
- verifier invalidation of payload pointers after `ebpf_flow_classify_pull_data()`;
- invalid-action handling, 64-bit payload lengths, action aggregation, and cleanup races.

### VM / live network stack

- TCP enrollment, ordered stream delivery, discontinuity, lazy payload access, allow, block, and need-more-data;
- multiple classifier maps and deterministic attachment order;
- stream-gap reporting and WFP waterfall visibility with an additional modifying callout;
- concurrent invocation without holding a lock across eBPF execution;
- persistent whole-flow blocking for stream and datagram traffic;
- natural flow deletion, explicit context removal, attachment removal, and map deletion cleanup;
- process/logon/admin identity validity and stability;
- direction reporting and program-side filtering;
- UDP and ICMP/ICMPv6 payload boundaries and metadata;
- USO/URO logical-datagram ordering, membership changes within a batch, and unchanged synchronous pass-through;
- whole-indication `BLOCK` and `PEND`, and fail-closed inbound-URO `PEND`;
- self-injected datagram bypass and third-party datagram reinjection behavior;
- upfront TCP pending-mode selection, synchronous verdicts on the out-of-band path, and notification only for `PEND`;
- datagram transition on `PEND`, retention and ordering of later datagrams, timeout, quota, race, and cancellation;
- stress with many flows, high data rates, attach/detach churn, and bounded-map exhaustion;
- resource limits and failure behavior; and
- observed on-wire behavior when `BLOCK` aborts a stream flow.
