# SOCK_OPS Hook Design

## Contents

- [Overview](#overview)
- [Program Information NPI Provider](#program-information-npi-provider)
  - [Program identity](#program-identity)
  - [Program context](#program-context)
  - [Notifications and return values](#notifications-and-return-values)
  - [Helper functions](#helper-functions)
- [Hook NPI Provider](#hook-npi-provider)
  - [Attach contract](#attach-contract)
  - [WFP integration](#wfp-integration)
  - [Filter context](#filter-context)
  - [Flow context](#flow-context)
  - [Flow establishment](#flow-establishment)
  - [Flow deletion](#flow-deletion)
  - [Filter-context cleanup](#filter-context-cleanup)
  - [Synchronization and ownership](#synchronization-and-ownership)

## Overview

The SOCK_OPS hook reports network-flow establishment and deletion to eBPF programs. The implementation is in
[`netebpfext/net_ebpf_ext_sock_ops.c`](../netebpfext/net_ebpf_ext_sock_ops.c) and exposes two Network Module Registrar
(NMR) providers:

- A **Program Information NPI provider**, which defines the program type, context, helper functions, and execution
  contract.
- A **Hook NPI provider**, which attaches programs to Windows Filtering Platform (WFP) flow-established callouts and
  manages per-filter and per-flow state.

The hook handles both IPv4 and IPv6 flows. A single program receives establishment and deletion notifications; the
`op` field in its context identifies the notification.

## Program Information NPI Provider

### Program identity

| Property | Value |
|---|---|
| eBPF program type | `EBPF_PROGRAM_TYPE_SOCK_OPS` |
| Linux-compatible program type | `BPF_PROG_TYPE_SOCK_OPS` |
| ELF section name | `sockops` |
| Context type | `bpf_sock_ops_t` |
| Attach type | `EBPF_ATTACH_TYPE_CGROUP_SOCK_OPS` / `BPF_CGROUP_SOCK_OPS` |

The Program Information NPI provider uses `EBPF_PROGRAM_TYPE_SOCK_OPS` as its NMR module identifier. Its program
descriptor declares a fixed-size `bpf_sock_ops_t` context with no packet-data or metadata pointers.

### Program context

Programs receive a `bpf_sock_ops_t` context with the following fields:

| Field | Meaning |
|---|---|
| `op` | Notification type: active establishment, passive establishment, or connection deletion. |
| `family` | `AF_INET` for IPv4 or `AF_INET6` for IPv6. |
| `local_ip4` / `local_ip6` | Local IP address in network byte order. Only the member matching `family` is valid. |
| `local_port` | Local transport port in network byte order. |
| `remote_ip4` / `remote_ip6` | Remote IP address in network byte order. Only the member matching `family` is valid. |
| `remote_port` | Remote transport port in network byte order. |
| `protocol` | IP protocol reported by WFP. |
| `compartment_id` | Windows network compartment identifier. |
| `interface_luid` | Locally unique identifier of the interface reported by WFP. |

The extension embeds this public context in an internal `net_ebpf_sock_ops_t` wrapper:

| Internal field | Purpose |
|---|---|
| `EBPF_CONTEXT_HEADER` | Header used by the eBPF execution context. |
| `context` | Public `bpf_sock_ops_t` passed to the program. |
| `process_id` | Process identifier captured from WFP metadata for helper use. |
| `flow_id` | WFP flow handle exposed by `bpf_sock_ops_get_flow_id`. |

The program-information context callbacks accept a `bpf_sock_ops_t` context and no separate data buffer.

### Notifications and return values

| `op` value | When it is delivered | Return-value handling |
|---|---|---|
| `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` | An outbound flow reaches the WFP flow-established layer. | `0` permits the flow; any nonzero value blocks it. |
| `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB` | An inbound flow reaches the WFP flow-established layer. | `0` permits the flow; any nonzero value blocks it. |
| `BPF_SOCK_OPS_CONNECTION_DELETED_CB` | WFP deletes an associated flow while the filter context remains active. | The return value is ignored. |

The establishment callback defaults to `FWP_ACTION_PERMIT`. A nonzero program result changes the action to
`FWP_ACTION_BLOCK` and clears `FWPS_RIGHT_ACTION_WRITE`, making the block decision final for lower-weight WFP filters.
If program invocation itself fails, the extension leaves the default permit action and does not publish or associate
the flow context.

Deletion notifications reuse the connection metadata captured at establishment and change only `op` to
`BPF_SOCK_OPS_CONNECTION_DELETED_CB`. No deletion notification is delivered after the filter context has begun
detaching.

### Helper functions

The provider supplies one global helper override and one SOCK_OPS-specific helper.

| Helper | Classification | Parameters | Return value |
|---|---|---|---|
| `bpf_get_current_pid_tgid()` | Global helper override with implicit context | No explicit parameters. The runtime supplies the current `bpf_sock_ops_t` context. | Process ID in the upper 32 bits and current thread ID in the lower 32 bits. |
| `bpf_sock_ops_get_flow_id(ctx)` | SOCK_OPS program-specific helper | `ctx`: pointer to the current `bpf_sock_ops_t`. | The 64-bit WFP flow handle. |

The `bpf_get_current_pid_tgid` override uses the process ID captured from WFP metadata rather than querying the
current process at helper invocation time. This preserves the originating process ID for a later deletion
notification. The thread ID is obtained at the time the helper runs.

`bpf_sock_ops_get_flow_id` retrieves the internal `flow_id` stored alongside the public context. The same value is
available during establishment and deletion notifications.

## Hook NPI Provider

### Attach contract

The Hook NPI provider supports `EBPF_ATTACH_TYPE_CGROUP_SOCK_OPS` and publishes `BPF_CGROUP_SOCK_OPS` with
`BPF_LINK_TYPE_CGROUP`.

Attach data selects a network compartment:

- A four-byte attach value is interpreted as a `uint32_t` compartment ID.
- Empty attach data is a wildcard and matches all compartments.
- Any other attach-data size is rejected.

The provider currently registers with `ATTACH_CAPABILITY_SINGLE_ATTACH_PER_HOOK`:

- At most one client can attach for a given compartment ID.
- A wildcard attachment is accepted only when no SOCK_OPS filter context exists.
- Distinct compartment-specific clients may coexist, each with its own filter context.

### WFP integration

Each filter context installs two WFP filters in the default sublayer:

| WFP layer | Callout |
|---|---|
| `FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4` | `EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4_CALLOUT` |
| `FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6` | `EBPF_HOOK_ALE_FLOW_ESTABLISHED_V6_CALLOUT` |

For a compartment-specific attachment, both filters include an equality condition on
`FWPM_CONDITION_COMPARTMENT_ID`. Wildcard attachments install the filters without a compartment condition.

The WFP filter's raw context points to the SOCK_OPS filter context. WFP passes that pointer to the flow-established
classify callback.

### Filter context

`net_ebpf_extension_sock_ops_wfp_filter_context_t` extends the common WFP filter context:

| Field | Purpose |
|---|---|
| `base` | Generic hook-provider state, including attached clients, WFP filter IDs, reference count, provider pointer, and detach state. |
| `compartment_id` | Compartment selected by the attach data, or `UNSPECIFIED_COMPARTMENT_ID` for a wildcard attachment. |
| `lock` | Spin lock protecting the SOCK_OPS flow-context list. |
| `flow_established_rundown` | Prevents cleanup from draining the list while a classify callback is publishing a new flow context. |
| `flow_context_list.count` | Number of linked flow contexts. |
| `flow_context_list.list_head` | Intrusive list of contexts associated with WFP flows. |

The flow-context list belongs to the filter context. It therefore represents all active flows covered by that filter
context rather than state owned by a single invocation.

The create-filter callback builds this context from the compartment attach parameter and installs the corresponding
IPv4 and IPv6 WFP filters.

### Flow context

Each established flow uses `net_ebpf_extension_sock_ops_wfp_flow_context_t`:

| Field | Purpose |
|---|---|
| `link` | Membership in the filter context's active-flow list. A self-linked entry is no longer in the list. |
| `parameters.flow_id` | WFP flow handle. |
| `parameters.layer_id` | WFP layer on which the context was associated. |
| `parameters.callout_id` | WFP callout owning the association. |
| `filter_context` | Referenced parent filter context. |
| `context` | Internal SOCK_OPS program context, including public connection metadata, process ID, and flow ID. |

Each flow context holds one reference on its parent filter context. That reference keeps the filter context alive
until WFP invokes the flow-delete callback and the flow context is freed.

### Flow establishment

`net_ebpf_extension_sock_ops_flow_established_classify` processes a new WFP flow:

While protected by `flow_established_rundown`, classify creates the per-flow state and invokes the program with
`BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` or `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB`. If invocation succeeds, classify
publishes the flow context in the filter context's list and associates it with WFP.

The program must run before
[`FwpsFlowAssociateContext`](https://learn.microsoft.com/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsflowassociatecontext0).
After a successful association, WFP can invoke
[`flowDeleteFn`](https://learn.microsoft.com/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_callout_flow_delete_notify_fn0)
and free the flow context at any time. Invoking the program first prevents the establishment path from using
transferred memory and prevents a deletion notification from preceding the establishment notification.

Publication, association, and rollback all finish before the rundown is released. Therefore cleanup cannot observe a
partially published flow context.

### Flow deletion

WFP passes the associated flow context to `net_ebpf_extension_sock_ops_flow_delete`. The callback removes the flow
from the active-flow list under the filter-context spin lock. If the filter context is still active, it invokes the
program with `BPF_SOCK_OPS_CONNECTION_DELETED_CB`. It then releases the parent reference and frees the flow context.

During detach, the deletion notification is suppressed, but the flow context is still unlinked and freed.

### Filter-context cleanup

The generic Hook NPI provider invokes `_net_ebpf_extension_sock_ops_cleanup_filter_context` after the last client
detaches, the filter context is marked as deleting, and its WFP filters have been deleted.

Cleanup waits on the flow-establishment rundown, ensuring no classify callback can still publish a flow context. It
then drains the stable list, claiming each entry under the spin lock and asking WFP to remove the association.

WFP completes each removal through
[`flowDeleteFn`](https://learn.microsoft.com/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_callout_flow_delete_notify_fn0),
which owns the final reference release and deallocation. Cleanup does not free flow contexts directly.

### Synchronization and ownership

The design uses separate mechanisms for separate lifetime boundaries:

| Mechanism | Protects |
|---|---|
| Client rundown in the common Hook NPI provider | An attached program while it is being invoked. |
| `flow_established_rundown` | The finite interval in which classify allocates, invokes the program, publishes, associates, or rolls back a flow context. |
| Filter-context spin lock | Membership and count of entries in `flow_context_list`. |
| Per-flow filter-context reference | The parent filter context until WFP finishes deleting that flow. |

Cleanup and
[`flowDeleteFn`](https://learn.microsoft.com/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_callout_flow_delete_notify_fn0)
may reach the same flow concurrently. The spin lock ensures that only one path removes the list entry, while final
memory ownership remains with
[`flowDeleteFn`](https://learn.microsoft.com/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_callout_flow_delete_notify_fn0).
