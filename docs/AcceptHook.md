# Recv_accept Hook

## Overview

The `BPF_CGROUP_INET4_RECV_ACCEPT` and `BPF_CGROUP_INET6_RECV_ACCEPT` attach types allow
`BPF_PROG_TYPE_CGROUP_SOCK_ADDR` programs to authorize inbound connections. The hooks are implemented as WFP callouts
at the `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4` and `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6` layers and are invoked for
TCP `accept()` processing and for the first unicast UDP packet from a unique remote address/port tuple. Programs are
not invoked when WFP reauthorizes an existing connection. Programs are also not invoked when the classify request does
not grant `FWPS_RIGHT_ACTION_WRITE` (for example, after a higher-priority filter has made a final decision); the
existing WFP action is then left unchanged.

## Attach Parameters

The recv_accept hooks support an optional attach parameter: a Windows network compartment ID.

- If a specific compartment ID is provided, the program is only invoked for inbound connections in that compartment.
- If no attach parameters are provided, or if the compartment ID is set to `UNSPECIFIED_COMPARTMENT_ID`, the
  attachment is treated as a **wildcard** and matches inbound connections in any compartment.

## Multi-Attach Semantics

Up to 16 programs can be attached with the same attach parameters. Programs attached with the same attach parameters
are invoked in attach order, and their verdicts are accumulated within that attachment scope using the following
priority:

`REJECT` > `PROCEED_HARD` > `PROCEED_SOFT`

- The most restrictive verdict returned by any program becomes the effective verdict.
- A `REJECT` verdict stops the program chain immediately.
- Unknown verdict values and program invocation failures are treated as `REJECT`.
- If no matching program is found, the effective verdict remains `PROCEED_SOFT`.
- Address and port changes are not supported at the recv_accept layer. The original context is restored after each
  program so one program's changes are not visible to programs invoked later in the chain.

The effective eBPF verdict is then translated to a WFP action:

- `PROCEED_SOFT` permits the connection while retaining `FWPS_RIGHT_ACTION_WRITE`.
- `PROCEED_HARD` permits the connection and clears `FWPS_RIGHT_ACTION_WRITE`.
- `REJECT` blocks the connection and clears `FWPS_RIGHT_ACTION_WRITE`.

These actions participate in normal WFP arbitration with filters in other sublayers. See
[WFP Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration) for details.
Wildcard and compartment-specific attachment scopes use separate WFP filters, so their effective verdicts are also
subject to WFP arbitration rather than being combined by the in-scope accumulator. See
[issue #5590](https://github.com/microsoft/ebpf-for-windows/issues/5590).

The two wildcard attach parameter representations (no attach parameter, and a compartment ID of
`UNSPECIFIED_COMPARTMENT_ID`, as passed by `bpf_prog_attach`) currently create separate attachment scopes. Programs
attached with different wildcard representations are not accumulated together and are subject to WFP arbitration in
the same way. See [issue #5589](https://github.com/microsoft/ebpf-for-windows/issues/5589).

## Multi-Attach Test Coverage

The following scenarios are exercised for TCP and UDP over both IPv4 and IPv6:

| Scenario | Expected result |
|---|---|
| Two soft permits | Connection allowed |
| Soft permit followed by reject | Connection blocked |
| Reject followed by soft permit | Connection blocked; chain stops on reject |
| Soft permit followed by an unknown verdict | Connection blocked |
| Soft permit followed by hard permit | Connection allowed |
| Two soft permits with a WFP block | Connection blocked |
| Soft permit followed by hard permit with a WFP block | Connection allowed |
| Hard permit followed by soft permit with a WFP block | Connection allowed |
| Reject followed by hard permit | Connection blocked |
| Hard permit followed by reject | Connection blocked |
| Three soft permits | Connection allowed |
| Third program rejects | Connection blocked |
| Third program hard-permits with a WFP block | Connection allowed |
| Detach the first rejecting program | Connection recovers |
| Detach the middle rejecting program | Connection recovers |
| Detach the last rejecting program | Connection recovers |
| Detach and reattach a program with a rejecting policy | Connection becomes blocked |
| Compartment-specific and wildcard soft permits, in both attachment orders | Connection allowed |
| Compartment-specific reject with wildcard permits, in both attachment orders | Connection blocked |
| Wildcard reject with compartment-specific soft permits, in both attachment orders | Expected to block; currently `[!mayfail]` because wildcard rejection is not enforced across attachment scopes |
| Wildcard reject with a compartment-specific hard permit, in both attachment orders | Expected to block; currently `[!mayfail]` because wildcard rejection is not enforced across attachment scopes |
