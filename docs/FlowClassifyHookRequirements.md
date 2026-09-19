<!-- Copyright (c) eBPF for Windows contributors -->
<!-- SPDX-License-Identifier: MIT -->

# eBPF for Windows Flow Classification Hook Requirements

## Purpose

Define the behavior required to inspect TCP stream data, UDP datagrams, and ICMP and ICMPv6 messages and use the
results to classify the associated network flow. The
[current design proposal](FlowClassifyHook.md) describes the original stream-only design and will be updated separately
to satisfy these requirements.

## Definitions

- A **network flow** is traffic with common endpoint and protocol metadata that is tracked under one stable identifier
  and lifecycle and classified as a unit. For TCP, this is a connection; for UDP, ICMP, and ICMPv6, related datagrams
  or messages are grouped under the same identifier.
- **Flow classification** is the inspection of a flow's metadata and payloads to make a policy decision for the flow
  rather than for each payload independently.

## Traffic Coverage and Selection

- Support payload inspection and flow classification for TCP stream data, UDP datagrams, and ICMP and ICMPv6 messages.
- Allow a program to select, per flow, whether payload inspection is needed.
- Allow payload inspection in the ingress direction, egress direction, or both.
- Do not invoke a classifier for unselected flows or directions.

## Flow Metadata

Make the following metadata accessible when selecting or classifying a flow:

- IP address family and local and remote IPv4 or IPv6 addresses.
- Transport protocol and applicable protocol-specific metadata, including local and remote ports for TCP and UDP and
  type and code for ICMP and ICMPv6.
- Network compartment and interface identifiers.
- The local process identifier and user-token-derived security identity associated with the flow, sufficient to identify
  the logon session and evaluate token-based authorization properties.
- Make the same process and user identity available throughout the flow lifecycle.
- Direction of the current payload and whether it is TCP stream data, a UDP datagram, or an ICMP or ICMPv6 message.
- A stable flow identifier for correlating establishment, payload, deletion, and asynchronous completion events.
- The lifecycle event represented by the invocation, including establishment, payload delivery, and deletion.
- An unambiguous indication of which optional metadata is valid, including when process or user identity is unavailable.

## Payload Delivery and Access

- Deliver TCP stream data in order.
- Preserve boundaries between UDP datagrams and between ICMP and ICMPv6 messages.
- Provide the total payload length without requiring the full payload to be copied into contiguous memory.
- Allow a classifier to request only the payload bytes it needs, deferring any required copy until that request.

## Classification and Lifecycle

- Support these synchronous results:
  - **Allow** the flow and stop invoking the returning program for it.
  - **Block** the flow and stop invoking all classifiers for it.
  - **Need more data** by allowing the current payload and invoking the returning program for later payloads.
- Allow a classifier to pend a flow so that an external component can be notified and complete classification
  asynchronously.
- Notify a classifier when a flow that it is still classifying is deleted so that per-flow state can be cleaned up.

## Multiple Programs

- Allow multiple programs to classify the same flow.
- Invoke programs in attachment order until a program blocks the flow.
- When a program allows a flow, stop invoking that program while continuing to invoke other programs that still need
  data.

## Scope

Raw IP datagrams, payload mutation, flow re-authorization, and redirection are out of scope.
