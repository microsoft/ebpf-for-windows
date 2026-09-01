<!-- Copyright (c) eBPF for Windows contributors -->
<!-- SPDX-License-Identifier: MIT -->

# eBPF for Windows Flow Classification Hook Requirements

## Purpose

Define the behavior required to classify network flows by inspecting transport payloads. The
[current design proposal](FlowClassifyHook.md) describes the original stream-only design and will be updated separately
to satisfy these requirements.

## Traffic Coverage and Selection

- Support flow classification for TCP streams and datagrams, including UDP.
- Allow a program to select, per flow, whether payload classification is needed.
- Allow classification in the ingress direction, egress direction, or both.
- Do not invoke a classifier for unselected flows or directions.

## Flow Metadata

Make the following metadata accessible when selecting or classifying a flow:

- IP address family and local and remote IPv4 or IPv6 addresses.
- Transport protocol and applicable protocol-specific metadata, including local and remote ports for TCP and UDP and
  type and code for ICMP and ICMPv6.
- Network compartment and interface identifiers.
- Direction of the current payload and whether it is stream data or a datagram.
- A stable flow identifier for correlating establishment, payload, deletion, and asynchronous completion events.
- The lifecycle event represented by the invocation, including establishment, payload delivery, and deletion.
- An unambiguous indication of which optional metadata is valid.

## Payload Delivery and Access

- Deliver TCP stream data in order and preserve datagram boundaries.
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

Payload mutation, flow re-authorization, and redirection are out of scope.
