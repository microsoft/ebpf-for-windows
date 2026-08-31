# Transparent Mesh Redirection Sample (connect_redirect_mesh)

This document describes the `connect_redirect_mesh` eBPF sample program, a
first-party, minimal example of **transparent outbound socket redirection to a
local loopback proxy**  the primitive used by service-mesh data planes
(Envoy, zTunnel, Linkerd) to intercept application traffic. It implements the
connect-redirect + connect-authorization pattern requested in
[#848](https://github.com/microsoft/ebpf-for-windows/issues/848).

The sample source lives at `tests/sample/connect_redirect_mesh.c` and is built
automatically by `tests/sample/sample.vcxproj` (the `CustomBuild Include="*.c"`
wildcard compiles every `.c` in that directory). It attaches to:

| Attach type                        | Layer                               | Role |
| ----------------------------------- | ----------------------------------- | ---- |
| `BPF_CGROUP_INET4_CONNECT`        | CONNECT (redirect)                  | Redirect outbound connections to the loopback proxy |
| `BPF_CGROUP_INET6_CONNECT`        | CONNECT (redirect)                  | Redirect outbound IPv6 connections |
| `BPF_CGROUP_INET4_CONNECT_AUTHORIZATION` | CONNECT_AUTHORIZATION       | Reauth-time allow policy (read-only) |
| `BPF_CGROUP_INET6_CONNECT_AUTHORIZATION` | CONNECT_AUTHORIZATION       | Reauth-time allow policy (read-only) |

## How it works

The sample redirects an outbound socket from a target process/pod to a loopback
proxy (default `127.0.0.1:15001`, the standard Envoy/sidecar static proxy port)
by rewriting the destination address/port in the CONNECT (redirect) layer. It
also attaches a CONNECT_AUTHORIZATION program to handle the reauthorization case
(see below).

### Maps

- `proxy_config_map` - single-entry hash map that lets a control plane program
  the proxy endpoint (IPv4 address and port). Falls back to `127.0.0.1:15001`.
- `proxy_pid_map` - hash map that lists the PIDs that are *themselves* the
  proxy, used for loop avoidance.
- `redirect_counter_map` - observability counter incremented each time a
  connection is redirected (useful for tests/telemetry).

### Loop avoidance

The proxy itself must not have its outbound upstream connections redirected back
into itself. The proxy PID is registered in `proxy_pid_map`. The CONNECT
program calls `bpf_get_current_pid_tgid()` to obtain the socket owner PID; if
that PID is present in `proxy_pid_map`, the connection is left unmodified. This
is how a sidecar avoids an infinite proxy self-dial loop.

## The reauth caveat  ->  use CONNECT_AUTHORIZATION

WFP reauthorization ("reauth") replays authorization for an established
connection without re-running the **redirect** layer. Consequently:

1. A CONNECT program is **bypassed during reauth**.
2. To keep enforcement consistent across the connection lifetime, attach a
   CONNECT_AUTHORIZATION program, which IS invoked on reauth.

The CONNECT_AUTHORIZATION layer runs **after route selection** and **cannot
redirect**; it can only **authorize**. It must treat the `bpf_sock_addr` context
as **read-only** - a program that writes source/destination IP/port at this layer
causes the extension to block the connection. The sample therefore only READS
network context (via `bpf_sock_addr_get_network_context()`) and returns
`BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT` for proxied traffic.

## Testing

The `connect_redirect_mesh` native module is loaded and verified by the
`connect_mesh_redirect_program_load` test case in
`tests/connect_redirect/connect_redirect_tests.cpp`: it opens and loads the
module and asserts that all four programs and all three maps resolve with valid
fds. A behavioral (real-socket) assertion is deliberately not added here: the
sample unconditionally redirects to `127.0.0.1:15001`, and this suite's
real-socket harness already owns the `BPF_CGROUP_INET4_CONNECT` attach point
via `connection_redirection_tests_*`, which cannot be held simultaneously
with a second module at the same attach point. The redirect + proxy-PID loop
avoidance behavior therefore belongs to the connection-redirection integration
suite.

> Note: this change was authored without a WDK/CMake/VS build environment, so the
> program has not been compiled or run here. It will be validated by the
> project's CI build and the eBPF verifier. Before merging, build `tests\sample`
> to produce `connect_redirect_mesh.o` + native images, and add bpf2c expected
> output (via `scripts\generate_expected_bpf2c_output.ps1`) if bpf2c coverage
> is added.

See also [ConnectAuthorizationAttachTypes.md](ConnectAuthorizationAttachTypes.md)
for the full CONNECT vs CONNECT_AUTHORIZATION behavior and constraints.
