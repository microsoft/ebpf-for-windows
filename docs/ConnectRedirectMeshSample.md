# Transparent Mesh Redirection Sample (connect_redirect_mesh)

This document describes the `connect_redirect_mesh` eBPF sample program, a
first-party, minimal example of **transparent outbound socket redirection to a
local loopback proxy**  the primitive used by service-mesh data planes
(Envoy, zTunnel, Linkerd) to intercept application traffic. It implements the
connect-redirect + connect-authorization pattern requested in
[#848](https://github.com/microsoft/ebpf-for-windows/issues/848).

> **Scope is deliberately narrow so the behavior is testable end-to-end.**
> The sample redirects **TCP only** (IPv4 and IPv6), at the
> `BPF_CGROUP_INET4_CONNECT` / `BPF_CGROUP_INET6_CONNECT` attach points and the
> matching `CONNECT_AUTHORIZATION` reauth attach points. It does **not**
> redirect UDP or other protocols, and it does not touch the bind/listen attach
> points. Claims below match what the code and tests actually do.

The sample source lives at `tests/sample/connect_redirect_mesh.c` and is built
automatically by `tests/sample/sample.vcxproj` (the `CustomBuild Include="*.c"`
wildcard compiles every `.c` in that directory). It attaches to:

| Attach type                        | Layer                               | Role |
| ----------------------------------- | ----------------------------------- | ---- |
| `BPF_CGROUP_INET4_CONNECT`        | CONNECT (redirect)                  | Redirect outbound TCP connections to the loopback proxy |
| `BPF_CGROUP_INET6_CONNECT`        | CONNECT (redirect)                  | Redirect outbound TCP over IPv6 |
| `BPF_CGROUP_INET4_CONNECT_AUTHORIZATION` | CONNECT_AUTHORIZATION       | Reauth-time allow policy (read-only) |
| `BPF_CGROUP_INET6_CONNECT_AUTHORIZATION` | CONNECT_AUTHORIZATION       | Reauth-time allow policy (read-only) |

## How it works

The sample redirects an outbound TCP socket from a target process/pod to a
loopback proxy by rewriting the destination address/port in the CONNECT
(redirect) layer. It also attaches a CONNECT_AUTHORIZATION program to handle the
reauthorization case (see below).

- **IPv4** connections are redirected to
  `proxy_config_map.proxy_ipv4 : proxy_port`.
- **IPv6** connections are redirected to the configured `proxy_ipv6` (16 bytes)
  when set; otherwise to the **IPv4-mapped loopback** form of the configured
  IPv4 endpoint (`::ffff:<proxy_ipv4>`), using the correct network-order prefix
  (`htonl(0xffff)`).
- Before rewriting, the sample publishes the **original destination tuple**
  (`{family, user_ip4/6, user_port}`) via `bpf_sock_addr_set_redirect_context()`.
  The proxy (in user mode) retrieves it with the
  `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` ioctl on the accepted socket, so it
  can learn where the connection was originally heading.

### Maps

- `proxy_config_map` - single-entry hash map that lets a control plane program
  the proxy endpoint (IPv4/IPv6 address and port). Falls back to
  `127.0.0.1:15001`.
- `proxy_pid_map` - hash map keyed by the **8-byte process id** (the upper 32
  bits of `bpf_get_current_pid_tgid()`) listing the PIDs that are *themselves*
  the proxy, used for loop avoidance. The program and its tests use matching
  `uint64_t` keys.
- `redirect_counter_map` - observability counter incremented each time a
  connection is redirected (useful for tests/telemetry). Key `0` is read
  tolerantly (a still-unseeded key reports zero rather than `-ENOENT`).

### Loop avoidance

The proxy itself must not have its outbound upstream connections redirected back
into itself. The proxy PID is registered in `proxy_pid_map`. The CONNECT
program calls `bpf_get_current_pid_tgid()` and takes the **upper 32 bits** (the
socket-owner **process id**, not the thread id); if that ID is present in
`proxy_pid_map`, the connection is left unmodified. This is how a sidecar avoids
an infinite proxy self-dial loop.

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
`BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT` for proxied TCP traffic.

## Testing

The `connect_redirect_mesh` native module is exercised by real, checked-in
integration tests in `tests/connect_redirect/connect_redirect_tests.cpp`
(tagged `[connect_mesh_redirect_tests]`):

- `connect_mesh_redirect_ipv4_config_and_protocol_scope` - verifies the program
  honors `proxy_config_map`, redirects TCP, and that UDP is **not** redirected,
  by invoking the program with `bpf_prog_test_run_opts` and inspecting output.
- `connect_mesh_redirect_ipv6_all_sixteen_bytes` - verifies the program writes
  the **full 16-byte** configured IPv6 proxy destination (regression guard for
  IPv6 such as the IPv4-mapped loopback prefix), via a synthetic context, and
  verifies proxy-PID loop avoidance using the real socket-owner **process id**.
- `connect_mesh_redirect_real_socket_ipv4` - attaches the mesh programs to real
  sockets, makes a real `connect()` through them, and asserts: the connection
  lands on the loopback proxy, the original destination tuple is handed off
  through the WFP redirect context
  (`SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT`), and once the owning PID is
  registered as the proxy, the proxy's own dial is **not** redirected.

The CONNECT / CONNECT_AUTHORIZATION attach points are single-slot, so these
cases attach the mesh programs and detach them on completion and are expected
to run in isolation from the `cgroup_sock_addr2` redirection suite.

> Note: this change was authored without a WDK/CMake/VS build environment, so the
> program and tests have not been compiled or run here. They will be validated
> by the project's CI build and the eBPF verifier. Before merging, build
> `tests\sample` to produce `connect_redirect_mesh.o` + native images, run the
> `[connect_mesh_redirect_tests]` cases, and add bpf2c expected output if
> bpf2c coverage is added.

See also [ConnectAuthorizationAttachTypes.md](ConnectAuthorizationAttachTypes.md)
for the full CONNECT vs CONNECT_AUTHORIZATION behavior and constraints.
