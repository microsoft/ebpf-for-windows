// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Transparent "mesh" injection sample: redirects outbound TCP sockets (IPv4 and
// IPv6) from a target process/pod to a local loopback proxy (default
// 127.0.0.1:15001), the primitive used by Windows sidecar (Envoy / zTunnel)
// service-mesh injection. This sample exercises both the CONNECT (redirect) and
// CONNECT_AUTHORIZATION (reauth allow-policy) attach types.
//
// Scope of this sample (deliberately narrow so behavior is testable end-to-end):
//   - TCP only (IPPROTO_TCP), at the BPF_CGROUP_INET4_CONNECT /
//     BPF_CGROUP_INET6_CONNECT (redirect) attach points and the matching
//     CONNECT_AUTHORIZATION reauth attach points. It does NOT redirect UDP or
//     other protocols, and it does not touch bind/listen attaches.
//   - IPv4 is redirected to proxy_config.proxy_ipv4:proxy_port.
//   - IPv6 is redirected to proxy_config.proxy_ipv6 (16 bytes) when set;
//     otherwise to the IPv4-mapped loopback form of proxy_config.proxy_ipv4.
//   - The original destination tuple ({family, user_ip4/6, user_port}) is
//     published to the proxy in the WFP connection REDIRECT_CONTEXT via
//     bpf_sock_addr_set_redirect_context(), so a proxy can learn where the
//     connection was originally heading.
//
// Design notes / loop avoidance and reauth caveat:
//   - Redirection only happens for sockets whose owner process is NOT itself the
//     proxy. Proxy PIDs are registered in 'proxy_pid_map' (uint64_t key == the
//     process id from bpf_get_current_pid_tgid()). When the proxy dials out
//     (e.g. to the upstream), the CONNECT program sees the proxy PID and does
//     not re-redirect, preventing a proxy self-dial loop.
//   - The CONNECT (redirect) layer is bypassed on WFP reauthorization (reauth)
//     of an established connection. Therefore the CONNECT_AUTHORIZATION program
//     acts as the reauth-time policy: it allows the already-redirected connection
//     (destined for the loopback proxy) to proceed. It cannot redirect (route
//     selection has already happened) and must treat the context as read-only.
//
// The proxy endpoint is configurable via 'proxy_config_map'. It defaults to
// 127.0.0.1:15001 (the standard Envoy / sidecar static proxy port).

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "ebpf_nethooks.h"
#include "net/ip.h"
#include "socket_tests_common.h"

// Default IPv4 loopback proxy endpoint (127.0.0.1) in network byte order.
#define MESH_PROXY_IPV4_DEFAULT 0x0100007f
#define MESH_PROXY_PORT_DEFAULT 15001

// Proxy endpoint configuration, programmable by the mesh control plane.
typedef struct _mesh_proxy_config
{
    uint32_t proxy_ipv4;      ///< Proxy IPv4 address in network byte order (0 => 127.0.0.1).
    uint32_t proxy_ipv6[4];   ///< Proxy IPv6 address in network byte order (all 0 => IPv4-mapped loopback).
    uint16_t proxy_port;      ///< Proxy port in host byte order (0 => MESH_PROXY_PORT_DEFAULT).
} mesh_proxy_config_t;

// Original destination tuple published to the proxy in the WFP redirect context.
// The user-mode proxy retrieves it with SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT.
typedef struct _mesh_original_destination
{
    uint32_t family;          ///< AF_INET or AF_INET6.
    union
    {
        uint32_t ipv4;        ///< Network byte order (valid when family == AF_INET).
        uint32_t ipv6[4];     ///< Network byte order (valid when family == AF_INET6).
    } address;
    uint16_t port;            ///< Network byte order (original destination port).
} mesh_original_destination_t;

// Single-entry config map: key 0 holds the proxy endpoint.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, mesh_proxy_config_t);
    __uint(max_entries, 1);
} proxy_config_map SEC(".maps");

// Set of PIDs that are themselves the proxy and must be exempted from
// redirection to avoid a proxy self-dial loop. The key is the 8-byte process id
// (the UPPER 32 bits of bpf_get_current_pid_tgid()).
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint64_t);
    __type(value, uint8_t); // 1 = proxy.
    __uint(max_entries, 64);
} proxy_pid_map SEC(".maps");

// Observability counter for tests/telemetry: number of redirects performed.
// The first increment seeds key 0 with an initial value (BPF_ANY), so a user-mode
// reader never observes -ENOENT for key 0 once a redirect has happened. A reader
// should still tolerate -ENOENT before the first redirect (see the tests).
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 1);
} redirect_counter_map SEC(".maps");

// Returns the socket owner PROCESS id (not the thread id). bpf_get_current_pid_tgid()
// packs (process_id << 32) | thread_id; take the UPPER 32 bits.
__inline uint64_t
get_current_process_id()
{
    return bpf_get_current_pid_tgid() >> 32;
}

// Returns non-zero if the current process is the registered proxy (loop avoidance).
__inline uint32_t
is_proxy_process()
{
    uint64_t process_id = get_current_process_id();
    uint8_t* is_proxy = bpf_map_lookup_elem(&proxy_pid_map, &process_id);
    return (is_proxy != NULL) && (*is_proxy != 0);
}

__inline void
read_proxy_config(mesh_proxy_config_t* proxy)
{
    uint32_t config_key = 0;
    mesh_proxy_config_t* config = bpf_map_lookup_elem(&proxy_config_map, &config_key);
    if (config != NULL) {
        __builtin_memcpy(proxy, config, sizeof(*proxy));
    } else {
        proxy->proxy_ipv4 = 0;
        proxy->proxy_ipv6[0] = 0;
        proxy->proxy_ipv6[1] = 0;
        proxy->proxy_ipv6[2] = 0;
        proxy->proxy_ipv6[3] = 0;
        proxy->proxy_port = 0;
    }

    // Apply defaults for unset fields.
    if (proxy->proxy_ipv4 == 0) {
        proxy->proxy_ipv4 = MESH_PROXY_IPV4_DEFAULT;
    }
    if (proxy->proxy_port == 0) {
        proxy->proxy_port = MESH_PROXY_PORT_DEFAULT;
    }
}

__inline void
increment_redirect_counter()
{
    uint32_t key = 0;
    uint64_t new_count = 0;
    uint64_t* current = bpf_map_lookup_elem(&redirect_counter_map, &key);
    if (current != NULL) {
        new_count = *current + 1;
        bpf_map_update_elem(&redirect_counter_map, &key, &new_count, BPF_EXIST);
    } else {
        // No entry yet: seed the count to 1 (avoids -ENOENT for user-mode readers).
        new_count = 1;
        bpf_map_update_elem(&redirect_counter_map, &key, &new_count, BPF_ANY);
    }
}

// Publish the original destination tuple into the WFP redirect context so the
// proxy can retrieve it via SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT. Only valid
// at the CONNECT (redirect) attach layers; returns < 0 at bind/listen.
__inline int
save_original_destination(bpf_sock_addr_t* ctx)
{
    mesh_original_destination_t original = {0};
    original.family = ctx->family;
    original.port = ctx->user_port;
    if (ctx->family == AF_INET6) {
        __builtin_memcpy(original.address.ipv6, ctx->user_ip6, sizeof(original.address.ipv6));
    } else {
        original.address.ipv4 = ctx->user_ip4;
    }
    return bpf_sock_addr_set_redirect_context(ctx, &original, sizeof(original));
}

// CONNECT (IPv4): redirect outbound TCP sockets to the loopback proxy unless the
// socket belongs to the proxy itself. Only TCP is in scope for this mesh sample.
SEC("cgroup/connect4")
int
mesh_redirect_connect4(bpf_sock_addr_t* ctx)
{
    if ((ctx->family != AF_INET) || (ctx->protocol != IPPROTO_TCP)) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    // Do not proxy the proxy's own outbound (upstream) sockets.
    if (is_proxy_process()) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    mesh_proxy_config_t proxy_config = {0};
    read_proxy_config(&proxy_config);

    // Preserve the original tuple for the proxy, then redirect to the endpoint.
    save_original_destination(ctx);

    ctx->user_ip4 = proxy_config.proxy_ipv4;
    ctx->user_port = htons(proxy_config.proxy_port);

    increment_redirect_counter();
    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}

// CONNECT (TCP over IPv6): redirect to the configured IPv6 endpoint, or to the
// IPv4-mapped loopback form of the IPv4 endpoint when proxy_ipv6 is unset.
SEC("cgroup/connect6")
int
mesh_redirect_connect6(bpf_sock_addr_t* ctx)
{
    if ((ctx->family != AF_INET6) || (ctx->protocol != IPPROTO_TCP)) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    if (is_proxy_process()) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    mesh_proxy_config_t proxy_config = {0};
    read_proxy_config(&proxy_config);

    // Preserve the original tuple for the proxy.
    save_original_destination(ctx);

    // Build the IPv6 proxy address: use the configured 16-byte proxy_ipv6 when
    // set; otherwise default to an IPv4-mapped loopback carrying proxy_ipv4.
    uint32_t proxy_ipv6[4];
    __builtin_memcpy(proxy_ipv6, proxy_config.proxy_ipv6, sizeof(proxy_ipv6));
    if ((proxy_ipv6[0] == 0) && (proxy_ipv6[1] == 0) && (proxy_ipv6[2] == 0) && (proxy_ipv6[3] == 0)) {
        proxy_ipv6[0] = 0;
        proxy_ipv6[1] = 0;
        proxy_ipv6[2] = htonl(0xffff); // IPv4-mapped prefix, network byte order.
        proxy_ipv6[3] = proxy_config.proxy_ipv4;
    }
    __builtin_memcpy(ctx->user_ip6, proxy_ipv6, sizeof(ctx->user_ip6));
    ctx->user_port = htons(proxy_config.proxy_port);

    increment_redirect_counter();
    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}

// CONNECT_AUTHORIZATION (IPv4): reauth-time allow-policy. On WFP reauth the
// CONNECT (redirect) layer is bypassed, so this program re-enforces that the
// proxied connection is allowed. The context is read-only at this layer: mutate
// at your own risk (the extension discards writes and blocks the connection).
SEC("cgroup/connect_authorization4")
int
mesh_authorize_connect4(bpf_sock_addr_t* ctx)
{
    if ((ctx->family != AF_INET) || (ctx->protocol != IPPROTO_TCP)) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    // Demonstrate the versioned network-context helper (route/tunnel aware).
    bpf_sock_addr_network_context_t net_ctx = {0};
    if (bpf_sock_addr_get_network_context(ctx, &net_ctx, sizeof(net_ctx)) < 0) {
        // Network context unavailable: fail closed.
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    // Mesh-redirected traffic reaches the loopback proxy on the loopback /
    // tunneled interface. Allow it to proceed. (Production would consult a
    // policy map rather than unconditional allow.)
    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}

// CONNECT_AUTHORIZATION (IPv6).
SEC("cgroup/connect_authorization6")
int
mesh_authorize_connect6(bpf_sock_addr_t* ctx)
{
    if ((ctx->family != AF_INET6) || (ctx->protocol != IPPROTO_TCP)) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    bpf_sock_addr_network_context_t net_ctx = {0};
    if (bpf_sock_addr_get_network_context(ctx, &net_ctx, sizeof(net_ctx)) < 0) {
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}
