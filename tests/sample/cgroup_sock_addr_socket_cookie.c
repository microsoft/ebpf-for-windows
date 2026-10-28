// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Whenever this sample program changes, bpf2c_tests will fail unless the
// expected files in tests\bpf2c_tests\expected are updated. The following
// script can be used to regenerate the expected files:
//     generate_expected_bpf2c_output.ps1
//
// Usage:
// .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>
// Example:
// .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\

/**
 * @brief Sample programs that query the socket cookie (via bpf_get_socket_cookie) for a
 * socket that is bound/listening/connecting on SOCKET_TEST_PORT, at each of the five
 * sock_addr hook families: bind, listen, connect, connect_authorization, and recv_accept,
 * and write the result into socket_cookie_capture_map.
 */

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "socket_tests_common.h"

// Identifies which hook family captured a given cookie. Used as the key into
// socket_cookie_capture_map.
typedef enum _socket_cookie_hook_id
{
    SOCKET_COOKIE_HOOK_BIND4 = 1,
    SOCKET_COOKIE_HOOK_BIND6,
    SOCKET_COOKIE_HOOK_LISTEN4,
    SOCKET_COOKIE_HOOK_LISTEN6,
    SOCKET_COOKIE_HOOK_CONNECT4,
    SOCKET_COOKIE_HOOK_CONNECT6,
    SOCKET_COOKIE_HOOK_CONNECT_AUTHORIZATION4,
    SOCKET_COOKIE_HOOK_CONNECT_AUTHORIZATION6,
    SOCKET_COOKIE_HOOK_RECV_ACCEPT4,
    SOCKET_COOKIE_HOOK_RECV_ACCEPT6,
} socket_cookie_hook_id_t;

// Map of hook_id -> captured socket cookie.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 16);
} socket_cookie_capture_map SEC(".maps");

static __inline void
capture_cookie(bpf_sock_addr_t* ctx, uint32_t hook_id)
{
    uint64_t cookie = bpf_get_socket_cookie(ctx);
    bpf_map_update_elem(&socket_cookie_capture_map, &hook_id, &cookie, BPF_ANY);
}

// Generates a program that captures the socket cookie when ctx->user_port matches
// SOCKET_TEST_PORT. user_port always carries the destination port of the packet: the port
// being bound/listened on for bind and listen, the destination port being connected to for
// connect and connect_authorization, and the local (server) port -- the destination of an
// inbound connection -- for recv_accept.
#define DEFINE_CAPTURE_PROGRAM(section, name, hook_id)       \
    SEC(section)                                             \
    int name(bpf_sock_addr_t* ctx)                           \
    {                                                        \
        if (ctx->user_port == bpf_htons(SOCKET_TEST_PORT)) { \
            capture_cookie(ctx, hook_id);                    \
        }                                                    \
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;           \
    }

DEFINE_CAPTURE_PROGRAM("cgroup/bind4", capture_bind4, SOCKET_COOKIE_HOOK_BIND4)
DEFINE_CAPTURE_PROGRAM("cgroup/bind6", capture_bind6, SOCKET_COOKIE_HOOK_BIND6)
DEFINE_CAPTURE_PROGRAM("cgroup/listen4", capture_listen4, SOCKET_COOKIE_HOOK_LISTEN4)
DEFINE_CAPTURE_PROGRAM("cgroup/listen6", capture_listen6, SOCKET_COOKIE_HOOK_LISTEN6)
DEFINE_CAPTURE_PROGRAM("cgroup/connect4", capture_connect4, SOCKET_COOKIE_HOOK_CONNECT4)
DEFINE_CAPTURE_PROGRAM("cgroup/connect6", capture_connect6, SOCKET_COOKIE_HOOK_CONNECT6)
DEFINE_CAPTURE_PROGRAM(
    "cgroup/connect_authorization4", capture_connect_authorization4, SOCKET_COOKIE_HOOK_CONNECT_AUTHORIZATION4)
DEFINE_CAPTURE_PROGRAM(
    "cgroup/connect_authorization6", capture_connect_authorization6, SOCKET_COOKIE_HOOK_CONNECT_AUTHORIZATION6)
DEFINE_CAPTURE_PROGRAM("cgroup/recv_accept4", capture_recv_accept4, SOCKET_COOKIE_HOOK_RECV_ACCEPT4)
DEFINE_CAPTURE_PROGRAM("cgroup/recv_accept6", capture_recv_accept6, SOCKET_COOKIE_HOOK_RECV_ACCEPT6)
