// Copyright (c) Microsoft Corporation
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

#include "bpf_helpers.h"
#include "socket_tests_common.h"

// #define REDIRECT_IP 16843009 // 1.1.1.1
#define REDIRECT_IP 0xc8010119 // Network byte order 25.1.1.200
#define PROXY_IP 0x64010119    // Network byte order 25.1.1.100
#define PERMIT_IP 33620225     // Network byte order 1.1.1.2
#define BLOCK_IP 50397441      // Network byte order 1.1.1.3

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define AF_INET 2

typedef struct _destination_entry
{
    uint32_t destination_ip;
    uint16_t destination_port;
} destination_entry_t;

SEC("maps")
struct bpf_map_def proxy_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(destination_entry_t),
    .value_size = sizeof(destination_entry_t),
    .max_entries = 100};

SEC("maps")
struct bpf_map_def frontend_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(destination_entry_t),
    .max_entries = 1};

SEC("maps")
struct bpf_map_def backend_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(destination_entry_t),
    .max_entries = 2};

SEC("maps")
struct bpf_map_def scratch_map = {
    .type = BPF_MAP_TYPE_ARRAY, .key_size = sizeof(uint32_t), .value_size = sizeof(uint32_t), .max_entries = 1};

SEC("cgroup/connect4/proxy")
int
proxy_v4(bpf_sock_addr_t* ctx)
{
    destination_entry_t entry = {0};
    entry.destination_ip = ctx->user_ip4;
    entry.destination_port = ctx->user_port;

    bpf_printk("anusa: ctx: %u, %u", ctx->user_ip4, ctx->user_port);

    if (ctx->protocol != IPPROTO_TCP) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED;
    }

    if (ctx->family != AF_INET) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED;
    }

    // Find the entry in the proxy map.
    destination_entry_t* proxy_entry = bpf_map_lookup_elem(&proxy_map, &entry);
    if (proxy_entry != NULL) {
        bpf_printk("anusa: found proxy entry: %u, %u", proxy_entry->destination_ip, proxy_entry->destination_port);
        ctx->user_ip4 = proxy_entry->destination_ip;
        ctx->user_port = proxy_entry->destination_port;

        return BPF_SOCK_ADDR_VERDICT_PROCEED;
    }

    return BPF_SOCK_ADDR_VERDICT_REJECT;
}

SEC("cgroup/connect4/lbnat")
int
lbnat_v4(bpf_sock_addr_t* ctx)
{
    // Get the frontend config.
    uint32_t key = 0;
    destination_entry_t* frontend = bpf_map_lookup_elem(&frontend_map, &key);
    if (!frontend) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED;
    }
    if (frontend->destination_ip != ctx->user_ip4 || frontend->destination_port != ctx->user_port) {
        // This connection does not match the NAT frontend. Allow it.
        return BPF_SOCK_ADDR_VERDICT_PROCEED;
    }

    key = 0;
    uint32_t* scratch_entry = bpf_map_lookup_elem(&scratch_map, &key);
    if (!scratch_entry) {
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }
    key = (*scratch_entry > 0) ? 1 : 0;
    *scratch_entry = key == 1 ? 0 : 1;

    // Get the backend info.
    destination_entry_t* backend = bpf_map_lookup_elem(&backend_map, &key);
    if (!backend) {
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    ctx->user_ip4 = backend->destination_ip;
    ctx->user_port = backend->destination_port;

    return BPF_SOCK_ADDR_VERDICT_PROCEED;
}

SEC("cgroup/connect4/blockall")
int
blockall_v4(bpf_sock_addr_t* ctx)
{
    return BPF_SOCK_ADDR_VERDICT_REJECT;
}
