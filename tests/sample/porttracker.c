// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c porttracker.c -o porttracker.o
//
// For bpf code: clang -target bpf -O2 -Werror -c porttracker.c -o porttracker.o
// this passes the checker

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

#define PROTOCOL_TCP 6
#define PROTOCOL_UDP 17

#define SUCCESS 0
#define FAILED 1
#define NOT_FOUND 2

typedef struct _process_entry
{
    uint64_t process_id;
    uint32_t count;
    uint8_t name[64];
} process_entry_t;

typedef struct in_addr
{
    union
    {
        struct
        {
            uint8_t s_b1, s_b2, s_b3, s_b4;
        } S_un_b;
        struct
        {
            uint16_t s_w1, s_w2;
        } S_un_w;
        uint32_t S_addr;
    } S_un;
#define s_addr S_un.S_addr       /* can be used for most tcp & ip code */
#define s_host S_un.S_un_b.s_b2  // host on imp
#define s_net S_un.S_un_b.s_b1   // network
#define s_imp S_un.S_un_w.s_w2   // imp
#define s_impno S_un.S_un_b.s_b4 // imp #
#define s_lh S_un.S_un_b.s_b3    // logical host
} IN_ADDR;

typedef struct _sockaddr_in
{
    uint16_t family;
    uint16_t sin_port;
    IN_ADDR sin_addr;
    uint8_t sin_zero[8];
} sockaddr_in;

#pragma clang section data = "maps"
ebpf_map_definition_in_file_t tcp_bind_map = {
    .size = sizeof(ebpf_map_definition_in_file_t),
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint16_t),
    .value_size = sizeof(process_entry_t),
    .max_entries = 1024};

ebpf_map_definition_in_file_t udp_bind_map = {
    .size = sizeof(ebpf_map_definition_in_file_t),
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint16_t),
    .value_size = sizeof(process_entry_t),
    .max_entries = 1024};

ebpf_map_definition_in_file_t range_map = {
    .size = sizeof(ebpf_map_definition_in_file_t),
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint16_t),
    .max_entries = 2};

inline int
insert_entry(bind_md_t* ctx, uint16_t port)
{
    void* map = ctx->protocol == PROTOCOL_TCP ? &tcp_bind_map : &udp_bind_map;

    process_entry_t* entry;
    process_entry_t value = {0};
    int index;
    entry = bpf_map_lookup_elem(map, &port);
    if (entry) {
        // An entry already exists. Increment the counter.
        entry->count++;
        return SUCCESS;
    }

    bpf_map_update_elem(map, &port, &value, 0);
    entry = bpf_map_lookup_elem(map, &port);
    if (!entry) {
        // Failed to retrieve the added entry.
        return FAILED;
    }

    entry->process_id = ctx->process_id;
    for (index = 0; index < 64; index++) {
        if ((ctx->app_id_start + index) >= ctx->app_id_end)
            break;

        entry->name[index] = ctx->app_id_start[index];
    }

    return SUCCESS;
}

inline int
delete_entry(bind_md_t* ctx, uint16_t port)
{
    void* map = ctx->protocol == PROTOCOL_TCP ? &tcp_bind_map : &udp_bind_map;

    process_entry_t* entry;
    int index;
    entry = bpf_map_lookup_elem(map, &port);
    if (!entry) {
        // Entry not found.
        return NOT_FOUND;
    }

    entry->count--;
    if (entry->count == 0) {
        bpf_map_delete_elem(map, &port);
    }

    return SUCCESS;
}

// The following line is optional, but is used to verify
// that the BindMonitor prototype is correct or the compiler
// would complain when the function is actually defined below.
bind_hook_t BindMonitor;

#pragma clang section text = "bind"
bind_action_t
PortTracker(bind_md_t* ctx)
{
    uint32_t track_all = 0;
    uint32_t start_port_key = 0;
    uint32_t end_port_key = 1;
    process_entry_t* entry;
    int result;
    uint16_t* start_port = bpf_map_lookup_elem(&range_map, &start_port_key);
    if (!start_port || *start_port == 0) {
        track_all = 1;
    }
    uint16_t* end_port = bpf_map_lookup_elem(&range_map, &end_port_key);
    if (!end_port || *end_port == 0) {
        track_all = 1;
    }

    sockaddr_in* addr = (sockaddr_in*)&ctx->socket_address;
    uint16_t port = addr->sin_port;

    if (ctx->protocol != PROTOCOL_TCP && ctx->protocol != PROTOCOL_UDP) {
        bpf_printk("Bind/Unbind for unknown protocol. Not tracking. Port=%u, Protocol=%u", port, ctx->protocol);
        return BIND_PERMIT;
    }

    switch (ctx->operation) {
    case BIND_OPERATION_BIND:
        result = insert_entry(ctx, port);
        if (result == SUCCESS) {
            bpf_printk("Reserve port=%u, protocol=%u", port, ctx->protocol);
        } else {
            bpf_printk("Reserve: Failed to track bind for port=%u, protocol=%u", port, ctx->protocol);
        }

        break;
    case BIND_OPERATION_UNBIND:
        result = delete_entry(ctx, port);
        if (result == SUCCESS) {
            bpf_printk("Release port=%u, protocol=%u", port, ctx->protocol);
        } else if (result == NOT_FOUND) {
            bpf_printk("Release: Existing entry not found for port=%u, protocol=%u", port, ctx->protocol);
        }

        break;
    default:
        break;
    }

    return BIND_PERMIT;
}
