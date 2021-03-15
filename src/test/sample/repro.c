/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

// clang -O2 -Wall -c droppacket.c -o dropjit.o
//
// For bpf code: clang -target bpf -O2 -Wall -c repro.c -o repro.o
// this passes the checker

#if defined(_MSC_VER)
typedef unsigned long long uint64_t;
#else
typedef unsigned long uint64_t;
#endif

typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;

typedef struct _bind_md
{
    char* app_id_start;
    char* app_id_end;
    uint64_t process_id;
    uint8_t socket_address[16];
    uint8_t socket_address_length;
    uint8_t operation;
    uint8_t protocol;
} bind_md_t;

typedef enum _bind_operation
{
    BIND_OPERATION_BIND,      // Entry to bind
    BIND_OPERATION_POST_BIND, // After port allocation
    BIND_OPERATION_UNBIND,    // Release port
} bind_operation_t;

typedef enum _bind_action
{
    BIND_PERMIT,
    BIND_DENY,
    BIND_REDIRECT,
} bind_action_t;

typedef struct _bpf_map_def
{
    uint32_t size;
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
} bpf_map_def_t;

typedef enum _ebpf_map_type
{
    EBPF_MAP_TYPE_UNSPECIFIED = 0,
    EBPF_MAP_TYPE_HASH = 1,
    EBPF_MAP_TYPE_ARRAY = 2,
} ebpf_map_type_t;

typedef void* (*ebpf_map_lookup_elem_t)(bpf_map_def_t* map, void* key);
#define ebpf_map_lookup_elem ((ebpf_map_lookup_elem_t)1)

typedef void (*ebpf_map_update_element_t)(bpf_map_def_t* map, void* key, void* data, uint64_t flags);
#define ebpf_map_update_element ((ebpf_map_update_element_t)2)

typedef void (*ebpf_map_delete_elem_t)(bpf_map_def_t* map, void* key);
#define ebpf_map_delete_elem ((ebpf_map_delete_elem_t)3)

#pragma clang section data = "maps"
bpf_map_def_t test_map = {
    .size = sizeof(bpf_map_def_t),
    .type = EBPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(uint64_t),
    .max_entries = 1};

#pragma clang section text = "bind"
int
BindMonitor(bind_md_t* ctx)
{
    uint64_t key = ctx->process_id;

    uint64_t* value = ebpf_map_lookup_elem(&test_map, &key);

    *value = 1;

    return BIND_PERMIT;
}