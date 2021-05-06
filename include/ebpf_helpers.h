// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include <stdint.h>

// This file contains APIs for global helpers that are
// exposed for use by all eBPF programs.

typedef struct _ebpf_map_definition
{
    uint32_t size;
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
} ebpf_map_definition_t;

typedef enum _ebpf_map_type
{
    EBPF_MAP_TYPE_UNSPECIFIED = 0,
    EBPF_MAP_TYPE_HASH = 1,
    EBPF_MAP_TYPE_ARRAY = 2,
} ebpf_map_type_t;

typedef void* (*ebpf_map_lookup_element_t)(ebpf_map_definition_t* map, void* key);
#define ebpf_map_lookup_element ((ebpf_map_lookup_element_t)1)

typedef int64_t (*ebpf_map_update_element_t)(ebpf_map_definition_t* map, void* key, void* data, uint64_t flags);
#define ebpf_map_update_element ((ebpf_map_update_element_t)2)

typedef int64_t (*ebpf_map_delete_element_t)(ebpf_map_definition_t* map, void* key);
#define ebpf_map_delete_element ((ebpf_map_delete_element_t)3)

//
// Defines for cross-platform compatibility.
//

#define bpf_map _ebpf_map_definition
#define bpf_map_lookup_elem ebpf_map_lookup_element
#define bpf_map_update_elem ebpf_map_update_element
#define bpf_map_delete_elem ebpf_map_delete_element

#define BPF_MAP_TYPE_UNSPECIFIED EBPF_MAP_TYPE_UNSPECIFIED
#define BPF_MAP_TYPE_HASH EBPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_ARRAY EBPF_MAP_TYPE_ARRAY
