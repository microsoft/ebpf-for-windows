#pragma once
/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/
#pragma once
#include "../../include/ebpf_windows.h"

typedef struct _ebpf_core_map {
    struct _ebpf_map_definition ebpf_map_definition;
    KSPIN_LOCK lock;
    uint8_t* data;
} ebpf_core_map_t;

typedef struct _ebpf_core_map_entry {
    LIST_ENTRY entry;
    ebpf_core_map_t map;
    uint64_t handle;
} ebpf_core_map_entry_t;

typedef struct _ebpf_map_function_table
{
    struct _ebpf_core_map_entry* (*create_map)(_In_ const struct _ebpf_map_definition* map_definition);
    void (*delete_map)(_In_ struct _ebpf_core_map_entry* map);
    uint8_t* (*lookup_entry)(_In_ struct _ebpf_core_map* map, _In_ const uint8_t* key);
    NTSTATUS(*update_entry)(_In_ struct _ebpf_core_map* map, _In_ const uint8_t* key, _In_ const uint8_t* value);
    NTSTATUS(*delete_entry)(_In_ struct _ebpf_core_map* map, _In_ const uint8_t* key);
} ebpf_map_function_table_t;

extern ebpf_map_function_table_t ebpf_map_function_tables[EBPF_MAP_TYPE_ARRAY + 1];