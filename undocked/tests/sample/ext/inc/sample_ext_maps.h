// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

// Sample extension custom map implementations.
// Common implementation to be included both in the sample extension driver and unit tests.

#include "ebpf_api.h"
#include "ebpf_extension.h"
#include "ebpf_extension_uuids.h"
#include "ebpf_nethooks.h"
#include "ebpf_program_types.h"
#include "ebpf_structs.h"
#include "ebpf_windows.h"
#include "sample_ext_program_info.h"

#define EBPF_SAMPLE_MAP_PROVIDER_GUID                                                  \
    {                                                                                  \
        0xf788ef4b, 0x207d, 0x4dc4, { 0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c } \
    }

extern uint32_t map_pool_tag;

typedef struct _sample_core_map
{
    uint32_t map_type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
} sample_core_map_t;

typedef struct _sample_hash_map_entry
{
    uint32_t value;
} sample_hash_map_entry_t;

static ebpf_result_t
_sample_object_hash_map_delete_entry_common(
    ebpf_base_map_client_dispatch_table_t* client_dispatch_table,
    size_t value_size,
    _In_reads_(value_size) const uint8_t* value,
    uint32_t flags)
{
    if (flags & EBPF_MAP_OPERATION_HELPER) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }

    UNREFERENCED_PARAMETER(value_size);

    // The value is a pointer to an object. Read the pointer.
    sample_hash_map_entry_t* entry = (sample_hash_map_entry_t*)ReadULong64NoFence((volatile const uint64_t*)value);

    if (entry == NULL) {
        return EBPF_KEY_NOT_FOUND;
    }

    // Free the object.
    client_dispatch_table->epoch_free(entry);

    return EBPF_SUCCESS;
}

static ebpf_result_t
_sample_object_hash_map_find_entry_common(
    size_t in_value_size,
    _In_reads_(in_value_size) const uint8_t* in_value,
    size_t out_value_size,
    _Out_writes_opt_(out_value_size) uint8_t* out_value)
{
    UNREFERENCED_PARAMETER(in_value_size);
    UNREFERENCED_PARAMETER(out_value_size);

    // out_value cannot be NULL for object map.
    if (out_value == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }

    // The in_value is a pointer to an object. Read the pointer.
    sample_hash_map_entry_t* value = (sample_hash_map_entry_t*)ReadULong64NoFence((volatile const uint64_t*)in_value);

    if (value == NULL) {
        return EBPF_KEY_NOT_FOUND;
    }

    // Copy the value from the object to out_value.
    memcpy(out_value, &value->value, sizeof(uint32_t));

    return EBPF_SUCCESS;
}

static ebpf_result_t
_sample_object_hash_map_update_entry_common(
    ebpf_base_map_client_dispatch_table_t* client_dispatch_table,
    size_t in_value_size,
    _In_reads_(in_value_size) const uint8_t* in_value,
    size_t out_value_size,
    _Out_writes_opt_(out_value_size) uint8_t* out_value)
{
    UNREFERENCED_PARAMETER(in_value_size);
    UNREFERENCED_PARAMETER(out_value_size);

    // out_value cannot be NULL for object map.
    if (out_value == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }

    // Create a new object to hold the value.
    sample_hash_map_entry_t* value = (sample_hash_map_entry_t*)client_dispatch_table->epoch_allocate_with_tag(
        sizeof(sample_hash_map_entry_t), map_pool_tag);
    if (value == NULL) {
        return EBPF_NO_MEMORY;
    }

    // Copy the value from in_value to the object.
    memcpy(&value->value, in_value, sizeof(uint32_t));

    // Store the pointer to the object as a uint64_t.
    WriteULong64NoFence((volatile uint64_t*)out_value, (uint64_t)value);

    return EBPF_SUCCESS;
}
