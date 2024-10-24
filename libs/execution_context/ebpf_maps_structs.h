// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_async.h"
#include "ebpf_bitmap.h"
#include "ebpf_epoch.h"
#include "ebpf_handle.h"
#include "ebpf_hash_table.h"
#include "ebpf_maps.h"
#include "ebpf_object.h"
#include "ebpf_program.h"
#include "ebpf_ring_buffer.h"
#include "ebpf_tracelog.h"

typedef struct _ebpf_core_map
{
    ebpf_core_object_t object;
    cxplat_utf8_string_t name;
    ebpf_map_definition_in_memory_t ebpf_map_definition;
    uint32_t original_value_size;
    uint8_t* data;
} ebpf_core_map_t;

typedef struct _ebpf_map_metadata_table
{
    ebpf_map_type_t map_type;
    ebpf_result_t (*create_map)(
        _In_ const ebpf_map_definition_in_memory_t* map_definition,
        ebpf_handle_t inner_map_handle,
        _Outptr_ ebpf_core_map_t** map);
    void (*delete_map)(_In_ _Post_invalid_ ebpf_core_map_t* map);
    ebpf_result_t (*associate_program)(_Inout_ ebpf_map_t* map, _In_ const ebpf_program_t* program);
    ebpf_result_t (*find_entry)(
        _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key, bool delete_on_success, _Outptr_ uint8_t** data);
    ebpf_core_object_t* (*get_object_from_entry)(_Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key);
    ebpf_result_t (*update_entry)(
        _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key, _In_ const uint8_t* value, ebpf_map_option_t option);
    ebpf_result_t (*update_entry_with_handle)(
        _Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key, uintptr_t value_handle, ebpf_map_option_t option);
    ebpf_result_t (*update_entry_per_cpu)(
        _Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* value, ebpf_map_option_t option);
    ebpf_result_t (*delete_entry)(_Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key);
    ebpf_result_t (*next_key_and_value)(
        _Inout_ ebpf_core_map_t* map,
        _In_ const uint8_t* previous_key,
        _Out_ uint8_t* next_key,
        _Inout_opt_ uint8_t** next_value);
    int zero_length_key : 1;
    int zero_length_value : 1;
    int per_cpu : 1;
    int key_history : 1;
} ebpf_map_metadata_table_t;

static ebpf_result_t
_create_array_map(
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_core_map_t** map);

static ebpf_result_t
_associate_program_with_prog_array_map(_Inout_ ebpf_core_map_t* map, _In_ const ebpf_program_t* program);

static ebpf_result_t
_create_hash_map(
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_core_map_t** map);

static void
_delete_hash_map(_In_ _Post_invalid_ ebpf_core_map_t* map);

static ebpf_result_t
_create_lpm_map(
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_core_map_t** map);

static ebpf_result_t
_create_lru_hash_map(
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_core_map_t** map);

static ebpf_result_t
_create_lru_hash_map(
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_core_map_t** map);

static ebpf_result_t
_create_object_array_map(
    _Inout_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_core_map_t** map);

static ebpf_result_t
_update_map_hash_map_entry_with_handle(
    _Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key, uintptr_t value_handle, ebpf_map_option_t option);

static ebpf_result_t
_update_prog_array_map_entry_with_handle(
    _Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key, uintptr_t value_handle, ebpf_map_option_t option);

ebpf_result_t
_update_hash_map_entry(
    _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key, _In_opt_ const uint8_t* data, ebpf_map_option_t option);

static ebpf_result_t
_next_hash_map_key_and_value(
    _Inout_ ebpf_core_map_t* map,
    _In_opt_ const uint8_t* previous_key,
    _Out_ uint8_t* next_key,
    _Inout_opt_ uint8_t** next_value);

ebpf_result_t
_update_array_map_entry(
    _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key, _In_opt_ const uint8_t* data, ebpf_map_option_t option);

static ebpf_result_t
_delete_map_hash_map_entry(_Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key);

static void
_delete_object_hash_map(_In_ _Post_invalid_ ebpf_core_map_t* map);

static ebpf_result_t
_create_object_hash_map(
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_core_map_t** map);

ebpf_result_t
_find_array_map_entry(
    _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key, bool delete_on_success, _Outptr_ uint8_t** data);

static ebpf_result_t
_find_circular_map_entry(
    _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key, bool delete_on_success, _Outptr_ uint8_t** data);

static void
_delete_map_array_map(_In_ _Post_invalid_ ebpf_core_map_t* map);

static ebpf_result_t
_delete_hash_map_entry(_Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key);

static void
_delete_circular_map(_In_ _Post_invalid_ ebpf_core_map_t* map);

static ebpf_result_t
_delete_lpm_map_entry(_In_ ebpf_core_map_t* map, _Inout_ const uint8_t* key);

static ebpf_result_t
_delete_map_array_map_entry(_Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key);

ebpf_result_t
_find_hash_map_entry(
    _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key, bool delete_on_success, _Outptr_ uint8_t** data);

static void
_delete_program_array_map(_In_ _Post_invalid_ ebpf_core_map_t* map);

static ebpf_result_t
_delete_program_array_map_entry(_Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key);

_Ret_maybenull_ ebpf_core_object_t*
_get_object_from_array_map_entry(_Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key);

_Must_inspect_result_ ebpf_result_t
_update_entry_per_cpu(
    _Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* value, ebpf_map_option_t option);

static ebpf_result_t
_next_array_map_key_and_value(
    _In_ const ebpf_core_map_t* map,
    _In_ const uint8_t* previous_key,
    _Out_ uint8_t* next_key,
    _Inout_opt_ uint8_t** value);

static void
_delete_array_map(_In_ _Post_invalid_ ebpf_core_map_t* map);

static ebpf_result_t
_delete_array_map_entry(_Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key);

static ebpf_result_t
_create_queue_map(
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_core_map_t** map);

static void
_delete_ring_buffer_map(_In_ _Post_invalid_ ebpf_core_map_t* map);

static ebpf_result_t
_create_ring_buffer_map(
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_core_map_t** map);

static ebpf_result_t
_create_stack_map(
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_core_map_t** map);

static ebpf_result_t
_find_lpm_map_entry(
    _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key, bool delete_on_success, _Outptr_ uint8_t** data);

_Ret_maybenull_ ebpf_core_object_t*
_get_object_from_hash_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key);

EBPF_INLINE_HINT
ebpf_result_t
_update_circular_map_entry(
    _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key, _In_opt_ const uint8_t* data, ebpf_map_option_t option);

ebpf_result_t
_update_lpm_map_entry(
    _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key, _In_opt_ const uint8_t* data, ebpf_map_option_t option);

static ebpf_result_t
_update_map_array_map_entry_with_handle(
    _Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key, uintptr_t value_handle, ebpf_map_option_t option);
