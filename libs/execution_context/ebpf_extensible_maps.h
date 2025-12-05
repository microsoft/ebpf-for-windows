// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_core.h"
#include "ebpf_extension.h"
#include "ebpf_maps.h"
#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief Create an extensible map.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_extensible_map_create(
        _In_ const ebpf_map_definition_in_memory_t* map_definition,
        ebpf_handle_t inner_map_handle,
        _Outptr_ ebpf_map_t** map);

    void
    ebpf_extensible_map_delete(_In_ _Post_ptr_invalid_ ebpf_core_map_t* map);

    /**
     * @brief Check if a map type is extensible (>= 4096).
     */
    bool __forceinline ebpf_map_type_is_extensible(uint32_t map_type);

    /**
     * @brief Find an element in an extensible map.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_extensible_map_find_entry(
        _Inout_ ebpf_map_t* map,
        size_t key_size,
        _In_reads_(key_size) const uint8_t* key,
        _Outptr_ uint8_t** value,
        int flags);

    /**
     * @brief Update an element in an extensible map.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_extensible_map_update_entry(
        _Inout_ ebpf_map_t* map,
        size_t key_size,
        _In_reads_(key_size) const uint8_t* key,
        size_t value_size,
        _In_reads_(value_size) const uint8_t* value,
        ebpf_map_option_t option,
        int flags);

    /**
     * @brief Delete an element from an extensible map.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_extensible_map_delete_entry(
        _In_ ebpf_map_t* map, size_t key_size, _In_reads_(key_size) const uint8_t* key, int flags);

    _Must_inspect_result_ ebpf_result_t
    ebpf_extensible_map_associate_program(_Inout_ ebpf_map_t* map, _In_ const struct _ebpf_program* program);

#ifdef __cplusplus
}
#endif