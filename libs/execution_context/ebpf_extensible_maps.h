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

    // Forward declarations
    // typedef struct _ebpf_extensible_map ebpf_extensible_map_t;
    typedef struct _ebpf_extensible_map_provider ebpf_extensible_map_provider_t;

    /**
     * @brief Map provider interface structure that extensions must implement.
     */
    typedef struct _ebpf_extensible_map_provider
    {
        // Provider identification
        GUID provider_guid;
        uint32_t supported_map_type_count;        // Number of supported map types
        const uint32_t* supported_map_types;     // Array of supported map types

        // Map lifecycle operations
        ebpf_result_t (*map_create)(
            uint32_t map_type,
            uint32_t key_size,
            uint32_t value_size,
            uint32_t max_entries,
            const ebpf_map_definition_in_memory_t* map_definition,
            void** map_context);

        void (*map_delete)(void* map_context);

        // Map data operations
        ebpf_result_t (*map_lookup)(void* map_context, const uint8_t* key, uint8_t* value);

        ebpf_result_t (*map_update)(void* map_context, const uint8_t* key, const uint8_t* value, uint64_t flags);

        ebpf_result_t (*map_delete_element)(void* map_context, const uint8_t* key);

        // Validation and compatibility
        ebpf_result_t (*validate_map_program_association)(uint32_t map_type, const GUID* program_type);

        // Iterator support (optional)
        ebpf_result_t (*map_get_next_key)(void* map_context, const uint8_t* previous_key, uint8_t* next_key);

    } ebpf_extensible_map_provider_t;

    /**
     * @brief Map provider extension data (similar to ebpf_extension_data_t).
     */
    typedef struct _ebpf_map_extension_data
    {
        uint16_t version;
        uint16_t size;
        uint32_t supported_map_type_count;        // Number of supported map types
        const uint32_t* supported_map_types;     // Array of supported map types
        const ebpf_extensible_map_provider_t* provider_interface;
    } ebpf_map_extension_data_t;

    /**
     * @brief Client binding context for extensible map provider.
     */
    typedef struct _ebpf_extensible_map_client_binding
    {
        HANDLE nmr_binding_handle;
        const ebpf_extensible_map_provider_t* provider_interface;
        uint32_t supported_map_type_count;
        uint32_t* supported_map_types;
    } ebpf_extensible_map_client_binding_t;

    // Function declarations

    /**
     * @brief Create an extensible map.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_extensible_map_create(
        _In_ const ebpf_map_definition_in_memory_t* map_definition,
        ebpf_handle_t inner_map_handle,
        _Outptr_ ebpf_map_t** map);

    /**
     * @brief Check if a map type is extensible (>= 4096).
     */
    _Must_inspect_result_ bool
    ebpf_map_type_is_extensible(uint32_t map_type);

    /**
     * @brief Safely call provider operation with rundown protection.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_extensible_map_invoke_with_provider(
        _In_ ebpf_extensible_map_t* extensible_map,
        _In_ void* operation_context,
        _In_ ebpf_result_t (*operation)(const ebpf_extensible_map_provider_t* provider, void* context));

#ifdef __cplusplus
}
#endif