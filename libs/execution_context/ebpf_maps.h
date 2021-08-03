// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_helpers.h"
#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct _ebpf_core_map ebpf_map_t;

    /**
     * @brief Allocate a new map.
     *
     * @param[in] ebpf_map_definition Definition of the new map.
     * @param[out] map Pointer to memory that will contain the map on success.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  map.
     */
    ebpf_result_t
    ebpf_map_create(_In_ const ebpf_map_definition_t* ebpf_map_definition, _Outptr_ ebpf_map_t** map);

    /**
     * @brief Get a pointer to the map definition.
     *
     * @param[in] map Map to get definition from.
     * @return Pointer to map definition.
     */
    const ebpf_map_definition_t*
    ebpf_map_get_definition(_In_ const ebpf_map_t* map);

    /**
     * @brief Get a pointer to an entry in the map.
     *
     * @param[in] map Map to search.
     * @param[in] key Key to use when searching map.
     * @param[in] is_helper True if called by an eBPF program.
     * @return Pointer to the value if found or NULL.
     */
    uint8_t*
    ebpf_map_find_entry(_In_ ebpf_map_t* map, _In_ const uint8_t* key, int is_helper);

    /**
     * @brief Insert or update an entry in the map.
     *
     * @param[in] map Map to update.
     * @param[in] key Key to use when searching and updating the map.
     * @param[in] value Value to insert into the map.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  entry.
     */
    ebpf_result_t
    ebpf_map_update_entry(_In_ ebpf_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* value);

    /**
     * @brief Insert or update an entry in the map.
     *
     * @param[in] map Map to update.
     * @param[in] key Key to use when searching and updating the map.
     * @param[in] value Value to insert into the map.
     * @param[in] value_handle Handle associated with the value.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  entry.
     */
    ebpf_result_t
    ebpf_map_update_entry_with_handle(
        _In_ ebpf_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* value, uintptr_t value_handle);

    /**
     * @brief Remove an entry from the map.
     *
     * @param[in] map Map to update.
     * @param[in] key Key to use when searching and updating the map.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_ARGUMENT One or more parameters are
     *  invalid.
     */
    ebpf_result_t
    ebpf_map_delete_entry(_In_ ebpf_map_t* map, _In_ const uint8_t* key);

    /**
     * @brief Retrieve the next key from the map.
     *
     * @param[in] map Map to search.
     * @param[in] previous_key The previous key need not be present. This will
     * return the next key lexicographically after the specified key.  A value of
     * null indicates that the first key is to be returned.
     * @param[out] next_key Next key on success.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MORE_KEYS There is no key following the specified
     * key in lexicographically order.
     */
    ebpf_result_t
    ebpf_map_next_key(_In_ ebpf_map_t* map, _In_opt_ const uint8_t* previous_key, _Out_ uint8_t* next_key);

    /**
     * @brief Get an object from a map entry that holds objects, such
     * as a program array or map of maps.  The object returned holds a
     * reference that the caller is responsible for releasing.
     *
     * @param[in] map Array map to search.
     * @param[in] index The index into the array.
     * @returns Object pointer, or NULL if none.
     */
    _Ret_maybenull_ struct _ebpf_object*
    ebpf_get_object_from_array_map(_In_ ebpf_map_t* map, uint32_t index);

#ifdef __cplusplus
}
#endif
