/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
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
    ebpf_map_create(const ebpf_map_definition_t* ebpf_map_definition, ebpf_map_t** map);

    /**
     * @brief Get a pointer to the map definition.
     *
     * @param[in] map Map to get definition from.
     * @return Pointer to map definition.
     */
    ebpf_map_definition_t*
    ebpf_map_get_definition(ebpf_map_t* map);

    /**
     * @brief Get a pointer to an entry in the map.
     *
     * @param[in] map Map to search.
     * @param[in] key Key to use when searching map.
     * @return Pointer to the value if found or NULL.
     */
    uint8_t*
    ebpf_map_find_entry(ebpf_map_t* map, const uint8_t* key);

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
    ebpf_map_update_entry(ebpf_map_t* map, const uint8_t* key, const uint8_t* value);

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
    ebpf_map_delete_entry(ebpf_map_t* map, const uint8_t* key);

    /**
     * @brief Retrieve the next key from the map.
     *
     * @param[in] map Map to search.
     * @param[in] previous_key The previous key need not be present. This will
     * return the next key lexicographically after the specified key.
     * @param[in] next_key Next key on success.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MORE_KEYS There is no key following the specified
     * key in lexicographically order.
     */
    ebpf_result_t
    ebpf_map_next_key(ebpf_map_t* map, const uint8_t* previous_key, uint8_t* next_key);

#ifdef __cplusplus
}
#endif
