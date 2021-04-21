/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#pragma once

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
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate resources for this
     *  map.
     */
    ebpf_error_code_t
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
     * @return uint8_t* Pointer to the value if found or NULL.
     */
    uint8_t*
    ebpf_map_lookup_entry(ebpf_map_t* map, const uint8_t* key);

    /**
     * @brief Insert or update an entry in the map.
     *
     * @param[in] map Map to update.
     * @param[in] key Key to use when searching and updating the map.
     * @param[in] value Value to insert into the map.
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate resources for this
     *  entry.
     */
    ebpf_error_code_t
    ebpf_map_update_entry(ebpf_map_t* map, const uint8_t* key, const uint8_t* value);

    /**
     * @brief Remove an entry from the map.
     *
     * @param[in] map Map to update.
     * @param[in] key Key to use when searching and updating the map.
     */
    ebpf_error_code_t
    ebpf_map_delete_entry(ebpf_map_t* map, const uint8_t* key);

    /**
     * @brief Retrieve the next key from the map.
     *
     * @param map Map to search.
     * @param previous_key Previous key or NULL.
     * @param next_key Next key on success.
     * @retval EBPF_ERROR_NO_MORE_KEYS Previous key is the last key in the map.
     */
    ebpf_error_code_t
    ebpf_map_next_key(ebpf_map_t* map, const uint8_t* previous_key, uint8_t* next_key);

#ifdef __cplusplus
}
#endif
