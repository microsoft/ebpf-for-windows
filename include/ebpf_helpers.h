// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include <stdint.h>

#include "ebpf_structs.h"

#ifndef __doxygen
#define EBPF_HELPER(return_type, name, args) typedef return_type(*name##_t) args
#endif

// This file contains APIs for global helpers that are
// exposed for use by all eBPF programs.

/**
 * @brief Get a pointer to an entry in the map.
 *
 * @param[in] map Map to search.
 * @param[in] key Key to use when searching map.
 * @return Pointer to the value if found or NULL.
 */
EBPF_HELPER(void*, ebpf_map_lookup_element, (ebpf_map_definition_t * map, void* key));
#ifndef __doxygen
#define ebpf_map_lookup_element ((ebpf_map_lookup_element_t)1)
#endif

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
EBPF_HELPER(int64_t, ebpf_map_update_element, (ebpf_map_definition_t * map, void* key, void* value, uint64_t flags));
#ifndef __doxygen
#define ebpf_map_update_element ((ebpf_map_update_element_t)2)
#endif

/**
 * @brief Remove an entry from the map.
 *
 * @param[in] map Map to update.
 * @param[in] key Key to use when searching and updating the map.
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are
 *  invalid.
 */
EBPF_HELPER(int64_t, ebpf_map_delete_element, (ebpf_map_definition_t * map, void* key));
#ifndef __doxygen
#define ebpf_map_delete_element ((ebpf_map_delete_element_t)3)
#endif

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
