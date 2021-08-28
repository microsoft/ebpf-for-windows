// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include <stdint.h>

#include "ebpf_structs.h"

#define MAX_TAIL_CALL_CNT 32

// In an execution context, struct bpf_map means struct _ebpf_map_definition,
// as opposed to for user mode apps, so define the alias here where the execution
// context and eBPF programs will get it.
#define bpf_map _ebpf_map_definition

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
EBPF_HELPER(void*, bpf_map_lookup_elem, (struct bpf_map * map, void* key));
#ifndef __doxygen
#define bpf_map_lookup_elem ((bpf_map_lookup_elem_t)1)
#endif

/**
 * @brief Insert or update an entry in the map.
 *
 * @param[in] map Map to update.
 * @param[in] key Key to use when searching and updating the map.
 * @param[in] value Value to insert into the map.
 * @param[in] flags Map flags.
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval -EBPF_NO_MEMORY Unable to allocate resources for this
 *  entry.
 */
EBPF_HELPER(int64_t, bpf_map_update_elem, (struct bpf_map * map, void* key, void* value, uint64_t flags));
#ifndef __doxygen
#define bpf_map_update_elem ((bpf_map_update_elem_t)2)
#endif

/**
 * @brief Remove an entry from the map.
 *
 * @param[in] map Map to update.
 * @param[in] key Key to use when searching and updating the map.
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval -EBPF_INVALID_ARGUMENT One or more parameters are invalid.
 */
EBPF_HELPER(int64_t, bpf_map_delete_elem, (struct bpf_map * map, void* key));
#ifndef __doxygen
#define bpf_map_delete_elem ((bpf_map_delete_elem_t)3)
#endif

/**
 * @brief Perform a tail call into another eBPF program.
 *
 * @param[in] ctx Context to pass to the called program.
 * @param[in] prog_array_map Map of program fds.
 * @param[in] index Index in map of program to call.
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval -EBPF_INVALID_ARGUMENT One or more parameters are invalid.
 */
EBPF_HELPER(int64_t, bpf_tail_call, (void* ctx, struct bpf_map* prog_array_map, uint32_t index));
#ifndef __doxygen
#define bpf_tail_call ((bpf_tail_call_t)4)
#endif

/**
 * @brief Get a pseudo-random number.
 *
 * @return A random 32-bit unsigned value.
 */
EBPF_HELPER(uint32_t, bpf_get_prandom_u32, ());
#ifndef __doxygen
#define bpf_get_prandom_u32 ((bpf_get_prandom_u32_t)5)
#endif

/**
 * @brief Return time elapsed since boot in nanoseconds.
 *
 * @return Time elapsed since boot in nanosecond units.
 */
EBPF_HELPER(uint64_t, bpf_ktime_get_boot_ns, ());
#ifndef __doxygen
#define bpf_ktime_get_boot_ns ((bpf_ktime_get_boot_ns_t)6)
#endif

/**
 * @brief Return SMP id of the processor running the program.
 *
 * @return SMP id of the processor running the program.
 */
EBPF_HELPER(uint64_t, bpf_get_smp_processor_id, ());
#ifndef __doxygen
#define bpf_get_smp_processor_id ((bpf_get_smp_processor_id_t)7)
#endif

#define SEC(name) __attribute__((section(name), used))
