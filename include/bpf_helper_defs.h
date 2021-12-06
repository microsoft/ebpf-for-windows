// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

// This file contains APIs for global helpers that are exposed for
// use by all eBPF programs.  Libbpf has bpf_helper_defs.h which is
// auto-generated but it's not platform-agnostic currently as it
// hard-codes the actual helper IDs.

/**
 * @brief Get a pointer to an entry in the map.
 *
 * @param[in] map Map to search.
 * @param[in] key Key to use when searching map.
 * @return Pointer to the value if found or NULL.
 */
EBPF_HELPER(void*, bpf_map_lookup_elem, (struct bpf_map * map, void* key));
#ifndef __doxygen
#define bpf_map_lookup_elem ((bpf_map_lookup_elem_t)BPF_FUNC_map_lookup_elem)
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
#define bpf_map_update_elem ((bpf_map_update_elem_t)BPF_FUNC_map_update_elem)
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
#define bpf_map_delete_elem ((bpf_map_delete_elem_t)BPF_FUNC_map_delete_elem)
#endif

/**
 * @brief Get a pointer to an entry in the map and erase that element.
 *
 * @param[in] map Map to search.
 * @param[in] key Key to use when searching map.
 * @return Pointer to the value if found or NULL.
 */
EBPF_HELPER(void*, bpf_map_lookup_and_delete_elem, (struct bpf_map * map, void* key));
#ifndef __doxygen
#define bpf_map_lookup_and_delete_elem ((bpf_map_lookup_and_delete_elem_t)BPF_FUNC_map_lookup_and_delete_elem)
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
#define bpf_tail_call ((bpf_tail_call_t)BPF_FUNC_tail_call)
#endif

/**
 * @brief Get a pseudo-random number.
 *
 * @return A random 32-bit unsigned value.
 */
EBPF_HELPER(uint32_t, bpf_get_prandom_u32, ());
#ifndef __doxygen
#define bpf_get_prandom_u32 ((bpf_get_prandom_u32_t)BPF_FUNC_get_prandom_u32)
#endif

/**
 * @brief Return time elapsed since boot in nanoseconds including time while suspended.
 *
 * @return Time elapsed since boot in nanosecond units.
 */
EBPF_HELPER(uint64_t, bpf_ktime_get_boot_ns, ());
#ifndef __doxygen
#define bpf_ktime_get_boot_ns ((bpf_ktime_get_boot_ns_t)BPF_FUNC_ktime_get_boot_ns)
#endif

/**
 * @brief Return SMP id of the processor running the program.
 *
 * @return SMP id of the processor running the program.
 */
EBPF_HELPER(uint64_t, bpf_get_smp_processor_id, ());
#ifndef __doxygen
#define bpf_get_smp_processor_id ((bpf_get_smp_processor_id_t)BPF_FUNC_get_smp_processor_id)
#endif

/**
 * @brief Return time elapsed since boot in nanoseconds excluding time while suspended.
 *
 * @return Time elapsed since boot in nanosecond units.
 */
EBPF_HELPER(uint64_t, bpf_ktime_get_ns, ());
#ifndef __doxygen
#define bpf_ktime_get_ns ((bpf_ktime_get_ns_t)BPF_FUNC_ktime_get_boot_ns)
#endif

/**
 * @brief Computes difference of checksum values for two input raw buffers using 1's complement arithmetic.
 *
 * @param[in] from Pointer to first raw buffer.
 * @param[in] from_size Length of the "from" buffer. Must be a multiple of 4.
 * @param[in] to Pointer to the second raw buffer, whose checksum will be subtracted from that of the "from" buffer.
 * @param[in] to_size Length of the "to" buffer. Must be a multiple of 4.
 * @param[in] seed  An optional integer that can be added to the value, which can be used to carry result of a previous
 * csum_diff operation.
 *
 * @returns The checksum delta on success, or <0 on failure.
 */
EBPF_HELPER(int, bpf_csum_diff, (void* from, int from_size, void* to, int to_size, int seed));
#ifndef __doxygen
#define bpf_csum_diff ((bpf_csum_diff_t)BPF_FUNC_csum_diff)
#endif

/**
 * @brief Copy data into the ring buffer map.
 *
 * @param[in,out] map Pointer to ring buffer map.
 * @param[in] data Data to copy into ring buffer map.
 * @param[in] size Length of data.
 * @param[in] flags Flags indicating if notification for new data availability should be sent.
 * @returns 0 on success and a negative value on error.
 */
EBPF_HELPER(int, bpf_ringbuf_output, (struct bpf_map * ring_buffer, void* data, uint64_t size, uint64_t flags));
#ifndef __doxygen
#define bpf_ringbuf_output ((bpf_ringbuf_output_t)BPF_FUNC_ringbuf_output)
#endif