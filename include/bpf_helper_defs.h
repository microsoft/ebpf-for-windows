// Copyright (c) eBPF for Windows contributors
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
EBPF_HELPER(void*, bpf_map_lookup_elem, (void* map, void* key));
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
EBPF_HELPER(int64_t, bpf_map_update_elem, (void* map, void* key, void* value, uint64_t flags));
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
EBPF_HELPER(int64_t, bpf_map_delete_elem, (void* map, void* key));
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
EBPF_HELPER(void*, bpf_map_lookup_and_delete_elem, (void* map, void* key));
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
EBPF_HELPER(int64_t, bpf_tail_call, (void* ctx, void* prog_array_map, uint32_t index));
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
#define bpf_ktime_get_ns ((bpf_ktime_get_ns_t)BPF_FUNC_ktime_get_ns)
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
 * @param[in, out] map Pointer to ring buffer map.
 * @param[in] data Data to copy into ring buffer map.
 * @param[in] size Length of data.
 * @param[in] flags Flags indicating if notification for new data availability should be sent.
 * @returns 0 on success and a negative value on error.
 */
EBPF_HELPER(int, bpf_ringbuf_output, (void* ring_buffer, void* data, uint64_t size, uint64_t flags));
#ifndef __doxygen
#define bpf_ringbuf_output ((bpf_ringbuf_output_t)BPF_FUNC_ringbuf_output)
#endif

/**
 * @brief Print debug output.
 *
 * @param[in] fmt Printf-style format string.
 * @param[in] fmt_size Size in bytes of *fmt*.
 *
 * @returns The number of bytes written, or a negative error in case of failure.
 */
EBPF_HELPER(long, bpf_trace_printk2, (const char* fmt, uint32_t fmt_size));
#ifndef __doxygen
#define bpf_trace_printk2 ((bpf_trace_printk2_t)BPF_FUNC_trace_printk2)
#endif

/**
 * @brief Print debug output.
 *
 * @param[in] fmt Printf-style format string.
 * @param[in] fmt_size Size in bytes of *fmt*.
 * @param[in] arg3 Numeric argument to be used by the format string.
 *
 * @returns The number of bytes written, or a negative error in case of failure.
 */
EBPF_HELPER(long, bpf_trace_printk3, (const char* fmt, uint32_t fmt_size, uint64_t arg3));
#ifndef __doxygen
#define bpf_trace_printk3 ((bpf_trace_printk3_t)BPF_FUNC_trace_printk3)
#endif

/**
 * @brief Print debug output.
 *
 * @param[in] fmt Printf-style format string.
 * @param[in] fmt_size Size in bytes of *fmt*.
 * @param[in] arg3 Numeric argument to be used by the format string.
 * @param[in] arg4 Numeric argument to be used by the format string.
 *
 * @returns The number of bytes written, or a negative error in case of failure.
 */
EBPF_HELPER(long, bpf_trace_printk4, (const char* fmt, uint32_t fmt_size, uint64_t arg3, uint64_t arg4));
#ifndef __doxygen
#define bpf_trace_printk4 ((bpf_trace_printk4_t)BPF_FUNC_trace_printk4)
#endif

/**
 * @brief Print debug output.
 *
 * @param[in] fmt Printf-style format string.
 * @param[in] fmt_size Size in bytes of *fmt*.
 * @param[in] arg3 Numeric argument to be used by the format string.
 * @param[in] arg4 Numeric argument to be used by the format string.
 * @param[in] arg5 Numeric argument to be used by the format string.
 *
 * @returns The number of bytes written, or a negative error in case of failure.
 */
EBPF_HELPER(long, bpf_trace_printk5, (const char* fmt, uint32_t fmt_size, uint64_t arg3, uint64_t arg4, uint64_t arg5));
#ifndef __doxygen
#define bpf_trace_printk5 ((bpf_trace_printk5_t)BPF_FUNC_trace_printk5)
#endif

#ifndef __doxygen
// The following macros allow bpf_printk to accept a variable number of arguments
// while mapping to separate helper functions that each have a strict prototype
// that can be understood by the verifier.
#define EBPF_CONCATENATE(X, Y) X##Y
#define EBPF_MAKE_HELPER_NAME(PREFIX, ARG_COUNT) EBPF_CONCATENATE(PREFIX, ARG_COUNT)
#define EBPF_GET_NTH_ARG(_1, _2, _3, _4, _5, N, ...) N
#define EBPF_COUNT_VA_ARGS(...) EBPF_GET_NTH_ARG(__VA_ARGS__, 5, 4, 3, 2, 1)
#define EBPF_VA_ARGS_HELPER(PREFIX, ...) EBPF_MAKE_HELPER_NAME(PREFIX, EBPF_COUNT_VA_ARGS(__VA_ARGS__))(__VA_ARGS__)

#undef bpf_trace_printk
#define bpf_trace_printk(fmt, size, ...) ({ EBPF_VA_ARGS_HELPER(bpf_trace_printk, fmt, size, ##__VA_ARGS__); })
#else
/**
 * @brief Print debug output.  For instructions on viewing the output, see the
 * <a href="https://github.com/microsoft/ebpf-for-windows/blob/main/docs/GettingStarted.md#using-tracing">Using
 * tracing</a> section of the Getting Started Guide for eBPF for Windows.
 *
 * @param[in] fmt Printf-style format string.
 * @param[in] size Size in bytes of the format string.
 * @param[in] ... Numeric arguments to be used by the format string.
 *
 * @returns The number of bytes written, or a negative error in case of failure.
 */
long
bpf_trace_printk(const char* fmt, uint32_t size, ...);
#endif

#ifndef __doxygen
#undef bpf_printk
#define bpf_printk(fmt, ...)                                       \
    ({                                                             \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#else
/**
 * @brief Print debug output.  For instructions on viewing the output, see the
 * <a href="https://github.com/microsoft/ebpf-for-windows/blob/main/docs/GettingStarted.md#using-tracing">Using
 * tracing</a> section of the Getting Started Guide for eBPF for Windows.
 *
 * @param[in] fmt Printf-style format string.
 * @param[in] ... Numeric arguments to be used by the format string.
 *
 * @returns The number of bytes written, or a negative error in case of failure.
 */
long
bpf_printk(const char* fmt, ...);
#endif

/**
 * @brief Insert an element at the end of the map (only valid for stack and queue).
 *
 * @param[in] map Map to update.
 * @param[in] value Value to insert into the map.
 * @param[in] flags Map flags - BPF_EXIST: If the map is full, the entry at the start of the map is discarded.
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval -EBPF_NO_MEMORY Unable to allocate resources for this
 *  entry.
 * @retval -EBPF_OUT_OF_SPACE Map is full and BPF_EXIST was not supplied.
 */
EBPF_HELPER(int64_t, bpf_map_push_elem, (void* map, void* value, uint64_t flags));
#ifndef __doxygen
#define bpf_map_push_elem ((bpf_map_push_elem_t)BPF_FUNC_map_push_elem)
#endif

/**
 * @brief Copy an entry from the map and remove it from the map (only valid for stack and queue).
 * Queue pops from the beginning of the map.
 * Stack pops from the end of the map.
 *
 * @param[in] map Map to search.
 * @param[out] value Value buffer to copy value from map into.
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval -EBPF_OBJECT_NOT_FOUND The map is empty.
 */
EBPF_HELPER(int64_t, bpf_map_pop_elem, (void* map, void* value));
#ifndef __doxygen
#define bpf_map_pop_elem ((bpf_map_pop_elem_t)BPF_FUNC_map_pop_elem)
#endif

/**
 * @brief Copy an entry from the map (only valid for stack and queue).
 * Queue peeks at the beginning of the map.
 * Stack peeks at the end of the map.
 *
 * @param[in] map Map to search.
 * @param[out] value Value buffer to copy value from map into.
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval -EBPF_OBJECT_NOT_FOUND The map is empty.
 */
EBPF_HELPER(int64_t, bpf_map_peek_elem, (void* map, void* value));
#ifndef __doxygen
#define bpf_map_peek_elem ((bpf_map_pop_elem_t)BPF_FUNC_map_peek_elem)
#endif

/**
 * @brief Get the current thread ID (PID) and process ID (TGID).
 *
 * @returns A 64-bit integer containing the current process ID and
 * thread ID, and created as such: (process ID << 32) | (thread ID).
 */
EBPF_HELPER(uint64_t, bpf_get_current_pid_tgid, ());
#ifndef __doxygen
#define bpf_get_current_pid_tgid ((bpf_get_current_pid_tgid_t)BPF_FUNC_get_current_pid_tgid)
#endif

/**
 * @brief Get the 64-bit logon ID of the current thread. In case of sock_addr
 * attach types, get the logon ID of the user mode app making the request. In other
 * cases, get the logon ID of the current thread.
 *
 * @param[in] ctx Context passed to the eBPF program.
 *
 * @returns The logon ID, or 0 in case of error.
 */
EBPF_HELPER(uint64_t, bpf_get_current_logon_id, (const void* ctx));
#ifndef __doxygen
#define bpf_get_current_logon_id ((bpf_get_current_logon_id_t)BPF_FUNC_get_current_logon_id)
#endif

/**
 * @brief Get whether the current user is admin. In case of sock_addr attach types,
 * returns whether the user initiating the request is admin or not. In other
 * cases, returns whether the current thread user is admin or not.
 *
 * @param[in] ctx Context passed to the eBPF program.
 *
 * @retval 1 Is admin.
 * @retval 0 Is not admin.
 * @retval <0 An error occurred.
 */
EBPF_HELPER(int32_t, bpf_is_current_admin, (const void* ctx));
#ifndef __doxygen
#define bpf_is_current_admin ((bpf_is_current_admin_t)BPF_FUNC_is_current_admin)
#endif

/**
 * @brief Copy memory from one location to another.
 *
 * @param[in] destination Destination buffer.
 * @param[in] destination_size Size of the destination buffer.
 * @param[in] source Source buffer.
 * @param[in] source_size Size of the source buffer.
 *
 * @retval 0 The operation was successful.
 * @retval -EINVAL One or more parameters are invalid.
 *
 * @note If possible, use __builtin_memcpy instead of this function as it is more efficient.
 *       This function is intended for use in cases where the memory regions sizes are not known at compile time,
 *       such as when the regions are map values.
 *
 */
EBPF_HELPER(long, bpf_memcpy_s, (void* destination, size_t destination_size, const void* source, size_t source_size));
#ifndef __doxygen
#define bpf_memcpy_s ((bpf_memcpy_s_t)BPF_FUNC_memcpy_s)
#endif

/**
 * @brief Compare two memory regions.
 *
 * @param[in] memory1 First memory region.
 * @param[in] memory1_size Size of the first memory region.
 * @param[in] memory2 Second memory region.
 * @param[in] memory2_size Size of the second memory region.
 *
 * @returns 0 if the contents of memory regions are equal, a negative value if the contents of memory1 is less than the
 * contents memory2, or a positive value if the contents memory1 is greater than the contents memory2.
 *
 * @note If possible, use __builtin_memcmp instead of this function as it is more efficient.
 *       This function is intended for use in cases where the memory regions sizes are not known at compile time,
 *       such as when the memory regions are map values.
 */

EBPF_HELPER(int, bpf_memcmp_s, (const void* memory1, size_t memory1_size, const void* memory2, size_t memory2_size));
#ifndef __doxygen
#define bpf_memcmp_s ((bpf_memcmp_s_t)BPF_FUNC_memcmp_s)
#endif

/**
 * @brief Set memory to a specific value.
 *
 * @param[in] memory Memory region to set.
 * @param[in] size Size of the memory region.
 * @param[in] value Value to set the memory region to.
 *
 * @returns Pointer to the memory region, or a negative error in case of failure.
 *
 * @note If possible, use __builtin_memset instead of this function as it is more efficient.
 *       This function is intended for use in cases where the memory region size is not known at compile time,
 *       such as when the memory region is a map value.
 */

EBPF_HELPER(long, bpf_memset, (void* memory, size_t size, int value));
#ifndef __doxygen
#define bpf_memset ((bpf_memset_t)BPF_FUNC_memset)
#endif

/**
 * @brief Copy memory from one location to another, handling overlapping regions.
 *
 * @param[in] destination Destination buffer.
 * @param[in] destination_size Size of the destination buffer.
 * @param[in] source Source buffer.
 * @param[in] source_size Size of the source buffer.
 *
 * @retval 0 The operation was successful.
 * @retval -EINVAL One or more parameters are invalid.
 *
 * @note If possible, use __builtin_memmove instead of this function as it is more efficient.
 *       This function is intended for use in cases where the memory region sizes are not known at compile time,
 *       such as when the memory regions are map values.
 */

EBPF_HELPER(long, bpf_memmove_s, (void* destination, size_t destination_size, const void* source, size_t source_size));
#ifndef __doxygen
#define bpf_memmove_s ((bpf_memmove_s_t)BPF_FUNC_memmove_s)
#endif

/**
 * @brief Get the socket cookie associated with the socket context.
 * The context can be *bpf_sock_addr* struct, *bpf_sock_ops* struct, or *bpf_sock* struct.
 *
 * @param[in] ctx Context passed to the eBPF program.
 *
 * @returns The socket cookie.
 */
EBPF_HELPER(int64_t, bpf_get_socket_cookie, (const void* ctx));
#ifndef __doxygen
#define bpf_get_socket_cookie ((bpf_get_socket_cookie_t)BPF_FUNC_get_socket_cookie)
#endif

/**
 * @brief Copy a string into a buffer, of a fixed size.
 *
 * @param[in] dest Destination buffer.
 * @param[in] dest_size Size of the destination buffer.
 * @param[in] src Source string.
 * @param[in] count Upper limit on bytes to copy.
 *
 * @retval 0 The operation was successful.
 * @retval -ERANGE The destination buffer isn't large enough for the string being copied.
 */
EBPF_HELPER(int, bpf_strncpy_s, (char* dest, size_t dest_size, const char* src, size_t count));
#ifndef __doxygen
#define bpf_strncpy_s ((bpf_strncpy_s_t)BPF_FUNC_strncpy_s)
#endif

/**
 * @brief Concatenate a string to an existing buffer, up to a certain number of characters.
 *
 * @param[in,out] dest Destination buffer.
 * @param[in] dest_size Size of the destination buffer.
 * @param[in] src String to append to the contents of dest.
 * @param[in] count Upper limit on the characters to append to dest.
 *
 * @retval 0 Concatenation was successful.
 * @retval <0 Error code on failure, depending on the error.
 */
EBPF_HELPER(int, bpf_strncat_s, (char* dest, size_t dest_size, const char* src, size_t count));
#ifndef __doxygen
#define bpf_strncat_s ((bpf_strncat_s_t)BPF_FUNC_strncat_s)
#endif

/**
 * @brief Find the length of a string, up to a certain number of characters.
 *
 * @param[in] str Buffer containing one or more null-terminated strings.
 * @param[in] str_size Buffer length.
 *
 * @returns The length of the first string encountered in the str buffer. If str[0] is the null terminator, or str
 * itself is null, returns 0. If there is no null terminator in the first str_size bytes, returns str_size.
 */
EBPF_HELPER(size_t, bpf_strnlen_s, (const char* str, size_t str_size));
#ifndef __doxygen
#define bpf_strnlen_s ((bpf_strnlen_s_t)BPF_FUNC_strnlen_s)
#endif

#if __clang__
#define memcpy(dest, src, dest_size) bpf_memcpy_s(dest, dest_size, src, dest_size)
#define memcmp(mem1, mem2, mem1_size) bpf_memcmp_s(mem1, mem1_size, mem2, mem1_size)
#define memset(mem, value, mem_size) bpf_memset(mem, mem_size, value)
#define memmove(dest, src, dest_size) bpf_memmove_s(dest, dest_size, src, dest_size)
#define memcpy_s bpf_memcpy_s
#define memmove_s bpf_memmove_s
#endif

/**
 * @brief Return time elapsed since boot in milliseconds including time while suspended.
 * This function uses a lower resolution clock source than bpf_ktime_get_boot_ns, but is faster.
 *
 * @return Time elapsed since boot in milliseconds.
 */
EBPF_HELPER(uint64_t, bpf_ktime_get_boot_ms, ());
#ifndef __doxygen
#define bpf_ktime_get_boot_ms ((bpf_ktime_get_boot_ms_t)BPF_FUNC_ktime_get_boot_ms)
#endif

/**
 * @brief Return time elapsed since boot in milliseconds excluding time while suspended.
 * This function uses a lower resolution clock source than bpf_ktime_get_ns, but is faster.
 *
 * @return Time elapsed since boot in milliseconds.
 */
EBPF_HELPER(uint64_t, bpf_ktime_get_ms, ());
#ifndef __doxygen
#define bpf_ktime_get_ms ((bpf_ktime_get_ms_t)BPF_FUNC_ktime_get_ms)
#endif

/**
 * @brief Copy data into perf event array map.
 *
 * @param[in, out] map Pointer to perf event array map.
 * @param[in] data Data to copy into perf event array map.
 * @param[in] size Length of data.
 * @param[in] flags Flags indicating which cpu to write to and context data to copy.
 * @retval 0 The operation was successful.
 * @retval -EBPF_INVALID_ARGUMENT One or more parameters are invalid.
 * @retval -EBPF_OPERATION_NOT_SUPPORTED Operation not supported on this program or map.
 * @retval -EBPF_NO_MEMORY Unable to allocate resources for this.
 *  entry.
 * @retval -EBPF_OUT_OF_SPACE Map is full.
 */
EBPF_HELPER(int, bpf_perf_event_output, (void* ctx, void* perf_event_array, uint64_t flags, void* data, uint64_t size));
#ifndef __doxygen
#define bpf_perf_event_output ((bpf_perf_event_output_t)BPF_FUNC_perf_event_output)
#endif
