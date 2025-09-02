// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "bpf_helpers.h"
#include "cxplat.h"
#include "ebpf_core_structs.h"
#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define EBPF_MAP_FLAG_HELPER 0x01      /* Called by an eBPF program. */
#define EBPF_MAP_FIND_FLAG_DELETE 0x02 /* Perform a find and delete. */

    typedef struct _ebpf_core_map ebpf_map_t;

    /**
     * @brief Allocate a new map.
     *
     * @param[in] map_name Name of the map.
     * @param[in] ebpf_map_definition Definition of the new map.
     * @param[in] inner_map_handle Handle to inner map, or ebpf_handle_invalid if none.
     * @param[out] map Pointer to memory that will contain the map on success.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  map.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_map_create(
        _In_ const cxplat_utf8_string_t* map_name,
        _In_ const ebpf_map_definition_in_memory_t* ebpf_map_definition,
        ebpf_handle_t inner_map_handle,
        _Outptr_ ebpf_map_t** map);

    /**
     * @brief Get a pointer to the map definition.
     *
     * @param[in] map Map to get definition from.
     * @return Pointer to map definition.
     */
    const ebpf_map_definition_in_memory_t*
    ebpf_map_get_definition(_In_ const ebpf_map_t* map);

    /**
     * @brief Get the map value size specified when the map was originally
     * created. For per-cpu maps this will be different from the value in the
     * returned ebpf_map_definition_t.
     *
     * @param[in] map Map to query
     * @return Effective value size of the entry.
     */
    uint32_t
    ebpf_map_get_effective_value_size(_In_ const ebpf_map_t* map);

    /**
     * @brief Get a pointer to an entry in the map.
     *
     * @param[in, out] map Map to search and update metadata in.
     * @param[in] key Key to use when searching map.
     * @param[in] flags Zero or more EBPF_MAP_FIND_ENTRY_FLAG_* flags.
     * @return Pointer to the value if found or NULL.
     */
    EBPF_INLINE_HINT
    _Must_inspect_result_ ebpf_result_t
    ebpf_map_find_entry(
        _Inout_ ebpf_map_t* map,
        size_t key_size,
        _In_reads_(key_size) const uint8_t* key,
        size_t value_size,
        _Out_writes_(value_size) uint8_t* value,
        int flags);

    /**
     * @brief Insert or update an entry in the map.
     *
     * @param[in, out] map Map to update.
     * @param[in] key Key to use when searching and updating the map.
     * @param[in] value Value to insert into the map.
     * @param[in] option One of ebpf_map_option_t options.
     * @param[in] flags EBPF_MAP_FLAG_HELPER if called from helper function.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this entry.
     */
    EBPF_INLINE_HINT
    _Must_inspect_result_ ebpf_result_t
    ebpf_map_update_entry(
        _Inout_ ebpf_map_t* map,
        size_t key_size,
        _In_reads_(key_size) const uint8_t* key,
        size_t value_size,
        _In_reads_(value_size) const uint8_t* value,
        ebpf_map_option_t option,
        int flags);

    /**
     * @brief Insert or update an entry in the map.
     *
     * @param[in, out] map Map to update.
     * @param[in] key Key to use when searching and updating the map.
     * @param[in] value_handle Handle associated with the value to insert.
     * @param[in] option One of ebpf_map_option_t options.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  entry.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_map_update_entry_with_handle(
        _Inout_ ebpf_map_t* map,
        size_t key_size,
        _In_reads_(key_size) const uint8_t* key,
        uintptr_t value_handle,
        ebpf_map_option_t option);

    /**
     * @brief Remove an entry from the map.
     *
     * @param[in] map Map to update.
     * @param[in] key Key to use when searching and updating the map.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_ARGUMENT One or more parameters are
     *  invalid.
     */
    EBPF_INLINE_HINT
    _Must_inspect_result_ ebpf_result_t
    ebpf_map_delete_entry(_In_ ebpf_map_t* map, size_t key_size, _In_reads_(key_size) const uint8_t* key, int flags);

    /**
     * @brief Retrieve the next key from the map.
     *
     * @param[in, out] map Map to search and update metadata in.
     * @param[in] previous_key The previous key need not be present. This will
     * return the next key lexicographically after the specified key.  A value of
     * null indicates that the first key is to be returned.
     * @param[out] next_key Next key on success.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_KEY_NOT_FOUND The specified previous key was not found.
     * @retval EBPF_NO_MORE_KEYS There is no key following the specified
     * key in lexicographical order.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_map_next_key(
        _Inout_ ebpf_map_t* map,
        size_t key_size,
        _In_reads_opt_(key_size) const uint8_t* previous_key,
        _Out_writes_(key_size) uint8_t* next_key);

    /**
     * @brief Get a program from an entry in a map that holds programs.  The
     * program returned holds a reference that the caller is responsible for
     * releasing.
     *
     * @param[in, out] map Map to search and update metadata in.
     * @param[in] key Pointer to key to search for.
     * @param[in] key_size Size of value to search for.
     * @returns Program pointer, or NULL if none.
     */
    EBPF_INLINE_HINT
    _Ret_maybenull_ struct _ebpf_program*
    ebpf_map_get_program_from_entry(_Inout_ ebpf_map_t* map, size_t key_size, _In_reads_(key_size) const uint8_t* key);

    /**
     * @brief Let a map take any actions when first
     * associated with a program.
     *
     * @param[in, out] map Map to update.
     * @param[in] program Program being associated with.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_FD The program is incompatible with this map.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_map_associate_program(_Inout_ ebpf_map_t* map, _In_ const struct _ebpf_program* program);

    /**
     * @brief Get bpf_map_info about a map.
     *
     * @param[in] map The map to get info about.
     * @param[out] buffer Buffer to write bpf_map_info into.
     * @param[in, out] info_size On input, the size in bytes of the buffer.
     * On output, the number of bytes actually written.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INSUFFICIENT_BUFFER The buffer was too small to hold bpf_map_info.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_map_get_info(
        _In_ const ebpf_map_t* map,
        _Out_writes_to_(*info_size, *info_size) uint8_t* buffer,
        _Inout_ uint16_t* info_size);

    /**
     * @brief Get pointer to the shared data for a map.
     *
     * @param[in] map Map to query.
     * @param[in] index index of buffer to query.
     * @param[out] buffer Pointer to the data.
     * @param[out] consumer_offset Offset of consumer in data.
     * @retval EBPF_SUCCESS Successfully mapped the buffer.
     * @retval EBPF_INVALID_ARGUMENT Unable to map the buffer.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_map_query_buffer(
        _In_ const ebpf_map_t* map, uint64_t index, _Outptr_ uint8_t** buffer, _Out_ size_t* consumer_offset);

    /**
     * @brief Map the shared data for a ring buffer map to user space.
     *
     * @param[in] map Map to query.
     * @param[out] consumer Pointer to the consumer buffer.
     * @param[out] producer Pointer to the producer buffer.
     * @param[out] data Pointer to the data buffer.
     * @param[out] data_size Size of the mapped data buffer.
     * @retval EBPF_SUCCESS Successfully mapped the buffer.
     * @retval EBPF_INVALID_ARGUMENT Unable to map the buffer.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_ring_buffer_map_map_user(
        _In_ const ebpf_map_t* map,
        _Outptr_ void** consumer,
        _Outptr_ void** producer,
        _Outptr_result_buffer_(*data_size) const uint8_t** data,
        _Out_ size_t* data_size);

    /**
     * @brief Unmap the memory of a ring buffer map.
     *
     * @param[in] map Map to unmap.
     * @param[in] consumer Pointer to the consumer buffer.
     * @param[in] producer Pointer to the producer buffer.
     * @param[in] data Pointer to the data buffer.
     * @retval EBPF_SUCCESS Successfully unmapped the buffer.
     * @retval EBPF_INVALID_ARGUMENT The operation is not supported on this map.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_ring_buffer_map_unmap_user(
        _In_ const ebpf_map_t* map, _In_ const void* consumer, _In_ const void* producer, _In_ const void* data);

    /**
     * @brief Set the wait handle for a map.
     *
     * @param[in] map Map to set the wait handle for.
     * @param[in] index Map index to set the wait handle for.
     * @param[in] wait_handle Handle to notify when new data is available.
     * @param[in] flags Flags to set for the wait handle (currently should be zero).
     * @retval EBPF_SUCCESS Successfully set the wait handle.
     * @retval EBPF_INVALID_ARGUMENT Unable to set the wait handle.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_map_set_wait_handle_internal(
        _In_ const ebpf_map_t* map, uint64_t index, ebpf_handle_t wait_handle, uint64_t flags);

    /**
     * @brief Issue asynchronous query to map.
     *
     * @param[in, out] map Map to issue async query on.
     * @param[in] index Index of buffer to query.
     * @param[in, out] async_query_result Pointer to structure for storing result of the async query.
     * @param[in, out] async_context Async context associated with the query.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Insufficient memory to complete this operation.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_map_async_query(
        _Inout_ ebpf_map_t* map,
        uint64_t index,
        _Inout_ ebpf_map_async_query_result_t* async_query_result,
        _Inout_ void* async_context);

    /**
     * @brief Return consumed buffer back to the map.
     *
     * @param[in] map Map to return buffer to.
     * @param[in] index buffer index in map.
     * @param[in] length Length of bytes to return.
     * @retval EBPF_SUCCESS Successfully returned buffer to the map.
     * @retval EBPF_INVALID_ARGUMENT Unable to return buffer to map.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_map_return_buffer(_In_ const ebpf_map_t* map, uint64_t index, size_t length);

    /**
     * @brief Write out a variable sized record to the map.
     *
     * @param[in, out] map Map to write to.
     * @param[in] flags Flags to control the write.
     * @param[in] data Data to copy into record.
     * @param[in] length Length of data to copy.
     * @retval EBPF_SUCCESS Successfully wrote record ring buffer.
     * @retval EBPF_OUT_OF_SPACE Unable to output to ring buffer due to inadequate space.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_map_write_data(_Inout_ ebpf_map_t* map, uint64_t flags, _In_reads_bytes_(length) uint8_t* data, size_t length);

    /**
     * @brief Write out a variable sized record to the ring buffer map.
     *
     * @param[in, out] map Pointer to map of type EBPF_MAP_TYPE_RINGBUF.
     * @param[in] data Data of record to write into ring buffer map.
     * @param[in] length Length of data.
     * @retval EBPF_SUCCESS Successfully wrote record into ring buffer.
     * @retval EBPF_OUT_OF_SPACE Unable to output to ring buffer due to inadequate space.
     */
    EBPF_INLINE_HINT
    _Must_inspect_result_ ebpf_result_t
    ebpf_ring_buffer_map_output(_Inout_ ebpf_map_t* map, _In_reads_bytes_(length) uint8_t* data, size_t length);

    /**
     * @brief Write out a variable sized record to the perf event array.
     *
     * Writes a simple record to the ring for the current CPU.
     *
     * @param[in, out] perf_event_array Perf event array to write to.
     * @param[in] data Data to copy into record.
     * @param[in] length Length of data to copy.
     * @retval EBPF_SUCCESS Successfully wrote record ring buffer.
     * @retval EBPF_OUT_OF_SPACE Unable to output to ring buffer due to inadequate space.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_perf_event_array_map_output(_Inout_ ebpf_map_t* map, _In_reads_bytes_(length) uint8_t* data, size_t length);

    /**
     * @brief Write out a variable sized record to the perf event array map with ctx and flags.
     *
     * Flags is used to select the CPU to write to and the context data to copy.
     * - EBPF_MAP_FLAG_INDEX_MASK - Mask for specifying cpu.
     * - EBPF_MAP_FLAG_CURRENT_CPU - Select current cpu.
     * - EBPF_MAP_FLAG_CTX_LENGTH_MASK - Mask for specifying context length.
     *
     * @note below dispatch you must specify `EBPF_MAP_FLAG_CURRENT_CPU`, and at dispatch
     * you may either use the current cpu flag or manually specify the current cpu.
     *
     * @param[in] ctx bpf program Context to copy data from.
     * @param[in, out] map Pointer to map of type EBPF_MAP_TYPE_PERF_EVENT_ARRAY.
     * @param[in] flags Flags to select cpu and how much context data to copy.
     * @param[in] data Data of record to write into perf event array map.
     * @param[in] length Length of data.
     * @retval EBPF_SUCCESS Successfully wrote record into perf event array.
     * @retval EBPF_OUT_OF_SPACE Unable to output to perf event array due to inadequate space.
     */
    EBPF_INLINE_HINT
    _Must_inspect_result_ ebpf_result_t
    ebpf_perf_event_array_map_output_with_capture(
        _In_ void* ctx, _Inout_ ebpf_map_t* map, uint64_t flags, _In_reads_bytes_(length) uint8_t* data, size_t length);

    /**
     * @brief Insert an element at the end of the map (only valid for stack and queue).
     *
     * @param[in, out] map Map to update.
     * @param[in] value_size Size of value to insert into the map.
     * @param[in] value Value to insert into the map.
     * @param[in] flags Map flags - BPF_EXIST: If the map is full, the entry at the start of the map is discarded.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  entry.
     * @retval EBPF_OUT_OF_SPACE Map is full and BPF_EXIST was not supplied.
     */
    EBPF_INLINE_HINT
    _Must_inspect_result_ ebpf_result_t
    ebpf_map_push_entry(
        _Inout_ ebpf_map_t* map, size_t value_size, _In_reads_(value_size) const uint8_t* value, int flags);

    /**
     * @brief Copy an entry from the map and remove it from the map (only valid for stack and queue).
     * Queue pops from the beginning of the map.
     * Stack pops from the end of the map.
     *
     * @param[in, out] map Map to search and update metadata on.
     * @param[in] value_size Size of the value buffer to copy value from map into.
     * @param[out] value Value buffer to copy value from map into.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_OBJECT_NOT_FOUND The map is empty.
     */
    EBPF_INLINE_HINT
    _Must_inspect_result_ ebpf_result_t
    ebpf_map_pop_entry(_Inout_ ebpf_map_t* map, size_t value_size, _Out_writes_(value_size) uint8_t* value, int flags);

    /**
     * @brief Copy an entry from the map (only valid for stack and queue).
     * Queue peeks at the beginning of the map.
     * Stack peeks at the end of the map.
     *
     * @param[in, out] map Map to search and update metadata on.
     * @param[in] value_size Size of the value buffer to copy value from map into.
     * @param[out] value Value buffer to copy value from map into.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_OBJECT_NOT_FOUND The map is empty.
     */
    EBPF_INLINE_HINT
    _Must_inspect_result_ ebpf_result_t
    ebpf_map_peek_entry(_Inout_ ebpf_map_t* map, size_t value_size, _Out_writes_(value_size) uint8_t* value, int flags);

    /**
     * @brief Get the ID of a given map.
     *
     * @param[in] map Map to get ID of.
     * @returns Map ID.
     */
    ebpf_id_t
    ebpf_map_get_id(_In_ const ebpf_map_t* map);

    /**
     * @brief Copy keys and values from the map to the caller provided buffer.
     *
     * @param[in, out] map Map to search and update metadata on.
     * @param[in] previous_key_length The length of the previous key.
     * @param[in] previous_key The previous key need not be present. This is the key to start the search from.
     * @param[in,out] key_and_value_length Length of the key and value buffer on input. On output, the number of bytes
     * actually written.
     * @param[out] key_and_value Buffer to write the keys and values into.
     * @param[in] flags Flags to control the behavior of the function.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_KEY_NOT_FOUND The specified previous key was not found.
     * @retval EBPF_NO_MORE_KEYS There is no key following the specified key.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_map_get_next_key_and_value_batch(
        _Inout_ ebpf_map_t* map,
        size_t previous_key_length,
        _In_reads_bytes_opt_(previous_key_length) const uint8_t* previous_key,
        _Inout_ size_t* key_and_value_length,
        _Out_writes_bytes_to_(*key_and_value_length, *key_and_value_length) uint8_t* key_and_value,
        int flags);

    /**
     * @brief Get the address of the first value in the map if it is an array or
     * return EBPF_INVALID_ARGUMENT if it is not an array map.
     *
     * @param[in] map Map to query.
     * @param[out] value_address Map value address.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_ARGUMENT The provided map is not valid.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_map_get_value_address(_In_ const ebpf_map_t* map, _Out_ uintptr_t* value_address);

#ifdef __cplusplus
}
#endif
