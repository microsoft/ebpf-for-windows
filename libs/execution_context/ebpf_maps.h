// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_core_structs.h"
#include "bpf_helpers.h"
#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define EBPF_MAP_FLAG_HELPER 0x01      /* Called by an eBPF program. */
#define EPBF_MAP_FIND_FLAG_DELETE 0x02 /* Perform a find and delete. */

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
    ebpf_result_t
    ebpf_map_create(
        _In_ const ebpf_utf8_string_t* map_name,
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
     * @return uint32_t effective value size of the entry.
     */
    uint32_t
    ebpf_map_get_effective_value_size(_In_ const ebpf_map_t* map);

    /**
     * @brief Get a pointer to an entry in the map.
     *
     * @param[in] map Map to search.
     * @param[in] key Key to use when searching map.
     * @param[in] flags Zero or more EBPF_MAP_FIND_ENTRY_FLAG_* flags.
     * @return Pointer to the value if found or NULL.
     */
    ebpf_result_t
    ebpf_map_find_entry(
        _In_ ebpf_map_t* map,
        size_t key_size,
        _In_reads_(key_size) const uint8_t* key,
        size_t value_size,
        _Out_writes_(value_size) uint8_t* value,
        int flags);

    /**
     * @brief Insert or update an entry in the map.
     *
     * @param[in] map Map to update.
     * @param[in] key Key to use when searching and updating the map.
     * @param[in] value Value to insert into the map.
     * @param[in] option One of ebpf_map_option_t options.
     * @param[in] flags EBPF_MAP_FLAG_HELPER if called from helper function.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  entry.
     */
    ebpf_result_t
    ebpf_map_update_entry(
        _In_ ebpf_map_t* map,
        size_t key_size,
        _In_reads_(key_size) const uint8_t* key,
        size_t value_size,
        _In_reads_(value_size) const uint8_t* value,
        ebpf_map_option_t option,
        int flags);

    /**
     * @brief Insert or update an entry in the map.
     *
     * @param[in] map Map to update.
     * @param[in] key Key to use when searching and updating the map.
     * @param[in] value_handle Handle associated with the value to insert.
     * @param[in] option One of ebpf_map_option_t options.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  entry.
     */
    ebpf_result_t
    ebpf_map_update_entry_with_handle(
        _In_ ebpf_map_t* map,
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
    ebpf_result_t
    ebpf_map_delete_entry(_In_ ebpf_map_t* map, size_t key_size, _In_reads_(key_size) const uint8_t* key, int flags);

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
    ebpf_map_next_key(
        _In_ ebpf_map_t* map,
        size_t key_size,
        _In_reads_opt_(key_size) const uint8_t* previous_key,
        _Out_writes_(key_size) uint8_t* next_key);

    /**
     * @brief Get a program from an entry in a map that holds programs.  The
     * program returned holds a reference that the caller is responsible for
     * releasing.
     *
     * @param[in] map Map to search.
     * @param[in] key Pointer to key to search for.
     * @param[in] key_size Size of value to search for.
     * @returns Program pointer, or NULL if none.
     */
    _Ret_maybenull_ struct _ebpf_program*
    ebpf_map_get_program_from_entry(_In_ ebpf_map_t* map, size_t key_size, _In_reads_(key_size) const uint8_t* key);

    /**
     * @brief Let a map take any actions when first
     * associated with a program.
     *
     * @param[in] map Map to update.
     * @param[in] program Program being associated with.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_FD The program is incompatible with this map.
     */
    ebpf_result_t
    ebpf_map_associate_program(_In_ ebpf_map_t* map, _In_ const struct _ebpf_program* program);

    /**
     * @brief Get bpf_map_info about a map.
     *
     * @param[in] map The map to get info about.
     * @param[out] buffer Buffer to write bpf_map_info into.
     * @param[in,out] info_size On input, the size in bytes of the buffer.
     * On output, the number of bytes actually written.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INSUFFICIENT_BUFFER The buffer was too small to hold bpf_map_info.
     */
    ebpf_result_t
    ebpf_map_get_info(
        _In_ const ebpf_map_t* map,
        _Out_writes_to_(*info_size, *info_size) uint8_t* buffer,
        _Inout_ uint16_t* info_size);

    /**
     * @brief Get pointer to the ring buffer map's shared data.
     *
     * @param[in] map Ring buffer map to query.
     * @param[out] buffer Pointer to ring buffer data.
     * @retval EPBF_SUCCESS Successfully mapped the ring buffer.
     * @retval EBPF_INVALID_ARGUMENT Unable to map the ring buffer.
     */
    ebpf_result_t
    ebpf_ring_buffer_map_query_buffer(_In_ const ebpf_map_t* map, _Outptr_ uint8_t** buffer);

    /**
     * @brief Return consumed buffer back to the ring buffer map.
     *
     * @param[in] map Ring buffer map.
     * @param[in] length Length of bytes to return to the ring buffer.
     * @retval EPBF_SUCCESS Successfully returned records to the ring buffer.
     * @retval EBPF_INVALID_ARGUMENT Unable to return records to the ring buffer.
     */
    ebpf_result_t
    ebpf_ring_buffer_map_return_buffer(_In_ const ebpf_map_t* map, size_t length);

    /**
     * @brief Issue an asynchronous query to ring buffer map.
     *
     * @param[in] map Ring buffer map to issue the async query on.
     * @param[in, out] async_query_result Pointer to structure for storing result of the async query.
     * @param[in] async_context Async context associated with the query.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Insufficient memory to complete this operation.
     */
    ebpf_result_t
    ebpf_ring_buffer_map_async_query(
        _In_ ebpf_map_t* map,
        _Inout_ ebpf_ring_buffer_map_async_query_result_t* async_query_result,
        _In_ void* async_context);

    /**
     * @brief Write out a variable sized record to the ring buffer map.
     *
     * @param[in] map Pointer to map of type EBPF_MAP_TYPE_RINGBUF.
     * @param[in] data Data of record to write into ring buffer map.
     * @param[in] length Length of data.
     * @retval EPBF_SUCCESS Successfully wrote record into ring buffer.
     * @retval EBPF_OUT_OF_SPACE Unable to output to ring buffer due to inadequate space.
     */
    ebpf_result_t
    ebpf_ring_buffer_map_output(_In_ ebpf_map_t* map, _In_reads_bytes_(length) uint8_t* data, size_t length);

#ifdef __cplusplus
}
#endif
