// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once
#include "ebpf_object.h"
#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif
    typedef struct _ebpf_pinning_table ebpf_pinning_table_t;

    /**
     * @brief eBPF pinning table entry.
     */
    typedef struct _ebpf_pinning_entry
    {
        cxplat_utf8_string_t path;
        ebpf_core_object_t* object;
    } ebpf_pinning_entry_t;

    /**
     * @brief Allocate a pinning table.
     *
     * @param[out] pinning_table Pointer to memory that will contain pinning
     *  table on success.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  pinning table.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_pinning_table_allocate(ebpf_pinning_table_t** pinning_table);

    /**
     * @brief Free a pinning table.
     *
     * @param[in] pinning_table Pinning table to free.
     */
    void
    ebpf_pinning_table_free(ebpf_pinning_table_t* pinning_table);

    /**
     * @brief Insert an entry into the pinning table and acquire a reference on
     *  the object.
     *
     * @param[in] pinning_table Pinning table to update.
     * @param[in] path Path to associate with this entry.
     * @param[in] object Ebpf object to associate with this entry.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  entry.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_pinning_table_insert(
        ebpf_pinning_table_t* pinning_table, const cxplat_utf8_string_t* path, ebpf_core_object_t* object);

    /**
     * @brief Find an entry in the pinning table and acquire a reference on the
     *  object associate with it.
     *
     * @param[in] pinning_table Pinning table to search.
     * @param[in] path Path to find in the pinning table.
     * @param[out] object Pointer to memory that contains the object on success.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_OBJECT_NOT_FOUND The path is not present in the pinning
     *  table.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_pinning_table_find(
        ebpf_pinning_table_t* pinning_table, const cxplat_utf8_string_t* path, ebpf_core_object_t** object);

    /**
     * @brief Find an entry in the pinning table, remove it and release a
     *  reference on the object associated with it.
     *
     * @param[in] pinning_table Pinning table to update.
     * @param[in] path Path to find in the pinning table.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_OBJECT_NOT_FOUND The path is not present in the pinning
     *  table.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_pinning_table_delete(ebpf_pinning_table_t* pinning_table, const cxplat_utf8_string_t* path);

    /**
     * @brief Returns all entries in the pinning table of specified object type after acquiring a reference.
     *
     * @param[in, out] pinning_table Pinning table to enumerate.
     * @param[in] object_type eBPF object type that will be used to filter pinning entries.
     * @param[out] entry_count Number of pinning entries being returned.
     * @param[out] pinning_entries Array of pinning entries being returned. Must be freed by caller
     * using ebpf_pinning_entries_release().
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Output array of entries could not be allocated.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_pinning_table_enumerate_entries(
        _Inout_ ebpf_pinning_table_t* pinning_table,
        ebpf_object_type_t object_type,
        _Out_ uint16_t* entry_count,
        _Outptr_result_buffer_maybenull_(*entry_count) ebpf_pinning_entry_t** pinning_entries);

    /**
     * @brief Gets the next path in the pinning table after a given path.
     *
     * @param[in, out] pinning_table Pinning table to enumerate.
     * @param[in] object_type Object type.
     * @param[in] start_path Path to look for an entry greater than.
     * @param[in, out] next_path Returns the next path, if one exists.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MORE_KEYS No more entries found.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_pinning_table_get_next_path(
        _Inout_ ebpf_pinning_table_t* pinning_table,
        ebpf_object_type_t object_type,
        _In_ const cxplat_utf8_string_t* start_path,
        _Inout_ cxplat_utf8_string_t* next_path);

    /**
     * @brief Releases entries returned by ebpf_pinning_table_enumerate_entries.
     * @param[in] entry_count Length of input array of entries.
     * @param[in] pinning_entries Array of entries to be released.
     */
    void
    ebpf_pinning_entries_release(
        uint16_t entry_count, _In_opt_count_(entry_count) ebpf_pinning_entry_t* pinning_entries);

#ifdef __cplusplus
}
#endif
