/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#pragma once
#include "ebpf_object.h"
#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif
    typedef struct _ebpf_pinning_table ebpf_pinning_table_t;

    /**
     * @brief Allocate a pinning table.
     *
     * @param[out] pinning_table Pointer to memory that will contain pinning
     *  table on success.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  pinning table.
     */
    ebpf_result_t
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
     * @param[in] name Name to associate with this entry.
     * @param[in] object Ebpf object to associate with this entry.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  entry.
     */
    ebpf_result_t
    ebpf_pinning_table_insert(
        ebpf_pinning_table_t* pinning_table, const ebpf_utf8_string_t* name, ebpf_object_t* object);

    /**
     * @brief Find an entry in the pinning table and acquire a reference on the
     *  object associate with it.
     *
     * @param[in] pinning_table Pinning table to search.
     * @param[in] name Name to find in the pinning table.
     * @param[out] object Pointer to memory that contains the object on success.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_OBJECT_NOT_FOUND The name is not present in the pinning
     *  table.
     */
    ebpf_result_t
    ebpf_pinning_table_find(
        ebpf_pinning_table_t* pinning_table, const ebpf_utf8_string_t* name, ebpf_object_t** object);

    /**
     * @brief Find an entry in the pinning table, remove it and release a
     *  reference on the object associated with it.
     *
     * @param[in] pinning_table Pinning table to update.
     * @param[in] name Name to find in the pinning table.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_OBJECT_NOT_FOUND The name is not present in the pinning
     *  table.
     */
    ebpf_result_t
    ebpf_pinning_table_delete(ebpf_pinning_table_t* pinning_table, const ebpf_utf8_string_t* name);

#ifdef __cplusplus
}
#endif
