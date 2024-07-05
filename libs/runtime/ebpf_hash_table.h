// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define EBPF_HASH_TABLE_NO_LIMIT 0
#define EBPF_HASH_TABLE_DEFAULT_BUCKET_COUNT 64

    typedef enum _ebpf_hash_table_operations
    {
        EBPF_HASH_TABLE_OPERATION_ANY = 0,
        EBPF_HASH_TABLE_OPERATION_INSERT = 1,
        EBPF_HASH_TABLE_OPERATION_REPLACE = 2,
    } ebpf_hash_table_operations_t;

    typedef struct _ebpf_hash_table ebpf_hash_table_t;

    typedef enum _ebpf_hash_table_notification_type
    {
        EBPF_HASH_TABLE_NOTIFICATION_TYPE_ALLOCATE, //< A key + value have been allocated.
        EBPF_HASH_TABLE_NOTIFICATION_TYPE_FREE,     //< A key + value have been freed.
        EBPF_HASH_TABLE_NOTIFICATION_TYPE_USE,      //< A key + value have been used.
    } ebpf_hash_table_notification_type_t;

    typedef void (*ebpf_hash_table_notification_function)(
        _Inout_ void* context,
        _In_ ebpf_hash_table_notification_type_t type,
        _In_ const uint8_t* key,
        _Inout_ uint8_t* value);

    typedef _Must_inspect_result_ _Ret_writes_maybenull_(size) void* (*ebpf_hash_table_allocate)(size_t size);

    typedef void (*ebpf_hash_table_free)(_Frees_ptr_opt_ void* memory);

    typedef void (*ebpf_hash_table_extract_function)(
        _In_ const uint8_t* value,
        _Outptr_result_buffer_((*length_in_bits + 7) / 8) const uint8_t** data,
        _Out_ size_t* length_in_bits);

    /**
     * @brief Options to pass to ebpf_hash_table_create.
     *
     * Some fields are required, others are optional.  If an optional field is
     * not specified, a default value will be used.
     */
    typedef struct _ebpf_hash_table_creation_options
    {
        // Required fields.
        size_t key_size;   //< Size of key in bytes.
        size_t value_size; //< Size of value in bytes.
        // Optional fields.
        ebpf_hash_table_extract_function extract_function; //< Function to extract key from stored value.
        ebpf_hash_table_allocate allocate; //< Function to allocate memory - defaults to ebpf_epoch_allocate.
        ebpf_hash_table_free free;         //< Function to free memory - defaults to ebpf_epoch_free.
        size_t minimum_bucket_count;       //< Minimum number of buckets to use - defaults to
                                           // EBPF_HASH_TABLE_DEFAULT_BUCKET_COUNT.
        size_t max_entries; //< Maximum number of entries in the hash table - defaults to EBPF_HASH_TABLE_NO_LIMIT.
        size_t supplemental_value_size; //< Size of supplemental value to store in each entry - defaults to 0.
        void* notification_context;     //< Context to pass to notification functions.
        ebpf_hash_table_notification_function
            notification_callback; //< Function to call when value storage is allocated or freed.
    } ebpf_hash_table_creation_options_t;

    /**
     * @brief Allocate and initialize a hash table.
     *
     * @param[out] hash_table Pointer to memory that will contain hash table on
     *   success.
     * @param[in] options Options to control hash table creation.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  hash table.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_hash_table_create(
        _Out_ ebpf_hash_table_t** hash_table, _In_ const ebpf_hash_table_creation_options_t* options);

    /**
     * @brief Remove all items from the hash table and release memory.
     *
     * @param[in] hash_table Hash-table to release.
     */
    void
    ebpf_hash_table_destroy(_In_opt_ _Post_ptr_invalid_ ebpf_hash_table_t* hash_table);

    /**
     * @brief Find an element in the hash table.
     *
     * @param[in] hash_table Hash-table to search.
     * @param[in] key Key to find in hash table.
     * @param[out] value Pointer to value if found.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NOT_FOUND Key not found in hash table.
     */
    EBPF_INLINE_HINT _Must_inspect_result_ ebpf_result_t
    ebpf_hash_table_find(_In_ const ebpf_hash_table_t* hash_table, _In_ const uint8_t* key, _Outptr_ uint8_t** value);

    /**
     * @brief Insert or update an entry in the hash table.
     *
     * @param[in, out] hash_table Hash-table to update.
     * @param[in] key Key to find and insert or update.
     * @param[in] value Value to insert into hash table or NULL to insert zero entry.
     * @param[in] operation One of ebpf_hash_table_operations_t operations.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate memory for this
     *  entry in the hash table.
     * @retval EBPF_OUT_OF_SPACE Unable to insert this entry in the hash table.
     */
    EBPF_INLINE_HINT _Must_inspect_result_ ebpf_result_t
    ebpf_hash_table_update(
        _Inout_ ebpf_hash_table_t* hash_table,
        _In_ const uint8_t* key,
        _In_opt_ const uint8_t* value,
        ebpf_hash_table_operations_t operation);

    /**
     * @brief Remove an entry from the hash table.
     *
     * @param[in, out] hash_table Hash-table to update.
     * @param[in] key Key to find and remove.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NOT_FOUND Key not found in hash table.
     */
    EBPF_INLINE_HINT _Must_inspect_result_ ebpf_result_t
    ebpf_hash_table_delete(_Inout_ ebpf_hash_table_t* hash_table, _In_ const uint8_t* key);

    /**
     * @brief Fetch pointers to keys and values from one or more buckets in the hash table. Whole buckets worth of keys
     * and values are returned at a time, with *count being the number of keys and values returned. If *count is too
     * small to hold all the keys and values in the next bucket, EBPF_INSUFFICIENT_BUFFER is returned.
     *
     * @param[in] hash_table Hash-table to iterate.
     * @param[in,out] cookie Cookie to pass to the iterator or NULL to restart. Updated on return.
     * @param[in,out] count On input, the number of keys and values that can be stored in the buffers. On output, the
     * number of keys and values returned.
     * @param[out] keys An array of pointers to keys in the hash table.
     * @param[out] values An array of pointers to values in the hash table.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_ARGUMENT An invalid argument was passed to this function.
     * @retval EBPF_NO_MORE_KEYS No more keys.
     * @retval EBPF_INSUFFICIENT_BUFFER The buffer is too small to hold all the keys and values in the bucket and *count
     * has been updated to reflect the number of keys and values in the next bucket.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_hash_table_iterate(
        _In_ const ebpf_hash_table_t* hash_table,
        _Inout_ size_t* bucket,
        _Inout_ size_t* count,
        _Out_writes_(*count) const uint8_t** keys,
        _Out_writes_(*count) const uint8_t** values);

    /**
     * @brief Find the next key in the hash table.
     *
     * @param[in] hash_table Hash-table to query.
     * @param[in] previous_key Previous key or NULL to restart.
     * @param[out] next_key Next key if it exists.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MORE_KEYS No keys exist in the hash table that
     * are lexicographically after the specified key.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_hash_table_next_key(
        _In_ const ebpf_hash_table_t* hash_table, _In_opt_ const uint8_t* previous_key, _Out_ uint8_t* next_key);

    /**
     * @brief Returns the next (key, value) pair in the hash table.
     *
     * @param[in] hash_table Hash-table to query.
     * @param[in] previous_key Previous key or NULL to restart.
     * @param[out] next_key Next key if it exists.
     * @param[out] next_value If non-NULL, returns the next value if it exists.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MORE_KEYS No keys exist in the hash table that
     * are lexicographically after the specified key.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_hash_table_next_key_and_value(
        _In_ const ebpf_hash_table_t* hash_table,
        _In_opt_ const uint8_t* previous_key,
        _Out_ uint8_t* next_key,
        _Inout_opt_ uint8_t** next_value);

    /**
     * @brief Returns the next (key, value) pair in the hash table in an unspecified order.
     * This function is faster than ebpf_hash_table_next_key_and_value_sorted but the order of keys is unspecified.
     * The keys are not sorted and no filter is applied.
     *
     * @param[in] hash_table Hash-table to query.
     * @param[in] previous_key Previous key or NULL to restart.
     * @param[out] next_key_pointer Pointer to next key if one exists.
     * @param[out] next_value If non-NULL, returns the next value if it exists.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MORE_KEYS No more keys exist in the hash table.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_hash_table_next_key_pointer_and_value(
        _In_ const ebpf_hash_table_t* hash_table,
        _In_opt_ const uint8_t* previous_key,
        _Outptr_ uint8_t** next_key_pointer,
        _Outptr_opt_ uint8_t** next_value);

    /**
     * @brief Get the number of keys in the hash table
     *
     * @param[in] hash_table Hash-table to query.
     * @return Count of entries in the hash table.
     */
    size_t
    ebpf_hash_table_key_count(_In_ const ebpf_hash_table_t* hash_table);

    /**
     * @brief Returns the next (key, value) pair in the hash table in lexicographical order.
     * The keys are sorted using the supplied comparison function and filtered using the supplied filter function.
     * Note: This function has a cost of O(n) where n is the number of keys in the hash table. If order is not
     * important, use ebpf_hash_table_next_key_pointer_and_value instead.
     *
     * @param[in] hash_table Hash-table to query.
     * @param[in] previous_key Previous key or NULL to restart.
     * @param[in] compare Comparison function to use to compare keys.
     * @param[in] filter_context Context to pass to filter function.
     * @param[in] filter Filter function to use to filter keys.
     * @param[out] next_key_pointer Pointer to next key if one exists.
     * @param[out] next_value If non-NULL, returns the next value if it exists.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MORE_KEYS No more keys exist in the hash table.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_hash_table_next_key_and_value_sorted(
        _In_ const ebpf_hash_table_t* hash_table,
        _In_opt_ const uint8_t* previous_key,
        _In_ int (*compare)(_In_ const uint8_t* key1, _In_ const uint8_t* key2),
        _In_opt_ void* filter_context,
        _In_ bool (*filter)(_In_opt_ void* filter_context, _In_ const uint8_t* key, _In_ const uint8_t* value),
        _Out_ uint8_t* next_key,
        _Inout_opt_ uint8_t** next_value);

#ifdef __cplusplus
}
#endif
