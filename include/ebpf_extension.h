// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_result.h"
#include "ebpf_structs.h"
#include "ebpf_windows.h"

#define EBPF_MAP_FLAG_HELPER 0x01      /* Called by an eBPF program. */
#define EBPF_MAP_FIND_FLAG_DELETE 0x02 /* Perform a find and delete. */

typedef ebpf_result_t (*_ebpf_extension_dispatch_function)();

typedef struct _ebpf_extension_dispatch_table
{
    uint16_t version; ///< Version of the dispatch table.
    uint16_t count;   ///< Number of entries in the dispatch table.
    _Field_size_(count) _ebpf_extension_dispatch_function function[1];
} ebpf_extension_dispatch_table_t;

/**
 * @brief Invoke the eBPF program.
 *
 * @param[in] extension_client_binding_context The context provided by the extension client when the binding was
 * created.
 * @param[in,out] program_context The context for this invocation of the eBPF program.
 * @param[out] result The result of the eBPF program.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MEMORY The operation failed due to lack of memory.
 * @retval EBPF_EXTENSION_FAILED_TO_LOAD The required extension is not loaded.
 */
typedef ebpf_result_t (*ebpf_program_invoke_function_t)(
    _In_ const void* extension_client_binding_context, _Inout_ void* program_context, _Out_ uint32_t* result);

/**
 * @brief Prepare the eBPF program for batch invocation.
 *
 * @param[in] state_size The size of the state to be allocated, which should be greater than or equal to
 * sizeof(ebpf_execution_context_state_t).
 * @param[out] state The state to be used for batch invocation.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MEMORY The operation failed due to lack of memory.
 * @retval EBPF_EXTENSION_FAILED_TO_LOAD The required extension is not loaded.
 */
typedef ebpf_result_t (*ebpf_program_batch_begin_invoke_function_t)(
    size_t state_size, _Out_writes_(state_size) void* state);

/**
 * @brief Invoke the eBPF program in batch mode.
 *
 * @param[in] extension_client_binding_context The context provided by the extension client when the binding was
 * created.
 * @param[in,out] program_context The context for this invocation of the eBPF program.
 * @param[out] result The result of the eBPF program.
 * @param[in] state The state to be used for batch invocation.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 */
typedef ebpf_result_t (*ebpf_program_batch_invoke_function_t)(
    _In_ const void* extension_client_binding_context,
    _Inout_ void* program_context,
    _Out_ uint32_t* result,
    _In_ const void* state);

/**
 * @brief Clean up the eBPF program after batch invocation.
 *
 * @param[in,out] state The state to be used for batch invocation.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 */
typedef ebpf_result_t (*ebpf_program_batch_end_invoke_function_t)(_Inout_ void* state);

typedef enum _ebpf_link_dispatch_table_version
{
    EBPF_LINK_DISPATCH_TABLE_VERSION_1 = 1, ///< Initial version of the dispatch table.
    EBPF_LINK_DISPATCH_TABLE_VERSION_CURRENT =
        EBPF_LINK_DISPATCH_TABLE_VERSION_1, ///< Current version of the dispatch table.
} ebpf_link_dispatch_table_version_t;

#define EBPF_LINK_DISPATCH_TABLE_FUNCTION_COUNT_1 4
#define EBPF_LINK_DISPATCH_TABLE_FUNCTION_COUNT_CURRENT \
    EBPF_LINK_DISPATCH_TABLE_FUNCTION_COUNT_1 ///< Current number of functions in the dispatch table.

typedef struct _ebpf_extension_program_dispatch_table
{
    uint16_t version; ///< Version of the dispatch table.
    uint16_t count;   ///< Number of entries in the dispatch table.
    ebpf_program_invoke_function_t ebpf_program_invoke_function;
    ebpf_program_batch_begin_invoke_function_t ebpf_program_batch_begin_invoke_function;
    ebpf_program_batch_invoke_function_t ebpf_program_batch_invoke_function;
    ebpf_program_batch_end_invoke_function_t ebpf_program_batch_end_invoke_function;
} ebpf_extension_program_dispatch_table_t;

typedef struct _ebpf_extension_data
{
    ebpf_extension_header_t header;
    const void* data;
    size_t data_size;
    uint64_t prog_attach_flags;
} ebpf_extension_data_t;

typedef struct _ebpf_attach_provider_data
{
    ebpf_extension_header_t header;
    ebpf_program_type_t supported_program_type;
    bpf_attach_type_t bpf_attach_type;
    enum bpf_link_type link_type;
} ebpf_attach_provider_data_t;

/***
 * The state of the execution context when the eBPF program was invoked.
 * This is used to cache state that won't change during the execution of
 * the eBPF program and is expensive to query.
 */
typedef struct _ebpf_execution_context_state
{
    uint64_t epoch_state[4];
    union
    {
        uint64_t thread;
        uint32_t cpu;
    } id;
    uint8_t current_irql;
    struct
    {
        const void* next_program;
        uint32_t count;
    } tail_call_state;
} ebpf_execution_context_state_t;

#define EBPF_CONTEXT_HEADER uint64_t context_header[8]
#define EBPF_CONTEXT_HEADER_SIZE (sizeof(uint64_t) * 8)

/**
 * @brief Create an eBPF map.
 *
 * @param[in] map_type The type of map to create.
 * @param[in] key_size The size of the key in bytes.
 * @param[in] value_size The size of the value in bytes.
 * @param[in] max_entries The maximum number of entries in the map.
 * @param[out] map_context The created map context.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MEMORY Unable to allocate memory.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are incorrect.
 */
typedef ebpf_result_t (*ebpf_map_create_t)(
    _In_ void* binding_context,
    uint32_t map_type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    _Outptr_ void** map_context);

/**
 * @brief Delete an eBPF map.
 *
 * @param[in] map_context The map context to delete.
 */
typedef void (*ebpf_map_delete_t)(_In_ _Post_invalid_ void* map_context);

/**
 * @brief Find an element in the eBPF map.
 *
 * @param[in] map The eBPF map to search.
 * @param[in] key_size The size of the key in bytes. Set to 0 in case of a helper function call.
 * @param[in] key Optionally, the key to search for.
 * @param[in] value_size The size of the value in bytes. Set to 0 in case of a helper function call.
 * @param[out] value Pointer to the value associated with the key.
 * @param[in] flags Find flags.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_OBJECT_NOT_FOUND The key was not found in the map.
 */
typedef ebpf_result_t (*ebpf_map_find_element_t)(
    _In_ void* map,
    size_t key_size,
    _In_reads_opt_(key_size) const uint8_t* key,
    _Outptr_ uint8_t** value,
    uint32_t flags);

/**
 * @brief Update an element in the eBPF map.
 *
 * @param[in] map The eBPF map to update.
 * @param[in] key_size The size of the key in bytes. Set to 0 in case of a helper function call.
 * @param[in] key Optionally, the key to update.
 * @param[in] value_size The size of the value in bytes. Set to 0 in case of a helper function call.
 * @param[in] value Optionally, the value to associate with the key.
 * @param[in] option Update option.
 * @param[in] flags Update flags.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_OBJECT_NOT_FOUND The key was not found in the map.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are incorrect.
 * @retval EBPF_NO_MEMORY Unable to allocate memory.
 */
typedef ebpf_result_t (*ebpf_map_update_element_t)(
    _In_ void* map,
    size_t key_size,
    _In_reads_opt_(key_size) const uint8_t* key,
    size_t value_size,
    _In_reads_opt_(value_size) const uint8_t* value,
    ebpf_map_option_t option,
    uint32_t flags);

/**
 * @brief Delete an element from the eBPF map.
 * @param[in] map The eBPF map to delete from.
 * @param[in] key_size The size of the key in bytes. Set to 0 in case of a helper function call.
 * @param[in] key Optionally, the key to delete. If the key is not found, the map is unchanged. If the key is found, the
 * associated value is deleted.
 * @param[in] flags Delete flags.
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_OBJECT_NOT_FOUND The key was not found in the map.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are incorrect.
 * @retval EBPF_NO_MEMORY Unable to allocate memory.
 */
typedef ebpf_result_t (*ebpf_map_delete_element_t)(
    _In_ void* map, size_t key_size, _In_reads_opt_(key_size) const uint8_t* key, uint32_t flags);

/**
 * @brief Get the next key and value in the eBPF map.
 *
 * @param[in] map The eBPF map to query.
 * @param[in] previous_key The previous key. If NULL, get the first key.
 * @param[out] next_key The next key in the map.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_OBJECT_NOT_FOUND No more keys in the map.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are incorrect.
 */
typedef ebpf_result_t (*ebpf_map_get_next_key_and_value_t)(
    _In_ void* map,
    size_t key_size,
    _In_reads_opt_(key_size) const uint8_t* previous_key,
    _Out_writes_(key_size) uint8_t* next_key,
    _Outptr_opt_ uint8_t** next_value);

/**
 * @brief Get the next key in the eBPF map.
 *
 * @param[in] map The eBPF map to query.
 * @param[in] program_type The program type.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_OPERATION_NOT_SUPPORTED The operation is not supported.
 */
typedef ebpf_result_t (*ebpf_map_associate_program_type_t)(
    _In_ void* map, _In_ const ebpf_program_type_t* program_type);

/**
 * Dispatch table implemented by the eBPF extension to provide map operations.
 * This table is used to provide map operations to the eBPF core.
 */
typedef struct _ebpf_map_provider_dispatch_table
{
    ebpf_extension_header_t header;
    _Notnull_ ebpf_map_create_t create_map_function;
    _Notnull_ ebpf_map_delete_t delete_map_function;
    _Notnull_ ebpf_map_associate_program_type_t associate_program_function;
    ebpf_map_find_element_t find_element_function;
    ebpf_map_update_element_t update_element_function;
    ebpf_map_delete_element_t delete_element_function;
    ebpf_map_get_next_key_and_value_t get_next_key_and_value_function;
} ebpf_map_provider_dispatch_table_t;

/**
 * @brief Allocate memory under epoch control.
 * @param[in] size Size of memory to allocate
 * @param[in] tag Pool tag to use.
 * @returns Pointer to memory block allocated, or null on failure.
 */
typedef _Ret_writes_maybenull_(size) void* (*epoch_allocate_with_tag_t)(size_t size, uint32_t tag);

/**
 * @brief Allocate cache aligned memory under epoch control.
 * @param[in] size Size of memory to allocate
 * @param[in] tag Pool tag to use.
 * @returns Pointer to memory block allocated, or null on failure.
 */
typedef _Ret_writes_maybenull_(size) void* (*epoch_allocate_cache_aligned_with_tag_t)(size_t size, uint32_t tag);

/**
 * @brief Free memory under epoch control.
 * @param[in] memory Allocation to be freed once epoch ends.
 */
typedef void (*epoch_free_t)(_In_opt_ void* memory);

/**
 * @brief Free memory under epoch control.
 * @param[in] memory Allocation to be freed once epoch ends.
 */
typedef void (*epoch_free_cache_aligned_t)(_In_opt_ void* pointer);

typedef ebpf_result_t (*ebpf_get_map_context_t)(_In_ const void* map, _Outptr_ void** map_context);

/**
 * Dispatch table implemented by the eBPF runtime to provide RCU / epoch operations.
 */
typedef struct _ebpf_map_client_dispatch_table
{
    ebpf_extension_header_t header;
    epoch_allocate_with_tag_t epoch_allocate_with_tag;
    epoch_allocate_cache_aligned_with_tag_t epoch_allocate_cache_aligned_with_tag;
    epoch_free_t epoch_free;
    epoch_free_cache_aligned_t epoch_free_cache_aligned;
} ebpf_map_client_dispatch_table_t;

/**
 * @brief Extensible map provider data.
 */
typedef struct _ebpf_map_provider_data
{
    ebpf_extension_header_t header;
    uint32_t map_type; // Extensible map type implemented by the provider.
    ebpf_map_provider_dispatch_table_t* dispatch_table;
} ebpf_map_provider_data_t;

/**
 * @brief Extensible map client data.
 */
typedef struct _ebpf_map_client_data
{
    ebpf_extension_header_t header; ///< Standard extension header containing version and size information.
    uint64_t map_context_offset;    ///< Offset within the map structure where the provider context data is stored.
    ebpf_map_client_dispatch_table_t* dispatch_table; ///< Pointer to client dispatch table.
} ebpf_map_client_data_t;

#define MAP_CONTEXT(map_pointer, offset) ((void**)(((uint8_t*)(map_pointer)) + (offset)))