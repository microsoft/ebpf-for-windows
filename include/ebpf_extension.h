// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_result.h"
#include "ebpf_structs.h"
#include "ebpf_windows.h"

#define EBPF_MAP_OPERATION_HELPER 0x01      /* Called by a BPF program. */
#define EBPF_MAP_OPERATION_UPDATE 0x02      /* Update operation. */
#define EBPF_MAP_OPERATION_MAP_CLEANUP 0x04 /* Map cleanup operation. */

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
 * @brief Process map creation notification.
 *
 * @param[in] binding_context The binding context provided when the map provider was bound.
 * @param[in] map_type The type of map to create.
 * @param[in] key_size The size of the key in bytes.
 * @param[in] value_size The value size requested by the caller in bytes.
 * @param[in] max_entries The maximum number of entries in the map.
 * @param[out] actual_value_size The value size in bytes that will actually be stored in the map.
 * @param[out] map_context Provider-defined per-map context. The eBPF core will pass this back to subsequent map
 *             operations and will eventually pass it to ebpf_process_map_delete_t.
 *
 * Note: When a map lookup happens from user mode, the value is copied into the buffer provided by the user.
 * Whereas when a map lookup happens from a BPF program, a pointer to the value is provided to the program,
 * and program can read or modify the value in place.
 *
 * Therefore, for maps where extension intends to *modify* the actual value being stored in the map,
 * map CRUD operations from BPF programs are disallowed by eBPF runtime.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MEMORY Unable to allocate memory.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are incorrect.
 */
typedef ebpf_result_t (*ebpf_process_map_create_t)(
    _In_ void* binding_context,
    uint32_t map_type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    _Out_ uint32_t* actual_value_size,
    _Outptr_ void** map_context);

/**
 * @brief Process a map delete notification.
 *
 * @param[in] binding_context The binding context provided when the map provider was bound.
 * @param[in] map_context The map context to delete.
 */
typedef void (*ebpf_process_map_delete_t)(_In_ void* binding_context, _In_ _Post_invalid_ void* map_context);

/**
 * @brief Find (lookup) an element in a provider-backed map.
 *
 * @param[in] binding_context The binding context provided when the map provider was bound.
 * @param[in] map_context The eBPF map context.
 * @param[in] key_size The size of the key in bytes.
 * @param[in] key Optionally, pointer to the key being looked up.
 * @param[in] in_value_size The size in bytes of the provider's stored value buffer.
 * @param[in] in_value Pointer to the provider's stored value buffer for the entry.
 * @param[in] out_value_size The size in bytes of the output value buffer.
 * @param[out] out_value Optional output buffer to receive the value bytes.
 * @param[in] flags Find flags. Supported values:
 *      EBPF_MAP_OPERATION_HELPER - The lookup is invoked from a BPF program.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_OPERATION_NOT_SUPPORTED The operation is not supported.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are incorrect.
 * @retval EBPF_KEY_NOT_FOUND The key was not found in the map.
 */
typedef ebpf_result_t (*ebpf_process_map_find_element_t)(
    _In_ void* binding_context,
    _In_ void* map_context,
    size_t key_size,
    _In_reads_opt_(key_size) const uint8_t* key,
    size_t in_value_size,
    _In_reads_(in_value_size) const uint8_t* in_value,
    size_t out_value_size,
    _Out_writes_opt_(out_value_size) uint8_t* out_value,
    uint32_t flags);

/**
 * @brief Add or update (insert/replace) an element in a provider-backed map.
 *
 * @param[in] binding_context The binding context provided when the map provider was bound.
 * @param[in] map_context The eBPF map context.
 * @param[in] key_size The size of the key in bytes.
 * @param[in] key Pointer to the key being updated (may be NULL for helper-mode operations, depending on the base map
 *             implementation).
 * @param[in] in_value_size The size in bytes of the input value.
 * @param[in] in_value Pointer to the input value bytes.
 * @param[in] out_value_size The size in bytes of the destination (stored) value buffer.
 * @param[out] out_value Pointer to the destination (stored) value buffer to populate.
 * @param[in] flags Update flags. Supported values:
 *      EBPF_MAP_OPERATION_HELPER - The update is invoked from a BPF program.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_OPERATION_NOT_SUPPORTED The operation is not supported.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are incorrect.
 * @retval EBPF_NO_MEMORY Unable to allocate memory.
 */
typedef ebpf_result_t (*ebpf_process_map_add_element_t)(
    _In_ void* binding_context,
    _In_ void* map_context,
    size_t key_size,
    _In_reads_opt_(key_size) const uint8_t* key,
    size_t in_value_size,
    _In_reads_(in_value_size) const uint8_t* in_value,
    size_t out_value_size,
    _Out_writes_opt_(out_value_size) uint8_t* out_value,
    uint32_t flags);

/**
 * @brief Delete an element from a provider-backed map.
 *
 * This function can be called in three scenarios:
 *      1. Normal map element deletion.
 *      2. Deletion performed as part of an update operation (replacing an existing entry).
 *      3. Deletion performed as part of map cleanup.
 * When deletion is part of an update operation, EBPF_MAP_OPERATION_UPDATE is set in the flags parameter.
 * When map cleanup is in progress, EBPF_MAP_OPERATION_MAP_CLEANUP is set in the flags parameter.
 * In both these cases, the provider must not fail the deletion.
 *
 * @param[in] binding_context The binding context provided when the map provider was bound.
 * @param[in] map_context The eBPF map context.
 * @param[in] key_size The size of the key in bytes.
 * @param[in] key Pointer to the key to delete. If the key is not found, the map is unchanged.
 * @param[in] value_size The size in bytes of the provider's stored value buffer.
 * @param[in] value Pointer to the provider's stored value buffer for the entry being deleted.
 * @param[in] flags Delete flags. Possible values:
 *      EBPF_MAP_OPERATION_UPDATE - The delete is invoked as part of an update operation.
 *      EBPF_MAP_OPERATION_MAP_CLEANUP - The delete is invoked as part of a map cleanup operation.
 *      EBPF_MAP_OPERATION_HELPER - The delete is invoked from a BPF program.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_KEY_NOT_FOUND The key was not found in the map.
 * @retval EBPF_OPERATION_NOT_SUPPORTED The operation is not supported.
 */
typedef ebpf_result_t (*ebpf_process_map_delete_element_t)(
    _In_ void* binding_context,
    _In_ void* map_context,
    size_t key_size,
    _In_reads_opt_(key_size) const uint8_t* key,
    size_t value_size,
    _In_reads_(value_size) const uint8_t* value,
    uint32_t flags);

/**
 * @brief Associate a program type with the map, which allows the map to be used by programs of that type.
 *
 * @param[in] map The eBPF map to query.
 * @param[in] program_type The program type.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_OPERATION_NOT_SUPPORTED The operation is not supported.
 */
typedef ebpf_result_t (*ebpf_map_associate_program_type_t)(
    _In_ void* binding_context, _In_ void* map_context, _In_ const ebpf_program_type_t* program_type);

typedef struct _ebpf_base_map_provider_properties
{
    ebpf_extension_header_t header;
    bool updates_original_value; // Whether the map supports lookup from BPF programs.
} ebpf_base_map_provider_properties_t;

/**
 * Dispatch table implemented by the eBPF extension to provide map operations.
 * This table is used to provide map operations to the eBPF core.
 */
typedef struct _ebpf_map_provider_dispatch_table
{
    ebpf_extension_header_t header;
    _Notnull_ ebpf_process_map_create_t process_map_create;
    _Notnull_ ebpf_process_map_delete_t process_map_delete;
    _Notnull_ ebpf_map_associate_program_type_t associate_program_function;
    ebpf_process_map_find_element_t process_map_find_element;
    ebpf_process_map_add_element_t process_map_add_element;
    ebpf_process_map_delete_element_t process_map_delete_element;
} ebpf_base_map_provider_dispatch_table_t;

/**
 * @brief Allocate memory under epoch control.
 *
 * @param[in] size Size of memory to allocate
 * @param[in] tag Pool tag to use.
 *
 * @returns Pointer to memory block allocated, or null on failure.
 */
typedef _Ret_writes_maybenull_(size) void* (*epoch_allocate_with_tag_t)(size_t size, uint32_t tag);

/**
 * @brief Allocate cache aligned memory under epoch control.
 *
 * @param[in] size Size of memory to allocate
 * @param[in] tag Pool tag to use.
 *
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

/**
 * @brief Find an element in an eBPF map (client/runtime helper version).
 *
 * @param[in] map The eBPF map to query.
 * @param[in] key Pointer to the key to search for.
 * @param[out] value Receives a pointer to the value associated with the key.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_KEY_NOT_FOUND The key was not found in the map.
 * @retval EBPF_INVALID_OBJECT An invalid map was provided.
 */
typedef ebpf_result_t (*ebpf_map_find_element_t)(
    _In_ const void* map, _In_ const uint8_t* key, _Outptr_ uint8_t** value);

/**
 * Dispatch table implemented by the eBPF runtime to provide RCU / epoch operations.
 *
 * Note: `find_element_function` can only be invoked in the context of a BPF program
 *       (i.e., when called from within a BPF helper function). Calling it from
 *       non-BPF program contexts may lead to use-after-free errors.
 */
typedef struct _ebpf_map_client_dispatch_table
{
    ebpf_extension_header_t header;
    ebpf_map_find_element_t find_element_function;
    epoch_allocate_with_tag_t epoch_allocate_with_tag;
    epoch_allocate_cache_aligned_with_tag_t epoch_allocate_cache_aligned_with_tag;
    epoch_free_t epoch_free;
    epoch_free_cache_aligned_t epoch_free_cache_aligned;
} ebpf_base_map_client_dispatch_table_t;

/**
 * @brief Custom map provider data.
 */
typedef struct _ebpf_map_provider_data
{
    ebpf_extension_header_t header;
    uint32_t map_type;                                            ///< Custom map type implemented by the provider.
    uint32_t base_map_type;                                       ///< Base map type used to implement the custom map.
    ebpf_base_map_provider_properties_t* base_properties;         ///< Base map provider properties.
    ebpf_base_map_provider_dispatch_table_t* base_provider_table; ///< Pointer to base map provider dispatch table.
} ebpf_map_provider_data_t;

/**
 * @brief Custom map client data.
 */
typedef struct _ebpf_map_client_data
{
    ebpf_extension_header_t header; ///< Standard extension header containing version and size information.
    uint64_t map_context_offset;    ///< Offset within the map structure where the provider context data is stored.
    ebpf_base_map_client_dispatch_table_t* base_client_table; ///< Pointer to base map client dispatch table.
} ebpf_map_client_data_t;

#define MAP_CONTEXT(map_pointer, offset) ((void**)(((uint8_t*)(map_pointer)) + (offset)))