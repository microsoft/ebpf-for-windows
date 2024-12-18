// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

// This file must only include headers that are safe
// to include in both user mode and kernel mode.
#include "ebpf_core_structs.h"

typedef enum _ebpf_operation_id
{
    EBPF_OPERATION_RESOLVE_HELPER,
    EBPF_OPERATION_RESOLVE_MAP,
    EBPF_OPERATION_CREATE_PROGRAM,
    EBPF_OPERATION_CREATE_MAP,
    EBPF_OPERATION_LOAD_CODE,
    EBPF_OPERATION_MAP_FIND_ELEMENT,
    EBPF_OPERATION_MAP_UPDATE_ELEMENT,
    EBPF_OPERATION_MAP_UPDATE_ELEMENT_WITH_HANDLE,
    EBPF_OPERATION_MAP_DELETE_ELEMENT,
    EBPF_OPERATION_MAP_GET_NEXT_KEY,
    EBPF_OPERATION_QUERY_PROGRAM_INFO,
    EBPF_OPERATION_UPDATE_PINNING,
    EBPF_OPERATION_GET_PINNED_OBJECT,
    EBPF_OPERATION_LINK_PROGRAM,
    EBPF_OPERATION_UNLINK_PROGRAM,
    EBPF_OPERATION_CLOSE_HANDLE,
    EBPF_OPERATION_GET_EC_FUNCTION,
    EBPF_OPERATION_GET_PROGRAM_INFO,
    EBPF_OPERATION_GET_PINNED_MAP_INFO,
    EBPF_OPERATION_GET_LINK_HANDLE_BY_ID,
    EBPF_OPERATION_GET_MAP_HANDLE_BY_ID,
    EBPF_OPERATION_GET_PROGRAM_HANDLE_BY_ID,
    EBPF_OPERATION_GET_NEXT_LINK_ID,
    EBPF_OPERATION_GET_NEXT_MAP_ID,
    EBPF_OPERATION_GET_NEXT_PROGRAM_ID,
    EBPF_OPERATION_GET_OBJECT_INFO,
    EBPF_OPERATION_GET_NEXT_PINNED_PROGRAM_PATH,
    EBPF_OPERATION_BIND_MAP,
    EBPF_OPERATION_RING_BUFFER_MAP_QUERY_BUFFER,
    EBPF_OPERATION_RING_BUFFER_MAP_ASYNC_QUERY,
    EBPF_OPERATION_RING_BUFFER_MAP_WRITE_DATA,
    EBPF_OPERATION_LOAD_NATIVE_MODULE,
    EBPF_OPERATION_LOAD_NATIVE_PROGRAMS,
    EBPF_OPERATION_PROGRAM_TEST_RUN,
    EBPF_OPERATION_MAP_UPDATE_ELEMENT_BATCH,
    EBPF_OPERATION_MAP_DELETE_ELEMENT_BATCH,
    EBPF_OPERATION_MAP_GET_NEXT_KEY_VALUE_BATCH,
} ebpf_operation_id_t;

typedef enum _ebpf_code_type
{
    EBPF_CODE_NONE,
    EBPF_CODE_JIT,
    EBPF_CODE_EBPF,
    EBPF_CODE_NATIVE,
    EBPF_CODE_MAX = EBPF_CODE_NATIVE,
} ebpf_code_type_t;

typedef struct _ebpf_operation_header
{
    uint16_t length;
    ebpf_operation_id_t id;
} ebpf_operation_header_t;

typedef enum _ebpf_ec_function
{
    EBPF_EC_FUNCTION_LOG
} ebpf_ec_function_t;

typedef struct _helper_function_address
{
    uint64_t address;
    bool implicit_context;
} helper_function_address_t;

#if !defined(CONFIG_BPF_JIT_DISABLED)
typedef struct _ebpf_operation_resolve_helper_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t program_handle;
    uint32_t helper_id[1];
} ebpf_operation_resolve_helper_request_t;

typedef struct _ebpf_operation_resolve_helper_reply
{
    struct _ebpf_operation_header header;
    helper_function_address_t address[1];
} ebpf_operation_resolve_helper_reply_t;

typedef struct _ebpf_operation_resolve_map_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t program_handle;
    ebpf_handle_t map_handle[1];
} ebpf_operation_resolve_map_request_t;

typedef struct _ebpf_operation_resolve_map_reply
{
    struct _ebpf_operation_header header;
    uintptr_t address[1];
} ebpf_operation_resolve_map_reply_t;
#endif

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
typedef struct _ebpf_operation_create_program_request
{
    struct _ebpf_operation_header header;
    ebpf_program_type_t program_type;
    uint16_t section_name_offset;
    uint16_t program_name_offset;
    uint8_t data[1];
} ebpf_operation_create_program_request_t;

typedef struct _ebpf_operation_create_program_reply
{
    struct _ebpf_operation_header header;
    ebpf_handle_t program_handle;
} ebpf_operation_create_program_reply_t;
#endif

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
typedef struct _ebpf_operation_load_code_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t program_handle;
    ebpf_code_type_t code_type;
    uint8_t code[1];
} ebpf_operation_load_code_request_t;
#endif

typedef struct _ebpf_operation_create_map_request
{
    struct _ebpf_operation_header header;
    ebpf_map_definition_in_memory_t ebpf_map_definition;
    ebpf_handle_t inner_map_handle;
    uint8_t data[1];
} ebpf_operation_create_map_request_t;

typedef struct _ebpf_operation_create_map_reply
{
    struct _ebpf_operation_header header;
    ebpf_handle_t handle;
} ebpf_operation_create_map_reply_t;

typedef struct _ebpf_operation_map_find_element_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t handle;
    bool find_and_delete;
    uint8_t key[1];
} ebpf_operation_map_find_element_request_t;

typedef struct _ebpf_operation_map_find_element_reply
{
    struct _ebpf_operation_header header;
    uint8_t value[1];
} ebpf_operation_map_find_element_reply_t;

typedef struct _ebpf_operation_map_update_element_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t handle;
    ebpf_map_option_t option;
    uint8_t data[1]; // data is key+value
} ebpf_operation_map_update_element_request_t;

typedef struct _ebpf_operation_map_update_element_with_handle_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t map_handle;
    ebpf_handle_t value_handle;
    ebpf_map_option_t option;
    uint8_t key[1];
} ebpf_operation_map_update_element_with_handle_request_t;

typedef struct _ebpf_operation_map_delete_element_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t handle;
    uint8_t key[1];
} ebpf_operation_map_delete_element_request_t;

typedef struct _ebpf_operation_get_next_map_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t previous_handle;
} ebpf_operation_get_next_map_request_t;

typedef struct _ebpf_operation_get_next_map_reply
{
    struct _ebpf_operation_header header;
    ebpf_handle_t next_handle;
} ebpf_operation_get_next_map_reply_t;

typedef struct _ebpf_operation_get_handle_by_id_request
{
    struct _ebpf_operation_header header;
    ebpf_id_t id;
} ebpf_operation_get_handle_by_id_request_t;

typedef struct _ebpf_operation_get_handle_by_id_reply
{
    struct _ebpf_operation_header header;
    ebpf_handle_t handle;
} ebpf_operation_get_handle_by_id_reply_t;

typedef struct _ebpf_operation_query_program_info_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t handle;
} ebpf_operation_query_program_info_request_t;

typedef struct _ebpf_operation_query_program_info_reply
{
    struct _ebpf_operation_header header;
    ebpf_code_type_t code_type;
    uint16_t file_name_offset;
    uint16_t section_name_offset;
    uint8_t data[1];
} ebpf_operation_query_program_info_reply_t;

typedef struct _ebpf_operation_map_get_next_key_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t handle;
    uint8_t previous_key[1];
} ebpf_operation_map_get_next_key_request_t;

typedef struct _ebpf_operation_map_get_next_key_reply
{
    struct _ebpf_operation_header header;
    ebpf_handle_t handle;
    uint8_t next_key[1];
} ebpf_operation_map_get_next_key_reply_t;

typedef struct _ebpf_operation_update_map_pinning_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t handle;
    uint8_t path[1];
} ebpf_operation_update_pinning_request_t;

typedef struct _ebpf_operation_get_pinned_object_request
{
    struct _ebpf_operation_header header;
    uint8_t path[1];
} ebpf_operation_get_pinned_object_request_t;

typedef struct _ebpf_operation_get_pinned_object_reply
{
    struct _ebpf_operation_header header;
    ebpf_handle_t handle;
} ebpf_operation_get_pinned_object_reply_t;

typedef struct _ebpf_operation_link_program_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t program_handle;
    ebpf_attach_type_t attach_type;
    uint8_t data[1];
} ebpf_operation_link_program_request_t;

typedef struct _ebpf_operation_link_program_reply
{
    struct _ebpf_operation_header header;
    ebpf_handle_t link_handle;
} ebpf_operation_link_program_reply_t;

typedef struct _ebpf_operation_unlink_program_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t link_handle;
    ebpf_handle_t program_handle;
    ebpf_attach_type_t attach_type;
    bool attach_data_present;
    uint8_t data[1];
} ebpf_operation_unlink_program_request_t;

typedef struct _ebpf_operation_close_handle_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t handle;
} ebpf_operation_close_handle_request_t;

#if !defined(CONFIG_BPF_JIT_DISABLED)
typedef struct _ebpf_operation_get_ec_function_request
{
    struct _ebpf_operation_header header;
    ebpf_ec_function_t function;
} ebpf_operation_get_ec_function_request_t;

typedef struct _ebpf_operation_get_ec_function_reply
{
    struct _ebpf_operation_header header;
    uintptr_t address;
} ebpf_operation_get_ec_function_reply_t;
#endif

typedef struct _ebpf_operation_get_program_info_request
{
    struct _ebpf_operation_header header;
    ebpf_program_type_t program_type;
    ebpf_handle_t program_handle;
} ebpf_operation_get_program_info_request_t;

typedef struct _ebpf_operation_get_program_info_reply
{
    struct _ebpf_operation_header header;
    uint16_t version;
    size_t size;
    uint8_t data[1];
} ebpf_operation_get_program_info_reply_t;

typedef struct _ebpf_operation_get_pinned_map_info_request
{
    struct _ebpf_operation_header header;
} ebpf_operation_get_pinned_map_info_request_t;

typedef struct _ebpf_operation_get_pinned_map_info_reply
{
    struct _ebpf_operation_header header;
    uint16_t map_count;
    size_t size;
    uint8_t data[1];
} ebpf_operation_get_pinned_map_info_reply_t;

typedef struct _ebpf_operation_get_next_id_request
{
    struct _ebpf_operation_header header;
    ebpf_id_t start_id;
} ebpf_operation_get_next_id_request_t;

typedef struct _ebpf_operation_get_next_id_reply
{
    struct _ebpf_operation_header header;
    ebpf_id_t next_id;
} ebpf_operation_get_next_id_reply_t;

typedef struct _ebpf_operation_get_next_pinned_program_path_request
{
    struct _ebpf_operation_header header;
    uint8_t start_path[1];
} ebpf_operation_get_next_pinned_program_path_request_t;

typedef struct _ebpf_operation_get_next_pinned_program_path_reply
{
    struct _ebpf_operation_header header;
    uint8_t next_path[1];
} ebpf_operation_get_next_pinned_program_path_reply_t;

typedef struct _ebpf_operation_get_object_info_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t handle;
    uint8_t info[1];
} ebpf_operation_get_object_info_request_t;

typedef struct _ebpf_operation_get_object_info_reply
{
    struct _ebpf_operation_header header;
    ebpf_object_type_t type;
    uint8_t info[1];
} ebpf_operation_get_object_info_reply_t;

typedef struct _ebpf_operation_bind_map_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t program_handle;
    ebpf_handle_t map_handle;
} ebpf_operation_bind_map_request_t;

typedef struct _ebpf_operation_ring_buffer_map_query_buffer_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t map_handle;
} ebpf_operation_ring_buffer_map_query_buffer_request_t;

typedef struct _ebpf_operation_ring_buffer_map_query_buffer_reply
{
    struct _ebpf_operation_header header;
    // Address to user-space read-only buffer for the ring-buffer records.
    uint64_t buffer_address;
    // The current consumer offset, so that subsequent reads can start from here.
    size_t consumer_offset;
} ebpf_operation_ring_buffer_map_query_buffer_reply_t;

typedef struct _ebpf_operation_ring_buffer_map_async_query_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t map_handle;
    // Offset till which the consumer has read data so far.
    size_t consumer_offset;
} ebpf_operation_ring_buffer_map_async_query_request_t;

typedef struct _ebpf_operation_ring_buffer_map_async_query_reply
{
    struct _ebpf_operation_header header;
    ebpf_ring_buffer_map_async_query_result_t async_query_result;
} ebpf_operation_ring_buffer_map_async_query_reply_t;

typedef struct _ebpf_operation_ring_buffer_map_write_data_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t map_handle;
    uint8_t data[1];
} ebpf_operation_ring_buffer_map_write_data_request_t;

typedef struct _ebpf_operation_load_native_module_request
{
    struct _ebpf_operation_header header;
    GUID module_id;
    // Service name (UTF16)
    uint8_t data[1];
} ebpf_operation_load_native_module_request_t;

typedef struct _ebpf_operation_load_native_module_reply
{
    struct _ebpf_operation_header header;
    ebpf_handle_t native_module_handle;
    size_t count_of_maps;
    size_t count_of_programs;
} ebpf_operation_load_native_module_reply_t;

typedef struct _ebpf_operation_load_native_programs_request
{
    struct _ebpf_operation_header header;
    GUID module_id;
} ebpf_operation_load_native_programs_request_t;

typedef struct _ebpf_program_information
{
    uint16_t length;
    ebpf_handle_t handle;
    ebpf_program_type_t program_type;
    ebpf_attach_type_t attach_type;
    // Order of data:
    // 1. program name
    // 2. section name
    uint16_t section_name_offset;
    uint8_t data[1];
} ebpf_program_information_t;

typedef struct _ebpf_map_information
{
    uint16_t length;
    ebpf_handle_t handle;
    ebpf_map_definition_in_file_t definition;
    // Map name.
    uint8_t data[1];
} ebpf_map_information_t;

typedef struct _ebpf_operation_load_native_programs_reply
{
    struct _ebpf_operation_header header;
    size_t program_handle_count;
    size_t map_handle_count;
    // Map handles followed by program handles.
    uint8_t data[1];
} ebpf_operation_load_native_programs_reply_t;

typedef struct _ebpf_operation_program_test_run_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t program_handle;
    size_t repeat_count;
    uint32_t flags;
    uint32_t cpu;
    size_t batch_size;
    uint16_t context_offset;
    uint8_t data[1];

} ebpf_operation_program_test_run_request_t;
typedef struct _ebpf_operation_program_test_run_reply
{
    struct _ebpf_operation_header header;
    uint64_t duration;
    uint64_t return_value;
    uint64_t context_offset;
    uint8_t data[1];
} ebpf_operation_program_test_run_reply_t;

typedef struct _ebpf_operation_map_update_element_batch_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t handle;
    ebpf_map_option_t option;
    // Count of elements is derived from the length of the request.
    // Data is a concatenation of key+value.
    uint8_t data[1];
} ebpf_operation_map_update_element_batch_request_t;

typedef struct _ebpf_operation_map_update_element_batch_reply
{
    struct _ebpf_operation_header header;
    uint32_t count_of_elements_processed;
} ebpf_operation_map_update_element_batch_reply_t;

typedef struct _ebpf_operation_map_delete_element_batch_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t handle;
    // Count of elements is derived from the length of the request.
    // Data is a concatenation of keys.
    uint8_t keys[1];
} ebpf_operation_map_delete_element_batch_request_t;

typedef struct _ebpf_operation_map_delete_element_batch_reply
{
    struct _ebpf_operation_header header;
    uint32_t count_of_elements_processed;
} ebpf_operation_map_delete_element_batch_reply_t;

typedef struct _ebpf_operation_map_get_next_key_value_batch_request
{
    struct _ebpf_operation_header header;
    ebpf_handle_t handle;
    bool find_and_delete;
    uint8_t previous_key[1];
} ebpf_operation_map_get_next_key_value_batch_request_t;

typedef struct _ebpf_operation_map_get_next_key_value_batch_reply
{
    struct _ebpf_operation_header header;
    // Count of elements is derived from the length of the reply.
    // Data is a concatenation of key+value.
    uint8_t data[1];
} ebpf_operation_map_get_next_key_value_batch_reply_t;
