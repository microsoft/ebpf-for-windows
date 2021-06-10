// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include "ebpf_core_structs.h"
#include "ebpf_helpers.h"
#include "ebpf_windows.h"

typedef enum _ebpf_operation_id
{
    EBPF_OPERATION_RESOLVE_HELPER,
    EBPF_OPERATION_RESOLVE_MAP,
    EBPF_OPERATION_CREATE_PROGRAM,
    EBPF_OPERATION_CREATE_MAP,
    EBPF_OPERATION_LOAD_CODE,
    EBPF_OPERATION_MAP_FIND_ELEMENT,
    EBPF_OPERATION_MAP_UPDATE_ELEMENT,
    EBPF_OPERATION_MAP_DELETE_ELEMENT,
    EBPF_OPERATION_MAP_GET_NEXT_KEY,
    EBPF_OPERATION_GET_NEXT_MAP,
    EBPF_OPERATION_GET_NEXT_PROGRAM,
    EBPF_OPERATION_QUERY_MAP_DEFINITION,
    EBPF_OPERATION_QUERY_PROGRAM_INFORMATION,
    EBPF_OPERATION_UPDATE_PINNING,
    EBPF_OPERATION_GET_PINNING,
    EBPF_OPERATION_LINK_PROGRAM,
    EBPF_OPERATION_CLOSE_HANDLE,
    EBPF_OPERATION_GET_EC_FUNCTION,
    EBPF_OPERATION_GET_PROGRAM_INFORMATION,
    EBPF_OPERATION_GET_MAP_INFORMATION,
} ebpf_operation_id_t;

typedef enum _ebpf_code_type
{
    EBPF_CODE_NONE,
    EBPF_CODE_NATIVE,
    EBPF_CODE_EBPF,
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

typedef struct _ebpf_operation_resolve_helper_request
{
    struct _ebpf_operation_header header;
    uint64_t program_handle;
    uint32_t helper_id[1];
} ebpf_operation_resolve_helper_request_t;

typedef struct _ebpf_operation_resolve_helper_reply
{
    struct _ebpf_operation_header header;
    uint64_t address[1];
} ebpf_operation_resolve_helper_reply_t;

typedef struct _ebpf_operation_resolve_map_request
{
    struct _ebpf_operation_header header;
    uint64_t program_handle;
    uint64_t map_handle[1];
} ebpf_operation_resolve_map_request_t;

typedef struct _ebpf_operation_resolve_map_reply
{
    struct _ebpf_operation_header header;
    uint64_t address[1];
} ebpf_operation_resolve_map_reply_t;

typedef struct _ebpf_operation_create_program_request
{
    struct _ebpf_operation_header header;
    ebpf_program_type_t program_type;
    uint16_t section_name_offset;
    uint8_t data[1];
} ebpf_operation_create_program_request_t;

typedef struct _ebpf_operation_create_program_reply
{
    struct _ebpf_operation_header header;
    uint64_t program_handle;
} ebpf_operation_create_program_reply_t;

typedef struct _ebpf_operation_load_code_request
{
    struct _ebpf_operation_header header;
    uint64_t program_handle;
    ebpf_code_type_t code_type;
    uint8_t code[1];
} ebpf_operation_load_code_request_t;

typedef struct _ebpf_operation_create_map_request
{
    struct _ebpf_operation_header header;
    struct _ebpf_map_definition ebpf_map_definition;
} ebpf_operation_create_map_request_t;

typedef struct _ebpf_operation_create_map_reply
{
    struct _ebpf_operation_header header;
    uint64_t handle;
} ebpf_operation_create_map_reply_t;

typedef struct _ebpf_operation_map_find_element_request
{
    struct _ebpf_operation_header header;
    uint64_t handle;
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
    uint64_t handle;
    uint8_t data[1]; // data is key+value
} epf_operation_map_update_element_request_t;

typedef struct _ebpf_operation_map_delete_element_request
{
    struct _ebpf_operation_header header;
    uint64_t handle;
    uint8_t key[1];
} ebpf_operation_map_delete_element_request_t;

typedef struct _ebpf_operation_get_next_map_request
{
    struct _ebpf_operation_header header;
    uint64_t previous_handle;
} ebpf_operation_get_next_map_request;

typedef struct _ebpf_operation_get_next_map_reply
{
    struct _ebpf_operation_header header;
    uint64_t next_handle;
} ebpf_operation_get_next_map_reply_t;

typedef struct _ebpf_operation_get_next_program_request
{
    struct _ebpf_operation_header header;
    uint64_t previous_handle;
} ebpf_operation_get_next_program_request;

typedef struct _ebpf_operation_get_next_program_reply
{
    struct _ebpf_operation_header header;
    uint64_t next_handle;
} ebpf_operation_get_next_program_reply_t;

typedef struct _ebpf_operation_query_map_definition_request
{
    struct _ebpf_operation_header header;
    uint64_t handle;
} ebpf_operation_query_map_definition_request;

typedef struct _ebpf_operation_query_map_definition_reply
{
    struct _ebpf_operation_header header;
    struct _ebpf_map_definition map_definition;
} ebpf_operation_query_map_definition_reply;

typedef struct _ebpf_operation_query_program_information_request
{
    struct _ebpf_operation_header header;
    uint64_t handle;
} ebpf_operation_query_program_information_request;

typedef struct _ebpf_operation_query_program_information_reply
{
    struct _ebpf_operation_header header;
    ebpf_code_type_t code_type;
    uint16_t file_name_offset;
    uint16_t section_name_offset;
    uint8_t data[1];
} ebpf_operation_query_program_information_reply;

typedef struct _ebpf_operation_map_get_next_key_request
{
    struct _ebpf_operation_header header;
    uint64_t handle;
    uint8_t previous_key[1];
} ebpf_operation_map_get_next_key_request_t;

typedef struct _ebpf_operation_map_get_next_key_reply
{
    struct _ebpf_operation_header header;
    uint64_t handle;
    uint8_t next_key[1];
} ebpf_operation_map_get_next_key_reply_t;

typedef struct _ebpf_operation_update_map_pinning_request
{
    struct _ebpf_operation_header header;
    uint64_t handle;
    uint8_t name[1];
} ebpf_operation_update_pinning_request_t;

typedef struct _ebpf_operation_get_pinning_request
{
    struct _ebpf_operation_header header;
    uint8_t name[1];
} ebpf_operation_get_pinning_request_t;

typedef struct _ebpf_operation_get_pinning_reply
{
    struct _ebpf_operation_header header;
    uint64_t handle;
} ebpf_operation_get_map_pinning_reply_t;

typedef struct _ebpf_operation_link_program_request
{
    struct _ebpf_operation_header header;
    uint64_t program_handle;
    ebpf_attach_type_t attach_type;
} ebpf_operation_link_program_request_t;

typedef struct _ebpf_operation_link_program_reply
{
    struct _ebpf_operation_header header;
    uint64_t link_handle;
} ebpf_operation_link_program_reply_t;

typedef struct _ebpf_operation_close_handle_request
{
    struct _ebpf_operation_header header;
    uint64_t handle;
} ebpf_operation_close_handle_request_t;

typedef struct _ebpf_operation_get_ec_function_request
{
    struct _ebpf_operation_header header;
    ebpf_ec_function_t function;
} ebpf_operation_get_ec_function_request_t;

typedef struct _ebpf_operation_get_ec_function_reply
{
    struct _ebpf_operation_header header;
    uint64_t address;
} ebpf_operation_get_ec_function_reply_t;

typedef struct _ebpf_operation_get_program_information_request
{
    struct _ebpf_operation_header header;
    ebpf_program_type_t program_type;
} ebpf_operation_get_program_information_request_t;

typedef struct _ebpf_operation_get_program_information_reply
{
    struct _ebpf_operation_header header;
    uint16_t version;
    uint16_t size;
    uint8_t data[1];
} ebpf_operation_get_program_information_reply_t;

typedef struct _ebpf_operation_get_map_information_request
{
    struct _ebpf_operation_header header;
    uint64_t handle;
} ebpf_operation_get_map_information_request_t;

typedef struct _ebpf_operation_get_map_information_reply
{
    struct _ebpf_operation_header header;
    uint16_t map_count;
    uint16_t size;
    uint8_t data[1];
} ebpf_operation_get_map_information_reply_t;
