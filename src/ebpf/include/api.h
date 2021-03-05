/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

#pragma once
#include "ebpf_windows.h"

#ifdef __cplusplus
extern "C" {
#endif

    typedef void* ebpf_handle_t;

    uint32_t ebpf_api_initiate();

    void ebpf_api_terminate();

    uint32_t ebpf_api_load_program(const char* file, const char* section_name, ebpf_handle_t* handle, const char** error_message);
    void ebpf_api_free_error_message(const char* error_message);
    void ebpf_api_unload_program(ebpf_handle_t handle);

    uint32_t ebpf_api_attach_program(ebpf_handle_t handle, ebpf_program_type_t hook_point);
    uint32_t ebpf_api_detach_program(ebpf_handle_t handle, ebpf_program_type_t hook_point);

    uint32_t ebpf_api_map_lookup_element(ebpf_handle_t handle, uint32_t key_size, const uint8_t* key, uint32_t value_size, uint8_t* value);
    uint32_t ebpf_api_map_update_element(ebpf_handle_t handle, uint32_t key_size, const uint8_t* key, uint32_t value_size, const uint8_t* value);
    uint32_t ebpf_api_map_delete_element(ebpf_handle_t handle, uint32_t key_size, const uint8_t* key);

    uint32_t ebpf_api_map_enumerate(ebpf_handle_t previous_handle, ebpf_handle_t* next_handle);
    uint32_t ebpf_api_map_query_definition(ebpf_handle_t handle, uint32_t* size, uint32_t* type, uint32_t* key_size, uint32_t* value_size, uint32_t* max_entries);

    void ebpf_api_delete_map(ebpf_handle_t handle);

    uint32_t ebpf_api_elf_enumerate_sections(const char* file, const char* section, bool verbose, const struct _tlv_type_length_value** data, const char** error_message);
    uint32_t ebpf_api_elf_disassemble_section(const char* file, const char* section, const char** dissassembly, const char** error_message);
    uint32_t ebpf_api_elf_verify_section(const char* file, const char* section, const char** report, const char** error_message);
    void ebpf_api_elf_free(const struct _tlv_type_length_value* data);

#ifdef __cplusplus
}
#endif
