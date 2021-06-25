// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_api.h"
#include "ebpf_platform.h"
#include "ebpf_windows.h"
#include "spec_type_descriptors.hpp"

struct _ebpf_object;

typedef struct _ebpf_program
{
    struct _ebpf_object* object;
    char* section_name;
    char* program_name;
    uint8_t* byte_code;
    uint32_t byte_code_size;
    ebpf_program_type_t program_type;
    ebpf_attach_type_t attach_type;
    ebpf_handle_t handle;
    fd_t fd;
} ebpf_program_t;

typedef struct _ebpf_map
{
    const struct _ebpf_object* object;
    char* name;
    ebpf_handle_t map_handle;
    fd_t map_fd;
    ebpf_map_definition_t map_defintion;
    char* pin_path;
    bool pinned;
} ebpf_map_t;

typedef struct _ebpf_object
{
    char* file_name = nullptr;
    std::vector<ebpf_program_t*> programs;
    std::vector<ebpf_map_t*> maps;
} ebpf_object_t;

_Return_type_success_(return == ERROR_SUCCESS) uint32_t ebpf_get_program_byte_code(
    _In_z_ const char* file_name,
    _In_z_ const char* section_name,
    bool mock_map_fd,
    std::vector<ebpf_program_t*>& programs,
    _Outptr_result_maybenull_ EbpfMapDescriptor** map_descriptors,
    _Out_ int* map_descriptors_count,
    _Outptr_result_maybenull_ const char** error_message);

uint32_t
get_program_information_data(ebpf_program_type_t program_type, ebpf_extension_data_t** program_information_data);

void
clean_up_ebpf_program(_In_ _Post_invalid_ ebpf_program_t* program);

void
clean_up_ebpf_programs(_Inout_ std::vector<ebpf_program_t*>& programs);

void
clean_up_ebpf_maps(_Inout_ std::vector<ebpf_map_t*>& maps);
