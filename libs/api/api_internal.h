// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_api.h"
#include "ebpf_platform.h"
#include "ebpf_windows.h"
#include "spec_type_descriptors.hpp"

struct ebpf_object;

typedef struct ebpf_program
{
    ebpf_list_entry_t list_entry;
    struct ebpf_object* object;
    char* section_name;
    char* program_name;
    uint8_t* byte_code;
    uint32_t byte_code_size;
    ebpf_program_type_t program_type;
    ebpf_attach_type_t attach_type;
    ebpf_handle_t handle;
    fd_t fd;
} ebpf_program_t;

typedef struct ebpf_map
{
    ebpf_list_entry_t list_entry;
    struct ebpf_object* object;
    char* name;
    ebpf_handle_t map_handle;
    fd_t map_fd;
    ebpf_map_definition_t map_defintion;
    char* pin_path;
    bool pinned;
} ebpf_map_t;

typedef struct ebpf_object
{
    char* file_name = nullptr;
    ebpf_list_entry_t programs;
    uint32_t programs_count;
    ebpf_list_entry_t maps;
    uint32_t maps_count;
} ebpf_object_t;

uint32_t
ebpf_get_program_byte_code(
    const char* file_name,
    const char* section_name,
    bool mock_map_fd,
    ebpf_list_entry_t* programs,
    uint32_t* programs_count,
    EbpfMapDescriptor** map_descriptors,
    int* map_descriptors_count,
    const char** error_message);

uint32_t
get_program_information_data(ebpf_program_type_t program_type, ebpf_extension_data_t** program_information_data);

void
clean_up_ebpf_program(ebpf_program_t* program);

void
clean_up_ebpf_programs(ebpf_list_entry_t& programs);

void
clean_up_ebpf_maps(ebpf_list_entry_t& maps);
