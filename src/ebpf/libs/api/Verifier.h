/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#pragma once

#include "config.hpp"
#undef VOID
#include "platform.hpp"
#define VOID void
typedef int (*map_create_fp)(
    uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, ebpf_verifier_options_t options);
int
get_file_size(const char* filename, size_t* byte_code_size);

int
load_byte_code(
    const char* filename,
    const char* sectionname,
    uint8_t* byte_code,
    size_t* byte_code_size,
    ebpf_program_type_t* program_type);

int
verify_byte_code(
    const char* path,
    const char* section_name,
    const uint8_t* byte_code,
    size_t byte_code_size,
    const char** error_message);
