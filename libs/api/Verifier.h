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
load_byte_code(
    const char* filename,
    const char* sectionname,
    ebpf_verifier_options_t* verifier_options,
    uint8_t* byte_code,
    size_t* byte_code_size,
    ebpf_program_type_t* program_type,
    const char** error_message);
