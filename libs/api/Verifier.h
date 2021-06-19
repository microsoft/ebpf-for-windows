// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "config.hpp"
#include "ebpf_program_types.h"
#include "ebpf_result.h"
#include "platform.hpp"
typedef int (*map_create_fp)(
    uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, ebpf_verifier_options_t options);

ebpf_result_t
load_byte_code(
    const char* file_name,
    const char* section_name,
    ebpf_verifier_options_t* verifier_options,
    ebpf_list_entry_t* programs,
    uint32_t* programs_count,
    const char** error_message) noexcept;

ebpf_result_t
get_program_type_info(const ebpf_program_information_t** info);
