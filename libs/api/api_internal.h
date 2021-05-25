/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once

#include "ebpf_windows.h"
#include "spec_type_descriptors.hpp"

uint32_t
ebpf_get_program_byte_code(
    const char* file_name,
    const char* section_name,
    ebpf_program_type_t* program_type,
    bool mock_map_fd,
    uint8_t** instructions,
    uint32_t* instructions_size,
    EbpfMapDescriptor** map_descriptors,
    int* map_descriptors_count,
    const char** error_message);
