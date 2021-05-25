/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once

#include <map>
#include <stdexcept>
#include "ebpf_api.h"
#include "ebpf_execution_context.h"
#undef VOID
#include "ebpf_helpers.h"
#include "platform.hpp"
extern "C"
{
#include "ubpf.h"
}

typedef struct _map_cache
{
    uintptr_t handle;
    EbpfMapDescriptor ebpf_map_descriptor;
} map_cache_t;

typedef struct _ebpf_maps_section_record_windows
{
    uint32_t size;
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
} ebpf_maps_section_record_windows;

const char*
allocate_error_string(const std::string& str, uint32_t* length = nullptr);

std::vector<uint8_t>
convert_ebpf_program_to_bytes(const std::vector<ebpf_inst>& instructions);

int
get_file_size(const char* filename, size_t* byte_code_size);

EbpfHelperPrototype
get_helper_prototype_windows(unsigned int n);

int
cache_map_handle(uint64_t handle, uint32_t type, uint32_t key_size, uint32_t value_size);

size_t
get_map_descriptor_size();

uintptr_t
get_map_handle(int map_fd);

std::vector<uintptr_t>
get_all_map_handles(void);
