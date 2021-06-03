// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <map>
#include <stdexcept>
#include "ebpf_api.h"
#include "ebpf_execution_context.h"
#undef VOID
#include "ebpf_helpers.h"
#include "ebpf_result.h"
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
get_map_descriptor_size(void);

uintptr_t
get_map_handle(int map_fd);

std::vector<uintptr_t>
get_all_map_handles(void);

std::vector<map_cache_t>
get_all_map_descriptors();

ebpf_result_t
windows_error_to_ebpf_result(uint32_t error);

uint32_t
query_map_definition(
    ebpf_handle_t handle,
    uint32_t* size,
    uint32_t* type,
    uint32_t* key_size,
    uint32_t* value_size,
    uint32_t* max_entries);