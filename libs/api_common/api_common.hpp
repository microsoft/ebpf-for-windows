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

    _map_cache() {}

    _map_cache(uintptr_t handle, EbpfMapDescriptor descriptor) : handle(handle), ebpf_map_descriptor(descriptor) {}

    _map_cache(
        uintptr_t handle,
        int original_fd,
        uint32_t type,
        unsigned int key_size,
        unsigned int value_size,
        unsigned int max_entries,
        unsigned int inner_map_fd)
        : handle(handle)
    {
        ebpf_map_descriptor.original_fd = original_fd;
        ebpf_map_descriptor.type = type;
        ebpf_map_descriptor.key_size = key_size;
        ebpf_map_descriptor.value_size = value_size;
        ebpf_map_descriptor.max_entries = max_entries;
        ebpf_map_descriptor.inner_map_fd = inner_map_fd;
    }
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
cache_map_handle(uint64_t handle, uint32_t type, uint32_t key_size, uint32_t value_size, uint32_t max_entries);

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