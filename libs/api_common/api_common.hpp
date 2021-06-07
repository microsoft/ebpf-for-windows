// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <map>
#include <stdexcept>

#include "ebpf_api.h"
#include "ebpf_execution_context.h"
#include "ebpf_platform.h"
#include "ebpf_result.h"
#undef VOID
#include "platform.hpp"

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
allocate_error_string(const std::string& str, uint32_t* length = nullptr) noexcept;

std::vector<uint8_t>
convert_ebpf_program_to_bytes(const std::vector<ebpf_inst>& instructions);

int
get_file_size(const char* filename, size_t* byte_code_size) noexcept;

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

__forceinline ebpf_result_t
windows_error_to_ebpf_result(uint32_t error)
{
    ebpf_result_t result;

    switch (error) {
    case ERROR_SUCCESS:
        result = EBPF_SUCCESS;
        break;

    case ERROR_OUTOFMEMORY:
    case ERROR_NOT_ENOUGH_MEMORY:
        result = EBPF_NO_MEMORY;
        break;

    case ERROR_NOT_FOUND:
        result = EBPF_ERROR_NOT_FOUND;
        break;

    case ERROR_INVALID_PARAMETER:
        result = EBPF_INVALID_ARGUMENT;
        break;

    case ERROR_NO_MORE_ITEMS:
        result = EBPF_ERROR_NO_MORE_KEYS;
        break;

    case ERROR_INVALID_HANDLE:
        result = EBPF_ERROR_INVALID_HANDLE;
        break;

    case ERROR_NOT_SUPPORTED:
        result = EBPF_ERROR_NOT_SUPPORTED;
        break;

    case ERROR_MORE_DATA:
        result = EBPF_ERROR_INSUFFICIENT_BUFFER;
        break;

    case ERROR_FILE_NOT_FOUND:
        result = EBPF_FILE_NOT_FOUND;
        break;

    case ERROR_ALREADY_INITIALIZED:
        result = EBPF_ALREADY_INITIALIZED;
        break;

    default:
        result = EBPF_FAILED;
        break;
    }

    return result;
}

ebpf_result_t
query_map_definition(
    ebpf_handle_t handle,
    uint32_t* size,
    uint32_t* type,
    uint32_t* key_size,
    uint32_t* value_size,
    uint32_t* max_entries) noexcept;