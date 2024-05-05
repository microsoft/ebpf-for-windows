// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * This file implements a cache of map descriptors as used by the
 * verifier.  It operates on original file descriptors (which
 * might be mock file descriptors) that appear in the eBPF byte
 * code before relocation, not map IDs as stored in the kernel.
 */

#include "api_common.hpp"

#include <vector>

thread_local static std::vector<map_cache_t> _map_file_descriptors;

void
cache_map_original_file_descriptors(const EbpfMapDescriptor* map_descriptors, uint32_t map_descriptors_count)
{
    for (uint32_t i = 0; i < map_descriptors_count; i++) {
        auto descriptor = map_descriptors[i];

        // Temporarily store the original_fd as a mock handle.
        ebpf_handle_t handle = (ebpf_handle_t)(uintptr_t)descriptor.original_fd;

        _map_file_descriptors.emplace_back(handle, 0, descriptor, LIBBPF_PIN_NONE);
    }
}

void
clear_map_descriptors(void)
{
    _map_file_descriptors.resize(0);
}

static map_cache_t&
get_map_cache_entry(uint64_t original_fd)
{
    size_t size = _map_file_descriptors.size();
    for (size_t i = 0; i < size; i++) {
        if (_map_file_descriptors[i].verifier_map_descriptor.original_fd == original_fd) {
            return _map_file_descriptors[i];
        }
    }

    throw std::runtime_error(
        std::string("Map cache entry for original map fd ") + std::to_string(original_fd) + " not found.");
}

EbpfMapDescriptor&
get_map_descriptor(int original_fd)
{
    return get_map_cache_entry(original_fd).verifier_map_descriptor;
}

EbpfMapDescriptor&
get_map_descriptor_at_index(int index)
{
    return _map_file_descriptors[index].verifier_map_descriptor;
}

ebpf_handle_t
get_map_handle(int map_fd)
{
    return get_map_cache_entry(map_fd).handle;
}

ebpf_handle_t
get_map_handle_at_index(size_t index)
{
    return _map_file_descriptors[index].handle;
}

std::vector<ebpf_handle_t>
get_all_map_handles()
{
    std::vector<ebpf_handle_t> handles;
    size_t size = _map_file_descriptors.size();
    for (size_t i = 0; i < size; i++) {
        handles.push_back(_map_file_descriptors[i].handle);
    }

    return handles;
}

std::vector<map_cache_t>&
get_all_map_descriptors()
{
    return _map_file_descriptors;
}

void
cache_map_original_file_descriptor_with_handle(
    int original_fd,
    uint32_t id,
    uint32_t type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    uint32_t inner_map_original_fd,
    uint32_t inner_id,
    ebpf_handle_t handle,
    size_t section_offset)
{
    _map_file_descriptors.emplace_back(map_cache_t(
        handle,
        id,
        original_fd,
        type,
        key_size,
        value_size,
        max_entries,
        inner_map_original_fd,
        inner_id,
        section_offset,
        LIBBPF_PIN_NONE));
}

void
cache_map_handle(
    ebpf_handle_t handle,
    uint32_t original_fd,
    uint32_t id,
    uint32_t type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    uint32_t inner_map_original_fd,
    uint32_t inner_id,
    size_t section_offset,
    ebpf_pin_type_t pinning)
{
    _map_file_descriptors.emplace_back(
        handle,
        (id ? id : EBPF_ID_NONE),
        (int)original_fd,
        type,
        key_size,
        value_size,
        max_entries,
        inner_map_original_fd,
        (inner_id ? inner_id : EBPF_ID_NONE),
        section_offset,
        pinning);
}

size_t
get_map_descriptor_size()
{
    return _map_file_descriptors.size();
}
