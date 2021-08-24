// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <vector>
#include "api_common.hpp"

thread_local static std::vector<map_cache_t> _map_file_descriptors;

void
cache_map_file_descriptors(const EbpfMapDescriptor* map_descriptors, uint32_t map_descriptors_count)
{
    for (uint32_t i = 0; i < map_descriptors_count; i++) {
        auto descriptor = map_descriptors[i];
        _map_file_descriptors.emplace_back((uintptr_t)descriptor.original_fd, 0, descriptor);
    }
}

void
clear_map_descriptors(void)
{
    _map_file_descriptors.resize(0);
}

static map_cache_t&
get_map_cache_entry(uint64_t map_fd)
{
    size_t size = _map_file_descriptors.size();
    for (size_t i = 0; i < size; i++) {
        if (_map_file_descriptors[i].ebpf_map_descriptor.original_fd == map_fd) {
            return _map_file_descriptors[i];
        }
    }

    throw std::runtime_error(std::string("Map cache entry for map fd ") + std::to_string(map_fd) + " not found.");
}

EbpfMapDescriptor&
get_map_descriptor(int map_fd)
{
    return get_map_cache_entry(map_fd).ebpf_map_descriptor;
}

EbpfMapDescriptor&
get_map_descriptor_at_index(int index)
{
    return _map_file_descriptors[index].ebpf_map_descriptor;
}

uintptr_t
get_map_handle(int map_fd)
{
    return get_map_cache_entry(map_fd).handle;
}

uintptr_t
get_map_handle_at_index(size_t index)
{
    return _map_file_descriptors[index].handle;
}

std::vector<uintptr_t>
get_all_map_handles()
{
    std::vector<uintptr_t> handles;
    size_t size = _map_file_descriptors.size();
    for (size_t i = 0; i < size; i++) {
        handles.push_back(_map_file_descriptors[i].handle);
    }

    return handles;
}

std::vector<map_cache_t>
get_all_map_descriptors()
{
    return _map_file_descriptors;
}

void
cache_map_file_descriptor(
    uint32_t type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, uint32_t inner_map_fd, int fd)
{
    _map_file_descriptors.emplace_back((uintptr_t)fd, fd, type, key_size, value_size, max_entries, inner_map_fd, 0);
}

void
cache_map_file_descriptor_with_handle(
    uint32_t type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    uint32_t inner_map_fd,
    int fd,
    uintptr_t handle,
    size_t section_offset)
{
    _map_file_descriptors.emplace_back(
        handle, fd, type, key_size, value_size, max_entries, inner_map_fd, section_offset);
}

int
cache_map_handle(
    uint64_t handle,
    uint32_t type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    uint32_t inner_map_fd,
    size_t section_offset)
{
    int fd = static_cast<int>(_map_file_descriptors.size() + 1);
    _map_file_descriptors.emplace_back(
        handle, fd, type, key_size, value_size, max_entries, inner_map_fd, section_offset);
    return static_cast<int>(_map_file_descriptors.size());
}

size_t
get_map_descriptor_size()
{
    return _map_file_descriptors.size();
}
