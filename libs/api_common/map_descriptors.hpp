// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "platform.hpp"

EbpfMapDescriptor&
get_map_descriptor(int map_fd);

void
cache_map_original_file_descriptors(const EbpfMapDescriptor* map_descriptors, uint32_t map_descriptors_count);

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
    size_t section_offset);

void
clear_map_descriptors(void);

EbpfMapDescriptor&
get_map_descriptor_at_index(int index);

ebpf_handle_t
get_map_handle_at_index(size_t index);
