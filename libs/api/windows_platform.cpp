// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "api_common.hpp"
#include "api_internal.h"
#include "crab_verifier_wrapper.hpp"
#include "ebpf_api.h"
#include "helpers.hpp"
#include "map_descriptors.hpp"
#include "platform.hpp"
#include "spec_type_descriptors.hpp"
#include "windows_platform.hpp"
#include "windows_platform_common.hpp"

#include <cassert>
#include <stdexcept>

static bool
_is_map_of_maps(ebpf_map_type_t type)
{
    return (type == BPF_MAP_TYPE_ARRAY_OF_MAPS || type == BPF_MAP_TYPE_HASH_OF_MAPS);
}

// Parse a legacy (non-BTF) maps section.
static void
_parse_maps_section_windows(
    std::vector<EbpfMapDescriptor>& verifier_map_descriptors,
    const char* data,
    size_t map_record_size,
    int map_count,
    const struct ebpf_platform_t*,
    ebpf_verifier_options_t)
{
    UNREFERENCED_PARAMETER(verifier_map_descriptors);

    // Add map definitions into the map cache.
    uint32_t previous_map_count = (uint32_t)get_map_descriptor_size();
    for (int i = 0; i < map_count; i++) {
        size_t section_offset = (i * map_record_size);
        uint32_t idx = previous_map_count + i;

        // Copy the data from the record into an ebpf_map_definition_in_file_t structure,
        // zero-padding any extra, and being careful not to overflow the buffer.
        ebpf_map_definition_in_file_t s{};
        memcpy(&s, data + section_offset, std::min(sizeof(s), map_record_size));

        fd_t inner_map_original_fd =
            _is_map_of_maps(s.type) ? map_idx_to_original_fd(s.inner_map_idx) : ebpf_fd_invalid;

        cache_map_handle(
            ebpf_handle_invalid,
            map_idx_to_original_fd(idx),
            s.id,
            s.type,
            s.key_size,
            s.value_size,
            s.max_entries,
            inner_map_original_fd,
            s.inner_id,
            section_offset,
            s.pinning);
    }
}

static void
_resolve_inner_map_references_windows(std::vector<EbpfMapDescriptor>& verifier_map_descriptors)
{
    auto& map_descriptors = get_all_map_descriptors();
    for (auto& map_descriptor : map_descriptors) {
        // Resolve the inner map original fd.
        unsigned int inner_map_original_fd = UINT_MAX;
        if (_is_map_of_maps((ebpf_map_type_t)map_descriptor.verifier_map_descriptor.type)) {
            uint32_t inner_map_idx = original_fd_to_map_idx(map_descriptor.verifier_map_descriptor.inner_map_fd);
            if (map_descriptor.inner_id != EBPF_ID_NONE) {
                for (auto& map_descriptor2 : map_descriptors) {
                    if (map_descriptor2.id == map_descriptor.inner_id) {
                        inner_map_original_fd = map_descriptor2.verifier_map_descriptor.original_fd;
                        break;
                    }
                }
            } else if ((inner_map_idx >= 0) && (inner_map_idx < map_descriptors.size())) {
                inner_map_original_fd = map_descriptors.at(inner_map_idx).verifier_map_descriptor.original_fd;
            }
            if (inner_map_original_fd == UINT_MAX) {
                throw std::runtime_error(
                    std::string("bad inner map (index ") + std::to_string(inner_map_idx) + std::string(" id ") +
                    std::to_string(map_descriptor.inner_id) + ") for map " +
                    std::to_string(map_descriptor.verifier_map_descriptor.original_fd));
            }
        }

        map_descriptor.verifier_map_descriptor.inner_map_fd = inner_map_original_fd;

        verifier_map_descriptors.push_back(map_descriptor.verifier_map_descriptor);
    }
}

const ebpf_platform_t g_ebpf_platform_windows = {
    get_program_type_windows,
    get_helper_prototype_windows,
    is_helper_usable_windows,
    sizeof(ebpf_map_definition_in_file_t),
    _parse_maps_section_windows,
    get_map_descriptor_windows,
    get_map_type_windows,
    _resolve_inner_map_references_windows,
    bpf_conformance_groups_t::default_groups};
