// Copyright (c) Microsoft Corporation
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

// Parse a legacy (non-BTF) maps section.
static void
parse_maps_section_windows(
    std::vector<EbpfMapDescriptor>& verifier_map_descriptors,
    const char* data,
    size_t size,
    int map_count,
    const struct ebpf_platform_t*,
    ebpf_verifier_options_t)
{
    UNREFERENCED_PARAMETER(verifier_map_descriptors);

    if (size % sizeof(ebpf_map_definition_in_file_t) != 0) {
        throw std::runtime_error(
            std::string("bad maps section size, must be a multiple of ") +
            std::to_string(sizeof(ebpf_map_definition_in_file_t)));
    }

    // Get map definitions from section into a local list.
    auto mapdefs = std::vector<ebpf_map_definition_in_file_t>(
        (ebpf_map_definition_in_file_t*)data, (ebpf_map_definition_in_file_t*)(data + size * map_count));

    // Add map definitions into the map cache.
    for (int i = 0; i < mapdefs.size(); i++) {
        auto& s = mapdefs[i];
        uint32_t section_offset = (i * sizeof(ebpf_map_definition_in_file_t));
        fd_t inner_map_original_fd = map_idx_to_verifier_fd(s.inner_map_idx);

        cache_map_handle(
            ebpf_handle_invalid,
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
resolve_inner_map_references_windows(std::vector<EbpfMapDescriptor>& verifier_map_descriptors)
{
    auto map_descriptors = get_all_map_descriptors();
    for (auto& map_descriptor : map_descriptors) {
        // Resolve the inner map original fd.
        unsigned int inner_map_original_fd = UINT_MAX;
        if (map_descriptor.verifier_map_descriptor.type == BPF_MAP_TYPE_ARRAY_OF_MAPS ||
            map_descriptor.verifier_map_descriptor.type == BPF_MAP_TYPE_HASH_OF_MAPS) {
            uint32_t inner_map_idx = verifier_fd_to_map_idx(map_descriptor.verifier_map_descriptor.inner_map_fd);
            if ((inner_map_idx >= 0) && (inner_map_idx < map_descriptors.size())) {
                inner_map_original_fd = map_descriptors.at(inner_map_idx).verifier_map_descriptor.original_fd;
            } else if (map_descriptor.inner_id != 0) {
                for (auto& map_descriptor2 : map_descriptors) {
                    if (map_descriptor2.id == map_descriptor.inner_id) {
                        inner_map_original_fd = map_descriptor2.verifier_map_descriptor.original_fd;
                        break;
                    }
                }
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
    parse_maps_section_windows,
    get_map_descriptor_windows,
    get_map_type_windows,
    resolve_inner_map_references_windows};
