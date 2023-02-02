// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "api_internal.h"
#include "crab_verifier_wrapper.hpp"
#include "api_common.hpp"
#include "ebpf_api.h"
#include "helpers.hpp"
#include "map_descriptors.hpp"
#include "platform.hpp"
#include "spec_type_descriptors.hpp"
#include "windows_platform.hpp"
#include "windows_platform_common.hpp"

#include <cassert>
#include <stdexcept>

void
parse_maps_section_windows(
    std::vector<EbpfMapDescriptor>& verifier_map_descriptors,
    const char* data,
    size_t size,
    int map_count,
    const struct ebpf_platform_t*,
    ebpf_verifier_options_t)
{
    if (size % sizeof(ebpf_map_definition_in_file_t) != 0) {
        throw std::runtime_error(
            std::string("bad maps section size, must be a multiple of ") +
            std::to_string(sizeof(ebpf_map_definition_in_file_t)));
    }

    // The map file descriptors that appear in eBPF bytecode start at 1,
    // in the order the maps appear in the maps section.
    const int ORIGINAL_FD_OFFSET = 1;

    auto mapdefs = std::vector<ebpf_map_definition_in_file_t>(
        (ebpf_map_definition_in_file_t*)data, (ebpf_map_definition_in_file_t*)(data + size * map_count));
    for (int i = 0; i < mapdefs.size(); i++) {
        auto& s = mapdefs[i];
        uint32_t section_offset = (i * sizeof(ebpf_map_definition_in_file_t));

        int original_fd = i + ORIGINAL_FD_OFFSET;
        unsigned int inner_map_original_fd = UINT_MAX;
        if (s.type == BPF_MAP_TYPE_ARRAY_OF_MAPS || s.type == BPF_MAP_TYPE_HASH_OF_MAPS) {
            if (s.inner_map_idx != 0) {
                inner_map_original_fd = (unsigned int)s.inner_map_idx + ORIGINAL_FD_OFFSET;
            } else if (s.inner_id != 0) {
                for (int j = 0; j < mapdefs.size(); j++) {
                    auto& inner_s = mapdefs[j];
                    if (inner_s.id == s.inner_id && i != j) {
                        inner_map_original_fd = j + ORIGINAL_FD_OFFSET;
                        break;
                    }
                }
            }
        }

        cache_map_handle(
            ebpf_handle_invalid,
            original_fd,
            s.type,
            s.key_size,
            s.value_size,
            s.max_entries,
            inner_map_original_fd,
            section_offset,
            s.pinning);

        verifier_map_descriptors.emplace_back(EbpfMapDescriptor{
            .original_fd = original_fd,
            .type = (uint32_t)s.type,
            .key_size = s.key_size,
            .value_size = s.value_size,
            .inner_map_fd = inner_map_original_fd});
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
};
