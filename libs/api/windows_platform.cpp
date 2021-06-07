// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <cassert>
#include <stdexcept>
#include "api_internal.h"
#pragma warning(push)
#pragma warning(disable : 4100) // 'identifier' : unreferenced formal parameter
#pragma warning(disable : 4244) // 'conversion' conversion from 'type1' to
                                // 'type2', possible loss of data
#include "crab_verifier.hpp"
#pragma warning(pop)
#include "api_common.hpp"
#include "ebpf_api.h"
#undef VOID
#include "ebpf_helpers.h"
#include "helpers.hpp"
#include "map_descriptors.hpp"
#include "platform.hpp"
#include "spec_type_descriptors.hpp"
#include "windows_platform.hpp"
#include "windows_platform_common.hpp"

int
create_map_function(
    uint32_t type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, ebpf_verifier_options_t options);

static int
create_map_windows(
    uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, ebpf_verifier_options_t options)
{
    int fd;
    if (options.mock_map_fds) {
        EbpfMapType type = get_map_type_windows(map_type);
        fd = create_map_crab(type, key_size, value_size, max_entries, options);
        cache_map_file_descriptor(map_type, key_size, value_size, max_entries, fd);
        return fd;
    }

    return create_map_function(map_type, key_size, value_size, max_entries, options);
}

void
parse_maps_section_windows(
    std::vector<EbpfMapDescriptor>& map_descriptors,
    const char* data,
    size_t size,
    const struct ebpf_platform_t*,
    ebpf_verifier_options_t options)
{
    if (size % sizeof(ebpf_map_definition_t) != 0) {
        throw std::runtime_error(
            std::string("bad maps section size, must be a multiple of ") +
            std::to_string(sizeof(ebpf_map_definition_t)));
    }

    auto mapdefs =
        std::vector<ebpf_map_definition_t>((ebpf_map_definition_t*)data, (ebpf_map_definition_t*)(data + size));
    for (auto s : mapdefs) {
        map_descriptors.emplace_back(EbpfMapDescriptor{
            .original_fd = create_map_windows(s.type, s.key_size, s.value_size, s.max_entries, options),
            .type = s.type,
            .key_size = s.key_size,
            .value_size = s.value_size,
        });
    }
}

const ebpf_platform_t g_ebpf_platform_windows = {
    get_program_type_windows,
    get_helper_prototype_windows,
    is_helper_usable_windows,
    sizeof(ebpf_map_definition_t),
    parse_maps_section_windows,
    get_map_descriptor_windows,
    get_map_type_windows,
};
