// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <cassert>
#include <stdexcept>
#pragma warning(push)
#pragma warning(disable:4100) // 'identifier' : unreferenced formal parameter
#pragma warning(disable:4244) // 'conversion' conversion from 'type1' to 'type2', possible loss of data
#include "crab_verifier.hpp"
#pragma warning(pop)
#include "ebpf_windows.h"
#include "spec_type_descriptors.hpp"
#include "helpers.hpp"
#include "platform.hpp"
#include "windows_platform.hpp"

#define PTYPE(name, descr, native_type, prefixes) \
               {name, descr, native_type, prefixes}

#define PTYPE_PRIVILEGED(name, descr, native_type, prefixes) \
                       {name, descr, native_type, prefixes, true}

// Allow for comma as a separator between multiple prefixes, to make
// the preprocessor treat a prefix list as one macro argument.
#define COMMA ,

constexpr EbpfContextDescriptor xdp_context_descriptor = {
    24, // Size of ctx struct.
    0, // Offset into ctx struct of pointer to data, or -1 if none.
    8, // Offset into ctx struct of pointer to end of data, or -1 if none.
    16, // Offset into ctx struct of pointer to metadata, or -1 if none.
};

const EbpfProgramType windows_xdp_program_type =
    PTYPE("xdp", xdp_context_descriptor, EBPF_PROGRAM_TYPE_XDP, {"xdp"});

const std::vector<EbpfProgramType> windows_program_types = {
    PTYPE("unspecified", {0}, EBPF_PROGRAM_TYPE_UNSPECIFIED, {}),
    windows_xdp_program_type,
};

static EbpfProgramType get_program_type_windows(const std::string& section, const std::string&)
{
    EbpfProgramType type{};

    for (const EbpfProgramType t : windows_program_types) {
        for (const std::string prefix : t.section_prefixes) {
            if (section.find(prefix) == 0)
                return t;
        }
    }

    return windows_xdp_program_type;
}

#define EBPF_MAP_TYPE(x) EBPF_MAP_TYPE_##x, #x

static const EbpfMapType windows_map_types[] = {
    {EBPF_MAP_TYPE(UNSPECIFIED)},
    {EBPF_MAP_TYPE(HASH)},
    {EBPF_MAP_TYPE(ARRAY), true},
};

EbpfMapType get_map_type_windows(uint32_t platform_specific_type)
{
    uint32_t index = platform_specific_type;
    if ((index == 0) || (index >= sizeof(windows_map_types) / sizeof(windows_map_types[0]))) {
        return windows_map_types[0];
    }
    EbpfMapType type = windows_map_types[index];
    assert(type.platform_specific_type == platform_specific_type);
    return type;
}

struct ebpf_maps_section_record_windows {
    uint32_t size;
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
};

int create_map_function(uint32_t type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, ebpf_verifier_options_t options);

static int create_map_windows(uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, ebpf_verifier_options_t options)
{
    if (options.mock_map_fds) {
        EbpfMapType type = get_map_type_windows(map_type);
        return create_map_crab(type, key_size, value_size, max_entries, options);
    }

    return create_map_function(map_type, key_size, value_size, max_entries, options);
}

void parse_maps_section_windows(std::vector<EbpfMapDescriptor>& map_descriptors, const char* data, size_t size, const struct ebpf_platform_t*, ebpf_verifier_options_t options)
{
    if (size % sizeof(ebpf_maps_section_record_windows) != 0) {
        throw std::runtime_error(std::string("bad maps section size, must be a multiple of ") +
                                 std::to_string(sizeof(ebpf_maps_section_record_windows)));
    }

    auto mapdefs = std::vector<ebpf_maps_section_record_windows>((ebpf_maps_section_record_windows*)data,
                                                                 (ebpf_maps_section_record_windows*)(data + size));
    for (auto s : mapdefs) {
        map_descriptors.emplace_back(EbpfMapDescriptor{
            .original_fd = create_map_windows(s.type, s.key_size, s.value_size, s.max_entries, options),
            .type = s.type,
            .key_size = s.key_size,
            .value_size = s.value_size,
        });
    }
}

EbpfMapDescriptor& get_map_descriptor_internal(int map_fd);

EbpfMapDescriptor& get_map_descriptor_windows(int map_fd)
{
    // First check if we already have the map descriptor cached.
    EbpfMapDescriptor* map = find_map_descriptor(map_fd);
    if (map != nullptr) {
        return *map;
    }

    return get_map_descriptor_internal(map_fd);
}

const ebpf_platform_t g_ebpf_platform_windows = {
    get_program_type_windows,
    get_helper_prototype_windows,
    is_helper_usable_windows,
    sizeof(ebpf_maps_section_record_windows),
    parse_maps_section_windows,
    get_map_descriptor_windows,
};
