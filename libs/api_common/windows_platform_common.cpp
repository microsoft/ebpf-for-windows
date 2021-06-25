// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <cassert>
#include <stdexcept>
#include "api_internal.h"
#include "api_common.hpp"
#pragma warning(push)
#pragma warning(disable : 4100)  // 'identifier' : unreferenced formal parameter
#pragma warning(disable : 4244)  // 'conversion' conversion from 'type1' to
                                 // 'type2', possible loss of data
#pragma warning(disable : 26451) // Arithmetic overflow
#include "crab_verifier.hpp"
#pragma warning(pop)
#include "ebpf_api.h"
#include "ebpf_helpers.h"
#include "helpers.hpp"
#include "map_descriptors.hpp"
#include "platform.hpp"
#include "spec_type_descriptors.hpp"
#include "windows_platform.hpp"

#define PTYPE(name, descr, native_type, prefixes) \
    {                                             \
        name, descr, native_type, prefixes        \
    }

#define PTYPE_PRIVILEGED(name, descr, native_type, prefixes) \
    {                                                        \
        name, descr, native_type, prefixes, true             \
    }

// Allow for comma as a separator between multiple prefixes, to make
// the preprocessor treat a prefix list as one macro argument.
#define COMMA ,

const ebpf_context_descriptor_t g_xdp_context_descriptor = {
    24, // Size of ctx struct.
    0,  // Offset into ctx struct of pointer to data, or -1 if none.
    8,  // Offset into ctx struct of pointer to end of data, or -1 if none.
    16, // Offset into ctx struct of pointer to metadata, or -1 if none.
};

const EbpfProgramType windows_xdp_program_type =
    PTYPE("xdp", &g_xdp_context_descriptor, (uint64_t)&EBPF_PROGRAM_TYPE_XDP, {"xdp"});

const ebpf_context_descriptor_t g_bind_context_descriptor = {
    43, // Size of ctx struct.
    0,  // Offset into ctx struct of pointer to data, or -1 if none.
    8,  // Offset into ctx struct of pointer to end of data, or -1 if none.
    -1, // Offset into ctx struct of pointer to metadata, or -1 if none.
};

const EbpfProgramType windows_bind_program_type =
    PTYPE("bind", &g_bind_context_descriptor, (uint64_t)&EBPF_PROGRAM_TYPE_BIND, {"bind"});

const std::vector<EbpfProgramType> windows_program_types = {
    PTYPE("unspecified", {0}, 0, {}),
    windows_xdp_program_type,
    windows_bind_program_type,
};

const std::map<ebpf_program_type_t*, ebpf_attach_type_t*> windows_program_type_to_attach_type = {
    {&EBPF_PROGRAM_TYPE_XDP, &EBPF_ATTACH_TYPE_XDP},
    {&EBPF_PROGRAM_TYPE_BIND, &EBPF_ATTACH_TYPE_BIND},
};

EbpfProgramType
get_program_type_windows(const GUID& program_type)
{
    // TODO: (Issue #67) Make an IOCTL call to fetch the program context
    //       information and then fill the EbpfProgramType struct.
    for (const EbpfProgramType t : windows_program_types) {
        if (t.platform_specific_data != 0) {
            if (IsEqualGUID(*(GUID*)t.platform_specific_data, program_type)) {
                return t;
            }
        }
    }

    return windows_xdp_program_type;
}

EbpfProgramType
get_program_type_windows(const std::string& section, const std::string&)
{
    // Check if a global program type is set.
    const ebpf_program_type_t* program_type = get_global_program_type();

    // TODO: (Issue #223) Read the registry to fetch all the section
    //       prefixes and corresponding program and attach types.
    for (const EbpfProgramType t : windows_program_types) {
        if (program_type != nullptr) {
            if (t.platform_specific_data != 0 && IsEqualGUID(*(GUID*)t.platform_specific_data, *program_type)) {
                return t;
            }
        } else {
            for (const std::string prefix : t.section_prefixes) {
                if (section.find(prefix) == 0)
                    return t;
            }
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

EbpfMapType
get_map_type_windows(uint32_t platform_specific_type)
{
    uint32_t index = platform_specific_type;
    if ((index == 0) || (index >= sizeof(windows_map_types) / sizeof(windows_map_types[0]))) {
        return windows_map_types[0];
    }
    EbpfMapType type = windows_map_types[index];
    assert(type.platform_specific_type == platform_specific_type);
    return type;
}

EbpfMapDescriptor&
get_map_descriptor_windows(int map_fd)
{
    // First check if we already have the map descriptor cached.
    EbpfMapDescriptor* map = find_map_descriptor(map_fd);
    if (map != nullptr) {
        return *map;
    }

    return get_map_descriptor(map_fd);
}

const ebpf_attach_type_t*
get_attach_type_windows(const std::string& section)
{
    // TODO: (Issue #223) Read the registry to fetch all the section
    //       prefixes and corresponding program and attach types.
    for (const EbpfProgramType t : windows_program_types) {
        for (const std::string prefix : t.section_prefixes) {
            if (section.find(prefix) == 0) {
                for (auto& [program_type, attach_type] : windows_program_type_to_attach_type) {
                    if (IsEqualGUID(*(GUID*)t.platform_specific_data, *program_type)) {
                        return attach_type;
                    }
                }
            }
        }
    }

    return &EBPF_ATTACH_TYPE_UNSPECIFIED;
}