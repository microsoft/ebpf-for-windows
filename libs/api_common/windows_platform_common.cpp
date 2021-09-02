// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <cassert>
#include <stdexcept>
#include "api_internal.h"
#include "api_common.hpp"
#include "crab_verifier_wrapper.hpp"
#include "ebpf_api.h"
#include "ebpf_nethooks.h"
#include "sample_ext_helpers.h"
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
    sizeof(xdp_md_t),
    EBPF_OFFSET_OF(xdp_md_t, data),
    EBPF_OFFSET_OF(xdp_md_t, data_end),
    EBPF_OFFSET_OF(xdp_md_t, data_meta)};

const EbpfProgramType windows_xdp_program_type =
    PTYPE("xdp", &g_xdp_context_descriptor, (uint64_t)&EBPF_PROGRAM_TYPE_XDP, {"xdp"});

const ebpf_context_descriptor_t g_bind_context_descriptor = {
    sizeof(bind_md_t), EBPF_OFFSET_OF(bind_md_t, app_id_start), EBPF_OFFSET_OF(bind_md_t, app_id_end), -1};

const EbpfProgramType windows_bind_program_type =
    PTYPE("bind", &g_bind_context_descriptor, (uint64_t)&EBPF_PROGRAM_TYPE_BIND, {"bind"});

const ebpf_context_descriptor_t g_sample_ext_context_descriptor = {
    sizeof(sample_program_context_t),
    EBPF_OFFSET_OF(sample_program_context_t, data_start),
    EBPF_OFFSET_OF(sample_program_context_t, data_end),
    -1, // Offset into ctx struct for pointer to metadata, or -1 if none.
};

const EbpfProgramType windows_sample_ext_program_type =
    PTYPE("sample_ext", &g_sample_ext_context_descriptor, (uint64_t)&EBPF_PROGRAM_TYPE_SAMPLE, {"sample_ext"});

const std::vector<EbpfProgramType> windows_program_types = {
    PTYPE("unspecified", {0}, 0, {}),
    windows_xdp_program_type,
    windows_bind_program_type,
    windows_sample_ext_program_type};

const std::map<ebpf_program_type_t*, ebpf_attach_type_t*> windows_program_type_to_attach_type = {
    {&EBPF_PROGRAM_TYPE_XDP, &EBPF_ATTACH_TYPE_XDP},
    {&EBPF_PROGRAM_TYPE_BIND, &EBPF_ATTACH_TYPE_BIND},
    {&EBPF_PROGRAM_TYPE_SAMPLE, &EBPF_ATTACH_TYPE_SAMPLE},
};

EbpfProgramType
get_program_type_windows(const GUID& program_type)
{
    // TODO: (Issue #67) Make an IOCTL call to fetch the program context
    //       info and then fill the EbpfProgramType struct.
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

#define BPF_MAP_TYPE(x) BPF_MAP_TYPE_##x, #x

static const EbpfMapType windows_map_types[] = {
    {BPF_MAP_TYPE(UNSPECIFIED)},
    {BPF_MAP_TYPE(HASH)},
    {BPF_MAP_TYPE(ARRAY), true},
    {BPF_MAP_TYPE(PROG_ARRAY), true, EbpfMapValueType::PROGRAM},
    {BPF_MAP_TYPE(PERCPU_HASH)},
    {BPF_MAP_TYPE(PERCPU_ARRAY), true},
    {BPF_MAP_TYPE(HASH_OF_MAPS), false, EbpfMapValueType::MAP},
    {BPF_MAP_TYPE(ARRAY_OF_MAPS), true, EbpfMapValueType::MAP},
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
get_map_descriptor_windows(int original_fd)
{
    // First check if we already have the map descriptor cached.
    EbpfMapDescriptor* map = find_map_descriptor(original_fd);
    if (map != nullptr) {
        return *map;
    }

    return get_map_descriptor(original_fd);
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
