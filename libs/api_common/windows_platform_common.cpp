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

//
// XDP program type.
//
const ebpf_context_descriptor_t g_xdp_context_descriptor = {
    sizeof(xdp_md_t),
    EBPF_OFFSET_OF(xdp_md_t, data),
    EBPF_OFFSET_OF(xdp_md_t, data_end),
    EBPF_OFFSET_OF(xdp_md_t, data_meta)};

const EbpfProgramType windows_xdp_program_type =
    PTYPE("xdp", &g_xdp_context_descriptor, (uint64_t)&EBPF_PROGRAM_TYPE_XDP, {"xdp"});

//
// Bind program type.
//
const ebpf_context_descriptor_t g_bind_context_descriptor = {
    sizeof(bind_md_t), EBPF_OFFSET_OF(bind_md_t, app_id_start), EBPF_OFFSET_OF(bind_md_t, app_id_end), -1};

const EbpfProgramType windows_bind_program_type =
    PTYPE("bind", &g_bind_context_descriptor, (uint64_t)&EBPF_PROGRAM_TYPE_BIND, {"bind"});

//
// eBPF Sample extensions program type.
//
const ebpf_context_descriptor_t g_sample_ext_context_descriptor = {
    sizeof(sample_program_context_t),
    EBPF_OFFSET_OF(sample_program_context_t, data_start),
    EBPF_OFFSET_OF(sample_program_context_t, data_end),
    -1, // Offset into ctx struct for pointer to metadata, or -1 if none.
};

const EbpfProgramType windows_sample_ext_program_type =
    PTYPE("sample_ext", &g_sample_ext_context_descriptor, (uint64_t)&EBPF_PROGRAM_TYPE_SAMPLE, {"sample_ext"});

//
// CGROUP_SOCK_ADDR.
//
const ebpf_context_descriptor_t g_sock_addr_context_descriptor = {
    sizeof(bpf_sock_addr_t),
    -1, // Offset into ctx struct for pointer to data, or -1 if none.
    -1, // Offset into ctx struct for pointer to data, or -1 if none.
    -1, // Offset into ctx struct for pointer to metadata, or -1 if none.
};

const EbpfProgramType windows_sock_addr_program_type = {
    "sock_addr",
    &g_sock_addr_context_descriptor,
    (uint64_t)&EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR,
    {"cgroup/connect4", "cgroup/connect6", "cgroup/recv_accept4", "cgroup/recv_accept6"}};

//
// SOCK_OPS.
//
const ebpf_context_descriptor_t g_sock_ops_context_descriptor = {
    sizeof(bpf_sock_ops_t),
    -1, // Offset into ctx struct for pointer to data, or -1 if none.
    -1, // Offset into ctx struct for pointer to data, or -1 if none.
    -1, // Offset into ctx struct for pointer to metadata, or -1 if none.
};

const EbpfProgramType windows_sock_ops_program_type = {
    "sockops", &g_sock_ops_context_descriptor, (uint64_t)&EBPF_PROGRAM_TYPE_SOCK_OPS, {"sockops"}};

//
// Global lists and vectors of program and attach types.
//

const std::vector<EbpfProgramType> windows_program_types = {
    PTYPE("unspecified", {0}, 0, {}),
    windows_xdp_program_type,
    windows_bind_program_type,
    windows_sock_addr_program_type,
    windows_sock_ops_program_type,
    windows_sample_ext_program_type};

typedef struct _ebpf_section_definition
{
    _Field_z_ const char* section_prefix;
    ebpf_program_type_t* prog_type;
    ebpf_attach_type_t* attach_type;
} ebpf_section_definition_t;

const std::vector<ebpf_section_definition_t> windows_section_definitions = {
    // XDP.
    {"xdp", &EBPF_PROGRAM_TYPE_XDP, &EBPF_ATTACH_TYPE_XDP},
    // Bind.
    {"bind", &EBPF_PROGRAM_TYPE_BIND, &EBPF_ATTACH_TYPE_BIND},
    // socket connect v4.
    {"cgroup/connect4", &EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR, &EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT},
    // socket connect v6.
    {"cgroup/connect4", &EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR, &EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT},
    // socket recv/accept v4.
    {"cgroup/recv_accept4", &EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR, &EBPF_ATTACH_TYPE_CGROUP_INET4_RECV_ACCEPT},
    // socket recv/accept v6.
    {"cgroup/recv_accept6", &EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR, &EBPF_ATTACH_TYPE_CGROUP_INET6_RECV_ACCEPT},
    // sockops.
    {"sockops", &EBPF_PROGRAM_TYPE_SOCK_OPS, &EBPF_ATTACH_TYPE_CGROUP_SOCK_OPS},
    // Sample Extension.
    {"sample_ext", &EBPF_PROGRAM_TYPE_SAMPLE, &EBPF_ATTACH_TYPE_SAMPLE},
};

struct ebpf_attach_type_compare
{
    bool
    operator()(const ebpf_attach_type_t& lhs, const ebpf_attach_type_t& rhs) const
    {
        return (memcmp(&lhs, &rhs, sizeof(ebpf_attach_type_t)) < 0);
    }
};

const std::map<ebpf_attach_type_t, const char*, ebpf_attach_type_compare> windows_section_names = {
    {EBPF_ATTACH_TYPE_XDP, "xdp"},
    {EBPF_ATTACH_TYPE_BIND, "bind"},
    {EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT, "cgroup/connect4"},
    {EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT, "cgroup/connect6"},
    {EBPF_ATTACH_TYPE_CGROUP_INET4_RECV_ACCEPT, "cgroup/recv_accept4"},
    {EBPF_ATTACH_TYPE_CGROUP_INET6_RECV_ACCEPT, "cgroup/recv_accept6"},
    {EBPF_ATTACH_TYPE_CGROUP_SOCK_OPS, "sockops"},
    {EBPF_ATTACH_TYPE_SAMPLE, "sample_ext"}};

const EbpfProgramType&
get_program_type_windows(const GUID& program_type)
{
    // TODO: (Issue #67) Make an IOCTL call to fetch the program context
    //       info and then fill the EbpfProgramType struct.
    for (const EbpfProgramType& t : windows_program_types) {
        if (t.platform_specific_data != 0) {
            ebpf_program_type_t* program_type_uuid = (ebpf_program_type_t*)t.platform_specific_data;
            if (IsEqualGUID(*program_type_uuid, program_type)) {
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
    for (const EbpfProgramType& t : windows_program_types) {
        if (program_type != nullptr) {
            if (t.platform_specific_data != 0) {
                ebpf_program_type_t* program_type_uuid = (ebpf_program_type_t*)t.platform_specific_data;
                if (IsEqualGUID(*program_type_uuid, *program_type)) {
                    return t;
                }
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
    {BPF_MAP_TYPE(UNSPEC)},
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

    for (const ebpf_section_definition_t& t : windows_section_definitions) {
        if (section.find(t.section_prefix) == 0)
            return t.attach_type;
    }

    return &EBPF_ATTACH_TYPE_UNSPECIFIED;
}

_Ret_maybenull_z_ const char*
get_attach_type_name(_In_ const ebpf_attach_type_t* attach_type)
{
    // TODO: (Issue #223) Read the registry to fetch attach types.
    auto it = windows_section_names.find(*attach_type);
    if (it != windows_section_names.end())
        return it->second;

    return nullptr;
}
