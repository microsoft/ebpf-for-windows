// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "crab_verifier_wrapper.hpp"
#include "ebpf_nethooks.h"
#include "sample_ext_helpers.h"

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