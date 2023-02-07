// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "crab_verifier_wrapper.hpp"
#include "ebpf_nethooks.h"
#include "ebpf_program_types.h"
#include "net_ebpf_ext_program_info.h"
#include "sample_ext_helpers.h"
#include "sample_ext_program_info.h"

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

const EbpfProgramType windows_unspecified_program_type =
    PTYPE("unspec", {0}, (uint64_t)&EBPF_PROGRAM_TYPE_UNSPECIFIED, {});

typedef struct _ebpf_section_definition
{
    _Field_z_ const char* section_prefix;
    ebpf_program_type_t* program_type;
    ebpf_attach_type_t* attach_type;
    bpf_prog_type_t bpf_prog_type;
    bpf_attach_type_t bpf_attach_type;
} ebpf_section_definition_t;

struct ebpf_attach_type_compare
{
    bool
    operator()(const ebpf_attach_type_t& lhs, const ebpf_attach_type_t& rhs) const
    {
        return (memcmp(&lhs, &rhs, sizeof(ebpf_attach_type_t)) < 0);
    }
};

struct helper_function_info_t
{
    template <typename T> helper_function_info_t(const T& t) : count(EBPF_COUNT_OF(t)), data(t) {}
    const size_t count;
    const ebpf_helper_function_prototype_t* data;
};

const std::map<ebpf_program_type_t, helper_function_info_t, ebpf_attach_type_compare>
    program_type_specific_helper_functions = {
        {EBPF_PROGRAM_TYPE_XDP, _xdp_ebpf_extension_helper_function_prototype},
        {EBPF_PROGRAM_TYPE_SAMPLE, _sample_ebpf_extension_helper_function_prototype},
};