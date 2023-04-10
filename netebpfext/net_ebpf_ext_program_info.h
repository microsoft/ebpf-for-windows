// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_nethooks.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"

#define XDP_EXT_HELPER_FUNCTION_START EBPF_MAX_GENERAL_HELPER_FUNCTION

// XDP helper function prototype descriptors.
static const ebpf_helper_function_prototype_t _xdp_ebpf_extension_helper_function_prototype[] = {
    {XDP_EXT_HELPER_FUNCTION_START + 1,
     "bpf_xdp_adjust_head",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_CTX, EBPF_ARGUMENT_TYPE_ANYTHING}}};

// XDP program information.
static const ebpf_context_descriptor_t _ebpf_xdp_context_descriptor = {
    sizeof(xdp_md_t),
    EBPF_OFFSET_OF(xdp_md_t, data),
    EBPF_OFFSET_OF(xdp_md_t, data_end),
    EBPF_OFFSET_OF(xdp_md_t, data_meta)};

static const ebpf_program_info_t _ebpf_xdp_program_info = {
    {"xdp", &_ebpf_xdp_context_descriptor, EBPF_PROGRAM_TYPE_XDP_GUID, BPF_PROG_TYPE_XDP},
    EBPF_COUNT_OF(_xdp_ebpf_extension_helper_function_prototype),
    _xdp_ebpf_extension_helper_function_prototype};

static const ebpf_program_section_info_t _ebpf_xdp_section_info[] = {
    {(const wchar_t*)L"xdp", &EBPF_PROGRAM_TYPE_XDP, &EBPF_ATTACH_TYPE_XDP, BPF_PROG_TYPE_XDP, BPF_XDP}};

// Bind program information.
static const ebpf_context_descriptor_t _ebpf_bind_context_descriptor = {
    sizeof(bind_md_t), EBPF_OFFSET_OF(bind_md_t, app_id_start), EBPF_OFFSET_OF(bind_md_t, app_id_end), -1};

static const ebpf_program_info_t _ebpf_bind_program_info = {
    {"bind", &_ebpf_bind_context_descriptor, EBPF_PROGRAM_TYPE_BIND_GUID, BPF_PROG_TYPE_BIND}, 0, NULL};

static const ebpf_program_section_info_t _ebpf_bind_section_info[] = {
    {L"bind", &EBPF_PROGRAM_TYPE_BIND, &EBPF_ATTACH_TYPE_BIND, BPF_PROG_TYPE_BIND, BPF_ATTACH_TYPE_BIND}};

// CGROUP_SOCK_ADDR extension specific helper function prototypes.
static const ebpf_helper_function_prototype_t _sock_addr_ebpf_extension_helper_function_prototype[] = {
    {BPF_FUNC_sock_addr_get_current_pid_tgid,
     "bpf_sock_addr_get_current_pid_tgid",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_CTX}}};

// CGROUP_SOCK_ADDR global helper function prototypes.
static const ebpf_helper_function_prototype_t _ebpf_sock_addr_global_helper_function_prototype[] = {
    {BPF_FUNC_get_current_logon_id,
     "bpf_get_current_logon_id",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_CTX}},
    {BPF_FUNC_is_current_admin, "bpf_is_current_admin", EBPF_RETURN_TYPE_INTEGER, {EBPF_ARGUMENT_TYPE_PTR_TO_CTX}}};

// CGROUP_SOCK_ADDR program information.
static const ebpf_context_descriptor_t _ebpf_sock_addr_context_descriptor = {
    sizeof(bpf_sock_addr_t),
    -1, // Offset into ctx struct for pointer to data, or -1 if none.
    -1, // Offset into ctx struct for pointer to data, or -1 if none.
    -1, // Offset into ctx struct for pointer to metadata, or -1 if none.
};

static const ebpf_program_info_t _ebpf_sock_addr_program_info = {
    {"sock_addr",
     &_ebpf_sock_addr_context_descriptor,
     EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR_GUID,
     BPF_PROG_TYPE_CGROUP_SOCK_ADDR},
    EBPF_COUNT_OF(_sock_addr_ebpf_extension_helper_function_prototype),
    _sock_addr_ebpf_extension_helper_function_prototype,
    EBPF_COUNT_OF(_ebpf_sock_addr_global_helper_function_prototype),
    _ebpf_sock_addr_global_helper_function_prototype};

static const ebpf_program_section_info_t _ebpf_sock_addr_section_info[] = {
    {L"cgroup/connect4",
     &EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR,
     &EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT,
     BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
     BPF_CGROUP_INET4_CONNECT},
    {L"cgroup/connect6",
     &EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR,
     &EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT,
     BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
     BPF_CGROUP_INET6_CONNECT},
    {L"cgroup/recv_accept4",
     &EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR,
     &EBPF_ATTACH_TYPE_CGROUP_INET4_RECV_ACCEPT,
     BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
     BPF_CGROUP_INET4_RECV_ACCEPT},
    {L"cgroup/recv_accept6",
     &EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR,
     &EBPF_ATTACH_TYPE_CGROUP_INET6_RECV_ACCEPT,
     BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
     BPF_CGROUP_INET6_RECV_ACCEPT}};

// SOCK_OPS program information.
static const ebpf_context_descriptor_t _ebpf_sock_ops_context_descriptor = {
    sizeof(bpf_sock_ops_t),
    -1, // Offset into ctx struct for pointer to data, or -1 if none.
    -1, // Offset into ctx struct for pointer to data, or -1 if none.
    -1, // Offset into ctx struct for pointer to metadata, or -1 if none.
};

static const ebpf_program_info_t _ebpf_sock_ops_program_info = {
    {"sockops", &_ebpf_sock_ops_context_descriptor, EBPF_PROGRAM_TYPE_SOCK_OPS_GUID, BPF_PROG_TYPE_SOCK_OPS}, 0, NULL};

static const ebpf_program_section_info_t _ebpf_sock_ops_section_info[] = {
    {L"sockops",
     &EBPF_PROGRAM_TYPE_SOCK_OPS,
     &EBPF_ATTACH_TYPE_CGROUP_SOCK_OPS,
     BPF_PROG_TYPE_SOCK_OPS,
     BPF_CGROUP_SOCK_OPS}};
