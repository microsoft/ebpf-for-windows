// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_program_types.h"
#include "ebpf_platform.h"
#include "ebpf_nethooks.h"

#define XDP_EXT_HELPER_FUNCTION_START EBPF_MAX_GENERAL_HELPER_FUNCTION

// XDP helper function prototype descriptors.
static ebpf_helper_function_prototype_t _xdp_ebpf_extension_helper_function_prototype[] = {
    {XDP_EXT_HELPER_FUNCTION_START + 1,
     "bpf_xdp_adjust_head",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_CTX, EBPF_ARGUMENT_TYPE_ANYTHING}}};

// XDP program information.
static ebpf_context_descriptor_t _ebpf_xdp_context_descriptor = {
    sizeof(xdp_md_t),
    EBPF_OFFSET_OF(xdp_md_t, data),
    EBPF_OFFSET_OF(xdp_md_t, data_end),
    EBPF_OFFSET_OF(xdp_md_t, data_meta)};
static ebpf_program_info_t _ebpf_xdp_program_info = {
    {"xdp", &_ebpf_xdp_context_descriptor, {0}},
    EBPF_COUNT_OF(_xdp_ebpf_extension_helper_function_prototype),
    _xdp_ebpf_extension_helper_function_prototype};

// Bind program information.
static ebpf_context_descriptor_t _ebpf_bind_context_descriptor = {
    sizeof(bind_md_t), EBPF_OFFSET_OF(bind_md_t, app_id_start), EBPF_OFFSET_OF(bind_md_t, app_id_end), -1};
static ebpf_program_info_t _ebpf_bind_program_info = {{"bind", &_ebpf_bind_context_descriptor, {0}}, 0, NULL};

// CGROUP_SOCK_ADDR program information.
static ebpf_context_descriptor_t _ebpf_sock_addr_context_descriptor = {
    sizeof(bpf_sock_addr_t),
    -1, // Offset into ctx struct for pointer to data, or -1 if none.
    -1, // Offset into ctx struct for pointer to data, or -1 if none.
    -1, // Offset into ctx struct for pointer to metadata, or -1 if none.
};
static ebpf_program_info_t _ebpf_sock_addr_program_info = {
    {"sock_addr", &_ebpf_sock_addr_context_descriptor, {0}}, 0, NULL};
