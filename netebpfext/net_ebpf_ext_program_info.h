// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_program_types.h"
#include "ebpf_platform.h"
#include "ebpf_nethooks.h"

#define XDP_EXT_HELPER_FUNCTION_START EBPF_MAX_GENERAL_HELPER_FUNCTION

// XDP Extension Helper function prototype descriptors.
static ebpf_helper_function_prototype_t _xdp_ebpf_extension_helper_function_prototype[] = {
    {XDP_EXT_HELPER_FUNCTION_START + 1,
     "bpf_xdp_adjust_head",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_CTX, EBPF_ARGUMENT_TYPE_ANYTHING}},
    {XDP_EXT_HELPER_FUNCTION_START + 2,
     "bpf_csum_diff",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_MEM_OR_NULL,
      EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
      EBPF_ARGUMENT_TYPE_PTR_TO_MEM_OR_NULL,
      EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
      EBPF_ARGUMENT_TYPE_ANYTHING}}};

// XDP Extension program information.
static ebpf_context_descriptor_t _ebpf_xdp_context_descriptor = {
    sizeof(xdp_md_t),
    EBPF_OFFSET_OF(xdp_md_t, data),
    EBPF_OFFSET_OF(xdp_md_t, data_end),
    EBPF_OFFSET_OF(xdp_md_t, data_meta)};
static ebpf_program_info_t _ebpf_xdp_program_info = {
    {"xdp", &_ebpf_xdp_context_descriptor, {0}},
    EBPF_COUNT_OF(_xdp_ebpf_extension_helper_function_prototype),
    _xdp_ebpf_extension_helper_function_prototype};