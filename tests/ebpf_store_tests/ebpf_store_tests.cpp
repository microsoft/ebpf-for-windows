// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#define USER_MODE

#include "ebpf_extension.h"
#include "ebpf_program_attach_type_guids.h"
#include "ebpf_store_helper.h"

#include <catch2/catch.hpp>

#define EBPF_OFFSET_OF(s, m) (((size_t) & ((s*)0)->m))

// Sample extension program context.
typedef struct _sample_program_context
{
    uint8_t* data_start;
    uint8_t* data_end;
    uint32_t uint32_data;
    uint16_t uint16_data;
} sample_program_context_t;

#define SAMPLE_EXT_HELPER_FUNCTION_START EBPF_MAX_GENERAL_HELPER_FUNCTION

static const ebpf_context_descriptor_t _sample_ebpf_context_descriptor = {
    sizeof(sample_program_context_t),
    EBPF_OFFSET_OF(sample_program_context_t, data_start),
    EBPF_OFFSET_OF(sample_program_context_t, data_end),
    -1};

// Sample Extension Helper function prototype descriptors.
static const ebpf_helper_function_prototype_t _sample_ebpf_extension_helper_function_prototype[] = {
    {SAMPLE_EXT_HELPER_FUNCTION_START + 1,
     "sample_ebpf_extension_helper_function1",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_CTX}},
    {SAMPLE_EXT_HELPER_FUNCTION_START + 2,
     "sample_ebpf_extension_find",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
      EBPF_ARGUMENT_TYPE_CONST_SIZE,
      EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
      EBPF_ARGUMENT_TYPE_CONST_SIZE}},
    {SAMPLE_EXT_HELPER_FUNCTION_START + 3,
     "sample_ebpf_extension_replace",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
      EBPF_ARGUMENT_TYPE_CONST_SIZE,
      EBPF_ARGUMENT_TYPE_ANYTHING,
      EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
      EBPF_ARGUMENT_TYPE_CONST_SIZE}}};

static const ebpf_helper_function_prototype_t _sample_ebpf_extension_global_helper_function_prototype[] = {
    {BPF_FUNC_get_current_pid_tgid, "bpf_get_current_pid_tgid", EBPF_RETURN_TYPE_INTEGER, {0}}};

static const ebpf_program_info_t _sample_ebpf_extension_program_info = {
    {"sample", &_sample_ebpf_context_descriptor, EBPF_PROGRAM_TYPE_SAMPLE_GUID, BPF_PROG_TYPE_SAMPLE},
    _countof(_sample_ebpf_extension_helper_function_prototype),
    _sample_ebpf_extension_helper_function_prototype,
    _countof(_sample_ebpf_extension_global_helper_function_prototype),
    _sample_ebpf_extension_global_helper_function_prototype};

static const ebpf_program_info_t* program_information_array[] = {&_sample_ebpf_extension_program_info};

TEST_CASE("test", "[test]") { REQUIRE(true); }
