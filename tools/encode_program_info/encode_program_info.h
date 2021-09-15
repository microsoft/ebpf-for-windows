// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_platform.h"
#include "ebpf_program_types.h"

extern "C"
{
    extern ebpf_helper_function_prototype_t* ebpf_core_helper_function_prototype;
    extern uint32_t ebpf_core_helper_functions_count;
}
