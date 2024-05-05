// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_program_types.h"
#include "ebpf_shared_framework.h"

extern "C"
{
    extern ebpf_helper_function_prototype_t* ebpf_core_helper_function_prototype;
    extern uint32_t ebpf_core_helper_functions_count;
}

void
print_help(_In_z_ const char* file_name);

uint32_t
export_all_program_information();

uint32_t
export_all_section_information();

int
export_global_helper_information();

uint32_t
clear_ebpf_store();
