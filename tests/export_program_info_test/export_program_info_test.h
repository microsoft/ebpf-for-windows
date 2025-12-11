// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>

uint32_t
export_program_information();

uint32_t
export_section_information();

uint32_t
clear_ebpf_store();

void
print_help(_In_z_ const char* file_name);
