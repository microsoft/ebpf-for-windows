// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_structs.h"

EbpfHelperPrototype
get_helper_prototype_windows(int32_t n);

bool
is_helper_usable_windows(int32_t n);

EbpfMapType
get_map_type_windows(uint32_t platform_specific_type);

const EbpfProgramType&
get_program_type_windows(const GUID& program_type);

EbpfProgramType
get_program_type_windows(const std::string& section, const std::string& path);

EbpfMapDescriptor&
get_map_descriptor_windows(int map_fd);

_Must_inspect_result_ ebpf_result_t
get_bpf_program_and_attach_type(
    const std::string& section, _Out_ bpf_prog_type_t* program_type, _Out_ bpf_attach_type_t* attach_type);

_Must_inspect_result_ ebpf_result_t
get_program_and_attach_type(
    const std::string& section, _Out_ ebpf_program_type_t* program_type, _Out_ ebpf_attach_type_t* attach_type);

_Ret_maybenull_ const ebpf_program_type_t*
get_ebpf_program_type(bpf_prog_type_t bpf_program_type);

const ebpf_attach_type_t*
get_attach_type_windows(const std::string& section);

_Ret_maybenull_z_ const char*
get_attach_type_name(_In_ const ebpf_attach_type_t* attach_type);

void
clear_ebpf_provider_data();

_Success_(return == EBPF_SUCCESS) ebpf_result_t
    get_program_type_info_from_tls(_Outptr_ const ebpf_program_info_t** info);

void
clear_program_info_cache();
