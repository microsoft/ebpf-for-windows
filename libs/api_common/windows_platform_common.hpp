// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_structs.h"
#include "ir/syntax.hpp"
#include "platform.hpp"

#include <optional>
#include <string>

namespace libbtf {
class btf_type_data;
}

prevail::EbpfHelperPrototype
get_helper_prototype_windows(int32_t n, _In_ const prevail::EbpfProgramType& program_type);

bool
is_helper_usable_windows(int32_t n, _In_ const prevail::EbpfProgramType& program_type);

prevail::EbpfMapType
get_map_type_windows(uint32_t platform_specific_type);

_Ret_maybenull_ const prevail::EbpfProgramType*
get_program_type_windows(_In_ const GUID& program_type);

prevail::EbpfProgramType
get_program_type_windows(_In_ const std::string& section, _In_ const std::string& path);

const prevail::EbpfMapDescriptor&
get_map_descriptor_windows(int map_fd, _In_ const std::vector<prevail::EbpfMapDescriptor>& descriptors);

_Must_inspect_result_ ebpf_result_t
get_bpf_program_and_attach_type(
    _In_ const std::string& section, _Out_ bpf_prog_type_t* program_type, _Out_ bpf_attach_type_t* attach_type);

_Must_inspect_result_ ebpf_result_t
get_program_and_attach_type(
    _In_ const std::string& section, _Out_ ebpf_program_type_t* program_type, _Out_ ebpf_attach_type_t* attach_type);

_Ret_maybenull_ const ebpf_program_type_t*
get_ebpf_program_type(bpf_prog_type_t bpf_program_type);

const ebpf_attach_type_t*
get_attach_type_windows(_In_ const std::string& section);

_Ret_maybenull_z_ const char*
get_attach_type_name(_In_ const ebpf_attach_type_t* attach_type);

void
clear_ebpf_provider_data();

_Success_(return == EBPF_SUCCESS) ebpf_result_t
    get_program_type_info_from_tls(_Outptr_ const ebpf_program_info_t** info);

_Success_(return == EBPF_SUCCESS) ebpf_result_t
    get_program_type_info(_In_ const prevail::EbpfProgramType& program_type, _Outptr_ const ebpf_program_info_t** info);

_Success_(return == EBPF_SUCCESS) ebpf_result_t get_btf_resolved_function_info_from_tls(
    int32_t btf_id, _Outptr_ const ebpf_btf_resolved_function_info_t** function_info);

void
cache_btf_resolved_functions(_In_ const libbtf::btf_type_data& btf_data);

std::optional<prevail::KsymBtfId>
resolve_ksym_btf_id_windows(_In_ const std::string& name);

std::optional<prevail::ResolvedCall>
resolve_kfunc_call_windows(
    int32_t btf_id,
    int16_t module,
    _In_ const prevail::EbpfProgramType& program_type,
    _Inout_opt_ std::string* why_not);

void
set_verification_program_type(_In_opt_ const prevail::EbpfProgramType* type);

void
clear_program_info_cache();
