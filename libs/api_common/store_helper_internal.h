// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "windows_program_type.h"

_Must_inspect_result_ ebpf_result_t
ebpf_store_load_program_data(
    _Outptr_result_buffer_maybenull_(*program_info_count) ebpf_program_info_t*** program_info,
    _Out_ uint32_t* program_info_count);

_Must_inspect_result_ ebpf_result_t
ebpf_store_load_section_information(
    _Outptr_result_buffer_maybenull_(*section_info_count) ebpf_section_definition_t*** section_info,
    _Out_ uint32_t* section_info_count);

_Must_inspect_result_ ebpf_result_t
ebpf_store_load_global_helper_information(
    _Outptr_result_buffer_maybenull_(*global_helper_info_count) ebpf_helper_function_prototype_t** global_helper_info,
    _Out_ uint32_t* global_helper_info_count);

_Must_inspect_result_ ebpf_result_t
ebpf_store_clear(_In_ const ebpf_store_key_t root_key_path);

/**
 * @brief Delete global helper information from the eBPF store.
 *
 * @param[in] helper_info Pointer to the helper information.
 *
 * @returns Status of the operation.
 */
ebpf_result_t
ebpf_store_delete_global_helper_information(_In_ ebpf_helper_function_prototype_t* helper_info);
