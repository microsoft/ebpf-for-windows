// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "api_internal.h"
#include "ebpf_api.h"
#include "ebpf_execution_context.h"
#include "ebpf_execution_type.h"
#include "ebpf_result.h"
#include "rpc_interface_h.h"

_Must_inspect_result_ ebpf_result_t
ebpf_verify_and_load_program(
    _In_ const GUID* program_type,
    ebpf_handle_t program_handle,
    ebpf_execution_context_t execution_context,
    ebpf_execution_type_t execution_type,
    uint32_t handle_map_count,
    _In_reads_(handle_map_count) original_fd_handle_map_t* handle_map,
    uint32_t instruction_count,
    _In_reads_(instruction_count) ebpf_inst* instructions,
    _Outptr_result_maybenull_z_ const char** error_message,
    _Out_ uint32_t* error_message_size) noexcept;

uint32_t
ebpf_service_initialize() noexcept;

void
ebpf_service_cleanup() noexcept;
