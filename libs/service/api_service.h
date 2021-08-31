// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "api_internal.h"
#include "ebpf_api.h"
#include "ebpf_execution_context.h"
#include "ebpf_execution_type.h"
#include "ebpf_result.h"
#include "rpc_interface_h.h"

ebpf_result_t
ebpf_verify_program(
    const GUID* program_type,
    ebpf_execution_context_t execution_context,
    uint32_t map_descriptors_count,
    EbpfMapDescriptor* map_descriptors,
    uint32_t byte_code_size,
    uint8_t* byte_code,
    const char** logs,
    uint32_t* logs_size) noexcept;

ebpf_result_t
ebpf_verify_and_load_program(
    const GUID* program_type,
    ebpf_handle_t program_handle,
    ebpf_execution_context_t execution_context,
    ebpf_execution_type_t execution_type,
    uint32_t handle_map_count,
    original_fd_handle_map_t* handle_map,
    uint32_t byte_code_size,
    uint8_t* byte_code,
    const char** error_message,
    uint32_t* error_message_size) noexcept;

uint32_t
ebpf_service_initialize() noexcept;

void
ebpf_service_cleanup() noexcept;