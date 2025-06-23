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

/**
 * @brief Authorize a native module to be loaded.
 *
 * @param[in] module_id GUID of the module to authorize.
 * @param[in] native_image_handle Handle to native image.
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MEMORY Out of memory.
 */
_Must_inspect_result_ ebpf_result_t
ebpf_authorize_native_module(_In_ const GUID* module_id, _In_ HANDLE native_image_handle) EBPF_NO_EXCEPT;

/**
 * @brief Verify the signature of a file and open it.
 *
 * @param[in] file_path Path to the file to open.
 * @param[out] file_handle Handle to the opened file.
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MEMORY Out of memory.
 * @retval EBPF_INVALID_ARGUMENT Invalid file path.
 */
_Must_inspect_result_ ebpf_result_t
ebpf_verify_signature_and_open_file(_In_z_ const char* file_path, _Out_ HANDLE* file_handle) noexcept;

uint32_t
ebpf_service_initialize() noexcept;

void
ebpf_service_cleanup() noexcept;
