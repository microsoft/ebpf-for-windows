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

/**
 * @brief Verify the signature of a system file.
 *
 * @param[in] file_name The name of the file to verify.
 * @param[in] issuer_name The name of the issuer to check against.
 * @param[in] eku_count The number of EKUs to check.
 * @param[in] eku_list The list of EKUs to check against.
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_OBJECT_NOT_FOUND The file does not have the expected signature.
 * @retval EBPF_INVALID_ARGUMENT The file name or issuer name is invalid.
 * @retval EBPF_NO_MEMORY Out of memory.
 * @retval EBPF_FAILED A failure occurred during the verification process.
 */
_Must_inspect_result_ ebpf_result_t
ebpf_verify_sys_file_signature(
    _In_z_ const wchar_t* file_name,
    _In_z_ const char* issuer_name,
    size_t eku_count,
    _In_reads_(eku_count) const char** eku_list);

uint32_t
ebpf_service_initialize() noexcept;

void
ebpf_service_cleanup() noexcept;

/**
 * @brief This macro defines the required issuer for eBPF verification.
 * The issuer must match the one used for signing eBPF programs.
 */
#define EBPF_REQUIRED_ISSUER "US, Washington, Redmond, Microsoft Corporation, Microsoft Corporation eBPF Verification"

/**
 * @brief This macro defines the EKU for code signing.
 */
#define EBPF_CODE_SIGNING_EKU "1.3.6.1.5.5.7.3.3"
/**
 * @brief This macro defines the EKU used by eBPF to denote that a BPF program has been verified using the eBPF
 * verification process.
 */
#define EBPF_VERIFICATION_EKU "1.3.6.1.4.1.311.133.1"
/**
 * @brief This macro defines the EKU used to denote that a driver is a Windows component.
 */
#define EBPF_WINDOWS_COMPONENT_EKU "1.3.6.1.4.1.311.10.3.6"
