// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#ifndef USER_MODE
#include "framework.h"
#else
#include "ebpf_utilities.h"
#endif

#include "ebpf_program_types.h"
#include "ebpf_windows.h"

#define GUID_STRING_LENGTH 38 // not including the null terminator.

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef USER_MODE
    typedef HANDLE ebpf_store_key_t;
#else
typedef HKEY ebpf_store_key_t;
#endif

    extern ebpf_store_key_t ebpf_store_root_key;
    extern const wchar_t* ebpf_store_root_sub_key;

    /**
     * @brief Update the provider prototype information in the eBPF store.
     *
     * @param[in] helper_info_key Pointer to the store key to be initialized.
     * @param[in] helper_info Pointer to the helper function prototype.
     *
     * @return Status of the operation.
     */
    ebpf_result_t
    ebpf_store_update_helper_prototype(
        ebpf_store_key_t helper_info_key, _In_ const ebpf_helper_function_prototype_t* helper_info);

    /**
     * @brief Update global helper information in the eBPF store.
     *
     * @param[in] helper_info Pointer to an array of helper function prototypes.
     * @param[in] helper_info_count Count of helper function prototypes.
     *
     * @returns Status of the operation.
     */
    ebpf_result_t
    ebpf_store_update_global_helper_information(
        _In_reads_(helper_info_count) ebpf_helper_function_prototype_t* helper_info, uint32_t helper_info_count);

    /**
     * @brief Update section information in eBPF store.
     *
     * @param[in] section_info Pointer to an array of section information.
     * @param[in] section_info_count Count of section information entries.
     *
     * @returns Status of the operation.
     */
    ebpf_result_t
    ebpf_store_update_section_information(
        _In_reads_(section_info_count) const ebpf_program_section_info_t* section_info, uint32_t section_info_count);

    /**
     * @brief Update program information in eBPF store.
     *
     * @param[in] program_info Pointer to an array of program information.
     * @param[in] program_info_count Count of program information entries.
     *
     * @returns Status of the operation.
     */
    ebpf_result_t
    ebpf_store_update_program_information(
        _In_reads_(program_info_count) const ebpf_program_info_t* program_info, uint32_t program_info_count);

#ifdef __cplusplus
}
#endif