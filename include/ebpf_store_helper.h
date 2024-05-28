// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_program_types.h"
#include "ebpf_utilities.h"
#include "ebpf_windows.h"

#define GUID_STRING_LENGTH 38 // not including the null terminator.

#ifdef __cplusplus
extern "C"
{
#endif

    typedef HKEY ebpf_store_key_t;

    extern ebpf_store_key_t ebpf_store_root_key;
    extern const wchar_t* ebpf_store_root_sub_key;

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
     * @brief Update section information in the eBPF store.
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
     * @brief Update program information in the eBPF store.
     *
     * @param[in] program_info Pointer to an array of program information.
     * @param[in] program_info_count Count of program information entries.
     *
     * @returns Status of the operation.
     */
    ebpf_result_t
    ebpf_store_update_program_information_array(
        _In_reads_(program_info_count) const ebpf_program_info_t* program_info, uint32_t program_info_count);

    /**
     * @brief Delete program information from the eBPF store.
     *
     * @param[in] program_info Pointer to the program information.
     *
     * @returns Status of the operation.
     */
    ebpf_result_t
    ebpf_store_delete_program_information(_In_ const ebpf_program_info_t* program_info);

    /**
     * @brief Delete section information from the eBPF store.
     *
     * @param[in] section_info Pointer to the section information.
     *
     * @returns Status of the operation.
     */
    ebpf_result_t
    ebpf_store_delete_section_information(_In_ const ebpf_program_section_info_t* section_info);

#ifdef __cplusplus
}
#endif
