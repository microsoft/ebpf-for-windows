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

    extern ebpf_store_key_t ebpf_store_hkcu_root_key;
    extern ebpf_store_key_t ebpf_store_hklm_root_key;
    extern const wchar_t* ebpf_store_root_sub_key;

    typedef struct _ebpf_btf_resolved_function_provider_info
    {
        ebpf_extension_header_t header;
        GUID module_guid;
        uint32_t btf_resolved_function_count;
        const ebpf_btf_resolved_function_prototype_t* btf_resolved_function_prototypes;
    } ebpf_btf_resolved_function_provider_info_t;

    typedef struct _ebpf_btf_resolved_function_info
    {
        GUID module_guid;
        ebpf_btf_resolved_function_prototype_t prototype;
    } ebpf_btf_resolved_function_info_t;

#define EBPF_BTF_RESOLVED_FUNCTION_PROVIDER_INFO_CURRENT_VERSION 1
#define EBPF_BTF_RESOLVED_FUNCTION_PROVIDER_INFO_CURRENT_VERSION_SIZE \
    EBPF_SIZE_INCLUDING_FIELD(ebpf_btf_resolved_function_provider_info_t, btf_resolved_function_prototypes)
#define EBPF_BTF_RESOLVED_FUNCTION_PROVIDER_INFO_CURRENT_VERSION_TOTAL_SIZE \
    sizeof(ebpf_btf_resolved_function_provider_info_t)
#define EBPF_BTF_RESOLVED_FUNCTION_PROVIDER_INFO_HEADER             \
    {EBPF_BTF_RESOLVED_FUNCTION_PROVIDER_INFO_CURRENT_VERSION,      \
     EBPF_BTF_RESOLVED_FUNCTION_PROVIDER_INFO_CURRENT_VERSION_SIZE, \
     EBPF_BTF_RESOLVED_FUNCTION_PROVIDER_INFO_CURRENT_VERSION_TOTAL_SIZE}

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
     * @brief Update BTF-resolved function provider information in the eBPF store.
     *
     * @param[in] provider_info Pointer to the BTF-resolved function provider information.
     *
     * @returns Status of the operation.
     */
    ebpf_result_t
    ebpf_store_update_btf_resolved_function_provider_information(
        _In_ const ebpf_btf_resolved_function_provider_info_t* provider_info);

    /**
     * @brief Delete BTF-resolved function provider information from the eBPF store.
     *
     * @param[in] provider_info Pointer to the BTF-resolved function provider information.
     *
     * @returns Status of the operation.
     */
    ebpf_result_t
    ebpf_store_delete_btf_resolved_function_provider_information(
        _In_ const ebpf_btf_resolved_function_provider_info_t* provider_info);

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
