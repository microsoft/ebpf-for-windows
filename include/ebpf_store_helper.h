// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_program_types.h"
#ifdef USER_MODE
#include "user\ebpf_registry_helper_um.h"
#else
#include "kernel\ebpf_registry_helper_km.h"
#endif
#include "ebpf_windows.h"

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef USER_MODE
    extern ebpf_registry_key_t ebpf_root_registry_key;
#endif

    uint32_t
    ebpf_store_open_or_create_provider_registry_key(_Out_ ebpf_registry_key_t* provider_key);

    __return_type
    ebpf_store_update_helper_prototype(
        ebpf_registry_key_t helper_info_key, _In_ const ebpf_helper_function_prototype_t* helper_info);

    /**
     * @brief Update section information in eBPF store.
     *
     * @param[in] section_info Pointer to an array of section information.
     * @param[in] section_info_count Count of section information entries.
     *
     * @returns Status of the operation.
     */
    __return_type
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
    __return_type
    ebpf_store_update_program_information(
        _In_reads_(program_info_count) const ebpf_program_info_t* program_info, uint32_t program_info_count);

    /**
     * @brief Update global helper information in eBPF store.
     *
     * @param[in] helper_info Pointer to an array of helper function prototypes.
     * @param[in] helper_info_count Count of helper function prototypes.
     *
     * @returns Status of the operation.
     */
    __return_type
    ebpf_store_update_global_helper_information(
        _In_reads_(helper_info_count) ebpf_helper_function_prototype_t* helper_info, uint32_t helper_info_count);

#ifdef __cplusplus
} /* extern "C" */
#endif