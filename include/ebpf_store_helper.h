// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_program_types.h"
#include "ebpf_registry_helper.h"
#include "ebpf_windows.h"

#ifdef USER_MODE
extern ebpf_registry_key_t ebpf_root_registry_key;
#endif

static uint32_t
_ebpf_store_open_or_create_provider_registry_key(_Out_ ebpf_registry_key_t* provider_key)
{
    __return_type status = _SUCCESS;
    ebpf_registry_key_t root_key = NULL;
    *provider_key = NULL;

    // Open (or create) root eBPF registry path.
#ifndef USER_MODE
    status = create_registry_key(NULL, EBPF_ROOT_REGISTRY_PATH, REG_CREATE_FLAGS, &root_key);
#else
    status = create_registry_key(ebpf_root_registry_key, EBPF_ROOT_RELATIVE_PATH, REG_CREATE_FLAGS, &root_key);
#endif
    if (!IS_SUCCESS(status)) {
        goto Exit;
    }

    // Open (or create) program data registry path.
    status = create_registry_key(root_key, EBPF_PROVIDERS_REGISTRY_PATH, REG_CREATE_FLAGS, provider_key);
    if (!IS_SUCCESS(status)) {
        goto Exit;
    }

Exit:
    if (root_key) {
        close_registry_key(root_key);
    }
    return status;
}

static __return_type
_ebpf_store_update_helper_prototype(
    ebpf_registry_key_t helper_info_key, _In_ const ebpf_helper_function_prototype_t* helper_info)
{
    __return_type status = _SUCCESS;
    uint32_t offset;
    ebpf_registry_key_t helper_function_key = NULL;
    char serialized_data[sizeof(ebpf_helper_function_prototype_t)] = {0};

    status = create_registry_key_ansi(helper_info_key, helper_info->name, REG_CREATE_FLAGS, &helper_function_key);
    if (!IS_SUCCESS(status)) {
        goto Exit;
    }

    // Serialize the helper prototype.
    offset = 0;
    memcpy(serialized_data, &helper_info->helper_id, sizeof(helper_info->helper_id));
    offset += sizeof(helper_info->helper_id);

    memcpy(serialized_data + offset, &helper_info->return_type, sizeof(helper_info->return_type));
    offset += sizeof(helper_info->return_type);

    memcpy(serialized_data + offset, helper_info->arguments, sizeof(helper_info->arguments));
    offset += sizeof(helper_info->arguments);

    // Save the helper prototype data.
    status = write_registry_value_binary(
        helper_function_key, EBPF_HELPER_DATA_PROTOTYPE, (uint8_t*)&serialized_data[0], offset);
    if (!IS_SUCCESS(status)) {
        goto Exit;
    }

Exit:
    if (helper_function_key) {
        close_registry_key(helper_function_key);
    }

    return status;
}

/**
 * @brief Update section information in eBPF store.
 *
 * @param[in] section_info Pointer to an array of section information.
 * @param[in] section_info_count Count of section information entries.
 *
 * @returns Status of the operation.
 */
static __return_type
_ebpf_store_update_section_information(
    _In_reads_(section_info_count) const ebpf_program_section_info_t* section_info, uint32_t section_info_count)
{
    __return_type status = _SUCCESS;
    ebpf_registry_key_t provider_key = NULL;
    ebpf_registry_key_t section_info_key = NULL;

    if (section_info_count == 0) {
        return status;
    }

    // Open (or create) provider registry path.
    status = _ebpf_store_open_or_create_provider_registry_key(&provider_key);
    if (!IS_SUCCESS(status)) {
        goto Exit;
    }

    // Open (or create) section data key.
    status = create_registry_key(provider_key, EBPF_SECTIONS_REGISTRY_PATH, REG_CREATE_FLAGS, &section_info_key);
    if (!IS_SUCCESS(status)) {
        goto Exit;
    }

    for (uint32_t i = 0; i < section_info_count; i++) {
        ebpf_registry_key_t section_key = NULL;

        // Open or create the registry path.
        status = create_registry_key(section_info_key, section_info[i].section_name, REG_CREATE_FLAGS, &section_key);
        if (!IS_SUCCESS(status)) {
            goto Exit;
        }

        // Save program type.
        status = write_registry_value_binary(
            section_key,
            EBPF_SECTION_DATA_PROGRAM_TYPE,
            (uint8_t*)section_info[i].program_type,
            sizeof(ebpf_program_type_t));
        if (!IS_SUCCESS(status)) {
            close_registry_key(section_key);
            goto Exit;
        }

        // Save attach type.
        status = write_registry_value_binary(
            section_key,
            EBPF_SECTION_DATA_ATTACH_TYPE,
            (uint8_t*)section_info[i].attach_type,
            sizeof(ebpf_attach_type_t));
        if (!IS_SUCCESS(status)) {
            close_registry_key(section_key);
            goto Exit;
        }

        // Save bpf_prog_type.
        status = write_registry_value_dword(section_key, EBPF_DATA_BPF_PROG_TYPE, section_info[i].bpf_program_type);
        if (!IS_SUCCESS(status)) {
            close_registry_key(section_key);
            goto Exit;
        }

        // Save bpf_attach_type.
        status = write_registry_value_dword(section_key, EBPF_DATA_BPF_ATTACH_TYPE, section_info[i].bpf_attach_type);
        if (!IS_SUCCESS(status)) {
            close_registry_key(section_key);
            goto Exit;
        }

        close_registry_key(section_key);
    }

Exit:
    if (section_info_key) {
        close_registry_key(section_info_key);
    }
    if (provider_key) {
        close_registry_key(provider_key);
    }

    return status;
}

/**
 * @brief Update program information in eBPF store.
 *
 * @param[in] program_info Pointer to an array of program information.
 * @param[in] program_info_count Count of program information entries.
 *
 * @returns Status of the operation.
 */
static __return_type
_ebpf_store_update_program_information(
    _In_reads_(program_info_count) const ebpf_program_info_t* program_info, uint32_t program_info_count)
{
    __return_type status = _SUCCESS;
    ebpf_registry_key_t provider_key = NULL;
    ebpf_registry_key_t program_info_key = NULL;

    if (program_info_count == 0) {
        return status;
    }

    // Open (or create) provider registry path.
    status = _ebpf_store_open_or_create_provider_registry_key(&provider_key);
    if (!IS_SUCCESS(status)) {
        goto Exit;
    }

    // Open (or create) program data registry path.
    status = create_registry_key(provider_key, EBPF_PROGRAM_DATA_REGISTRY_PATH, REG_CREATE_FLAGS, &program_info_key);
    if (!IS_SUCCESS(status)) {
        goto Exit;
    }

    for (uint32_t i = 0; i < program_info_count; i++) {
        ebpf_registry_key_t program_key = {0};
        ebpf_registry_key_t helper_info_key = {0};

        // Convert program type GUID to string.
        wchar_t guid_string[GUID_STRING_LENGTH + 1];
        status = convert_guid_to_string(
            &program_info[i].program_type_descriptor.program_type, guid_string, GUID_STRING_LENGTH + 1);
        if (status != _SUCCESS) {
            return status;
        }

        status = create_registry_key(program_info_key, guid_string, REG_CREATE_FLAGS, &program_key);
        if (!IS_SUCCESS(status)) {
            goto Exit;
        }

        // Save the friendly program type name.
        status = write_registry_value_ansi_string(
            program_key, EBPF_PROGRAM_DATA_NAME, program_info[i].program_type_descriptor.name);
        if (!IS_SUCCESS(status)) {
            close_registry_key(program_key);
            goto Exit;
        }

        // Save context descriptor.
        status = write_registry_value_binary(
            program_key,
            EBPF_PROGRAM_DATA_CONTEXT_DESCRIPTOR,
            (uint8_t*)program_info[i].program_type_descriptor.context_descriptor,
            sizeof(ebpf_context_descriptor_t));
        if (!IS_SUCCESS(status)) {
            close_registry_key(program_key);
            goto Exit;
        }

        // Save bpf_prog_type.
        status = write_registry_value_dword(
            program_key, EBPF_DATA_BPF_PROG_TYPE, program_info[i].program_type_descriptor.bpf_prog_type);
        if (!IS_SUCCESS(status)) {
            close_registry_key(program_key);
            goto Exit;
        }

        // Save "is_privileged".
        status = write_registry_value_dword(
            program_key, EBPF_PROGRAM_DATA_PRIVILEGED, program_info[i].program_type_descriptor.is_privileged);
        if (!IS_SUCCESS(status)) {
            close_registry_key(program_key);
            goto Exit;
        }

        // Save helper count.
        status = write_registry_value_dword(
            program_key, EBPF_PROGRAM_DATA_HELPER_COUNT, program_info[i].count_of_program_type_specific_helpers);
        if (!IS_SUCCESS(status)) {
            close_registry_key(program_key);
            goto Exit;
        }

        if (program_info[i].count_of_program_type_specific_helpers != 0) {
            // Create (or open) helper registry path.
            status = create_registry_key(
                program_key, EBPF_PROGRAM_DATA_HELPERS_REGISTRY_PATH, REG_CREATE_FLAGS, &helper_info_key);
            if (!IS_SUCCESS(status)) {
                close_registry_key(program_key);
                goto Exit;
            }

            // Iterate over all the helper prototypes and save in registry.
            for (uint32_t count = 0; count < program_info[i].count_of_program_type_specific_helpers; count++) {
                status = _ebpf_store_update_helper_prototype(
                    helper_info_key, &(program_info[i].program_type_specific_helper_prototype[count]));
                if (!IS_SUCCESS(status)) {
                    close_registry_key(program_key);
                    close_registry_key(helper_info_key);
                    goto Exit;
                }
            }

            close_registry_key(helper_info_key);
        }
        close_registry_key(program_key);
    }

Exit:
    if (program_info_key) {
        close_registry_key(program_info_key);
    }
    if (provider_key) {
        close_registry_key(provider_key);
    }

    return status;
}

/**
 * @brief Update global helper information in eBPF store.
 *
 * @param[in] helper_info Pointer to an array of helper function prototypes.
 * @param[in] helper_info_count Count of helper function prototypes.
 *
 * @returns Status of the operation.
 */
static __return_type
_ebpf_store_update_global_helper_information(
    _In_reads_(helper_info_count) ebpf_helper_function_prototype_t* helper_info, uint32_t helper_info_count)
{
    __return_type status = _SUCCESS;
    ebpf_registry_key_t provider_key = NULL;
    ebpf_registry_key_t helper_info_key = NULL;

    if (helper_info_count == 0) {
        return status;
    }

    // Open (or create) provider registry path.
    status = _ebpf_store_open_or_create_provider_registry_key(&provider_key);
    if (!IS_SUCCESS(status)) {
        goto Exit;
    }

    // Open (or create) global helpers registry path.
    status = create_registry_key(provider_key, EBPF_GLOBAL_HELPERS_REGISTRY_PATH, REG_CREATE_FLAGS, &helper_info_key);
    if (!IS_SUCCESS(status)) {
        goto Exit;
    }

    for (uint32_t i = 0; i < helper_info_count; i++) {

        status = _ebpf_store_update_helper_prototype(helper_info_key, &helper_info[i]);
        if (!IS_SUCCESS(status)) {
            goto Exit;
        }
    }

Exit:
    if (helper_info_key) {
        close_registry_key(helper_info_key);
    }
    if (provider_key) {
        close_registry_key(provider_key);
    }

    return status;
}