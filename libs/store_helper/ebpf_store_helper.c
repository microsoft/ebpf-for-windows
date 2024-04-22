// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_program_types.h"
#include "ebpf_registry_helper.h"
#include "ebpf_serialize.h"
#include "ebpf_shared_framework.h"
#include "ebpf_store_helper.h"
#include "ebpf_windows.h"

#define IS_SUCCESS(x) (x == EBPF_SUCCESS)

static ebpf_result_t
_ebpf_store_update_extension_header_information(ebpf_store_key_t key, _In_ const ebpf_extension_header_t* header)
{
    ebpf_result_t result;
    result = ebpf_write_registry_value_dword(key, EBPF_EXTENSION_HEADER_VERSION, header->version);
    if (!IS_SUCCESS(result))
        return result;
    result = ebpf_write_registry_value_dword(key, EBPF_EXTENSION_HEADER_SIZE, (uint32_t)header->size);
    return result;
}

static ebpf_result_t
_ebpf_store_open_or_create_provider_registry_key(_Out_ ebpf_store_key_t* provider_key)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_store_key_t root_key = NULL;
    *provider_key = NULL;

    // Open (or create) root eBPF registry path.
    result = ebpf_create_registry_key(ebpf_store_root_key, ebpf_store_root_sub_key, REG_CREATE_FLAGS, &root_key);

    if (!IS_SUCCESS(result)) {
        goto Exit;
    }

    // Open (or create) program data registry path.
    result = ebpf_create_registry_key(root_key, EBPF_PROVIDERS_REGISTRY_KEY, REG_CREATE_FLAGS, provider_key);
    if (!IS_SUCCESS(result)) {
        goto Exit;
    }

Exit:
    ebpf_close_registry_key(root_key);
    return result;
}

static ebpf_result_t
_ebpf_store_update_helper_prototype(
    ebpf_store_key_t helper_info_key, _In_ const ebpf_helper_function_prototype_t* helper_info)
{
    ebpf_result_t result = EBPF_SUCCESS;
    uint32_t offset;
    ebpf_store_key_t helper_function_key = NULL;
    char serialized_data[sizeof(ebpf_helper_function_prototype_t)] = {0};

    wchar_t* wide_helper_name = ebpf_get_wstring_from_string(helper_info->name);
    if (wide_helper_name == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    result = ebpf_create_registry_key(helper_info_key, wide_helper_name, REG_CREATE_FLAGS, &helper_function_key);
    if (!IS_SUCCESS(result)) {
        goto Exit;
    }

    // Save header information.
    result = _ebpf_store_update_extension_header_information(helper_function_key, &helper_info->header);
    if (!IS_SUCCESS(result)) {
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
    result = ebpf_write_registry_value_binary(
        helper_function_key, EBPF_HELPER_DATA_PROTOTYPE, (uint8_t*)&serialized_data[0], offset);
    if (!IS_SUCCESS(result)) {
        goto Exit;
    }

    if (helper_info->header.size >= EBPF_SIZE_INCLUDING_FIELD(ebpf_helper_function_prototype_t, flags)) {
        // Save the reallocate_packet flag.
        uint32_t reallocate_packet_value = helper_info->flags.reallocate_packet ? 1 : 0;
        result = ebpf_write_registry_value_dword(
            helper_function_key, EBPF_HELPER_DATA_REALLOCATE_PACKET, reallocate_packet_value);
        if (!IS_SUCCESS(result)) {
            goto Exit;
        }
    }

Exit:
    ebpf_free_wstring(wide_helper_name);
    ebpf_close_registry_key(helper_function_key);

    return result;
}

ebpf_result_t
ebpf_store_update_global_helper_information(
    _In_reads_(helper_info_count) ebpf_helper_function_prototype_t* helper_info, uint32_t helper_info_count)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_store_key_t provider_key = NULL;
    ebpf_store_key_t helper_info_key = NULL;

    if (helper_info_count == 0) {
        return result;
    }

    if (!ebpf_validate_helper_function_prototype_array(helper_info, helper_info_count)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    // Open (or create) provider registry path.
    result = _ebpf_store_open_or_create_provider_registry_key(&provider_key);
    if (!IS_SUCCESS(result)) {
        goto Exit;
    }

    // Open (or create) global helpers registry path.
    result =
        ebpf_create_registry_key(provider_key, EBPF_GLOBAL_HELPERS_REGISTRY_KEY, REG_CREATE_FLAGS, &helper_info_key);
    if (!IS_SUCCESS(result)) {
        goto Exit;
    }

    for (uint32_t i = 0; i < helper_info_count; i++) {
        result = _ebpf_store_update_helper_prototype(helper_info_key, &helper_info[i]);
        if (!IS_SUCCESS(result)) {
            goto Exit;
        }
    }

Exit:
    ebpf_close_registry_key(helper_info_key);
    ebpf_close_registry_key(provider_key);

    return result;
}

ebpf_result_t
ebpf_store_update_section_information(
    _In_reads_(section_info_count) const ebpf_program_section_info_t* section_info, uint32_t section_info_count)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_store_key_t provider_key = NULL;
    ebpf_store_key_t section_info_key = NULL;

    if (section_info_count == 0) {
        return result;
    }

    // Open (or create) provider registry path.
    result = _ebpf_store_open_or_create_provider_registry_key(&provider_key);
    if (!IS_SUCCESS(result)) {
        goto Exit;
    }

    // Open (or create) section data key.
    result = ebpf_create_registry_key(provider_key, EBPF_SECTIONS_REGISTRY_KEY, REG_CREATE_FLAGS, &section_info_key);
    if (!IS_SUCCESS(result)) {
        goto Exit;
    }

    for (uint32_t i = 0; i < section_info_count; i++) {
        ebpf_store_key_t section_key = NULL;

        if (!ebpf_validate_program_section_info(&section_info[i])) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        // Open or create the registry path.
        result =
            ebpf_create_registry_key(section_info_key, section_info[i].section_name, REG_CREATE_FLAGS, &section_key);
        if (!IS_SUCCESS(result)) {
            goto Exit;
        }

        // Save header information.
        result = _ebpf_store_update_extension_header_information(section_key, &section_info[i].header);

        // Save program type.
        result = ebpf_write_registry_value_binary(
            section_key,
            EBPF_SECTION_DATA_PROGRAM_TYPE,
            (uint8_t*)section_info[i].program_type,
            sizeof(ebpf_program_type_t));
        if (!IS_SUCCESS(result)) {
            ebpf_close_registry_key(section_key);
            goto Exit;
        }

        // Save attach type.
        result = ebpf_write_registry_value_binary(
            section_key,
            EBPF_SECTION_DATA_ATTACH_TYPE,
            (uint8_t*)section_info[i].attach_type,
            sizeof(ebpf_attach_type_t));
        if (!IS_SUCCESS(result)) {
            ebpf_close_registry_key(section_key);
            goto Exit;
        }

        // Save bpf_prog_type.
        result =
            ebpf_write_registry_value_dword(section_key, EBPF_DATA_BPF_PROG_TYPE, section_info[i].bpf_program_type);
        if (!IS_SUCCESS(result)) {
            ebpf_close_registry_key(section_key);
            goto Exit;
        }

        // Save bpf_attach_type.
        result =
            ebpf_write_registry_value_dword(section_key, EBPF_DATA_BPF_ATTACH_TYPE, section_info[i].bpf_attach_type);
        if (!IS_SUCCESS(result)) {
            ebpf_close_registry_key(section_key);
            goto Exit;
        }

        ebpf_close_registry_key(section_key);
    }

Exit:
    ebpf_close_registry_key(section_info_key);
    ebpf_close_registry_key(provider_key);

    return result;
}

static ebpf_result_t
_ebpf_store_update_program_descriptor(
    ebpf_store_key_t descriptor_key, _In_ const ebpf_program_type_descriptor_t* program_type_descriptor)
{
    ebpf_result_t result = EBPF_SUCCESS;

    // Save header information.
    result = _ebpf_store_update_extension_header_information(descriptor_key, &program_type_descriptor->header);
    if (!IS_SUCCESS(result)) {
        return result;
    }

    // Save the friendly program type name.
    wchar_t* wide_program_name = ebpf_get_wstring_from_string(program_type_descriptor->name);
    if (wide_program_name == NULL) {
        return EBPF_NO_MEMORY;
    }
    result = ebpf_write_registry_value_string(descriptor_key, EBPF_PROGRAM_DATA_NAME, wide_program_name);
    if (!IS_SUCCESS(result)) {
        ebpf_free_wstring(wide_program_name);
        return result;
    }
    ebpf_free_wstring(wide_program_name);

    // Save context descriptor.
    result = ebpf_write_registry_value_binary(
        descriptor_key,
        EBPF_PROGRAM_DATA_CONTEXT_DESCRIPTOR,
        (uint8_t*)program_type_descriptor->context_descriptor,
        sizeof(ebpf_context_descriptor_t));
    if (!IS_SUCCESS(result)) {
        return result;
    }

    // Save bpf_prog_type.
    result = ebpf_write_registry_value_dword(
        descriptor_key, EBPF_DATA_BPF_PROG_TYPE, program_type_descriptor->bpf_prog_type);
    if (!IS_SUCCESS(result)) {
        return result;
    }

    // Save "is_privileged".
    result = ebpf_write_registry_value_dword(
        descriptor_key, EBPF_PROGRAM_DATA_PRIVILEGED, program_type_descriptor->is_privileged);
    if (!IS_SUCCESS(result)) {
        return result;
    }

    return result;
}

static ebpf_result_t
_ebpf_store_update_program_info(ebpf_store_key_t program_key, _In_ const ebpf_program_info_t* program_info)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_store_key_t descriptor_key = {0};
    ebpf_store_key_t helper_info_key = {0};

    // Save program info header information.
    result = _ebpf_store_update_extension_header_information(program_key, &program_info->header);
    if (!IS_SUCCESS(result)) {
        goto Exit;
    }

    // Create a subkey to store the program type descriptor.
    result = ebpf_create_registry_key(
        program_key, EBPF_PROGRAM_TYPE_DESCRIPTOR_REGISTRY_KEY, REG_CREATE_FLAGS, &descriptor_key);
    if (!IS_SUCCESS(result)) {
        goto Exit;
    }

    // Save program type descriptor.
    result = _ebpf_store_update_program_descriptor(descriptor_key, program_info->program_type_descriptor);
    if (!IS_SUCCESS(result)) {
        goto Exit;
    }

    // Save helper count.
    result = ebpf_write_registry_value_dword(
        program_key, EBPF_PROGRAM_DATA_HELPER_COUNT, program_info->count_of_program_type_specific_helpers);
    if (!IS_SUCCESS(result)) {
        goto Exit;
    }

    if (program_info->count_of_program_type_specific_helpers == 0) {
        // No helpers to save.
        goto Exit;
    }

    // Create (or open) helper registry path.
    result = ebpf_create_registry_key(
        program_key, EBPF_PROGRAM_DATA_HELPERS_REGISTRY_KEY, REG_CREATE_FLAGS, &helper_info_key);
    if (!IS_SUCCESS(result)) {
        goto Exit;
    }

    // Iterate over all the helper prototypes and save in registry.
    for (uint32_t count = 0; count < program_info->count_of_program_type_specific_helpers; count++) {
        result = _ebpf_store_update_helper_prototype(
            helper_info_key, &(program_info->program_type_specific_helper_prototype[count]));
        if (!IS_SUCCESS(result)) {
            goto Exit;
        }
    }

Exit:
    ebpf_close_registry_key(helper_info_key);
    ebpf_close_registry_key(descriptor_key);
    return result;
}

ebpf_result_t
ebpf_store_update_program_information_array(
    _In_reads_(program_info_count) const ebpf_program_info_t* program_info, uint32_t program_info_count)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_store_key_t provider_key = NULL;
    ebpf_store_key_t program_data_key = NULL;
    ebpf_program_info_t* new_program_info = NULL;

    if (program_info_count == 0) {
        return result;
    }

    // Open (or create) provider registry path.
    result = _ebpf_store_open_or_create_provider_registry_key(&provider_key);
    if (!IS_SUCCESS(result)) {
        goto Exit;
    }

    // Open (or create) program data registry path.
    result =
        ebpf_create_registry_key(provider_key, EBPF_PROGRAM_DATA_REGISTRY_KEY, REG_CREATE_FLAGS, &program_data_key);
    if (!IS_SUCCESS(result)) {
        goto Exit;
    }

    // Populate the information for each program type.
    for (uint32_t i = 0; i < program_info_count; i++) {
        ebpf_store_key_t program_info_key = {0};

        if (!ebpf_validate_program_info(&program_info[i])) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        // Duplicate the program information to the latest version with safe defaults.
        result = ebpf_duplicate_program_info(&program_info[i], &new_program_info);
        if (!IS_SUCCESS(result)) {
            goto Exit;
        }

        // Convert program type GUID to string.
        wchar_t guid_string[GUID_STRING_LENGTH + 1];
        result = ebpf_convert_guid_to_string(
            &new_program_info->program_type_descriptor->program_type, guid_string, GUID_STRING_LENGTH + 1);
        if (!IS_SUCCESS(result)) {
            goto Exit;
        }

        // Create program information key with the program type GUID as the name.
        result = ebpf_create_registry_key(program_data_key, guid_string, REG_CREATE_FLAGS, &program_info_key);
        if (!IS_SUCCESS(result)) {
            goto Exit;
        }

        // Save program information.
        result = _ebpf_store_update_program_info(program_info_key, (const ebpf_program_info_t*)new_program_info);
        ebpf_close_registry_key(program_info_key);
        if (!IS_SUCCESS(result)) {
            goto Exit;
        }

        ebpf_program_info_free(new_program_info);
        new_program_info = NULL;
    }

Exit:
    ebpf_close_registry_key(program_data_key);
    ebpf_close_registry_key(provider_key);
    if (new_program_info != NULL) {
        ebpf_program_info_free(new_program_info);
    }

    return result;
}

ebpf_result_t
ebpf_store_delete_program_information(_In_ const ebpf_program_info_t* program_info)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_store_key_t provider_key = NULL;
    ebpf_store_key_t program_info_key = NULL;

    // Open (or create) provider registry path.
    result = _ebpf_store_open_or_create_provider_registry_key(&provider_key);
    if (!IS_SUCCESS(result)) {
        goto Exit;
    }

    // Open program data registry path.
    result = ebpf_open_registry_key(provider_key, EBPF_PROGRAM_DATA_REGISTRY_KEY, REG_CREATE_FLAGS, &program_info_key);
    if (!IS_SUCCESS(result)) {
        goto Exit;
    }

    // Convert program type GUID to string.
    wchar_t guid_string[GUID_STRING_LENGTH + 1];
    result = ebpf_convert_guid_to_string(
        &program_info->program_type_descriptor->program_type, guid_string, GUID_STRING_LENGTH + 1);
    if (!IS_SUCCESS(result)) {
        goto Exit;
    }

    result = ebpf_delete_registry_tree(program_info_key, guid_string);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

Exit:
    ebpf_close_registry_key(program_info_key);
    ebpf_close_registry_key(provider_key);

    return result;
}

ebpf_result_t
ebpf_store_delete_section_information(_In_ const ebpf_program_section_info_t* section_info)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_store_key_t provider_key = NULL;
    ebpf_store_key_t section_info_key = NULL;

    // Open (or create) provider registry path.
    result = _ebpf_store_open_or_create_provider_registry_key(&provider_key);
    if (!IS_SUCCESS(result)) {
        goto Exit;
    }

    // Open (or create) section data key.
    result = ebpf_open_registry_key(provider_key, EBPF_SECTIONS_REGISTRY_KEY, REG_DELETE_FLAGS, &section_info_key);
    if (!IS_SUCCESS(result)) {
        goto Exit;
    }

    result = ebpf_delete_registry_tree(section_info_key, section_info->section_name);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

Exit:
    ebpf_close_registry_key(section_info_key);
    ebpf_close_registry_key(provider_key);

    return result;
}
