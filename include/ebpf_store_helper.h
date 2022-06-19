// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_program_types.h"
#ifndef USER_MODE
#include "ebpf_registry_helper.h"
#else
#include "um_registry_helper.h"
#endif
#include "ebpf_windows.h"

#ifndef USER_MODE
#define __return_type NTSTATUS
#define IS_SUCCESS(x) (NT_SUCCESS(x))
#define _SUCCESS STATUS_SUCCESS
#else
#define __return_type uint32_t
#define IS_SUCCESS(x) (x == ERROR_SUCCESS)
#define _SUCCESS NO_ERROR
#endif

typedef struct _ebpf_registry_key ebpf_registry_key_t;

#ifdef USER_MODE
extern ebpf_registry_key_t root_registry_key;
#endif

static uint32_t
_open_or_create_provider_registry_key(_Out_ ebpf_registry_key_t* provider_key)
{
    __return_type status = _SUCCESS;
    ebpf_registry_key_t root_handle = {0};
    provider_key->key = NULL;

    // Open (or create) root eBPF registry path.
#ifndef USER_MODE
    status = create_registry_key(NULL, EBPF_ROOT_REGISTRY_PATH, REG_CREATE_FLAGS, &root_handle);
#else
    status = create_registry_key(&root_registry_key, EBPF_ROOT_RELATIVE_PATH, REG_CREATE_FLAGS, &root_handle);
#endif
    if (!IS_SUCCESS(status)) {
        goto Exit;
    }

    // Open (or create) program data registry path.
#ifndef USER_MODE
    status = create_registry_key(&root_handle, EBPF_PROVIDERS_REGISTRY_PATH, REG_CREATE_FLAGS, provider_key);
#else
    status = create_registry_key(&root_handle, EBPF_PROVIDERS_REGISTRY_PATH, REG_CREATE_FLAGS, provider_key);
#endif
    if (!IS_SUCCESS(status)) {
        goto Exit;
    }

Exit:
    close_registry_handle(&root_handle);
    return status;
}

static __forceinline __return_type
_update_helper_prototype(
    _In_ const ebpf_registry_key_t* helper_info_handle, _In_ const ebpf_helper_function_prototype_t* helper_info)
{
    __return_type status = _SUCCESS;
    uint32_t offset;
    ebpf_registry_key_t helper_function_handle = {0};
    char serialized_data[sizeof(ebpf_helper_function_prototype_t)] = {0};

    status = create_registry_key_ansi(helper_info_handle, helper_info->name, REG_CREATE_FLAGS, &helper_function_handle);
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
        &helper_function_handle, EBPF_HELPER_DATA_PROTOTYPE, (uint8_t*)&serialized_data[0], offset);
    if (!IS_SUCCESS(status)) {
        goto Exit;
    }

Exit:
    close_registry_handle(&helper_function_handle);

    return status;
}

static __forceinline __return_type
ebpf_store_update_section_information(
    _In_reads_(section_info_count) ebpf_program_section_info_t* section_info, int section_info_count)
{
    __return_type status = _SUCCESS;
    ebpf_registry_key_t provider_handle = {0};
    ebpf_registry_key_t section_info_handle = {0};

    if (section_info_count == 0) {
        return status;
    }

    // Open (or create) provider registry path.
    status = _open_or_create_provider_registry_key(&provider_handle);
    if (!IS_SUCCESS(status)) {
        goto Exit;
    }

    // Open (or create) section data handle.
    status = create_registry_key(&provider_handle, EBPF_SECTIONS_REGISTRY_PATH, REG_CREATE_FLAGS, &section_info_handle);
    if (!IS_SUCCESS(status)) {
        goto Exit;
    }

    for (int i = 0; i < section_info_count; i++) {
        ebpf_registry_key_t section_handle = {0};

        // Open or create the registry path.
        status =
            create_registry_key(&section_info_handle, section_info[i].section_name, REG_CREATE_FLAGS, &section_handle);
        if (!IS_SUCCESS(status)) {
            goto Exit;
        }

        // Save program type.
        status = write_registry_value_binary(
            &section_handle,
            EBPF_SECTION_DATA_PROGRAM_TYPE,
            (uint8_t*)section_info[i].program_type,
            sizeof(ebpf_program_type_t));
        if (!IS_SUCCESS(status)) {
            close_registry_handle(&section_handle);
            goto Exit;
        }

        // Save attach type.
        status = write_registry_value_binary(
            &section_handle,
            EBPF_SECTION_DATA_ATTACH_TYPE,
            (uint8_t*)section_info[i].attach_type,
            sizeof(ebpf_attach_type_t));
        if (!IS_SUCCESS(status)) {
            close_registry_handle(&section_handle);
            goto Exit;
        }

        // Save bpf_prog_type
        status = write_registry_value_dword(
            &section_handle, EBPF_PROGRAM_DATA_BPF_PROG_TYPE, section_info[i].bpf_program_type);
        if (!IS_SUCCESS(status)) {
            close_registry_handle(&section_handle);
            goto Exit;
        }

        // Save bpf_attach_type
        status = write_registry_value_dword(
            &section_handle, EBPF_SECTION_DATA_BPF_ATTACH_TYPE, section_info[i].bpf_attach_type);
        if (!IS_SUCCESS(status)) {
            close_registry_handle(&section_handle);
            goto Exit;
        }

        close_registry_handle(&section_handle);
    }

Exit:
    close_registry_handle(&section_info_handle);
    close_registry_handle(&provider_handle);

    return status;
}

static __forceinline __return_type
ebpf_store_update_program_information(
    _In_reads_(program_info_count) ebpf_program_info_t* program_info, int program_info_count)
{
    __return_type status = _SUCCESS;
    ebpf_registry_key_t provider_handle = {0};
    ebpf_registry_key_t program_info_handle = {0};

    if (program_info_count == 0) {
        return status;
    }

    // Open (or create) provider registry path.
    status = _open_or_create_provider_registry_key(&provider_handle);
    if (!IS_SUCCESS(status)) {
        goto Exit;
    }

    // Open (or create) program data registry path.
    status =
        create_registry_key(&provider_handle, EBPF_PROGRAM_DATA_REGISTRY_PATH, REG_CREATE_FLAGS, &program_info_handle);
    if (!IS_SUCCESS(status)) {
        goto Exit;
    }

    for (int i = 0; i < program_info_count; i++) {
        ebpf_registry_key_t program_handle = {0};
        ebpf_registry_key_t helper_info_handle = {0};

        // Convert program type GUID to string
        wchar_t guid_string[GUID_STRING_LENGTH + 1];
        status = convert_guid_to_string(
            &program_info[i].program_type_descriptor.program_type, guid_string, GUID_STRING_LENGTH + 1);
        if (status != _SUCCESS) {
            return status;
        }

        status = create_registry_key(&program_info_handle, guid_string, REG_CREATE_FLAGS, &program_handle);
        if (!IS_SUCCESS(status)) {
            goto Exit;
        }

        // Save the friendly program type name.
        status = write_registry_value_ansi_string(
            &program_handle, EBPF_PROGRAM_DATA_NAME, program_info[i].program_type_descriptor.name);
        if (!IS_SUCCESS(status)) {
            close_registry_handle(&program_handle);
            goto Exit;
        }

        // Save context descriptor.
        status = write_registry_value_binary(
            &program_handle,
            EBPF_PROGRAM_DATA_CONTEXT_DESCRIPTOR,
            (uint8_t*)program_info[i].program_type_descriptor.context_descriptor,
            sizeof(ebpf_context_descriptor_t));
        if (!IS_SUCCESS(status)) {
            close_registry_handle(&program_handle);
            goto Exit;
        }

        // Save bpf_prog_type.
        status = write_registry_value_dword(
            &program_handle, EBPF_PROGRAM_DATA_BPF_PROG_TYPE, program_info[i].program_type_descriptor.bpf_prog_type);
        if (!IS_SUCCESS(status)) {
            close_registry_handle(&program_handle);
            goto Exit;
        }

        // Save "is_privileged"
        status = write_registry_value_dword(
            &program_handle, EBPF_PROGRAM_DATA_PRIVELEGED, program_info[i].program_type_descriptor.is_privileged);
        if (!IS_SUCCESS(status)) {
            close_registry_handle(&program_handle);
            goto Exit;
        }

        // Save helper count.
        status = write_registry_value_dword(
            &program_handle, EBPF_PROGRAM_DATA_HELPER_COUNT, program_info[i].count_of_helpers);
        if (!IS_SUCCESS(status)) {
            close_registry_handle(&program_handle);
            goto Exit;
        }

        if (program_info[i].count_of_helpers != 0) {
            // Create (or open) helper registry path.
            status = create_registry_key(
                &program_handle, EBPF_PROGRAM_DATA_HELPERS_REGISTRY_PATH, REG_CREATE_FLAGS, &helper_info_handle);
            if (!IS_SUCCESS(status)) {
                close_registry_handle(&program_handle);
                goto Exit;
            }

            // Iterate over all the helper prototypes and save in registry.
            for (uint32_t count = 0; count < program_info[i].count_of_helpers; count++) {
                status = _update_helper_prototype(&helper_info_handle, &(program_info[i].helper_prototype[count]));
                if (!IS_SUCCESS(status)) {
                    close_registry_handle(&program_handle);
                    close_registry_handle(&helper_info_handle);
                    goto Exit;
                }
            }

            close_registry_handle(&helper_info_handle);
        }
        close_registry_handle(&program_handle);
    }

Exit:
    close_registry_handle(&program_info_handle);
    close_registry_handle(&provider_handle);

    return status;
}

static __forceinline __return_type
ebpf_store_update_global_helper_information(
    _In_reads_(helper_info_count) ebpf_helper_function_prototype_t* helper_info, int helper_info_count)
{
    __return_type status = _SUCCESS;
    ebpf_registry_key_t provider_handle = {0};
    ebpf_registry_key_t helper_info_handle = {0};

    if (helper_info_count == 0) {
        return status;
    }

    // Open (or create) provider registry path.
    status = _open_or_create_provider_registry_key(&provider_handle);
    if (!IS_SUCCESS(status)) {
        goto Exit;
    }

    // Open (or create) global helpers registry path.
    status =
        create_registry_key(&provider_handle, EBPF_GLOBAL_HELPERS_REGISTRY_PATH, REG_CREATE_FLAGS, &helper_info_handle);
    if (!IS_SUCCESS(status)) {
        goto Exit;
    }

    for (int i = 0; i < helper_info_count; i++) {

        status = _update_helper_prototype(&helper_info_handle, &helper_info[i]);
        if (!IS_SUCCESS(status)) {
            goto Exit;
        }
    }

Exit:

    close_registry_handle(&helper_info_handle);
    close_registry_handle(&provider_handle);

    return status;
}

/*
static __forceinline __return_type
ebpf_registry_delete_program_information(
    _In_reads_(program_count) ebpf_program_type_t* program_types, int program_count)
{
    __return_type status = _SUCCESS;
    HANDLE root_handle = NULL;
    HANDLE provider_handle = NULL;
    HANDLE program_info_handle = NULL;
    UNICODE_STRING registry_path;
    OBJECT_ATTRIBUTES object_attributes = {0};

    if (program_info_count == 0) {
        return status;
    }

    // Open root eBPF registry path.
    RtlInitUnicodeString(&registry_path, EBPF_ROOT_REGISTRY_PATH);
    InitializeObjectAttributes(
        &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    // status = ZwCreateKey(&root_handle, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    status = ZwOpenKey(&root_handle, KEY_READ | KEY_NOTIFY | KEY_WRITE, &object_attributes);
    if (!IS_SUCCESS(status)) {
        goto Exit;
    }

    // Open provider registry path.
    RtlInitUnicodeString(&registry_path, EBPF_PROVIDERS_REGISTRY_PATH);
    InitializeObjectAttributes(
        &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, root_handle, NULL);

    // status = ZwCreateKey(&provider_handle, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    status = ZwOpenKey(&provider_handle, KEY_READ | KEY_NOTIFY | KEY_WRITE, &object_attributes);
    if (!IS_SUCCESS(status)) {
        goto Exit;
    }

    // Open program data registry path.
    RtlInitUnicodeString(&registry_path, EBPF_PROGRAM_DATA_REGISTRY_PATH);
    InitializeObjectAttributes(
        &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, provider_handle, NULL);

    // status = ZwCreateKey(&program_info_handle, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE,
NULL); status = ZwOpenKey(&program_info_handle, KEY_READ | KEY_NOTIFY | KEY_WRITE, &object_attributes); if
(!IS_SUCCESS(status)) { goto Exit;
    }

    for (int i = 0; i < program_info_count; i++) {
        OBJECT_ATTRIBUTES program_attributes = {0};
        UNICODE_STRING value_name;
        ANSI_STRING friendly_name;
        UNICODE_STRING unicode_friendly_name;
        HANDLE program_handle;

        // Convert program type GUID to string
        status = RtlStringFromGUID(&program_info[i].program_type_descriptor.program_type, &value_name);
        if (status != _SUCCESS) {
            return status;
        }

        InitializeObjectAttributes(
            &program_attributes, &value_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, program_info_handle, NULL);

        // Open or create the registry path.
        status = ZwCreateKey(&program_handle, KEY_WRITE, &program_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);

        if (!IS_SUCCESS(status)) {
            goto Exit;
        }

        // Save the friendly program type name.
        RtlInitUnicodeString(&value_name, EBPF_PROGRAM_DATA_NAME);
        RtlInitAnsiString(&friendly_name, program_info[i].program_type_descriptor.name);
        status = RtlAnsiStringToUnicodeString(&unicode_friendly_name, &friendly_name, TRUE);
        if (!IS_SUCCESS(status)) {
            ZwClose(program_handle);
            goto Exit;
        }
        status = ZwSetValueKey(
            program_handle, &value_name, 0, REG_SZ, unicode_friendly_name.Buffer, unicode_friendly_name.Length);
        if (!IS_SUCCESS(status)) {
            ZwClose(program_handle);
            RtlFreeUnicodeString(&unicode_friendly_name);
            goto Exit;
        }
        RtlFreeUnicodeString(&unicode_friendly_name);

        // Save context descriptor.
        RtlInitUnicodeString(&value_name, EBPF_PROGRAM_DATA_CONTEXT_DESCRIPTOR);
        status = ZwSetValueKey(
            program_handle,
            &value_name,
            0,
            REG_BINARY,
            &program_info[i].program_type_descriptor.context_descriptor,
            sizeof(ebpf_context_descriptor_t));
        if (!IS_SUCCESS(status)) {
            ZwClose(program_handle);
            goto Exit;
        }

        // Save "is_privileged"
        RtlInitUnicodeString(&value_name, EBPF_PROGRAM_DATA_PRIVELEGED);
        uint32_t is_privileged = program_info[i].program_type_descriptor.is_privileged;
        status = ZwSetValueKey(program_handle, &value_name, 0, REG_DWORD, &is_privileged, sizeof(uint32_t));
        if (!IS_SUCCESS(status)) {
            ZwClose(program_handle);
            goto Exit;
        }

        // TODO: Save helper information.

        ZwClose(program_handle);
    }

Exit:
    if (program_info_handle) {
        ZwClose(program_info_handle);
    }
    if (provider_handle) {
        ZwClose(provider_handle);
    }
    if (root_handle) {
        ZwClose(root_handle);
    }
    return status;
}
*/
