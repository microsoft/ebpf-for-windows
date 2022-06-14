// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <ntddk.h>
#include "ebpf_program_types.h"
#include "ebpf_windows.h"

#define EBPF_ROOT_REGISTRY_PATH L"\\Registry\\Machine\\Software\\eBPF"

#define EBPF_PROVIDERS_REGISTRY_PATH L"Providers"
#define EBPF_SECTIONS_REGISTRY_PATH L"SectionData"
#define EBPF_PROGRAM_DATA_REGISTRY_PATH L"ProgramData"
#define EBPF_PROGRAM_DATA_HELPERS_REGISTRY_PATH L"Helpers"
#define EBPF_GLOBAL_HELPERS_REGISTRY_PATH L"GlobalHelpers"

#define EBPF_SECTION_DATA_PROGRAM_TYPE L"ProgramType"
#define EBPF_SECTION_DATA_ATTACH_TYPE L"AttachType"

#define EBPF_PROGRAM_DATA_NAME L"Name"
#define EBPF_PROGRAM_DATA_CONTEXT_DESCRIPTOR L"ContextDescriptor"
#define EBPF_PROGRAM_DATA_PLATFORM_SPECIFIC_DATA L"PlatformSpecificData"
#define EBPF_PROGRAM_DATA_PRIVELEGED L"IsPrivileged"
#define EBPF_PROGRAM_DATA_BPF_PROG_TYPE L"BpfProgType"
#define EBPF_PROGRAM_DATA_HELPER_COUNT L"HelperCount"

#define EBPF_HELPER_DATA_PROTOTYPE L"Prototype"

typedef struct _ebpf_store_section_info
{
    wchar_t* section_name;
    ebpf_program_type_t program_type;
    ebpf_attach_type_t attach_type;
    uint32_t bpf_program_type;
    uint32_t bpf_attach_type;
} ebpf_store_section_info_t;

static __forceinline NTSTATUS
_update_helper_prototype(HANDLE helper_info_handle, _In_ const ebpf_helper_function_prototype_t* helper_info)
{
    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES helper_attributes = {0};
    UNICODE_STRING value_name;
    ANSI_STRING helper_name;
    HANDLE helper_function_handle = NULL;
    RtlInitAnsiString(&helper_name, helper_info->name);
    status = RtlAnsiStringToUnicodeString(&value_name, &helper_name, TRUE);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    InitializeObjectAttributes(
        &helper_attributes, &value_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, helper_info_handle, NULL);

    // Open or create the registry path.
    status =
        ZwCreateKey(&helper_function_handle, KEY_WRITE, &helper_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(status)) {
        RtlFreeUnicodeString(&value_name);
        goto Exit;
    }

    RtlFreeUnicodeString(&value_name);

    // Serialize the helper prototype.
    char serialized_data[sizeof(ebpf_helper_function_prototype_t)] = {0};
    uint32_t offset = 0;
    memcpy(serialized_data, &helper_info->helper_id, sizeof(helper_info->helper_id));
    offset += sizeof(helper_info->helper_id);

    memcpy(serialized_data + offset, &helper_info->return_type, sizeof(helper_info->return_type));
    offset += sizeof(helper_info->return_type);

    memcpy(serialized_data + offset, helper_info->arguments, sizeof(helper_info->arguments));
    offset += sizeof(helper_info->arguments);

    // Save the helper prototype data.
    RtlInitUnicodeString(&value_name, EBPF_HELPER_DATA_PROTOTYPE);
    status = ZwSetValueKey(helper_function_handle, &value_name, 0, REG_BINARY, &serialized_data[0], offset);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

Exit:
    if (helper_function_handle) {
        ZwClose(helper_function_handle);
    }
    return status;
}

static __forceinline NTSTATUS
ebpf_store_update_section_information(
    _In_reads_(section_info_count) ebpf_store_section_info_t* section_info, int section_info_count)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE root_handle = NULL;
    HANDLE provider_handle = NULL;
    HANDLE section_info_handle = NULL;
    UNICODE_STRING registry_path;
    OBJECT_ATTRIBUTES object_attributes = {0};

    if (section_info_count == 0) {
        return status;
    }

    // Open (or create) root eBPF registry path.
    RtlInitUnicodeString(&registry_path, EBPF_ROOT_REGISTRY_PATH);
    InitializeObjectAttributes(
        &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateKey(&root_handle, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    // Open (or create) provider registry path.
    RtlInitUnicodeString(&registry_path, EBPF_PROVIDERS_REGISTRY_PATH);
    InitializeObjectAttributes(
        &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, root_handle, NULL);

    status = ZwCreateKey(&provider_handle, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    // Open (or create) section data handle.
    RtlInitUnicodeString(&registry_path, EBPF_SECTIONS_REGISTRY_PATH);
    InitializeObjectAttributes(
        &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, provider_handle, NULL);

    status = ZwCreateKey(&section_info_handle, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    for (int i = 0; i < section_info_count; i++) {
        OBJECT_ATTRIBUTES section_attributes = {0};
        UNICODE_STRING value_name;
        HANDLE section_handle;

        RtlInitUnicodeString(&value_name, section_info[i].section_name);
        InitializeObjectAttributes(
            &section_attributes, &value_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, section_info_handle, NULL);

        // Open or create the registry path.
        status = ZwCreateKey(&section_handle, KEY_WRITE, &section_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);

        if (!NT_SUCCESS(status)) {
            goto Exit;
        }

        // Save program type.
        RtlInitUnicodeString(&value_name, EBPF_SECTION_DATA_PROGRAM_TYPE);
        status = ZwSetValueKey(
            section_handle, &value_name, 0, REG_BINARY, &section_info[i].program_type, sizeof(ebpf_program_type_t));
        if (!NT_SUCCESS(status)) {
            ZwClose(section_handle);
            goto Exit;
        }

        // Save attach type.
        RtlInitUnicodeString(&value_name, EBPF_SECTION_DATA_ATTACH_TYPE);
        status = ZwSetValueKey(
            section_handle, &value_name, 0, REG_BINARY, &section_info[i].attach_type, sizeof(ebpf_attach_type_t));
        if (!NT_SUCCESS(status)) {
            ZwClose(section_handle);
            goto Exit;
        }

        ZwClose(section_handle);
    }

Exit:
    if (section_info_handle) {
        ZwClose(section_info_handle);
    }
    if (provider_handle) {
        ZwClose(provider_handle);
    }
    if (root_handle) {
        ZwClose(root_handle);
    }

    return status;
}

static __forceinline NTSTATUS
ebpf_store_update_program_information(
    _In_reads_(program_info_count) ebpf_program_info_t* program_info, int program_info_count)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE root_handle = NULL;
    HANDLE provider_handle = NULL;
    HANDLE program_info_handle = NULL;
    UNICODE_STRING registry_path;
    OBJECT_ATTRIBUTES object_attributes = {0};

    if (program_info_count == 0) {
        return status;
    }

    // Open (or create) root eBPF registry path.
    RtlInitUnicodeString(&registry_path, EBPF_ROOT_REGISTRY_PATH);
    InitializeObjectAttributes(
        &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateKey(&root_handle, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    // Open (or create) provider registry path.
    RtlInitUnicodeString(&registry_path, EBPF_PROVIDERS_REGISTRY_PATH);
    InitializeObjectAttributes(
        &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, root_handle, NULL);

    status = ZwCreateKey(&provider_handle, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    // Open program data registry path.
    RtlInitUnicodeString(&registry_path, EBPF_PROGRAM_DATA_REGISTRY_PATH);
    InitializeObjectAttributes(
        &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, provider_handle, NULL);

    status = ZwCreateKey(&program_info_handle, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    for (int i = 0; i < program_info_count; i++) {
        OBJECT_ATTRIBUTES program_attributes = {0};
        UNICODE_STRING value_name;
        ANSI_STRING friendly_name;
        UNICODE_STRING unicode_friendly_name;
        HANDLE program_handle;
        HANDLE helper_info_handle;

        // Convert program type GUID to string
        status = RtlStringFromGUID(&program_info[i].program_type_descriptor.program_type, &value_name);
        if (status != STATUS_SUCCESS) {
            return status;
        }

        InitializeObjectAttributes(
            &program_attributes, &value_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, program_info_handle, NULL);

        status = ZwCreateKey(&program_handle, KEY_WRITE, &program_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
        if (!NT_SUCCESS(status)) {
            goto Exit;
        }

        // Save the friendly program type name.
        RtlInitUnicodeString(&value_name, EBPF_PROGRAM_DATA_NAME);
        RtlInitAnsiString(&friendly_name, program_info[i].program_type_descriptor.name);
        status = RtlAnsiStringToUnicodeString(&unicode_friendly_name, &friendly_name, TRUE);
        if (!NT_SUCCESS(status)) {
            ZwClose(program_handle);
            goto Exit;
        }
        status = ZwSetValueKey(
            program_handle, &value_name, 0, REG_SZ, unicode_friendly_name.Buffer, unicode_friendly_name.Length);
        if (!NT_SUCCESS(status)) {
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
        if (!NT_SUCCESS(status)) {
            ZwClose(program_handle);
            goto Exit;
        }

        // Save bpf_prog_type
        RtlInitUnicodeString(&value_name, EBPF_PROGRAM_DATA_BPF_PROG_TYPE);
        uint32_t bpf_prog_type = program_info[i].program_type_descriptor.bpf_prog_type;
        status = ZwSetValueKey(program_handle, &value_name, 0, REG_DWORD, &bpf_prog_type, sizeof(uint32_t));
        if (!NT_SUCCESS(status)) {
            ZwClose(program_handle);
            goto Exit;
        }

        // Save "is_privileged"
        RtlInitUnicodeString(&value_name, EBPF_PROGRAM_DATA_PRIVELEGED);
        uint32_t is_privileged = program_info[i].program_type_descriptor.is_privileged;
        status = ZwSetValueKey(program_handle, &value_name, 0, REG_DWORD, &is_privileged, sizeof(uint32_t));
        if (!NT_SUCCESS(status)) {
            ZwClose(program_handle);
            goto Exit;
        }

        // Save helper count.
        RtlInitUnicodeString(&value_name, EBPF_PROGRAM_DATA_HELPER_COUNT);
        uint32_t helper_count = program_info[i].count_of_helpers;
        status = ZwSetValueKey(program_handle, &value_name, 0, REG_DWORD, &helper_count, sizeof(uint32_t));
        if (!NT_SUCCESS(status)) {
            ZwClose(program_handle);
            goto Exit;
        }

        if (program_info[i].count_of_helpers != 0) {
            // Create (or open) helper registry path.
            RtlInitUnicodeString(&registry_path, EBPF_PROGRAM_DATA_HELPERS_REGISTRY_PATH);
            InitializeObjectAttributes(
                &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, program_handle, NULL);

            status =
                ZwCreateKey(&helper_info_handle, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
            if (!NT_SUCCESS(status)) {
                ZwClose(program_handle);
                goto Exit;
            }

            // Iterate over all the helper prototypes and save in registry.
            for (uint32_t count = 0; count < program_info[i].count_of_helpers; count++) {
                status = _update_helper_prototype(helper_info_handle, &(program_info[i].helper_prototype[count]));
                if (!NT_SUCCESS(status)) {
                    ZwClose(program_handle);
                    ZwClose(helper_info_handle);
                    goto Exit;
                }
            }

            ZwClose(helper_info_handle);
        }
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

static __forceinline NTSTATUS
ebpf_store_update_global_helper_information(
    _In_reads_(helper_info_count) ebpf_helper_function_prototype_t* helper_info, int helper_info_count)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE root_handle = NULL;
    HANDLE provider_handle = NULL;
    HANDLE helper_info_handle = NULL;
    UNICODE_STRING registry_path;
    OBJECT_ATTRIBUTES object_attributes = {0};

    if (helper_info_count == 0) {
        return status;
    }

    // Open (or create) root eBPF registry path.
    RtlInitUnicodeString(&registry_path, EBPF_ROOT_REGISTRY_PATH);
    InitializeObjectAttributes(
        &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateKey(&root_handle, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    // Open (or create) provider registry path.
    RtlInitUnicodeString(&registry_path, EBPF_PROVIDERS_REGISTRY_PATH);
    InitializeObjectAttributes(
        &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, root_handle, NULL);

    status = ZwCreateKey(&provider_handle, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    // Open global helpers registry path.
    RtlInitUnicodeString(&registry_path, EBPF_GLOBAL_HELPERS_REGISTRY_PATH);
    InitializeObjectAttributes(
        &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, provider_handle, NULL);

    status = ZwCreateKey(&helper_info_handle, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    for (int i = 0; i < helper_info_count; i++) {

        status = _update_helper_prototype(helper_info_handle, &helper_info[i]);
        if (!NT_SUCCESS(status)) {
            goto Exit;
        }

        /*
        OBJECT_ATTRIBUTES helper_attributes = {0};
        UNICODE_STRING value_name;
        ANSI_STRING helper_name;
        HANDLE helper_function_handle;

        RtlInitAnsiString(&helper_name, helper_info[i].name);
        status = RtlAnsiStringToUnicodeString(&value_name, &helper_name, TRUE);
        if (!NT_SUCCESS(status)) {
            goto Exit;
        }

        InitializeObjectAttributes(
            &helper_attributes, &value_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, helper_info_handle, NULL);

        // Open or create the registry path.
        status = ZwCreateKey(&helper_function_handle, KEY_WRITE, &helper_attributes, 0, NULL, REG_OPTION_NON_VOLATILE,
        NULL); if (!NT_SUCCESS(status)) { RtlFreeUnicodeString(&value_name); goto Exit;
        }

        RtlFreeUnicodeString(&value_name);

        // Serialize the helper prototype.
        char serialized_data[sizeof(ebpf_helper_function_prototype_t)];
        uint32_t total_size = 0;
        memcpy(serialized_data, &helper_info[i].helper_id, sizeof(helper_info[i].helper_id));
        total_size += sizeof(helper_info[i].helper_id);

        memcpy(serialized_data + total_size, &helper_info[i].return_type, sizeof(helper_info[i].return_type));
        total_size += sizeof(helper_info[i].return_type);

        memcpy(serialized_data + total_size, helper_info[i].arguments, sizeof(helper_info[i].arguments));
        total_size += sizeof(helper_info[i].arguments);

        // Save the helper prototype data.
        RtlInitUnicodeString(&value_name, EBPF_HELPER_DATA_PROTOTYPE);
        status = ZwSetValueKey(
            helper_function_handle, &value_name, 0, REG_SZ, serialized_data, total_size);
        if (!NT_SUCCESS(status)) {
            ZwClose(helper_function_handle);
            goto Exit;
        }

        ZwClose(helper_function_handle);
        */
    }

Exit:
    if (helper_info_handle) {
        ZwClose(helper_info_handle);
    }
    if (provider_handle) {
        ZwClose(provider_handle);
    }
    if (root_handle) {
        ZwClose(root_handle);
    }
    return status;
}

/*
static __forceinline NTSTATUS
ebpf_registry_delete_program_information(
    _In_reads_(program_count) ebpf_program_type_t* program_types, int program_count)
{
    NTSTATUS status = STATUS_SUCCESS;
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
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    // Open provider registry path.
    RtlInitUnicodeString(&registry_path, EBPF_PROVIDERS_REGISTRY_PATH);
    InitializeObjectAttributes(
        &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, root_handle, NULL);

    // status = ZwCreateKey(&provider_handle, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    status = ZwOpenKey(&provider_handle, KEY_READ | KEY_NOTIFY | KEY_WRITE, &object_attributes);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    // Open program data registry path.
    RtlInitUnicodeString(&registry_path, EBPF_PROGRAM_DATA_REGISTRY_PATH);
    InitializeObjectAttributes(
        &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, provider_handle, NULL);

    // status = ZwCreateKey(&program_info_handle, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE,
NULL); status = ZwOpenKey(&program_info_handle, KEY_READ | KEY_NOTIFY | KEY_WRITE, &object_attributes); if
(!NT_SUCCESS(status)) { goto Exit;
    }

    for (int i = 0; i < program_info_count; i++) {
        OBJECT_ATTRIBUTES program_attributes = {0};
        UNICODE_STRING value_name;
        ANSI_STRING friendly_name;
        UNICODE_STRING unicode_friendly_name;
        HANDLE program_handle;

        // Convert program type GUID to string
        status = RtlStringFromGUID(&program_info[i].program_type_descriptor.program_type, &value_name);
        if (status != STATUS_SUCCESS) {
            return status;
        }

        InitializeObjectAttributes(
            &program_attributes, &value_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, program_info_handle, NULL);

        // Open or create the registry path.
        status = ZwCreateKey(&program_handle, KEY_WRITE, &program_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);

        if (!NT_SUCCESS(status)) {
            goto Exit;
        }

        // Save the friendly program type name.
        RtlInitUnicodeString(&value_name, EBPF_PROGRAM_DATA_NAME);
        RtlInitAnsiString(&friendly_name, program_info[i].program_type_descriptor.name);
        status = RtlAnsiStringToUnicodeString(&unicode_friendly_name, &friendly_name, TRUE);
        if (!NT_SUCCESS(status)) {
            ZwClose(program_handle);
            goto Exit;
        }
        status = ZwSetValueKey(
            program_handle, &value_name, 0, REG_SZ, unicode_friendly_name.Buffer, unicode_friendly_name.Length);
        if (!NT_SUCCESS(status)) {
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
        if (!NT_SUCCESS(status)) {
            ZwClose(program_handle);
            goto Exit;
        }

        // Save "is_privileged"
        RtlInitUnicodeString(&value_name, EBPF_PROGRAM_DATA_PRIVELEGED);
        uint32_t is_privileged = program_info[i].program_type_descriptor.is_privileged;
        status = ZwSetValueKey(program_handle, &value_name, 0, REG_DWORD, &is_privileged, sizeof(uint32_t));
        if (!NT_SUCCESS(status)) {
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
