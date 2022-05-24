// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <ntddk.h>
#include "ebpf_program_types.h"
#include "ebpf_windows.h"

#define EBPF_ROOT_REGISTRY_PATH L"\\Registry\\Machine\\Software\\eBPF"
// #define EBPF_SECTIONS_REGISTRY_PATH L"\\Registry\\Machine\\Software\\eBPF\\Providers\\SectionData"
// #define EBPF_PROGRAM_DATA_REGISTRY_PATH L"\\Registry\\Machine\\Software\\eBPF\\Providers\\ProgramData"

#define EBPF_PROVIDERS_REGISTRY_PATH L"Providers"
#define EBPF_SECTIONS_REGISTRY_PATH L"SectionData"
#define EBPF_PROGRAM_DATA_REGISTRY_PATH L"ProgramData"

#define EBPF_SECTION_DATA_PROGRAM_TYPE L"ProgramType"
#define EBPF_SECTION_DATA_ATTACH_TYPE L"AttachType"

#define EBPF_PROGRAM_DATA_NAME L"Name"
#define EBPF_PROGRAM_DATA_CONTEXT_DESCRIPTOR L"ContextDescriptor"
#define EBPF_PROGRAM_DATA_PLATFORM_SPECIFIC_DATA L"PlatformSpecificData"
#define EBPF_PROGRAM_DATA_PRIVELEGED L"IsPrivileged"

typedef struct _ebpf_section_info
{
    wchar_t* section_name;
    ebpf_program_type_t program_type;
    ebpf_attach_type_t attach_type;
} ebpf_section_info_t;

static __forceinline NTSTATUS
ebpf_registry_update_section_information(
    _In_reads_(section_info_count) ebpf_section_info_t* section_info, int section_info_count)
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
ebpf_registry_update_program_information(
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

    // Open or create the registry path.
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
        /*
                RtlInitUnicodeString(&value_name, EBPF_PROGRAM_DATA_NAME);
                status = ZwSetValueKey(program_handle, &value_name, 0, REG_BINARY,
           (void*)program_info[i].program_type_descriptor.name,
           (ULONG)strlen(program_info[i].program_type_descriptor.name)); if (!NT_SUCCESS(status)) {
                    ZwClose(program_handle);
                    goto Exit;
                }
        */
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
