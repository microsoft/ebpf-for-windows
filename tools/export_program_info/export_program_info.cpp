// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define USER_MODE
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#include <codecvt>

#include "ebpf_api.h"
#include "ebpf_nethooks.h"
#include "ebpf_store_helper.h"
#include "export_program_info.h"
#include "windows_program_type.h"

#include "ebpf_general_helpers.c"

#define REG_CREATE_FLAGS (KEY_WRITE | DELETE | KEY_READ)
#define REG_OPEN_FLAGS (DELETE | KEY_READ)

// TODO: Issue #XYZ Change to using HKEY_LOCAL_MACHINE
ebpf_registry_key_t root_registry_key = {HKEY_CURRENT_USER};

#define SIZE_OF_ARRAY(x) (sizeof(x) / sizeof(x[0]))

typedef struct _ebpf_program_section_info_with_count
{
    ebpf_program_section_info_t* section_info;
    size_t section_info_count;
} ebpf_program_section_info_with_count_t;

static ebpf_program_info_t* program_information_array[] = {
    &_ebpf_bind_program_info,
    &_ebpf_sock_addr_program_info,
    &_ebpf_sock_ops_program_info,
    &_ebpf_xdp_program_info,
    &_sample_ebpf_extension_program_info};

ebpf_program_section_info_t _sample_ext_section_info[] = {
    {L"sample_ext", &EBPF_PROGRAM_TYPE_SAMPLE, &EBPF_ATTACH_TYPE_SAMPLE, BPF_PROG_TYPE_SAMPLE, BPF_ATTACH_TYPE_SAMPLE}};

static std::vector<ebpf_program_section_info_with_count_t> _section_information = {
    {&_ebpf_bind_section_info[0], SIZE_OF_ARRAY(_ebpf_bind_section_info)},
    {&_ebpf_xdp_section_info[0], SIZE_OF_ARRAY(_ebpf_xdp_section_info)},
    {&_ebpf_sock_addr_section_info[0], SIZE_OF_ARRAY(_ebpf_sock_addr_section_info)},
    {&_ebpf_sock_ops_section_info[0], SIZE_OF_ARRAY(_ebpf_sock_ops_section_info)},
    {&_sample_ext_section_info[0], SIZE_OF_ARRAY(_sample_ext_section_info)},
};

/*
static uint32_t
_write_registry_value_dword(_In_ HKEY key, _In_ const wchar_t* value_name, uint32_t value)
{
    return RegSetValueEx(key, value_name, 0, REG_DWORD, (PBYTE)&value, sizeof(value));
}

static uint32_t
_write_registry_value_binary(
    _In_ HKEY key, _In_ const wchar_t* value_name, _In_reads_(value_size) uint8_t* value, _In_ size_t value_size)
{
    assert(value_name);
    assert(value);

    return RegSetValueEx(key, value_name, 0, REG_BINARY, value, (DWORD)value_size);
}

static uint32_t
_write_registry_value_string(_In_ HKEY key, _In_ const wchar_t* value_name, _In_z_ const wchar_t* value)
{
    assert(value_name);
    assert(value);

    auto length = (wcslen(value) + 1) * sizeof(wchar_t);
    return RegSetValueEx(key, value_name, 0, REG_SZ, (uint8_t*)value, (DWORD)length);
}
*/

/*
static uint32_t
_create_registry_key(_In_ HKEY root_key, _In_ const wchar_t* sub_key, uint32_t flags, _Out_ HKEY* key)
{
    return RegCreateKeyEx(root_key, sub_key, 0, nullptr, 0, flags, nullptr, key, nullptr);
}
*/

static uint32_t
_open_registry_key(_In_ HKEY root_key, _In_ const wchar_t* sub_key, uint32_t flags, _Out_ HKEY* key)
{
    return RegOpenKeyEx(root_key, sub_key, 0, flags, key);
}

static uint32_t
_delete_registry_key(_In_ HKEY root_key, _In_ const wchar_t* sub_key)
{
    return RegDeleteKeyEx(root_key, sub_key, 0, 0);
}

/*
static uint32_t
_open_or_create_provider_registry_key(_Out_ HKEY* provider_handle)
{
    HKEY root_handle = nullptr;
    uint32_t status;

    *provider_handle = nullptr;

    // Open (or create) root eBPF registry path.
    status = _create_registry_key(_root_registry_key, EBPF_ROOT_RELATIVE_PATH, REG_CREATE_FLAGS, &root_handle);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    // Open (or create) provider registry path.
    status = _create_registry_key(root_handle, EBPF_PROVIDERS_REGISTRY_PATH, REG_CREATE_FLAGS, provider_handle);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

Exit:
    if (root_handle) {
        RegCloseKey(root_handle);
    }

    return status;
}
*/

/*
static __forceinline NTSTATUS
_update_helper_prototype(HKEY helper_info_handle, _In_ const ebpf_helper_function_prototype_t* helper_info)
{
    uint32_t status = ERROR_SUCCESS;
    // OBJECT_ATTRIBUTES helper_attributes = { 0 };
    // UNICODE_STRING value_name;
    // ANSI_STRING helper_name;
    HKEY helper_function_handle = nullptr;
    uint8_t serialized_data[sizeof(ebpf_helper_function_prototype_t)] = {0};
    uint32_t offset;

    // Open or create the registry path.
    std::wstring helper_name = _get_wstring_from_string(std::string(helper_info->name));
    status = _create_registry_key(helper_info_handle, helper_name.c_str(), REG_CREATE_FLAGS, &helper_function_handle);
    if (status != ERROR_SUCCESS) {
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
    _write_registry_value_binary(helper_function_handle, EBPF_HELPER_DATA_PROTOTYPE, &serialized_data[0], offset);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

Exit:
    if (helper_function_handle) {
        RegCloseKey(helper_function_handle);
    }
    return status;
}
*/

/*
// TODO: Fix this function. This function should take array of pointers as input.
int
ebpf_store_update_program_information(
    _In_reads_(program_info_count) ebpf_program_info_t* program_info, int program_info_count)
{
    uint32_t status = ERROR_SUCCESS;
    RPC_STATUS rpc_status;
    HKEY provider_handle = nullptr;
    HKEY program_info_handle = nullptr;

    if (program_info_count == 0) {
        return status;
    }

    status = _open_or_create_provider_registry_key(&provider_handle);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    // Open program data registry path.
    status =
        _create_registry_key(provider_handle, EBPF_PROGRAM_DATA_REGISTRY_PATH, REG_CREATE_FLAGS, &program_info_handle);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    for (int i = 0; i < program_info_count; i++) {
        wchar_t* value_name;
        HKEY program_handle;
        HKEY helper_info_handle;

        // Convert program type GUID to string
        rpc_status = UuidToString(&program_info[i].program_type_descriptor.program_type, (RPC_WSTR*)&value_name);
        if (rpc_status != RPC_S_OK) {
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        std::wstring value_name_string(value_name);

        // UuidToString returns string without braces. Add braces to the resulting string.
        value_name_string = L"{" + value_name_string + L"}";
        status =
            _create_registry_key(program_info_handle, value_name_string.c_str(), REG_CREATE_FLAGS, &program_handle);
        if (status != ERROR_SUCCESS) {
            goto Exit;
        }

        // Save the friendly program type name.
        std::wstring wide_friendly_name =
            _get_wstring_from_string(std::string(program_info[i].program_type_descriptor.name));

        status = _write_registry_value_string(program_handle, EBPF_PROGRAM_DATA_NAME, wide_friendly_name.c_str());
        if (status != ERROR_SUCCESS) {
            RegCloseKey(program_handle);
            goto Exit;
        }

        // Save context descriptor.
        status = _write_registry_value_binary(
            program_handle,
            EBPF_PROGRAM_DATA_CONTEXT_DESCRIPTOR,
            (uint8_t*)program_info[i].program_type_descriptor.context_descriptor,
            sizeof(ebpf_context_descriptor_t));
        if (status != ERROR_SUCCESS) {
            RegCloseKey(program_handle);
            goto Exit;
        }

        // Save bpf_prog_type
        uint32_t bpf_prog_type = program_info[i].program_type_descriptor.bpf_prog_type;
        status = _write_registry_value_dword(program_handle, EBPF_PROGRAM_DATA_BPF_PROG_TYPE, bpf_prog_type);
        if (status != ERROR_SUCCESS) {
            RegCloseKey(program_handle);
            goto Exit;
        }

        // Save "is_privileged"
        uint32_t is_privileged = program_info[i].program_type_descriptor.is_privileged;
        status = _write_registry_value_dword(program_handle, EBPF_PROGRAM_DATA_PRIVELEGED, is_privileged);
        if (status != ERROR_SUCCESS) {
            RegCloseKey(program_handle);
            goto Exit;
        }

        // Save helper count.
        status = _write_registry_value_dword(
            program_handle, EBPF_PROGRAM_DATA_HELPER_COUNT, program_info[i].count_of_helpers);
        if (status != ERROR_SUCCESS) {
            RegCloseKey(program_handle);
            goto Exit;
        }

        if (program_info[i].count_of_helpers != 0) {
            // Create (or open) helper registry path.
            status = _create_registry_key(
                program_handle, EBPF_PROGRAM_DATA_HELPERS_REGISTRY_PATH, REG_CREATE_FLAGS, &helper_info_handle);
            if (status != ERROR_SUCCESS) {
                RegCloseKey(program_handle);
                goto Exit;
            }

            // Iterate over all the helper prototypes and save in registry.
            for (uint32_t count = 0; count < program_info[i].count_of_helpers; count++) {
                status = _update_helper_prototype(helper_info_handle, &(program_info[i].helper_prototype[count]));
                if (status != ERROR_SUCCESS) {
                    RegCloseKey(program_handle);
                    RegCloseKey(helper_info_handle);
                    goto Exit;
                }
            }
            RegCloseKey(helper_info_handle);
        }
        RegCloseKey(program_handle);
    }

Exit:
    if (program_info_handle) {
        RegCloseKey(program_info_handle);
    }
    if (provider_handle) {
        RegCloseKey(provider_handle);
    }
    return status;
}
*/

/*
static __forceinline NTSTATUS
ebpf_store_update_section_information(
    _In_reads_(section_info_count) ebpf_program_section_info_t* section_info, uint32_t section_info_count)
{
    uint32_t status = ERROR_SUCCESS;
    HKEY provider_handle = NULL;
    HKEY section_info_handle = NULL;

    if (section_info_count == 0) {
        return status;
    }

    status = _open_or_create_provider_registry_key(&provider_handle);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    // Open (or create) section data handle.
    status = _create_registry_key(provider_handle, EBPF_SECTIONS_REGISTRY_PATH, REG_CREATE_FLAGS, &section_info_handle);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    for (uint32_t i = 0; i < section_info_count; i++) {
        HKEY section_handle;

        // Open or create the registry path.
        status =
            _create_registry_key(section_info_handle, section_info[i].section_name, REG_CREATE_FLAGS, &section_handle);
        if (status != ERROR_SUCCESS) {
            goto Exit;
        }

        // Save program type.
        status = _write_registry_value_binary(
            section_handle,
            EBPF_SECTION_DATA_PROGRAM_TYPE,
            (uint8_t*)section_info[i].program_type,
            sizeof(ebpf_program_type_t));
        if (status != ERROR_SUCCESS) {
            RegCloseKey(section_handle);
            goto Exit;
        }

        // Save attach type.
        status = _write_registry_value_binary(
            section_handle,
            EBPF_SECTION_DATA_ATTACH_TYPE,
            (uint8_t*)section_info[i].attach_type,
            sizeof(ebpf_attach_type_t));
        if (status != ERROR_SUCCESS) {
            RegCloseKey(section_handle);
            goto Exit;
        }

        // Save bpf_prog_type
        status = _write_registry_value_dword(
            section_handle, EBPF_PROGRAM_DATA_BPF_PROG_TYPE, section_info[i].bpf_program_type);
        if (status != ERROR_SUCCESS) {
            RegCloseKey(section_handle);
            goto Exit;
        }

        // Save bpf_attach_type
        status = _write_registry_value_dword(
            section_handle, EBPF_SECTION_DATA_BPF_ATTACH_TYPE, section_info[i].bpf_attach_type);
        if (status != ERROR_SUCCESS) {
            RegCloseKey(section_handle);
            goto Exit;
        }

        RegCloseKey(section_handle);
    }

Exit:
    if (section_info_handle) {
        RegCloseKey(section_info_handle);
    }
    if (provider_handle) {
        RegCloseKey(provider_handle);
    }

    return status;
}
*/

uint32_t
export_all_program_information()
{
    uint32_t status = ERROR_SUCCESS;
    size_t array_size = sizeof(program_information_array) / sizeof(program_information_array[0]);
    for (uint32_t i = 0; i < array_size; i++) {
        auto program_type = program_information_array[i];
        switch (program_type->program_type_descriptor.bpf_prog_type) {
        case BPF_PROG_TYPE_BIND:
            program_type->program_type_descriptor.program_type = EBPF_PROGRAM_TYPE_BIND;
            break;
        case BPF_PROG_TYPE_XDP:
            program_type->program_type_descriptor.program_type = EBPF_PROGRAM_TYPE_XDP;
            break;
        case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
            program_type->program_type_descriptor.program_type = EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR;
            break;
        case BPF_PROG_TYPE_SOCK_OPS:
            program_type->program_type_descriptor.program_type = EBPF_PROGRAM_TYPE_SOCK_OPS;
            break;
        case BPF_PROG_TYPE_SAMPLE:
            program_type->program_type_descriptor.program_type = EBPF_PROGRAM_TYPE_SAMPLE;
            break;
        };

        status = ebpf_store_update_program_information(program_information_array[i], 1);
        if (status != ERROR_SUCCESS) {
            break;
        }
    }

    return status;
}

/*
static uint32_t
ebpf_store_update_global_helper_information(
    _In_reads_(helper_info_count) ebpf_helper_function_prototype_t* helper_info, int helper_info_count)
{
    uint32_t status = ERROR_SUCCESS;
    HKEY provider_handle = NULL;
    HKEY helper_info_handle = NULL;

    if (helper_info_count == 0) {
        return status;
    }

    status = _open_or_create_provider_registry_key(&provider_handle);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    // Open (or create) global helpers registry path.
    status =
        _create_registry_key(provider_handle, EBPF_GLOBAL_HELPERS_REGISTRY_PATH, REG_CREATE_FLAGS, &helper_info_handle);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    for (int i = 0; i < helper_info_count; i++) {

        status = _update_helper_prototype(helper_info_handle, &helper_info[i]);
        if (status != ERROR_SUCCESS) {
            goto Exit;
        }
    }

Exit:
    if (helper_info_handle) {
        RegCloseKey(helper_info_handle);
    }
    if (provider_handle) {
        RegCloseKey(provider_handle);
    }
    return status;
}
*/

uint32_t
export_all_section_information()
{
    uint32_t status = ERROR_SUCCESS;
    for (const auto& section : _section_information) {
        status = ebpf_store_update_section_information(section.section_info, (uint32_t)section.section_info_count);
        if (status != ERROR_SUCCESS) {
            break;
        }
    }

    return status;
}

int
export_global_helper_information()
{
    return ebpf_store_update_global_helper_information(
        ebpf_core_helper_function_prototype, ebpf_core_helper_functions_count);
}

static uint32_t
_clear_ebpf_store(HKEY root_key)
{
    HKEY root_handle = nullptr;
    HKEY provider_handle = nullptr;
    uint32_t status;

    // Open root registry key.
    status = _open_registry_key(root_key, EBPF_ROOT_RELATIVE_PATH, REG_CREATE_FLAGS, &root_handle);
    if (status != ERROR_SUCCESS) {
        if (status == ERROR_FILE_NOT_FOUND) {
            status = ERROR_SUCCESS;
        }

        goto Exit;
    }

    // Open "providers" registry key.
    status = _open_registry_key(root_handle, EBPF_PROVIDERS_REGISTRY_PATH, REG_CREATE_FLAGS, &provider_handle);
    if (status != ERROR_SUCCESS) {
        if (status == ERROR_FILE_NOT_FOUND) {
            status = ERROR_SUCCESS;
        }

        goto Exit;
    }

    // Delete subtree of provider reg key.
    status = RegDeleteTree(provider_handle, nullptr);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }
    RegCloseKey(provider_handle);
    provider_handle = nullptr;

    status = _delete_registry_key(root_handle, EBPF_PROVIDERS_REGISTRY_PATH);

Exit:
    if (provider_handle != nullptr) {
        RegCloseKey(provider_handle);
    }
    if (root_handle != nullptr) {
        RegCloseKey(root_handle);
    }
    return status;
}

uint32_t
clear_all_ebpf_stores()
{
    // std::cout << "Clearing eBPF store HKEY_LOCAL_MACHINE" << std::endl;
    // _clear_ebpf_store(HKEY_LOCAL_MACHINE);
    std::cout << "Clearing eBPF store HKEY_CURRENT_USER" << std::endl;
    return _clear_ebpf_store(HKEY_CURRENT_USER);
}

void
print_help(_In_ const char* file_name)
{
    std::cerr << "Usage: " << file_name << " [--clear]" << std::endl;
}
