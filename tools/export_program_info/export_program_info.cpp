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
