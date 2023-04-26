// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define USER_MODE
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include "ebpf_api.h"
#include "ebpf_nethooks.h"
#include "ebpf_store_helper.h"
#include "export_program_info.h"
#include "store_helper_internal.h"
#include "windows_program_type.h"

#include <codecvt>

#include "ebpf_general_helpers.c"

#define REG_CREATE_FLAGS (KEY_WRITE | DELETE | KEY_READ)
#define REG_OPEN_FLAGS (DELETE | KEY_READ)

extern ebpf_registry_key_t ebpf_root_registry_key;

typedef struct _ebpf_program_section_info_with_count
{
    _Field_size_(section_info_count) const ebpf_program_section_info_t* section_info;
    size_t section_info_count;
} ebpf_program_section_info_with_count_t;

static const ebpf_program_info_t* program_information_array[] = {
    &_ebpf_bind_program_info,
    &_ebpf_sock_addr_program_info,
    &_ebpf_sock_ops_program_info,
    &_ebpf_xdp_program_info,
    &_sample_ebpf_extension_program_info};

ebpf_program_section_info_t _sample_ext_section_info[] = {
    {L"sample_ext", &EBPF_PROGRAM_TYPE_SAMPLE, &EBPF_ATTACH_TYPE_SAMPLE, BPF_PROG_TYPE_SAMPLE, BPF_ATTACH_TYPE_SAMPLE}};

static std::vector<ebpf_program_section_info_with_count_t> _section_information = {
    {&_ebpf_bind_section_info[0], _countof(_ebpf_bind_section_info)},
    {&_ebpf_xdp_section_info[0], _countof(_ebpf_xdp_section_info)},
    {&_ebpf_sock_addr_section_info[0], _countof(_ebpf_sock_addr_section_info)},
    {&_ebpf_sock_ops_section_info[0], _countof(_ebpf_sock_ops_section_info)},
    {&_sample_ext_section_info[0], _countof(_sample_ext_section_info)},
};

uint32_t
export_all_program_information()
{
    uint32_t status = ERROR_SUCCESS;
    size_t array_size = _countof(program_information_array);
    for (uint32_t i = 0; i < array_size; i++) {
        status = _ebpf_store_update_program_information(program_information_array[i], 1);
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
        status = _ebpf_store_update_section_information(section.section_info, (uint32_t)section.section_info_count);
        if (status != ERROR_SUCCESS) {
            break;
        }
    }

    return status;
}

int
export_global_helper_information()
{
    return _ebpf_store_update_global_helper_information(
        ebpf_core_helper_function_prototype, ebpf_core_helper_functions_count);
}

uint32_t
clear_all_ebpf_stores()
{
    // TODO: Issue #1231 Change to using HKEY_LOCAL_MACHINE
    std::cout << "Clearing eBPF store HKEY_CURRENT_USER" << std::endl;
    return ebpf_store_clear(ebpf_root_registry_key);
}

void
print_help(_In_z_ const char* file_name)
{
    std::cerr << "Usage: " << file_name << " [--clear]" << std::endl;
}
