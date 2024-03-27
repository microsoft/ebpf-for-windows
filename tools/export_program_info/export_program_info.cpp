// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include "ebpf_api.h"
#include "ebpf_nethooks.h"
#include "ebpf_store_helper.h"
#include "export_program_info.h"
#include "net_ebpf_ext_program_info.h"
#include "store_helper_internal.h"
#include "windows_program_type.h"

#include <codecvt>

#include "ebpf_general_helpers.c"

// Export XDP program information to allow for our unit tests to mock the XDP API surface.
static const ebpf_program_type_descriptor_t _mock_xdp_program_type_descriptor = {
    {EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION, EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION_SIZE},
    "xdp",
    &_ebpf_xdp_test_context_descriptor,
    EBPF_PROGRAM_TYPE_XDP_GUID,
    BPF_PROG_TYPE_XDP};
static const ebpf_program_info_t _mock_xdp_program_info = {
    {EBPF_PROGRAM_INFORMATION_CURRENT_VERSION, EBPF_PROGRAM_INFORMATION_CURRENT_VERSION_SIZE},
    &_mock_xdp_program_type_descriptor,
    EBPF_COUNT_OF(_xdp_test_ebpf_extension_helper_function_prototype),
    _xdp_test_ebpf_extension_helper_function_prototype};

typedef struct _ebpf_program_section_info_with_count
{
    _Field_size_(section_info_count) const ebpf_program_section_info_t* section_info;
    size_t section_info_count;
} ebpf_program_section_info_with_count_t;

static const ebpf_program_info_t* _program_information_array[] = {
    &_ebpf_bind_program_info,
    &_ebpf_sock_addr_program_info,
    &_ebpf_sock_ops_program_info,
    &_mock_xdp_program_info,
    &_ebpf_xdp_test_program_info};

ebpf_program_section_info_t _mock_xdp_section_info[] = {
    {{EBPF_PROGRAM_SECTION_INFORMATION_CURRENT_VERSION, EBPF_PROGRAM_SECTION_INFORMATION_CURRENT_VERSION_SIZE},
     L"xdp",
     &EBPF_PROGRAM_TYPE_XDP,
     &EBPF_ATTACH_TYPE_XDP,
     BPF_PROG_TYPE_XDP,
     BPF_XDP}};

static std::vector<ebpf_program_section_info_with_count_t> _section_information = {
    {&_ebpf_bind_section_info[0], _countof(_ebpf_bind_section_info)},
    {&_mock_xdp_section_info[0], _countof(_mock_xdp_section_info)},
    {&_ebpf_sock_addr_section_info[0], _countof(_ebpf_sock_addr_section_info)},
    {&_ebpf_sock_ops_section_info[0], _countof(_ebpf_sock_ops_section_info)},
    {&_ebpf_xdp_test_section_info[0], _countof(_ebpf_xdp_test_section_info)},
};

uint32_t
export_all_program_information()
{
    uint32_t status = ERROR_SUCCESS;
    size_t array_size = _countof(_program_information_array);
    for (uint32_t i = 0; i < array_size; i++) {
        status = ebpf_store_update_program_information_array(_program_information_array[i], 1);
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

uint32_t
clear_ebpf_store()
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_result_t return_result = EBPF_SUCCESS;

    std::cout << "Clearing eBPF store (docked)" << std::endl;
    for (const auto& section : _section_information) {
        for (size_t i = 0; i < section.section_info_count; i++) {
            result = ebpf_store_delete_section_information(section.section_info + i);
            if (result != EBPF_SUCCESS && result != EBPF_FILE_NOT_FOUND) {
                std::cout << "Failed to delete section information" << std::endl;
                return_result = result;
            }
        }
    }
    for (const auto& program : _program_information_array) {
        result = ebpf_store_delete_program_information(program);
        if (result != EBPF_SUCCESS && result != EBPF_FILE_NOT_FOUND) {
            std::cout << "Failed to delete program information" << std::endl;
            return_result = result;
        }
    }
    for (size_t i = 0; i < ebpf_core_helper_functions_count; i++) {
        result = ebpf_store_delete_global_helper_information(ebpf_core_helper_function_prototype + i);
        if (result != EBPF_SUCCESS && result != EBPF_FILE_NOT_FOUND) {
            std::cout << "Failed to delete global helper information" << std::endl;
            return_result = result;
        }
    }

    return return_result;
}

void
print_help(_In_z_ const char* file_name)
{
    std::cerr << "Usage: " << file_name << " [--clear]" << std::endl;
}
