// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include "ebpf_api.h"
#include "ebpf_extension.h"
#include "ebpf_program_attach_type_guids.h"
#include "ebpf_program_types.h"
#include "ebpf_shared_framework.h"
#include "ebpf_store_helper.h"
#include "ebpf_windows.h"
#include "xdp_hooks.h"

#include <codecvt>
#include <iostream>
#include <vector>

#define REG_CREATE_FLAGS (KEY_WRITE | DELETE | KEY_READ)
#define REG_OPEN_FLAGS (DELETE | KEY_READ)

typedef struct _ebpf_program_section_info_with_count
{
    _Field_size_(section_info_count) const ebpf_program_section_info_t* section_info;
    size_t section_info_count;
} ebpf_program_section_info_with_count_t;

// XDP Test program information
static const ebpf_context_descriptor_t _ebpf_xdp_test_context_descriptor = {
    sizeof(xdp_md_t),
    EBPF_OFFSET_OF(xdp_md_t, data),
    EBPF_OFFSET_OF(xdp_md_t, data_end),
    EBPF_OFFSET_OF(xdp_md_t, data_meta)};

static const ebpf_program_type_descriptor_t _ebpf_xdp_test_program_type_descriptor = {
    EBPF_PROGRAM_TYPE_DESCRIPTOR_HEADER,
    "xdp",
    &_ebpf_xdp_test_context_descriptor,
    EBPF_PROGRAM_TYPE_XDP_GUID,
    BPF_PROG_TYPE_XDP,
    0};

// XDP helper function prototypes
static const ebpf_helper_function_prototype_t _xdp_test_ebpf_extension_helper_function_prototype[] = {
    {EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
     XDP_EXT_HELPER_FUNCTION_START + 1,
     "bpf_xdp_adjust_head",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_CTX, EBPF_ARGUMENT_TYPE_ANYTHING},
     // Flags.
     {HELPER_FUNCTION_REALLOCATE_PACKET}}};

static const ebpf_program_info_t _ebpf_xdp_test_program_info = {
    EBPF_PROGRAM_INFORMATION_HEADER,
    &_ebpf_xdp_test_program_type_descriptor,
    EBPF_COUNT_OF(_xdp_test_ebpf_extension_helper_function_prototype),
    _xdp_test_ebpf_extension_helper_function_prototype,
    0,
    NULL};

static const ebpf_program_info_t* _program_information_array[] = {&_ebpf_xdp_test_program_info};

ebpf_program_section_info_t _xdp_test_section_info[] = {
    {EBPF_PROGRAM_SECTION_INFORMATION_HEADER,
     L"xdp",
     &EBPF_PROGRAM_TYPE_XDP,
     &EBPF_ATTACH_TYPE_XDP,
     BPF_PROG_TYPE_XDP,
     BPF_XDP}};

static std::vector<ebpf_program_section_info_with_count_t> _section_information = {
    {&_xdp_test_section_info[0], _countof(_xdp_test_section_info)},
};

uint32_t
export_program_information()
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
export_section_information()
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

uint32_t
clear_ebpf_store()
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_result_t return_result = EBPF_SUCCESS;

    std::cout << "Clearing eBPF store (test)" << std::endl;
    for (size_t i = 0; i < _countof(_xdp_test_section_info); i++) {
        result = ebpf_store_delete_section_information(&_xdp_test_section_info[i]);
        if (result != EBPF_SUCCESS && result != EBPF_FILE_NOT_FOUND) {
            std::cout << "Failed to delete section information" << std::endl;
            return_result = result;
        }
    }
    for (const auto& program : _program_information_array) {
        result = ebpf_store_delete_program_information(program);
        if (result != EBPF_SUCCESS && result != EBPF_FILE_NOT_FOUND) {
            std::cout << "Failed to delete program information" << std::endl;
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
