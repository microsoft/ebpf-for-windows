// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include "ebpf_api.h"
#include "ebpf_extension.h"
#include "ebpf_program_types.h"
#include "ebpf_store_helper.h"
#include "sample_ext_program_info.h"

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

static const ebpf_program_info_t* _program_information_array[] = {&_sample_ebpf_extension_program_info};

static const GUID _sample_btf_module_guid = SAMPLE_EXT_BTF_MODULE_GUID_INITIALIZER;

static const ebpf_btf_resolved_function_prototype_t _sample_btf_function_prototypes[] = {
    {EBPF_BTF_RESOLVED_FUNCTION_PROTOTYPE_HEADER,
     SAMPLE_EXT_BTF_FUNCTION_NAME,
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_ANYTHING,
      EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
      EBPF_ARGUMENT_TYPE_CONST_SIZE,
      EBPF_ARGUMENT_TYPE_DONTCARE,
      EBPF_ARGUMENT_TYPE_DONTCARE},
     0}};

static const ebpf_btf_resolved_function_provider_info_t _sample_btf_provider_info = {
    EBPF_BTF_RESOLVED_FUNCTION_PROVIDER_INFO_HEADER,
    _sample_btf_module_guid,
    static_cast<uint32_t>(_countof(_sample_btf_function_prototypes)),
    _sample_btf_function_prototypes};

ebpf_program_section_info_t _sample_ext_section_info[] = {
    {EBPF_PROGRAM_SECTION_INFORMATION_HEADER,
     L"sample_ext",
     &EBPF_PROGRAM_TYPE_SAMPLE,
     &EBPF_ATTACH_TYPE_SAMPLE,
     BPF_PROG_TYPE_SAMPLE,
     BPF_ATTACH_TYPE_SAMPLE}};

static std::vector<ebpf_program_section_info_with_count_t> _section_information = {
    {&_sample_ext_section_info[0], _countof(_sample_ext_section_info)},
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
export_btf_resolved_function_information()
{
    return ebpf_store_update_btf_resolved_function_provider_information(&_sample_btf_provider_info);
}

uint32_t
clear_ebpf_store()
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_result_t return_result = EBPF_SUCCESS;

    std::cout << "Clearing eBPF store (undocked)" << std::endl;
    for (const auto& section : _sample_ext_section_info) {
        result = ebpf_store_delete_section_information(&section);
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

    result = ebpf_store_delete_btf_resolved_function_provider_information(&_sample_btf_provider_info);
    if (result != EBPF_SUCCESS && result != EBPF_FILE_NOT_FOUND) {
        std::cout << "Failed to delete BTF-resolved function provider information" << std::endl;
        return_result = result;
    }

    return return_result;
}

void
print_help(_In_z_ const char* file_name)
{
    std::cerr << "Usage: " << file_name << " [--clear]" << std::endl;
}
