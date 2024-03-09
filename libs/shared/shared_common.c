// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_program_types.h"
#include "ebpf_shared_framework.h"

static bool
_ebpf_validate_helper_function_prototype(const ebpf_helper_function_prototype_t* helper_prototype)
{
    return (
        (helper_prototype != NULL) &&
        (helper_prototype->header.version == EBPF_HELPER_FUNCTION_PROTOTYPE_VERSION_LATEST) &&
        (helper_prototype->header.size >= EBPF_HELPER_FUNCTION_PROTOTYPE_VERSION_0_MINIMUM_SIZE) &&
        (helper_prototype->name != NULL));
}

bool
ebpf_validate_helper_function_prototype_array(
    _In_reads_(count) const ebpf_helper_function_prototype_t* helper_prototype, uint32_t count)
{
    if (count > 0) {
        for (uint32_t i = 0; i < count; i++) {
            if (!_ebpf_validate_helper_function_prototype(&helper_prototype[i])) {
                return false;
            }
        }
    }
    return true;
}

static bool
_ebpf_validate_context_descriptor(_In_ const ebpf_context_descriptor_t* context_descriptor)
{
    return ((context_descriptor != NULL) && (context_descriptor->size >= sizeof(ebpf_context_descriptor_t)));
}

static bool
_ebpf_validate_program_type_descriptor(_In_ const ebpf_program_type_descriptor_t* program_type_descriptor)
{
    return (
        (program_type_descriptor != NULL) &&
        (program_type_descriptor->header.version == EBPF_PROGRAM_TYPE_DESCRIPTOR_VERSION_LATEST) &&
        (program_type_descriptor->header.size >= EBPF_PROGRAM_TYPE_DESCRIPTOR_VERSION_0_MINIMUM_SIZE) &&
        (program_type_descriptor->name != NULL) &&
        _ebpf_validate_context_descriptor(program_type_descriptor->context_descriptor));
}

bool
ebpf_validate_program_info(_In_ const ebpf_program_info_t* program_info)
{
    return (
        (program_info != NULL) && (program_info->header.version == EBPF_PROGRAM_INFORMATION_VERSION_LATEST) &&
        (program_info->header.size >= EBPF_PROGRAM_INFO_VERSION_0_MINIMUM_SIZE) &&
        _ebpf_validate_program_type_descriptor(program_info->program_type_descriptor) &&
        ebpf_validate_helper_function_prototype_array(
            program_info->program_type_specific_helper_prototype,
            program_info->count_of_program_type_specific_helpers) &&
        ebpf_validate_helper_function_prototype_array(
            program_info->global_helper_prototype, program_info->count_of_global_helpers));
}

bool
ebpf_validate_program_section_info(_In_ const ebpf_program_section_info_t* section_info)
{
    return (
        (section_info != NULL) && (section_info->header.size >= sizeof(ebpf_program_section_info_t)) &&
        (section_info->header.version == EBPF_PROGRAM_SECTION_VERSION_LATEST) && (section_info->section_name != NULL) &&
        (section_info->program_type != NULL) && (section_info->attach_type != NULL));
}

ebpf_result_t
ebpf_result_from_cxplat_status(cxplat_status_t status)
{
    switch (status) {
    case CXPLAT_STATUS_SUCCESS:
        return EBPF_SUCCESS;
    case CXPLAT_STATUS_NO_MEMORY:
        return EBPF_NO_MEMORY;
    case CXPLAT_STATUS_ARITHMETIC_OVERFLOW:
        return EBPF_ARITHMETIC_OVERFLOW;
    default:
        return EBPF_FAILED;
    }
}
