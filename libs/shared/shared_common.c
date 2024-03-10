// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_program_types.h"
#include "ebpf_shared_framework.h"

enum _extension_object_type
{
    EBPF_ATTACH_PROVIDER_DATA = 0,
    EBPF_PROGRAM_TYPE_DESCRIPTOR,
    EBPF_HELPER_FUNCTION_PROTOTYPE,
    EBPF_PROGRAM_INFO,
    EBPF_HELPER_FUNCTION_ADDRESSES,
    EBPF_PROGRAM_DATA,
    EBPF_PROGRAM_SECTION,
};

// Supported version and sizes of the various extension data structures.

uint16_t _supported_ebpf_extension_version[] = {
    EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION,
    EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION,
    EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION,
    EBPF_PROGRAM_INFORMATION_CURRENT_VERSION,
    EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION,
    EBPF_PROGRAM_DATA_CURRENT_VERSION,
    EBPF_PROGRAM_SECTION_INFORMATION_CURRENT_VERSION,
};

#define EBPF_ATTACH_PROVIDER_DATA_SIZE_0 \
    EBPF_OFFSET_OF(ebpf_attach_provider_data_t, link_type) + sizeof(enum bpf_link_type)
size_t _ebpf_attach_provider_data_supported_size[] = {EBPF_ATTACH_PROVIDER_DATA_SIZE_0};

#define EBPF_PROGRAM_TYPE_DESCRIPTOR_SIZE_0 EBPF_OFFSET_OF(ebpf_program_type_descriptor_t, is_privileged) + sizeof(char)
size_t _ebpf_program_type_descriptor_supported_size[] = {EBPF_PROGRAM_TYPE_DESCRIPTOR_SIZE_0};

#define EBPF_HELPER_FUNCTION_PROTOTYPE_SIZE_0 EBPF_SIZE_INCLUDING_FIELD(ebpf_helper_function_prototype_t, arguments)
#define EBPF_HELPER_FUNCTION_PROTOTYPE_SIZE_1 EBPF_SIZE_INCLUDING_FIELD(ebpf_helper_function_prototype_t, flags)
size_t _ebpf_helper_function_prototype_supported_size[] = {
    EBPF_HELPER_FUNCTION_PROTOTYPE_SIZE_0, EBPF_HELPER_FUNCTION_PROTOTYPE_SIZE_1};

#define EBPF_PROGRAM_INFO_SIZE_0 EBPF_SIZE_INCLUDING_FIELD(ebpf_program_info_t, global_helper_prototype)
size_t _ebpf_program_info_supported_size[] = {EBPF_PROGRAM_INFO_SIZE_0};

#define EBPF_HELPER_FUNCTION_ADDRESSES_SIZE_0 \
    EBPF_OFFSET_OF(ebpf_helper_function_addresses_t, helper_function_address) + sizeof(uint64_t*)
size_t _ebpf_helper_function_addresses_supported_size[] = {EBPF_HELPER_FUNCTION_ADDRESSES_SIZE_0};

#define EBPF_PROGRAM_DATA_SIZE_0 EBPF_OFFSET_OF(ebpf_program_data_t, required_irql) + sizeof(uint8_t)
size_t _ebpf_program_data_supported_size[] = {EBPF_PROGRAM_DATA_SIZE_0};

#define EBPF_PROGRAM_SECTION_SIZE_0 EBPF_SIZE_INCLUDING_FIELD(ebpf_program_section_info_t, bpf_attach_type)
size_t _ebpf_program_section_supported_size[] = {EBPF_PROGRAM_SECTION_SIZE_0};

struct _ebpf_extension_data_structure_supported_sizes
{
    size_t* supported_sizes;
    uint16_t count;
};
struct _ebpf_extension_data_structure_supported_sizes _ebpf_extension_type_supported_sizes[] = {
    {_ebpf_attach_provider_data_supported_size, EBPF_COUNT_OF(_ebpf_attach_provider_data_supported_size)},
    {_ebpf_program_type_descriptor_supported_size, EBPF_COUNT_OF(_ebpf_program_type_descriptor_supported_size)},
    {_ebpf_helper_function_prototype_supported_size, EBPF_COUNT_OF(_ebpf_helper_function_prototype_supported_size)},
    {_ebpf_program_info_supported_size, EBPF_COUNT_OF(_ebpf_program_info_supported_size)},
    {_ebpf_helper_function_addresses_supported_size, EBPF_COUNT_OF(_ebpf_helper_function_addresses_supported_size)},
    {_ebpf_program_data_supported_size, EBPF_COUNT_OF(_ebpf_program_data_supported_size)},
    {_ebpf_program_section_supported_size, EBPF_COUNT_OF(_ebpf_program_section_supported_size)},
};

static bool
_ebpf_is_size_supported(_In_count_(count) const size_t* supported_sizes, uint16_t count, size_t size)
{
    for (uint16_t i = 0; i < count; i++) {
        if (size == supported_sizes[i]) {
            return true;
        }
    }
    return false;
}

static bool
_ebpf_validate_extension_object_header(
    enum _extension_object_type object_type, _In_ const ebpf_extension_header_t* header)
{
    size_t* supported_sizes = _ebpf_extension_type_supported_sizes[object_type].supported_sizes;
    uint16_t count = _ebpf_extension_type_supported_sizes[object_type].count;
    __analysis_assume(supported_sizes != NULL);

    return (
        (header->version == _supported_ebpf_extension_version[object_type]) &&
        (_ebpf_is_size_supported(supported_sizes, count, header->size)));
}

#ifndef GUID_NULL
static const GUID GUID_NULL = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};
#endif

bool
ebpf_validate_attach_provider_data(_In_ const ebpf_attach_provider_data_t* attach_provider_data)
{
    return (
        (attach_provider_data != NULL) &&
        _ebpf_validate_extension_object_header(EBPF_ATTACH_PROVIDER_DATA, &attach_provider_data->header) &&
        !IsEqualGUID(&attach_provider_data->supported_program_type, &GUID_NULL) &&
        (attach_provider_data->link_type < BPF_LINK_TYPE_MAX) &&
        (attach_provider_data->bpf_attach_type < __MAX_BPF_ATTACH_TYPE));
}

static bool
_ebpf_validate_helper_function_prototype(const ebpf_helper_function_prototype_t* helper_prototype)
{
    return (
        (helper_prototype != NULL) &&
        _ebpf_validate_extension_object_header(EBPF_HELPER_FUNCTION_PROTOTYPE, &helper_prototype->header) &&
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
        _ebpf_validate_extension_object_header(EBPF_PROGRAM_TYPE_DESCRIPTOR, &program_type_descriptor->header) &&
        (program_type_descriptor->name != NULL) &&
        _ebpf_validate_context_descriptor(program_type_descriptor->context_descriptor));
}

bool
ebpf_validate_program_info(_In_ const ebpf_program_info_t* program_info)
{
    return (
        (program_info != NULL) && _ebpf_validate_extension_object_header(EBPF_PROGRAM_INFO, &program_info->header) &&
        _ebpf_validate_program_type_descriptor(program_info->program_type_descriptor) &&
        ebpf_validate_helper_function_prototype_array(
            program_info->program_type_specific_helper_prototype,
            program_info->count_of_program_type_specific_helpers) &&
        ebpf_validate_helper_function_prototype_array(
            program_info->global_helper_prototype, program_info->count_of_global_helpers));
}

bool
_ebpf_validate_helper_function_addresses(_In_ const ebpf_helper_function_addresses_t* helper_function_addresses)
{
    return (
        (helper_function_addresses != NULL) &&
        _ebpf_validate_extension_object_header(EBPF_HELPER_FUNCTION_ADDRESSES, &helper_function_addresses->header) &&
        (helper_function_addresses->helper_function_count > 0) &&
        (helper_function_addresses->helper_function_address != NULL));
}

bool
ebpf_validate_program_data(_In_ const ebpf_program_data_t* program_data)
{
    return (
        (program_data != NULL) && _ebpf_validate_extension_object_header(EBPF_PROGRAM_DATA, &program_data->header) &&
        ((program_data->global_helper_function_addresses == NULL) ||
         _ebpf_validate_helper_function_addresses(program_data->global_helper_function_addresses)) &&
        ((program_data->program_type_specific_helper_function_addresses == NULL) ||
         _ebpf_validate_helper_function_addresses(program_data->program_type_specific_helper_function_addresses)) &&
        ebpf_validate_program_info(program_data->program_info));
}

bool
ebpf_validate_program_section_info(_In_ const ebpf_program_section_info_t* section_info)
{
    return (
        (section_info != NULL) && _ebpf_validate_extension_object_header(EBPF_PROGRAM_SECTION, &section_info->header) &&
        (section_info->section_name != NULL) && (section_info->program_type != NULL) &&
        (section_info->attach_type != NULL));
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
