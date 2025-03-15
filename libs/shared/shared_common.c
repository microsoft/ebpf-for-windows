// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf2c.h"
#include "ebpf_program_types.h"
#include "ebpf_serialize.h"
#include "ebpf_shared_framework.h"
#include "ebpf_tracelog.h"

enum _extension_object_type
{
    // eBPF extension object types.
    EBPF_ATTACH_PROVIDER_DATA = 0,
    EBPF_PROGRAM_TYPE_DESCRIPTOR,
    EBPF_HELPER_FUNCTION_PROTOTYPE,
    EBPF_PROGRAM_INFO,
    EBPF_HELPER_FUNCTION_ADDRESSES,
    EBPF_PROGRAM_DATA,
    EBPF_PROGRAM_SECTION,

    // eBPF native module object types.
    EBPF_NATIVE_HELPER_FUNCTION_ENTRY,
    EBPF_NATIVE_HELPER_FUNCTION_DATA,
    EBPF_NATIVE_MAP_ENTRY,
    EBPF_NATIVE_MAP_DATA,
    EBPF_NATIVE_PROGRAM_ENTRY,
    EBPF_NATIVE_PROGRAM_RUNTIME_CONTEXT,
    EBPF_NATIVE_MAP_INITIAL_VALUES,
    EBPF_NATIVE_GLOBAL_VARIABLE_SECTION_INFO,
    EBPF_NATIVE_GLOBAL_VARIABLE_SECTION_DATA,
};

// Supported version and sizes of the various extension data structures.

uint16_t _supported_ebpf_extension_version[] = {
    // eBPF extension object versions.
    EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION,
    EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION,
    EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION,
    EBPF_PROGRAM_INFORMATION_CURRENT_VERSION,
    EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION,
    EBPF_PROGRAM_DATA_CURRENT_VERSION,
    EBPF_PROGRAM_SECTION_INFORMATION_CURRENT_VERSION,

    // eBPF native module object versions.
    EBPF_NATIVE_HELPER_FUNCTION_ENTRY_CURRENT_VERSION,
    EBPF_NATIVE_HELPER_FUNCTION_DATA_CURRENT_VERSION,
    EBPF_NATIVE_MAP_ENTRY_CURRENT_VERSION,
    EBPF_NATIVE_MAP_DATA_CURRENT_VERSION,
    EBPF_NATIVE_PROGRAM_ENTRY_CURRENT_VERSION,
    EBPF_NATIVE_PROGRAM_RUNTIME_CONTEXT_CURRENT_VERSION,
    EBPF_NATIVE_MAP_INITIAL_VALUES_CURRENT_VERSION,
    EBPF_NATIVE_GLOBAL_VARIABLE_SECTION_INFO_CURRENT_VERSION,
    EBPF_NATIVE_GLOBAL_VARIABLE_SECTION_DATA_CURRENT_VERSION,
};

#define EBPF_ATTACH_PROVIDER_DATA_SIZE_1 EBPF_SIZE_INCLUDING_FIELD(ebpf_attach_provider_data_t, link_type)
size_t _ebpf_attach_provider_data_supported_size[] = {EBPF_ATTACH_PROVIDER_DATA_SIZE_1};

#define EBPF_PROGRAM_TYPE_DESCRIPTOR_SIZE_0 EBPF_OFFSET_OF(ebpf_program_type_descriptor_t, is_privileged) + sizeof(char)
size_t _ebpf_program_type_descriptor_supported_size[] = {EBPF_PROGRAM_TYPE_DESCRIPTOR_SIZE_0};

#define EBPF_HELPER_FUNCTION_PROTOTYPE_SIZE_0 EBPF_SIZE_INCLUDING_FIELD(ebpf_helper_function_prototype_t, arguments)
#define EBPF_HELPER_FUNCTION_PROTOTYPE_SIZE_1 EBPF_SIZE_INCLUDING_FIELD(ebpf_helper_function_prototype_t, flags)
#define EBPF_HELPER_FUNCTION_PROTOTYPE_SIZE_2 \
    EBPF_SIZE_INCLUDING_FIELD(ebpf_helper_function_prototype_t, implicit_context)
size_t _ebpf_helper_function_prototype_supported_size[] = {
    EBPF_HELPER_FUNCTION_PROTOTYPE_SIZE_0,
    EBPF_HELPER_FUNCTION_PROTOTYPE_SIZE_1,
    EBPF_HELPER_FUNCTION_PROTOTYPE_SIZE_2};

#define EBPF_PROGRAM_INFO_SIZE_0 EBPF_SIZE_INCLUDING_FIELD(ebpf_program_info_t, global_helper_prototype)
size_t _ebpf_program_info_supported_size[] = {EBPF_PROGRAM_INFO_SIZE_0};

#define EBPF_HELPER_FUNCTION_ADDRESSES_SIZE_0 \
    EBPF_OFFSET_OF(ebpf_helper_function_addresses_t, helper_function_address) + sizeof(uint64_t*)
size_t _ebpf_helper_function_addresses_supported_size[] = {EBPF_HELPER_FUNCTION_ADDRESSES_SIZE_0};

#define EBPF_PROGRAM_DATA_SIZE_0 EBPF_SIZE_INCLUDING_FIELD(ebpf_program_data_t, required_irql)
#define EBPF_PROGRAM_DATA_SIZE_1 EBPF_SIZE_INCLUDING_FIELD(ebpf_program_data_t, capabilities)
size_t _ebpf_program_data_supported_size[] = {EBPF_PROGRAM_DATA_SIZE_0, EBPF_PROGRAM_DATA_SIZE_1};

#define EBPF_PROGRAM_SECTION_SIZE_0 EBPF_SIZE_INCLUDING_FIELD(ebpf_program_section_info_t, bpf_attach_type)
size_t _ebpf_program_section_supported_size[] = {EBPF_PROGRAM_SECTION_SIZE_0};

#define EBPF_NATIVE_HELPER_FUNCTION_ENTRY_SIZE_0 EBPF_SIZE_INCLUDING_FIELD(helper_function_entry_t, name)
size_t _ebpf_native_helper_function_entry_supported_size[] = {EBPF_NATIVE_HELPER_FUNCTION_ENTRY_SIZE_0};

#define EBPF_NATIVE_HELPER_FUNCTION_DATA_SIZE_0 EBPF_SIZE_INCLUDING_FIELD(helper_function_data_t, tail_call)
size_t _ebpf_native_helper_function_data_supported_size[] = {EBPF_NATIVE_HELPER_FUNCTION_DATA_SIZE_0};

#define EBPF_NATIVE_MAP_ENTRY_SIZE_0 EBPF_SIZE_INCLUDING_FIELD(map_entry_t, name)
size_t _ebpf_native_map_entry_supported_size[] = {EBPF_NATIVE_MAP_ENTRY_SIZE_0};

#define EBPF_NATIVE_MAP_DATA_SIZE_0 EBPF_SIZE_INCLUDING_FIELD(map_data_t, address)
size_t _ebpf_native_map_data_supported_size[] = {EBPF_NATIVE_MAP_DATA_SIZE_0};

#define EBPF_NATIVE_PROGRAM_ENTRY_SIZE_0 EBPF_SIZE_INCLUDING_FIELD(program_entry_t, program_info_hash_type)
size_t _ebpf_native_program_entry_supported_size[] = {EBPF_NATIVE_PROGRAM_ENTRY_SIZE_0};

#define EBPF_NATIVE_PROGRAM_RUNTIME_CONTEXT_SIZE_0 \
    EBPF_SIZE_INCLUDING_FIELD(program_runtime_context_t, global_variable_section_data)
size_t _ebpf_native_program_runtime_context_supported_size[] = {EBPF_NATIVE_PROGRAM_RUNTIME_CONTEXT_SIZE_0};

#define EBPF_NATIVE_MAP_INITIAL_VALUES_SIZE_0 EBPF_SIZE_INCLUDING_FIELD(map_initial_values_t, values)
size_t _ebpf_native_map_initial_values_supported_size[] = {EBPF_NATIVE_MAP_INITIAL_VALUES_SIZE_0};

#define EBPF_NATIVE_GLOBAL_VARIABLE_SECTION_INFO_SIZE_0 \
    EBPF_SIZE_INCLUDING_FIELD(global_variable_section_info_t, initial_data)
size_t _ebpf_native_global_variable_section_info_supported_size[] = {EBPF_NATIVE_GLOBAL_VARIABLE_SECTION_INFO_SIZE_0};

#define EBPF_NATIVE_GLOBAL_VARIABLE_SECTION_DATA_SIZE_0 \
    EBPF_SIZE_INCLUDING_FIELD(global_variable_section_data_t, address_of_map_value)
size_t _ebpf_native_global_variable_section_data_supported_size[] = {EBPF_NATIVE_GLOBAL_VARIABLE_SECTION_DATA_SIZE_0};

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
    {_ebpf_native_helper_function_entry_supported_size,
     EBPF_COUNT_OF(_ebpf_native_helper_function_entry_supported_size)},
    {_ebpf_native_helper_function_data_supported_size, EBPF_COUNT_OF(_ebpf_native_helper_function_data_supported_size)},
    {_ebpf_native_map_entry_supported_size, EBPF_COUNT_OF(_ebpf_native_map_entry_supported_size)},
    {_ebpf_native_map_data_supported_size, EBPF_COUNT_OF(_ebpf_native_map_data_supported_size)},
    {_ebpf_native_program_entry_supported_size, EBPF_COUNT_OF(_ebpf_native_program_entry_supported_size)},
    {_ebpf_native_program_runtime_context_supported_size,
     EBPF_COUNT_OF(_ebpf_native_program_runtime_context_supported_size)},
    {_ebpf_native_map_initial_values_supported_size, EBPF_COUNT_OF(_ebpf_native_map_initial_values_supported_size)},
    {_ebpf_native_global_variable_section_info_supported_size,
     EBPF_COUNT_OF(_ebpf_native_global_variable_section_info_supported_size)},
    {_ebpf_native_global_variable_section_data_supported_size,
     EBPF_COUNT_OF(_ebpf_native_global_variable_section_data_supported_size)},
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
        !IsEqualGUID(&attach_provider_data->supported_program_type, &GUID_NULL));
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
    _In_reads_(count) const ebpf_helper_function_prototype_t* helper_prototype_array, uint32_t count)
{
    if (count > 0) {
        // The helper_prototype_array cannot be NULL.
        if (helper_prototype_array == NULL) {
            return false;
        }
        // Use "total_size" to calculate the actual size of the ebpf_helper_function_prototype_t struct.
        size_t helper_prototype_size = helper_prototype_array[0].header.total_size;
        for (uint32_t i = 0; i < count; i++) {
            ebpf_helper_function_prototype_t* helper_prototype = (ebpf_helper_function_prototype_t*)ARRAY_ELEMENT_INDEX(
                helper_prototype_array, i, helper_prototype_size);
            if (!_ebpf_validate_helper_function_prototype(helper_prototype)) {
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

bool
ebpf_validate_object_header_native_helper_function_entry(
    _In_ const ebpf_extension_header_t* native_helper_function_entry_header)
{
    return (
        (native_helper_function_entry_header != NULL) &&
        _ebpf_validate_extension_object_header(EBPF_NATIVE_HELPER_FUNCTION_ENTRY, native_helper_function_entry_header));
}

bool
ebpf_validate_object_header_native_map_entry(_In_ const ebpf_extension_header_t* native_map_entry_header)
{
    return (
        (native_map_entry_header != NULL) &&
        _ebpf_validate_extension_object_header(EBPF_NATIVE_MAP_ENTRY, native_map_entry_header));
}

bool
ebpf_validate_object_header_native_program_entry(_In_ const ebpf_extension_header_t* native_program_entry_header)
{
    return (
        (native_program_entry_header != NULL) &&
        _ebpf_validate_extension_object_header(EBPF_NATIVE_PROGRAM_ENTRY, native_program_entry_header));
}

bool
ebpf_validate_object_header_native_map_initial_values(
    _In_ const ebpf_extension_header_t* native_map_initial_values_header)
{
    return (
        (native_map_initial_values_header != NULL) &&
        _ebpf_validate_extension_object_header(EBPF_NATIVE_MAP_INITIAL_VALUES, native_map_initial_values_header));
}

bool
ebpf_validate_object_header_native_global_variable_section_info(
    _In_ const ebpf_extension_header_t* native_global_variable_section_info_header)
{
    return (
        (native_global_variable_section_info_header != NULL) &&
        _ebpf_validate_extension_object_header(
            EBPF_NATIVE_GLOBAL_VARIABLE_SECTION_INFO, native_global_variable_section_info_header));
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

static void
_ebpf_program_type_descriptor_free(_In_opt_ _Post_invalid_ ebpf_program_type_descriptor_t* descriptor)
{
    if (descriptor != NULL) {
        ebpf_free((void*)descriptor->context_descriptor);
        ebpf_free((void*)descriptor->name);
        ebpf_free(descriptor);
    }
}

static ebpf_result_t
_duplicate_program_descriptor(
    _In_ const ebpf_program_type_descriptor_t* program_type_descriptor,
    _Out_ ebpf_program_type_descriptor_t** new_program_type_descriptor)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_program_type_descriptor_t* program_type_descriptor_copy = NULL;
    ebpf_context_descriptor_t* context_descriptor_copy = NULL;

    program_type_descriptor_copy =
        (ebpf_program_type_descriptor_t*)ebpf_allocate(sizeof(ebpf_program_type_descriptor_t));
    if (program_type_descriptor_copy == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    memcpy(program_type_descriptor_copy, program_type_descriptor, program_type_descriptor->header.size);
    program_type_descriptor_copy->header.version = EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION;
    program_type_descriptor_copy->header.size = EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION_SIZE;
    program_type_descriptor_copy->header.total_size = EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION_TOTAL_SIZE;

    // Initialize pointers to NULL.
    program_type_descriptor_copy->context_descriptor = NULL;

    program_type_descriptor_copy->name = cxplat_duplicate_string(program_type_descriptor->name);
    if (program_type_descriptor_copy->name == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    context_descriptor_copy = (ebpf_context_descriptor_t*)ebpf_allocate(sizeof(ebpf_context_descriptor_t));
    if (context_descriptor_copy == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    memcpy(context_descriptor_copy, program_type_descriptor->context_descriptor, sizeof(ebpf_context_descriptor_t));
    program_type_descriptor_copy->context_descriptor = context_descriptor_copy;
    context_descriptor_copy = NULL;

    *new_program_type_descriptor = program_type_descriptor_copy;
    program_type_descriptor_copy = NULL;

Exit:
    _ebpf_program_type_descriptor_free(program_type_descriptor_copy);
    ebpf_free(context_descriptor_copy);

    return result;
}

static ebpf_result_t
_duplicate_helper_function_prototype_array(
    _In_reads_(count) const ebpf_helper_function_prototype_t* helper_prototype_array,
    uint32_t count,
    _Outptr_result_buffer_maybenull_(count) ebpf_helper_function_prototype_t** new_helper_prototype_array)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_helper_function_prototype_t* local_helper_prototype_array = NULL;
    size_t helper_prototype_size = 0;

    if (count == 0) {
        *new_helper_prototype_array = NULL;
        goto Exit;
    }

    // The ebpf_helper_function_prototype_t struct gets padded at arguments[5] field.
    helper_prototype_size = EBPF_PAD_8(helper_prototype_array[0].header.size);

    local_helper_prototype_array =
        (ebpf_helper_function_prototype_t*)ebpf_allocate(count * sizeof(ebpf_helper_function_prototype_t));
    if (local_helper_prototype_array == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    for (uint32_t i = 0; i < count; i++) {
        ebpf_helper_function_prototype_t* helper_prototype =
            (ebpf_helper_function_prototype_t*)ARRAY_ELEMENT_INDEX(helper_prototype_array, i, helper_prototype_size);
        memcpy(&local_helper_prototype_array[i], helper_prototype, helper_prototype_size);
        local_helper_prototype_array[i].header.version = EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION;
        local_helper_prototype_array[i].header.size = EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION_SIZE;
        local_helper_prototype_array[i].header.total_size = EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION_TOTAL_SIZE;

        local_helper_prototype_array[i].name = cxplat_duplicate_string(helper_prototype->name);
        if (local_helper_prototype_array[i].name == NULL) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }
        if (local_helper_prototype_array[i].header.size == EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION) {
            local_helper_prototype_array[i].flags = helper_prototype[i].flags;
        }
    }

    *new_helper_prototype_array = local_helper_prototype_array;
    local_helper_prototype_array = NULL;

Exit:
    if (local_helper_prototype_array != NULL) {
        for (uint32_t i = 0; i < count; i++) {
            ebpf_free((void*)local_helper_prototype_array[i].name);
        }
        ebpf_free(local_helper_prototype_array);
    }

    return result;
}

void
ebpf_program_info_free(_In_opt_ _Post_invalid_ ebpf_program_info_t* program_info)
{
    if (program_info != NULL) {
        _ebpf_program_type_descriptor_free((ebpf_program_type_descriptor_t*)program_info->program_type_descriptor);

        if (program_info->program_type_specific_helper_prototype != NULL) {
            for (uint32_t i = 0; i < program_info->count_of_program_type_specific_helpers; i++) {
                const ebpf_helper_function_prototype_t* helper_prototype =
                    &program_info->program_type_specific_helper_prototype[i];
                void* name = (void*)helper_prototype->name;
                ebpf_free(name);
            }
        }
        if (program_info->global_helper_prototype != NULL) {
            for (uint32_t i = 0; i < program_info->count_of_global_helpers; i++) {
                const ebpf_helper_function_prototype_t* helper_prototype = &program_info->global_helper_prototype[i];
                void* name = (void*)helper_prototype->name;
                ebpf_free(name);
            }
        }

        ebpf_free((void*)program_info->program_type_specific_helper_prototype);
        ebpf_free((void*)program_info->global_helper_prototype);
        ebpf_free(program_info);
    }
}

ebpf_result_t
ebpf_duplicate_program_info(_In_ const ebpf_program_info_t* info, _Outptr_ ebpf_program_info_t** new_info)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_program_info_t* program_info = NULL;

    EBPF_LOG_ENTRY();

    program_info = (ebpf_program_info_t*)ebpf_allocate(sizeof(ebpf_program_info_t));
    if (program_info == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    program_info->header.version = EBPF_PROGRAM_INFORMATION_CURRENT_VERSION;
    program_info->header.size = EBPF_PROGRAM_INFORMATION_CURRENT_VERSION_SIZE;
    program_info->header.total_size = EBPF_PROGRAM_INFORMATION_CURRENT_VERSION_TOTAL_SIZE;

    program_info->count_of_global_helpers = info->count_of_global_helpers;
    if (info->count_of_global_helpers > 0) {
        result = _duplicate_helper_function_prototype_array(
            info->global_helper_prototype, info->count_of_global_helpers, &program_info->global_helper_prototype);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }
    }

    program_info->count_of_program_type_specific_helpers = info->count_of_program_type_specific_helpers;
    if (info->count_of_program_type_specific_helpers > 0) {
        result = _duplicate_helper_function_prototype_array(
            info->program_type_specific_helper_prototype,
            info->count_of_program_type_specific_helpers,
            &program_info->program_type_specific_helper_prototype);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }
    }

    result = _duplicate_program_descriptor(info->program_type_descriptor, &program_info->program_type_descriptor);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    *new_info = program_info;
    program_info = NULL;

Exit:
    ebpf_program_info_free(program_info);

    EBPF_RETURN_RESULT(result);
}

static void
_ebpf_helper_function_addresses_free(_In_opt_ ebpf_helper_function_addresses_t* helper_function_addresses)
{
    if (helper_function_addresses == NULL) {
        return;
    }

    ebpf_free(helper_function_addresses->helper_function_address);
    ebpf_free(helper_function_addresses);
}

static ebpf_result_t
_duplicate_helper_function_addresses(
    _In_ const ebpf_helper_function_addresses_t* helper_function_addresses,
    _Outptr_ ebpf_helper_function_addresses_t** new_helper_function_addresses)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_helper_function_addresses_t* helper_function_addresses_copy = NULL;

    *new_helper_function_addresses = NULL;

    helper_function_addresses_copy =
        (ebpf_helper_function_addresses_t*)ebpf_allocate(sizeof(ebpf_helper_function_addresses_t));
    if (helper_function_addresses_copy == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    memcpy(helper_function_addresses_copy, helper_function_addresses, helper_function_addresses->header.size);
    helper_function_addresses_copy->header.version = EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION;
    helper_function_addresses_copy->header.size = EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION_SIZE;
    helper_function_addresses_copy->header.total_size = EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION_TOTAL_SIZE;

    helper_function_addresses_copy->helper_function_address =
        (uint64_t*)ebpf_allocate(helper_function_addresses->helper_function_count * sizeof(uint64_t));
    if (helper_function_addresses_copy->helper_function_address == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    memcpy(
        helper_function_addresses_copy->helper_function_address,
        helper_function_addresses->helper_function_address,
        helper_function_addresses->helper_function_count * sizeof(uint64_t));

    *new_helper_function_addresses = helper_function_addresses_copy;
    helper_function_addresses_copy = NULL;

Exit:
    _ebpf_helper_function_addresses_free(helper_function_addresses_copy);

    return result;
}

void
ebpf_program_data_free(_In_opt_ ebpf_program_data_t* program_data)
{
    if (program_data == NULL) {
        return;
    }

    ebpf_program_info_free((ebpf_program_info_t*)program_data->program_info);
    _ebpf_helper_function_addresses_free(
        (ebpf_helper_function_addresses_t*)program_data->global_helper_function_addresses);
    _ebpf_helper_function_addresses_free(
        (ebpf_helper_function_addresses_t*)program_data->program_type_specific_helper_function_addresses);
    ebpf_free(program_data);
}

ebpf_result_t
ebpf_duplicate_program_data(
    _In_ const ebpf_program_data_t* program_data, _Outptr_ ebpf_program_data_t** new_program_data)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_program_data_t* program_data_copy = NULL;

    EBPF_LOG_ENTRY();

    program_data_copy = (ebpf_program_data_t*)ebpf_allocate(sizeof(ebpf_program_data_t));
    if (program_data_copy == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    memcpy(program_data_copy, program_data, program_data->header.size);
    program_data_copy->header.version = EBPF_PROGRAM_DATA_CURRENT_VERSION;
    program_data_copy->header.size = EBPF_PROGRAM_DATA_CURRENT_VERSION_SIZE;
    program_data_copy->header.total_size = EBPF_PROGRAM_DATA_CURRENT_VERSION_TOTAL_SIZE;

    // Initialize pointers to NULL.
    program_data_copy->program_type_specific_helper_function_addresses = NULL;
    program_data_copy->program_info = NULL;

    if (program_data->global_helper_function_addresses != NULL) {
        result = _duplicate_helper_function_addresses(
            program_data->global_helper_function_addresses, &program_data_copy->global_helper_function_addresses);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }
    }

    if (program_data->program_type_specific_helper_function_addresses != NULL) {
        result = _duplicate_helper_function_addresses(
            program_data->program_type_specific_helper_function_addresses,
            &program_data_copy->program_type_specific_helper_function_addresses);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }
    }

    result = ebpf_duplicate_program_info(program_data->program_info, &program_data_copy->program_info);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    *new_program_data = program_data_copy;
    program_data_copy = NULL;

Exit:
    ebpf_program_data_free(program_data_copy);

    EBPF_RETURN_RESULT(result);
}
