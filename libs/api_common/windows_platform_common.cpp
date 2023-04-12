// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "api_common.hpp"
#include "api_internal.h"
#include "crab_verifier_wrapper.hpp"
#include "device_helper.hpp"
#include "ebpf_api.h"
#include "ebpf_nethooks.h"
#include "ebpf_protocol.h"
#include "ebpf_registry_helper.h"
#include "ebpf_serialize.h"
#include "helpers.hpp"
#include "map_descriptors.hpp"
#include "platform.hpp"
#include "spec_type_descriptors.hpp"
#include "store_helper_internal.h"
#include "utilities.hpp"
#include "windows_platform.hpp"
#include "windows_program_type.h"

#include <cassert>
#include <stdexcept>

#define GET_PROGRAM_INFO_REPLY_BUFFER_SIZE 2048

static thread_local ebpf_handle_t _program_under_verification = ebpf_handle_invalid;

extern bool use_ebpf_store;

struct guid_compare
{
    bool
    operator()(_In_ const GUID& a, _In_ const GUID& b) const
    {
        return (memcmp(&a, &b, sizeof(GUID)) < 0);
    }
};

struct _ebpf_program_info_deleter
{
    void
    operator()(_In_ _Post_invalid_ ebpf_program_info_t* program_info)
    {
        ebpf_program_info_free(program_info);
    }
};

static void
_ebpf_program_descriptor_free(_Frees_ptr_opt_ EbpfProgramType* descriptor)
{
    EBPF_LOG_ENTRY();
    if (descriptor == nullptr) {
        EBPF_RETURN_VOID();
    }

    ebpf_free((void*)descriptor->context_descriptor);
    ebpf_free((void*)descriptor->platform_specific_data);

    delete descriptor;

    EBPF_RETURN_VOID();
}

struct EbpfProgramType_deleter
{
    void
    operator()(_In_ _Post_invalid_ EbpfProgramType* descriptor)
    {
        _ebpf_program_descriptor_free(descriptor);
    }
};

static void
_ebpf_section_info_free(_Frees_ptr_opt_ ebpf_section_definition_t* info)
{
    EBPF_LOG_ENTRY();
    if (info == nullptr) {
        EBPF_RETURN_VOID();
    }

    ebpf_free(info->program_type);
    ebpf_free(info->attach_type);
    ebpf_free((void*)info->section_prefix);

    ebpf_free(info);

    EBPF_RETURN_VOID();
}

struct _ebpf_section_info_deleter
{
    void
    operator()(_In_ _Post_invalid_ ebpf_section_definition_t* section_info)
    {
        _ebpf_section_info_free(section_info);
    }
};

// Thread local cache for program information queried from execution context.
typedef std::unique_ptr<ebpf_program_info_t, _ebpf_program_info_deleter> ebpf_program_info_ptr_t;
static thread_local std::map<ebpf_program_type_t, ebpf_program_info_ptr_t, guid_compare> _program_info_cache;

// Thread local cache for program descriptor queried from execution context.
typedef std::unique_ptr<EbpfProgramType, EbpfProgramType_deleter> ebpf_program_descriptor_ptr_t;
static thread_local std::map<ebpf_program_type_t, ebpf_program_descriptor_ptr_t, guid_compare>
    _program_descriptor_cache;

// Global cache for the program and section information queried from eBPF store.
typedef std::unique_ptr<ebpf_section_definition_t, _ebpf_section_info_deleter> ebpf_section_info_ptr_t;
static std::map<ebpf_program_type_t, ebpf_program_descriptor_ptr_t, guid_compare> _windows_program_types;
static std::vector<ebpf_section_info_ptr_t> _windows_section_definitions;
static std::map<ebpf_program_type_t, ebpf_program_info_ptr_t, guid_compare> _windows_program_information;

void
set_program_under_verification(ebpf_handle_t program)
{
    _program_under_verification = program;
}

static ebpf_result_t
_get_program_descriptor_from_info(_In_ const ebpf_program_info_t* info, _Outptr_ EbpfProgramType** descriptor) noexcept
{
    ebpf_result_t result = EBPF_SUCCESS;
    EbpfProgramType* type = nullptr;
    char* name = nullptr;

    try {
        type = new (std::nothrow) EbpfProgramType();
        if (type == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }

        name = ebpf_duplicate_string(info->program_type_descriptor.name);
        if (name == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }
        type->name = std::string(name);
        type->context_descriptor = (ebpf_context_descriptor_t*)ebpf_allocate(sizeof(ebpf_context_descriptor_t));
        if (type->context_descriptor == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }
        memcpy(
            (void*)type->context_descriptor,
            info->program_type_descriptor.context_descriptor,
            sizeof(ebpf_context_descriptor_t));
        ebpf_program_type_t* program_type = (ebpf_program_type_t*)ebpf_allocate(sizeof(ebpf_program_type_t));
        if (program_type == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }
        *program_type = info->program_type_descriptor.program_type;
        type->platform_specific_data = (uint64_t)program_type;
        type->is_privileged = info->program_type_descriptor.is_privileged;

        *descriptor = type;
    } catch (...) {
        result = EBPF_NO_MEMORY;
    }

Exit:
    ebpf_free(name);

    if (result != EBPF_SUCCESS) {
        _ebpf_program_descriptor_free(type);
    }
    return result;
}

static ebpf_result_t
_get_program_info_data(ebpf_program_type_t program_type, _Outptr_ ebpf_program_info_t** program_info)
{
    ebpf_protocol_buffer_t reply_buffer(GET_PROGRAM_INFO_REPLY_BUFFER_SIZE);
    size_t required_buffer_length;
    ebpf_operation_get_program_info_request_t request{
        sizeof(request),
        ebpf_operation_id_t::EBPF_OPERATION_GET_PROGRAM_INFO,
        program_type,
        _program_under_verification};

    *program_info = nullptr;

    auto reply = reinterpret_cast<ebpf_operation_get_program_info_reply_t*>(reply_buffer.data());
    ebpf_result_t result = win32_error_code_to_ebpf_result(invoke_ioctl(request, reply_buffer));
    if ((result != EBPF_SUCCESS) && (result != EBPF_INSUFFICIENT_BUFFER)) {
        goto Exit;
    }

    if (result == EBPF_INSUFFICIENT_BUFFER) {
        required_buffer_length = reply->header.length;
        reply_buffer.resize(required_buffer_length);
        reply = reinterpret_cast<ebpf_operation_get_program_info_reply_t*>(reply_buffer.data());
        result = win32_error_code_to_ebpf_result(invoke_ioctl(request, reply_buffer));
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }
    }

    if (reply->header.id != ebpf_operation_id_t::EBPF_OPERATION_GET_PROGRAM_INFO) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    // Deserialize the reply data into program info.
    result = ebpf_deserialize_program_info(reply->size, reply->data, program_info);

Exit:
    return result;
}

const EbpfProgramType&
get_program_type_windows(const GUID& program_type)
{
    ebpf_result_t result;

    // See if we have the descriptor in the thread local cache.
    auto it = _program_descriptor_cache.find(program_type);
    if (it != _program_descriptor_cache.end()) {
        return *_program_descriptor_cache[program_type].get();
    }

    // Descriptor not found in thread local cache, try to query
    // the info from execution context.
    ebpf_program_info_t* program_info = nullptr;
    EbpfProgramType* descriptor = nullptr;
    result = _get_program_info_data(program_type, &program_info);
    if (result == EBPF_SUCCESS) {
        _program_info_cache[program_type] = ebpf_program_info_ptr_t(program_info);
        // Convert program info to program descriptor.
        result = _get_program_descriptor_from_info(program_info, &descriptor);
        if (result == EBPF_SUCCESS) {
            _program_descriptor_cache[program_type] = ebpf_program_descriptor_ptr_t(descriptor);
            return *_program_descriptor_cache[program_type].get();
        }
    }

    // Failed to query from execution context. Consult static cache.
    if (use_ebpf_store) {
        auto it2 = _windows_program_types.find(program_type);
        if (it2 != _windows_program_types.end()) {
            return *it2->second.get();
        }
    }

    auto guid_string = guid_to_string(&program_type);
    throw std::runtime_error(std::string("ProgramType not found for GUID ") + guid_string);
}

static const ebpf_section_definition_t*
_get_section_definition(const std::string& section)
{
    int32_t match_index = -1;
    size_t match_length = 0;
    for (size_t index = 0; index < _windows_section_definitions.size(); index++) {
        std::string section_prefix(_windows_section_definitions[index].get()->section_prefix);
        if (section.find(section_prefix) == 0) {
            size_t prefix_length = strlen(_windows_section_definitions[index].get()->section_prefix);
            if (match_length < prefix_length) {
                match_index = int32_t(index);
                match_length = prefix_length;
            }
        }
    }

    if (match_index >= 0) {
        return _windows_section_definitions[match_index].get();
    }

    return nullptr;
}

_Ret_maybenull_ const ebpf_program_type_t*
get_ebpf_program_type(bpf_prog_type_t bpf_program_type)
{
    for (auto const& [key, value] : _windows_program_information) {
        if (value.get()->program_type_descriptor.bpf_prog_type == (uint32_t)bpf_program_type) {
            return &key;
        }
    }

    return nullptr;
}

_Ret_maybenull_ const ebpf_attach_type_t*
get_ebpf_attach_type(bpf_attach_type_t bpf_attach_type) noexcept
{
    for (const auto& definition : _windows_section_definitions) {
        if (definition.get()->bpf_attach_type == bpf_attach_type) {
            return definition.get()->attach_type;
        }
    }

    return nullptr;
}

bpf_prog_type_t
get_bpf_program_type(_In_ const ebpf_program_type_t* ebpf_program_type) noexcept
{
    for (auto const& [key, value] : _windows_program_information) {
        if (IsEqualGUID(*ebpf_program_type, key)) {
            return (bpf_prog_type_t)value.get()->program_type_descriptor.bpf_prog_type;
        }
    }

    return BPF_PROG_TYPE_UNSPEC;
}

bpf_attach_type_t
get_bpf_attach_type(_In_ const ebpf_attach_type_t* ebpf_attach_type) noexcept
{
    for (const auto& definition : _windows_section_definitions) {
        if (IsEqualGUID(*ebpf_attach_type, *definition.get()->attach_type)) {
            return definition.get()->bpf_attach_type;
        }
    }

    return BPF_ATTACH_TYPE_UNSPEC;
}

_Must_inspect_result_ ebpf_result_t
get_bpf_program_and_attach_type(
    const std::string& section, _Out_ bpf_prog_type_t* program_type, _Out_ bpf_attach_type_t* attach_type)
{
    ebpf_result_t result = EBPF_SUCCESS;

    const ebpf_section_definition_t* definition = _get_section_definition(section);
    if (definition == nullptr) {
        result = EBPF_KEY_NOT_FOUND;
        goto Exit;
    }

    *program_type = definition->bpf_prog_type;
    *attach_type = definition->bpf_attach_type;

Exit:
    return result;
}

_Must_inspect_result_ ebpf_result_t
get_program_and_attach_type(
    const std::string& section, _Out_ ebpf_program_type_t* program_type, _Out_ ebpf_attach_type_t* attach_type)
{
    ebpf_result_t result = EBPF_SUCCESS;

    const ebpf_section_definition_t* definition = _get_section_definition(section);
    if (definition == nullptr) {
        result = EBPF_KEY_NOT_FOUND;
        goto Exit;
    }

    *program_type = *definition->program_type;
    *attach_type = *definition->attach_type;

Exit:
    return result;
}

EbpfProgramType
get_program_type_windows(const std::string& section, const std::string&)
{
    bool global_program_type_found = true;
    const ebpf_program_type_t* global_program_type = get_global_program_type();
    ebpf_program_type_t program_type;
    ebpf_attach_type_t attach_type;

    if (global_program_type == nullptr) {
        // Global program type is not set. Find the program type from the section prefixes.
        // Find the longest matching section prefix.
        global_program_type_found = false;

        ebpf_result_t result = get_program_and_attach_type(section, &program_type, &attach_type);
        if (result == EBPF_SUCCESS) {
            global_program_type = &program_type;
        } else {
            global_program_type = &EBPF_PROGRAM_TYPE_UNSPECIFIED;
        }
    }

    // Note: Ideally this function should throw an exception whenever a matching ProgramType
    // is not found, but that causes a problem in the following scenario:
    //
    // This function is called by verifier code in 2 cases:
    //   1. When verifying the code
    //   2. When parsing the ELF file and unmarshalling the code.
    // For the second case mentioned above, if the ELF file contains an unknown section name (".text", for example),
    // and this function is called while unmarshalling that section, throwing an exception here
    // will fail the parsing of the ELF file.
    //
    // Hence this function returns ProgramType for EBPF_PROGRAM_TYPE_UNSPECIFIED when verification is not
    // in progress, and throws an exception otherwise.
    try {
        return get_program_type_windows(*global_program_type);
    } catch (...) {
        if (!get_verification_in_progress()) {
            return windows_unspecified_program_type;
        } else {
            if (global_program_type_found) {
                auto guid_string = guid_to_string(global_program_type);
                throw std::runtime_error(std::string("ProgramType not found for GUID ") + guid_string);
            } else {
                throw std::runtime_error(std::string("ProgramType not found for section " + section));
            }
        }
    }
}

#define BPF_MAP_TYPE(x) BPF_MAP_TYPE_##x, #x

static const EbpfMapType windows_map_types[] = {
    {BPF_MAP_TYPE(UNSPEC)},
    {BPF_MAP_TYPE(HASH)},
    {BPF_MAP_TYPE(ARRAY), true},
    {BPF_MAP_TYPE(PROG_ARRAY), true, EbpfMapValueType::PROGRAM},
    {BPF_MAP_TYPE(PERCPU_HASH)},
    {BPF_MAP_TYPE(PERCPU_ARRAY), true},
    {BPF_MAP_TYPE(HASH_OF_MAPS), false, EbpfMapValueType::MAP},
    {BPF_MAP_TYPE(ARRAY_OF_MAPS), true, EbpfMapValueType::MAP},
};

EbpfMapType
get_map_type_windows(uint32_t platform_specific_type)
{
    uint32_t index = platform_specific_type;
    if ((index == 0) || (index >= sizeof(windows_map_types) / sizeof(windows_map_types[0]))) {
        return windows_map_types[0];
    }
    EbpfMapType type = windows_map_types[index];
    assert(type.platform_specific_type == platform_specific_type);
    return type;
}

EbpfMapDescriptor&
get_map_descriptor_windows(int original_fd)
{
    // First check if we already have the map descriptor cached.
    EbpfMapDescriptor* map = find_map_descriptor(original_fd);
    if (map != nullptr) {
        return *map;
    }

    return get_map_descriptor(original_fd);
}

const ebpf_attach_type_t*
get_attach_type_windows(const std::string& section)
{
    const ebpf_section_definition_t* definition = _get_section_definition(section);
    if (definition != nullptr) {
        return definition->attach_type;
    }

    return &EBPF_ATTACH_TYPE_UNSPECIFIED;
}

_Ret_maybenull_z_ const char*
get_attach_type_name(_In_ const ebpf_attach_type_t* attach_type)
{
    for (const auto& t : _windows_section_definitions) {
        if (IsEqualGUID(*t.get()->attach_type, *attach_type)) {
            return t.get()->section_prefix;
        }
    }

    return nullptr;
}

static ebpf_result_t
_update_global_helpers_for_program_information(
    _In_reads_(global_helper_count) const ebpf_helper_function_prototype_t* global_helpers,
    uint32_t global_helper_count)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_helper_function_prototype_t* new_helpers = nullptr;
    size_t total_helper_count = 0;
    size_t total_helper_size = 0;

    if (global_helper_count == 0) {
        return result;
    }

    // Iterate over all the program information and append the global
    // helper functions to each of the program information.
    for (auto& iterator : _windows_program_information) {
        ebpf_program_info_t* program_info = iterator.second.get();
        total_helper_count = static_cast<size_t>(global_helper_count) +
                             static_cast<size_t>(program_info->count_of_program_type_specific_helpers);
        if (total_helper_count < global_helper_count ||
            total_helper_count < program_info->count_of_program_type_specific_helpers) {
            result = EBPF_ARITHMETIC_OVERFLOW;
            goto Exit;
        }
        total_helper_size = total_helper_count * sizeof(ebpf_helper_function_prototype_t);
        new_helpers = (ebpf_helper_function_prototype_t*)ebpf_allocate(total_helper_size);
        if (new_helpers == nullptr) {
            result = EBPF_NO_MEMORY;
            break;
        }

        memset(new_helpers, 0, total_helper_size);

#pragma warning(push)
#pragma warning(disable : 6386) // Buffer overrun while writing to 'new_helpers':  the writable size is
                                // 'total_helper_size' bytes, but '80' bytes might be written
        // Copy the global helpers to the new helpers.
        for (uint32_t i = 0; i < global_helper_count; i++) {
            new_helpers[i] = global_helpers[i];
            new_helpers[i].name = nullptr;
            auto name = ebpf_duplicate_string(global_helpers[i].name);
            if (name == nullptr) {
                result = EBPF_NO_MEMORY;
                goto Exit;
            }
            new_helpers[i].name = name;
        }
#pragma warning(pop)

        if (program_info->count_of_program_type_specific_helpers > 0) {
            memcpy(
                new_helpers + global_helper_count,
                program_info->program_type_specific_helper_prototype,
                (program_info->count_of_program_type_specific_helpers * sizeof(ebpf_helper_function_prototype_t)));
            ebpf_free((void*)program_info->program_type_specific_helper_prototype);
        }

        program_info->program_type_specific_helper_prototype = new_helpers;
        program_info->count_of_program_type_specific_helpers = (uint32_t)total_helper_count;
        new_helpers = nullptr;
        total_helper_count = 0;
    }

Exit:
#pragma warning(push)
#pragma warning(disable : 6385) // Reading invalid data from 'new_helpers'.
#pragma warning(disable : 6001) // Using uninitialized memory '*new_helpers.name'.
    if (result != EBPF_SUCCESS) {
        if (new_helpers) {
            for (uint32_t i = 0; i < total_helper_count; i++) {
                if (new_helpers[i].name) {
                    ebpf_free((void*)new_helpers[i].name);
                }
            }
            ebpf_free(new_helpers);
        }
    }
#pragma warning(pop)
    return result;
}

static void
_helper_info_free(_Frees_ptr_opt_ ebpf_helper_function_prototype_t* helper_info, uint32_t helper_info_count)
{
    if (!helper_info) {
        return;
    }

#pragma warning(push)
#pragma warning(disable : 6001) // Using uninitialized memory '*helper_info.name'
    for (uint32_t index = 0; index < helper_info_count; index++) {
        ebpf_free((void*)helper_info[index].name);
    }
#pragma warning(pop)

    ebpf_free(helper_info);
}

static ebpf_result_t
_load_all_global_helper_information()
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_helper_function_prototype_t* helper_info = nullptr;
    uint32_t helper_info_count = 0;

    result = ebpf_store_load_global_helper_information(&helper_info, &helper_info_count);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    if (!helper_info) {
        goto Exit;
        // No global helper functions found.
    }

    result = _update_global_helpers_for_program_information(helper_info, helper_info_count);

Exit:
    _helper_info_free(helper_info, helper_info_count);
    return result;
}

static ebpf_result_t
_load_all_section_data_information()
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_section_definition_t** section_info = nullptr;
    uint32_t section_info_count = 0;

    result = ebpf_store_load_section_information(&section_info, &section_info_count);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    if (section_info_count == 0 || section_info == nullptr) {
        goto Exit;
    }

    try {
        for (uint32_t index = 0; index < section_info_count; index++) {
            ebpf_section_definition_t* info = section_info[index];
            _windows_section_definitions.emplace_back(ebpf_section_info_ptr_t(info));
            section_info[index] = nullptr;
        }
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
    } catch (...) {
        result = EBPF_FAILED;
    }

Exit:
    if (result != EBPF_SUCCESS) {
        _windows_section_definitions.clear();
    }
    if (section_info) {
        for (uint32_t index = 0; index < section_info_count; index++) {
            _ebpf_section_info_free(section_info[index]);
            section_info[index] = nullptr;
        }
        ebpf_free(section_info);
    }
    return result;
}

static ebpf_result_t
_load_all_program_data_information()
{
    ebpf_result_t result;
    ebpf_program_info_t** program_info = nullptr;
    uint32_t program_info_count = 0;

    result = ebpf_store_load_program_information(&program_info, &program_info_count);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    if (program_info_count == 0 || program_info == nullptr) {
        // No entries found in the store.
        goto Exit;
    }

    try {
        for (uint32_t index = 0; index < program_info_count; index++) {
            ebpf_program_info_t* info = program_info[index];
            ebpf_program_type_t program_type = info->program_type_descriptor.program_type;
            _windows_program_information[program_type] = ebpf_program_info_ptr_t(info);
            program_info[index] = nullptr;

            EbpfProgramType* program_data = nullptr;
            result = _get_program_descriptor_from_info(info, &program_data);
            if (result != EBPF_SUCCESS) {
                goto Exit;
            }
            _windows_program_types[program_type] = ebpf_program_descriptor_ptr_t(program_data);
        }
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
    } catch (...) {
        result = EBPF_FAILED;
    }

Exit:
    if (result != EBPF_SUCCESS) {
        _windows_program_information.clear();
        _windows_program_types.clear();
    }
    if (program_info) {
        for (uint32_t index = 0; index < program_info_count; index++) {
            ebpf_program_info_free(program_info[index]);
            program_info[index] = nullptr;
        }
        ebpf_free(program_info);
    }
    return result;
}

_Must_inspect_result_ ebpf_result_t
load_ebpf_provider_data()
{
    ebpf_result_t result = _load_all_program_data_information();
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    result = _load_all_section_data_information();
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    result = _load_all_global_helper_information();
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

Exit:
    return result;
}

void
clear_ebpf_provider_data()
{
    _windows_program_types.clear();
    _windows_section_definitions.clear();
    _windows_program_information.clear();
}

_Ret_maybenull_ static const ebpf_program_info_t*
_get_static_program_info(_In_ const ebpf_program_type_t* program_type)
{
    for (auto& iterator : _windows_program_information) {
        if (IsEqualGUID(*program_type, iterator.first)) {
            return iterator.second.get();
        }
    }

    return nullptr;
}

_Success_(return == EBPF_SUCCESS) ebpf_result_t get_program_type_info(_Outptr_ const ebpf_program_info_t** info)
{
    const GUID* program_type = reinterpret_cast<const GUID*>(global_program_info->type.platform_specific_data);
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_program_info_t* program_info;
    bool fall_back = false;

    // See if we already have the program info cached.
    auto it = _program_info_cache.find(*program_type);
    if (it == _program_info_cache.end()) {
        // Try to query the info from the execution context.
        result = _get_program_info_data(*program_type, &program_info);
        if (result != EBPF_SUCCESS) {
            fall_back = true;
        } else {
            _program_info_cache[*program_type] = ebpf_program_info_ptr_t(program_info);
            *info = (const ebpf_program_info_t*)_program_info_cache[*program_type].get();
        }
    } else {
        *info = (const ebpf_program_info_t*)_program_info_cache[*program_type].get();
    }

    if (use_ebpf_store && fall_back) {
        // Query static data loaded from eBPF store.
        *info = _get_static_program_info(program_type);
        if (*info == nullptr) {
            result = EBPF_OBJECT_NOT_FOUND;
        } else {
            result = EBPF_SUCCESS;
        }
    }

    return result;
}

void
clear_program_info_cache()
{
    _program_info_cache.clear();
    _program_descriptor_cache.clear();
}
