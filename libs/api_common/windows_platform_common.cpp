// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "..\store_helper\user\ebpf_registry_helper.h"
#include "api_common.hpp"
#include "api_internal.h"
#include "device_helper.hpp"
#include "ebpf_api.h"
#include "ebpf_nethooks.h"
#include "ebpf_protocol.h"
#include "ebpf_serialize.h"
#include "ebpf_store_helper.h"
#include "ebpf_verifier_wrapper.hpp"
#include "ir/arg_kind.hpp"
#pragma warning(push)
#pragma warning(disable : 26495) // Always initialize a member variable
#define ebpf_inst ebpf_inst_btf
#include "..\..\external\ebpf-verifier\external\libbtf\libbtf\btf_type_data.h"
#undef ebpf_inst
#pragma warning(pop)
#include "map_descriptors.hpp"
#include "platform.hpp"
#include "store_helper_internal.h"
#include "utilities.hpp"
#include "windows_platform.hpp"
#include "windows_program_type.h"

#include <array>
#include <cassert>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string_view>

#define GET_PROGRAM_INFO_REPLY_BUFFER_SIZE 4096

#ifndef GUID_NULL
const GUID GUID_NULL = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};
#endif

static thread_local ebpf_handle_t _program_under_verification = ebpf_handle_invalid;
static thread_local ebpf_program_type_t _current_verification_program_guid = {};
static thread_local bool _current_verification_program_guid_set = false;

typedef struct _btf_resolved_function_identity
{
    GUID module_guid;
    std::string function_name;
} btf_resolved_function_identity_t;

struct _ebpf_btf_resolved_function_info_deleter
{
    void
    operator()(_In_ _Post_invalid_ ebpf_btf_resolved_function_info_t* function_info)
    {
        ebpf_store_free_btf_resolved_function(function_info);
    }
};

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
_ebpf_program_descriptor_free(_Frees_ptr_opt_ prevail::EbpfProgramType* descriptor)
{
    EBPF_LOG_ENTRY();
    if (descriptor == nullptr) {
        EBPF_RETURN_VOID();
    }

    ebpf_free((void*)descriptor->ctx_descriptor);
    ebpf_free((void*)descriptor->platform_specific_data);

    delete descriptor;

    EBPF_RETURN_VOID();
}

struct EbpfProgramType_deleter
{
    void
    operator()(_In_ _Post_invalid_ prevail::EbpfProgramType* descriptor)
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
typedef std::unique_ptr<prevail::EbpfProgramType, EbpfProgramType_deleter> ebpf_program_descriptor_ptr_t;
static thread_local std::map<ebpf_program_type_t, ebpf_program_descriptor_ptr_t, guid_compare>
    _program_descriptor_cache;

typedef std::unique_ptr<ebpf_btf_resolved_function_info_t, _ebpf_btf_resolved_function_info_deleter>
    ebpf_btf_resolved_function_info_ptr_t;
static thread_local std::map<std::string, int32_t> _btf_resolved_function_name_to_id;
static thread_local std::map<int32_t, btf_resolved_function_identity_t> _btf_resolved_function_identities;
static thread_local std::map<int32_t, ebpf_btf_resolved_function_info_ptr_t> _btf_resolved_function_cache;
static thread_local int32_t _next_btf_resolved_function_id = 1;

// Global cache for the program and section information queried from eBPF store.
typedef std::unique_ptr<ebpf_section_definition_t, _ebpf_section_info_deleter> ebpf_section_info_ptr_t;
std::unique_ptr<std::once_flag> _windows_program_information_init_flag = std::make_unique<std::once_flag>();
static std::map<ebpf_program_type_t, ebpf_program_descriptor_ptr_t, guid_compare> _windows_program_types;
static std::vector<ebpf_section_info_ptr_t> _windows_section_definitions;
static std::map<ebpf_program_type_t, ebpf_program_info_ptr_t, guid_compare> _windows_program_information;

static void
_load_ebpf_provider_data();

static void
_clear_btf_resolved_function_state()
{
    _btf_resolved_function_name_to_id.clear();
    _btf_resolved_function_identities.clear();
    _btf_resolved_function_cache.clear();
    _next_btf_resolved_function_id = 1;
}

static void
_set_unsupported(_Out_opt_ std::string* why_not, const std::string& reason)
{
    if (why_not != nullptr) {
        *why_not = reason;
    }
}

static ebpf_btf_resolved_function_info_t*
_get_btf_resolved_function_info(int32_t btf_id)
{
    auto cache_entry = _btf_resolved_function_cache.find(btf_id);
    if (cache_entry != _btf_resolved_function_cache.end()) {
        return cache_entry->second.get();
    }

    auto identity = _btf_resolved_function_identities.find(btf_id);
    if (identity == _btf_resolved_function_identities.end()) {
        return nullptr;
    }

    ebpf_btf_resolved_function_info_t* function_info = nullptr;
    if (ebpf_store_load_btf_resolved_function(
            &identity->second.module_guid, identity->second.function_name.c_str(), &function_info) != EBPF_SUCCESS) {
        return nullptr;
    }

    _btf_resolved_function_cache[btf_id] = ebpf_btf_resolved_function_info_ptr_t(function_info);
    return _btf_resolved_function_cache[btf_id].get();
}

static GUID
_parse_module_guid_or_throw(const std::string& tag_string)
{
    static constexpr std::string_view module_id_prefix{"module_id:"};
    GUID module_guid = GUID_NULL;
    wchar_t* guid_string = nullptr;

    if (tag_string.compare(0, module_id_prefix.size(), module_id_prefix) != 0) {
        throw std::runtime_error("Unsupported BTF decl_tag format: " + tag_string);
    }

    guid_string = ebpf_get_wstring_from_string(tag_string.substr(module_id_prefix.size()).c_str());
    if (guid_string == nullptr) {
        throw std::runtime_error("Out of memory parsing BTF module GUID");
    }

    ebpf_result_t result = ebpf_convert_string_to_guid(guid_string, &module_guid);
    ebpf_free_wstring(guid_string);
    if (result != EBPF_SUCCESS) {
        throw std::runtime_error("Invalid BTF module GUID decl_tag: " + tag_string);
    }

    return module_guid;
}

void
set_program_under_verification(ebpf_handle_t program)
{
    _program_under_verification = program;
}

static ebpf_result_t
_get_program_descriptor_from_info(
    _In_ const ebpf_program_info_t* info, _Outptr_ prevail::EbpfProgramType** descriptor) noexcept
{
    ebpf_result_t result = EBPF_SUCCESS;
    prevail::EbpfProgramType* type = nullptr;
    char* name = nullptr;

    try {
        type = new (std::nothrow) prevail::EbpfProgramType();
        if (type == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }

        if (info->program_type_descriptor == nullptr) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        if (info->program_type_descriptor->context_descriptor == nullptr) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        name = cxplat_duplicate_string(info->program_type_descriptor->name);
        if (name == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }
        type->name = std::string(name);
        type->ctx_descriptor =
            (ebpf_ctx_descriptor_t*)ebpf_allocate_with_tag(sizeof(ebpf_ctx_descriptor_t), EBPF_POOL_TAG_DEFAULT);
        if (type->ctx_descriptor == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }
        memcpy(
            (void*)type->ctx_descriptor,
            info->program_type_descriptor->context_descriptor,
            sizeof(ebpf_ctx_descriptor_t));
        ebpf_program_type_t* program_type =
            (ebpf_program_type_t*)ebpf_allocate_with_tag(sizeof(ebpf_program_type_t), EBPF_POOL_TAG_DEFAULT);
        if (program_type == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }
        *program_type = info->program_type_descriptor->program_type;
        type->platform_specific_data = (uint64_t)program_type;
        type->is_privileged = info->program_type_descriptor->is_privileged;

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

_Ret_maybenull_ const prevail::EbpfProgramType*
get_program_type_windows(const GUID& program_type)
{
    ebpf_result_t result;
    auto guid_string = guid_to_string(&program_type);

    _load_ebpf_provider_data();

    // See if we have the descriptor in the thread local cache.
    auto it = _program_descriptor_cache.find(program_type);
    if (it != _program_descriptor_cache.end()) {
        return _program_descriptor_cache[program_type].get();
    }

    // Descriptor not found in thread local cache, try to query
    // the info from execution context.
    ebpf_program_info_t* program_info = nullptr;
    prevail::EbpfProgramType* descriptor = nullptr;
    result = _get_program_info_data(program_type, &program_info);
    if (result == EBPF_SUCCESS) {
        _program_info_cache[program_type] = ebpf_program_info_ptr_t(program_info);
        // Convert program info to program descriptor.
        result = _get_program_descriptor_from_info(program_info, &descriptor);
        if (result == EBPF_SUCCESS) {
            _program_descriptor_cache[program_type] = ebpf_program_descriptor_ptr_t(descriptor);
            return _program_descriptor_cache[program_type].get();
        }
    }

    // Failed to query from execution context. Consult static cache.
    if (use_ebpf_store) {
        auto it2 = _windows_program_information.find(program_type);
        if (it2 != _windows_program_information.end()) {
            // Cache the descriptor in thread local cache.
            result = ebpf_duplicate_program_info(it2->second.get(), &program_info);
            if (result != EBPF_SUCCESS) {
                throw std::runtime_error(std::string("Failed to duplicate program info.") + guid_string);
            }
            _program_info_cache[program_type] = ebpf_program_info_ptr_t(program_info);
            result = _get_program_descriptor_from_info(program_info, &descriptor);
            if (result == EBPF_SUCCESS) {
                _program_descriptor_cache[program_type] = ebpf_program_descriptor_ptr_t(descriptor);
                return _program_descriptor_cache[program_type].get();
            } else {
                throw std::runtime_error(std::string("Failed to get program descriptor.") + guid_string);
            }
        }
    }

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
    _load_ebpf_provider_data();

    for (auto const& [key, value] : _windows_program_information) {
        if (value.get()->program_type_descriptor->bpf_prog_type == (uint32_t)bpf_program_type) {
            return &key;
        }
    }

    return nullptr;
}

_Ret_maybenull_ const ebpf_attach_type_t*
get_ebpf_attach_type(bpf_attach_type_t bpf_attach_type) noexcept
{
    _load_ebpf_provider_data();

    for (const auto& definition : _windows_section_definitions) {
        if (definition.get()->bpf_attach_type == bpf_attach_type) {
            return definition.get()->attach_type;
        }
    }

    return nullptr;
}

_Must_inspect_result_ ebpf_result_t
ebpf_get_ebpf_attach_type(bpf_attach_type_t bpf_attach_type, _Out_ ebpf_attach_type_t* ebpf_attach_type) noexcept
{
    const ebpf_attach_type_t* result = get_ebpf_attach_type(bpf_attach_type);
    if (result == nullptr) {
        *ebpf_attach_type = GUID_NULL;
        return EBPF_INVALID_ARGUMENT;
    }

    *ebpf_attach_type = *result;
    return EBPF_SUCCESS;
}

bpf_prog_type_t
ebpf_get_bpf_program_type(_In_ const ebpf_program_type_t* ebpf_program_type) noexcept
{
    _load_ebpf_provider_data();

    for (auto const& [key, value] : _windows_program_information) {
        if (IsEqualGUID(*ebpf_program_type, key)) {
            return (bpf_prog_type_t)value.get()->program_type_descriptor->bpf_prog_type;
        }
    }

    return BPF_PROG_TYPE_UNSPEC;
}

bpf_attach_type_t
ebpf_get_bpf_attach_type(_In_ const ebpf_attach_type_t* ebpf_attach_type) noexcept
{
    _load_ebpf_provider_data();

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
    _load_ebpf_provider_data();

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
    _load_ebpf_provider_data();

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

prevail::EbpfProgramType
get_program_type_windows(const std::string& section, const std::string&)
{
    bool global_program_type_found = true;
    const ebpf_program_type_t* global_program_type = get_global_program_type();
    ebpf_program_type_t program_type;
    ebpf_attach_type_t attach_type;

    _load_ebpf_provider_data();

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

    try {
        return *get_program_type_windows(*global_program_type);
    } catch (...) {
        return PTYPE("unspec", {0}, (uint64_t)&EBPF_PROGRAM_TYPE_UNSPECIFIED, {});
    }
}

#define BPF_MAP_TYPE(x) BPF_MAP_TYPE_##x, #x

static const prevail::EbpfMapType windows_map_types[] = {
    {BPF_MAP_TYPE(UNSPEC)},
    {BPF_MAP_TYPE(HASH)},
    {BPF_MAP_TYPE(ARRAY), true},
    {BPF_MAP_TYPE(PROG_ARRAY), true, prevail::EbpfMapValueType::PROGRAM},
    {BPF_MAP_TYPE(PERCPU_HASH)},
    {BPF_MAP_TYPE(PERCPU_ARRAY), true},
    {BPF_MAP_TYPE(HASH_OF_MAPS), false, prevail::EbpfMapValueType::MAP},
    {BPF_MAP_TYPE(ARRAY_OF_MAPS), true, prevail::EbpfMapValueType::MAP},
};

prevail::EbpfMapType
get_map_type_windows(uint32_t platform_specific_type)
{
    uint32_t index = platform_specific_type;
    if ((index == 0) || (index >= sizeof(windows_map_types) / sizeof(windows_map_types[0]))) {
        return windows_map_types[0];
    }
    prevail::EbpfMapType type = windows_map_types[index];
    assert(type.platform_specific_type == platform_specific_type);
    return type;
}

const prevail::EbpfMapDescriptor&
get_map_descriptor_windows(int original_fd, const std::vector<prevail::EbpfMapDescriptor>& descriptors)
{
    // First check if we already have the map descriptor in the provided descriptors.
    for (const auto& map : descriptors) {
        if (map.original_fd == original_fd) {
            return map;
        }
    }

    return get_map_descriptor(original_fd);
}

const ebpf_attach_type_t*
get_attach_type_windows(const std::string& section)
{
    _load_ebpf_provider_data();

    const ebpf_section_definition_t* definition = _get_section_definition(section);
    if (definition != nullptr) {
        return definition->attach_type;
    }

    return &EBPF_ATTACH_TYPE_UNSPECIFIED;
}

_Ret_maybenull_z_ const char*
get_attach_type_name(_In_ const ebpf_attach_type_t* attach_type)
{
    _load_ebpf_provider_data();

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
        result =
            ebpf_safe_size_t_multiply(total_helper_count, sizeof(ebpf_helper_function_prototype_t), &total_helper_size);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }
        new_helpers =
            (ebpf_helper_function_prototype_t*)ebpf_allocate_with_tag(total_helper_size, EBPF_POOL_TAG_DEFAULT);
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
            auto name = cxplat_duplicate_string(global_helpers[i].name);
            if (name == nullptr) {
                result = EBPF_NO_MEMORY;
                goto Exit;
            }
            new_helpers[i].name = name;
        }
#pragma warning(pop)

        if (program_info->count_of_program_type_specific_helpers > 0) {
            size_t destination_helper_count = 0;
            result = ebpf_safe_size_t_subtract(total_helper_count, global_helper_count, &destination_helper_count);
            if (result != EBPF_SUCCESS) {
                goto Exit;
            }
            if (program_info->count_of_program_type_specific_helpers > destination_helper_count) {
                result = EBPF_INVALID_ARGUMENT;
                goto Exit;
            }

            ebpf_helper_function_prototype_t* source_helpers =
                (ebpf_helper_function_prototype_t*)program_info->program_type_specific_helper_prototype;
            for (size_t i = 0; i < program_info->count_of_program_type_specific_helpers; i++) {
#pragma warning(suppress : 6385) // Source helper array length matches count_of_program_type_specific_helpers.
                new_helpers[global_helper_count + i] = source_helpers[i];
            }
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
            section_info[index] = nullptr;
            _windows_section_definitions.emplace_back(ebpf_section_info_ptr_t(info));
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

    result = ebpf_store_load_program_data(&program_info, &program_info_count);
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
            program_info[index] = nullptr;
            ebpf_program_type_t program_type = info->program_type_descriptor->program_type;
            _windows_program_information[program_type] = ebpf_program_info_ptr_t(info);

            prevail::EbpfProgramType* program_data = nullptr;
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

/**
 * @brief This function loads all the program information from the store.
 * It is relatively expensive and should be called only when needed instead
 * of when DllMain is invoked. It is idempotent and multi-thread safe.
 */
static void
_load_ebpf_provider_data()
{
    try {
        std::call_once(*_windows_program_information_init_flag, [] {
            ebpf_result_t result = _load_all_program_data_information();
            if (result != EBPF_SUCCESS) {
                throw std::runtime_error("Failed to load program information from eBPF store.");
            }

            result = _load_all_section_data_information();
            if (result != EBPF_SUCCESS) {
                throw std::runtime_error("Failed to load section information from eBPF store.");
            }

            result = _load_all_global_helper_information();
            if (result != EBPF_SUCCESS) {
                throw std::runtime_error("Failed to load global helper information from eBPF store.");
            }
        });
    } catch (...) {
        _windows_program_types.clear();
        _windows_section_definitions.clear();
        _windows_program_information.clear();
    }
}

void
clear_ebpf_provider_data()
{
    _windows_program_types.clear();
    _windows_section_definitions.clear();
    _windows_program_information.clear();

    // Reset the flag so that the data is reloaded when needed.
    _windows_program_information_init_flag = std::make_unique<std::once_flag>();
}

_Success_(return == EBPF_SUCCESS) ebpf_result_t
    get_program_type_info(const prevail::EbpfProgramType& program_type, _Outptr_ const ebpf_program_info_t** info)
{
    const GUID* guid = reinterpret_cast<const GUID*>(program_type.platform_specific_data);
    ebpf_result_t result = EBPF_SUCCESS;

    _load_ebpf_provider_data();

    // Get program information from the TLS cache.
    auto it = _program_info_cache.find(*guid);
    if (it == _program_info_cache.end()) {
        result = EBPF_OBJECT_NOT_FOUND;
    } else {
        *info = (const ebpf_program_info_t*)_program_info_cache[*guid].get();
    }

    return result;
}

void
cache_btf_resolved_functions(const libbtf::btf_type_data& btf_data)
{
    constexpr uint32_t top_level_component_index = std::numeric_limits<uint32_t>::max();
    std::map<libbtf::btf_type_id, GUID> function_modules;
    std::set<libbtf::btf_type_id> ksym_function_type_ids;

    _clear_btf_resolved_function_state();

    const auto ksyms_id = btf_data.get_id(".ksyms");
    if (ksyms_id != 0) {
        libbtf::btf_kind_data_section ksyms;
        try {
            ksyms = btf_data.get_kind_type<libbtf::btf_kind_data_section>(ksyms_id);
        } catch (const std::exception& e) {
            throw std::runtime_error(
                std::string("Unsupported or invalid BTF .ksyms section (id ") + std::to_string(ksyms_id) +
                "): " + e.what());
        }

        for (const auto& member : ksyms.members) {
            if (btf_data.get_kind_index(member.type) == libbtf::BTF_KIND_FUNCTION) {
                ksym_function_type_ids.insert(member.type);
            }
        }
    }

    for (libbtf::btf_type_id id = 1; id <= btf_data.last_type_id(); id++) {
        if (btf_data.get_kind_index(id) != libbtf::BTF_KIND_DECL_TAG) {
            continue;
        }

        auto decl_tag = btf_data.get_kind_type<libbtf::btf_kind_decl_tag>(id);
        if (decl_tag.component_index != top_level_component_index) {
            continue;
        }

        GUID module_guid = _parse_module_guid_or_throw(decl_tag.name);
        auto existing = function_modules.find(decl_tag.type);
        if (existing != function_modules.end()) {
            if (!IsEqualGUID(existing->second, module_guid)) {
                throw std::runtime_error(
                    std::string("Conflicting module_id decl_tag entries for BTF function type ") +
                    std::to_string(decl_tag.type));
            }
            continue;
        }

        function_modules.emplace(decl_tag.type, module_guid);
        if (btf_data.get_kind_index(decl_tag.type) == libbtf::BTF_KIND_FUNCTION) {
            ksym_function_type_ids.insert(decl_tag.type);
        }
    }

    for (const auto& type_id : ksym_function_type_ids) {
        libbtf::btf_kind_function function;
        try {
            function = btf_data.get_kind_type<libbtf::btf_kind_function>(type_id);
        } catch (const std::exception& e) {
            throw std::runtime_error(
                std::string("Unsupported or invalid BTF kfunc declaration (type ") + std::to_string(type_id) +
                "): " + e.what());
        }

        if (function.name.empty()) {
            continue;
        }

        auto module = function_modules.find(type_id);
        if (module == function_modules.end()) {
            throw std::runtime_error("Missing module_id decl_tag for BTF-resolved function " + function.name);
        }

        auto existing_name = _btf_resolved_function_name_to_id.find(function.name);
        if (existing_name != _btf_resolved_function_name_to_id.end()) {
            const auto& existing_identity = _btf_resolved_function_identities.at(existing_name->second);
            if (!IsEqualGUID(existing_identity.module_guid, module->second)) {
                throw std::runtime_error(
                    "Ambiguous BTF-resolved function name across multiple module GUIDs: " + function.name);
            }
            continue;
        }

        const int32_t btf_id = _next_btf_resolved_function_id++;
        _btf_resolved_function_name_to_id.emplace(function.name, btf_id);
        _btf_resolved_function_identities.emplace(
            btf_id, btf_resolved_function_identity_t{.module_guid = module->second, .function_name = function.name});
    }
}

std::optional<prevail::KsymBtfId>
resolve_ksym_btf_id_windows(const std::string& name)
{
    auto identity = _btf_resolved_function_name_to_id.find(name);
    if (identity == _btf_resolved_function_name_to_id.end()) {
        return std::nullopt;
    }

    return prevail::KsymBtfId{.btf_id = identity->second, .module = 0};
}

std::optional<prevail::ResolvedCall>
resolve_kfunc_call_windows(
    int32_t btf_id, int16_t module, const prevail::EbpfProgramType& program_type, std::string* why_not)
{
    UNREFERENCED_PARAMETER(program_type);
    UNREFERENCED_PARAMETER(module);

    auto function_info = _get_btf_resolved_function_info(btf_id);
    if (function_info == nullptr) {
        _set_unsupported(why_not, "kfunc prototype lookup failed for BTF id " + std::to_string(btf_id));
        return std::nullopt;
    }

    const auto& prototype = function_info->prototype;
    const std::string function_name = prototype.name != nullptr ? prototype.name : std::to_string(btf_id);

    if (prototype.flags != 0) {
        _set_unsupported(why_not, "kfunc has unsupported flags: " + function_name);
        return std::nullopt;
    }

    if (prototype.return_type == EBPF_RETURN_TYPE_UNSUPPORTED) {
        _set_unsupported(why_not, "kfunc prototype is unavailable on this platform: " + function_name);
        return std::nullopt;
    }

    const auto return_info = prevail::classify_call_return_type(prototype.return_type);
    if (!return_info.has_value()) {
        _set_unsupported(why_not, "kfunc return type is unsupported on this platform: " + function_name);
        return std::nullopt;
    }

    prevail::ResolvedCall result;
    result.call = prevail::Call{.func = btf_id, .kind = prevail::CallKind::kfunc, .module = module};
    result.name = function_name;
    result.contract.return_ptr_type = return_info->pointer_type;
    result.contract.return_nullable = return_info->pointer_nullable;
    result.contract.is_map_lookup = prototype.return_type == EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL;

    const std::array<ebpf_argument_type_t, 7> arguments = {
        {EBPF_ARGUMENT_TYPE_DONTCARE,
         prototype.arguments[0],
         prototype.arguments[1],
         prototype.arguments[2],
         prototype.arguments[3],
         prototype.arguments[4],
         EBPF_ARGUMENT_TYPE_DONTCARE}};

    for (size_t index = 1; index < arguments.size() - 1;) {
        switch (prevail::process_arg(result.contract, arguments, index)) {
        case prevail::ArgOutcome::Single:
            index += 1;
            break;
        case prevail::ArgOutcome::Pair:
            index += 2;
            break;
        case prevail::ArgOutcome::Stop:
            return result;
        case prevail::ArgOutcome::Unavailable:
            _set_unsupported(why_not, "kfunc argument type is unsupported on this platform: " + function_name);
            return std::nullopt;
        case prevail::ArgOutcome::MismatchedSize:
            _set_unsupported(
                why_not,
                "kfunc pointer argument not followed by EBPF_ARGUMENT_TYPE_CONST_SIZE or "
                "EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO: " +
                    function_name);
            return std::nullopt;
        }
    }

    return result;
}

void
set_verification_program_type(const prevail::EbpfProgramType* type)
{
    if (type != nullptr) {
        _current_verification_program_guid =
            *reinterpret_cast<const ebpf_program_type_t*>(type->platform_specific_data);
        _current_verification_program_guid_set = true;
    } else {
        _current_verification_program_guid = {};
        _current_verification_program_guid_set = false;
    }
}

_Success_(return == EBPF_SUCCESS) ebpf_result_t
    get_program_type_info_from_tls(_Outptr_ const ebpf_program_info_t** info)
{
    if (!_current_verification_program_guid_set) {
        return EBPF_OBJECT_NOT_FOUND;
    }

    _load_ebpf_provider_data();

    // Get program information from the TLS cache.
    auto it = _program_info_cache.find(_current_verification_program_guid);
    if (it == _program_info_cache.end()) {
        return EBPF_OBJECT_NOT_FOUND;
    }
    *info = (const ebpf_program_info_t*)it->second.get();
    return EBPF_SUCCESS;
}

_Success_(return == EBPF_SUCCESS) ebpf_result_t get_btf_resolved_function_info_from_tls(
    int32_t btf_id, _Outptr_ const ebpf_btf_resolved_function_info_t** function_info)
{
    auto* info = _get_btf_resolved_function_info(btf_id);
    if (info == nullptr) {
        return EBPF_OBJECT_NOT_FOUND;
    }

    *function_info = info;
    return EBPF_SUCCESS;
}

void
clear_program_info_cache()
{
    _program_info_cache.clear();
    _program_descriptor_cache.clear();
    _clear_btf_resolved_function_state();
}
