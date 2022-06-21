// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <cassert>
#include <stdexcept>
#include "api_internal.h"
#include "api_common.hpp"
#include "crab_verifier_wrapper.hpp"
#include "device_helper.hpp"
#include "ebpf_api.h"
#include "ebpf_nethooks.h"
#include "ebpf_protocol.h"
#include "ebpf_serialize.h"
#include "helpers.hpp"
#include "map_descriptors.hpp"
#include "platform.hpp"
#include "spec_type_descriptors.hpp"
#include "utilities.hpp"
#include "windows_program_type.h"
#include "windows_platform.hpp"
#include "um_registry_helper.h"

#define GET_PROGRAM_INFO_REPLY_BUFFER_SIZE 2048

static thread_local ebpf_handle_t _program_under_verification = ebpf_handle_invalid;

// TODO: Issue #1231 Change to using HKEY_LOCAL_MACHINE
static HKEY _root_registry_key = HKEY_CURRENT_USER;

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
_ebpf_program_descriptor_free(_In_opt_ EbpfProgramType* descriptor)
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

// Thread local cache for program information queried from execution context.
typedef std::unique_ptr<ebpf_program_info_t, _ebpf_program_info_deleter> ebpf_program_info_ptr_t;
static thread_local std::map<ebpf_program_type_t, ebpf_program_info_ptr_t, guid_compare> _program_info_cache;

// Thread local cache for program descriptor queried from execution context.
typedef std::unique_ptr<EbpfProgramType, EbpfProgramType_deleter> ebpf_program_descriptor_ptr_t;
static thread_local std::map<ebpf_program_type_t, ebpf_program_descriptor_ptr_t, guid_compare>
    _program_descriptor_cache;

// Global cache for the program and section information queried from eBPF store.
static std::map<ebpf_program_type_t, EbpfProgramType, guid_compare> _windows_program_types;
static std::vector<ebpf_section_definition_t> _windows_section_definitions;
static std::map<ebpf_program_type_t, ebpf_program_info_t, guid_compare> _windows_program_information;

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

    try {
        char* name = nullptr;
        type = new (std::nothrow) EbpfProgramType();
        if (type == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }

        name = _strdup(info->program_type_descriptor.name);
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
    if ((result != EBPF_SUCCESS) && (result != EBPF_INSUFFICIENT_BUFFER))
        goto Exit;

    if (result == EBPF_INSUFFICIENT_BUFFER) {
        required_buffer_length = reply->header.length;
        reply_buffer.resize(required_buffer_length);
        reply = reinterpret_cast<ebpf_operation_get_program_info_reply_t*>(reply_buffer.data());
        result = win32_error_code_to_ebpf_result(invoke_ioctl(request, reply_buffer));
        if (result != EBPF_SUCCESS)
            goto Exit;
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
            return it2->second;
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
    for (uint32_t index = 0; index < _windows_section_definitions.size(); index++) {
        std::string section_prefix(_windows_section_definitions[index].section_prefix);
        if (section.find(section_prefix) == 0) {
            size_t prefix_length = strlen(_windows_section_definitions[index].section_prefix);
            if (match_length < prefix_length) {
                match_index = index;
                match_length = prefix_length;
            }
        }
    }

    if (match_index >= 0) {
        return &_windows_section_definitions[match_index];
    }

    return nullptr;
}

_Ret_maybenull_ const ebpf_program_type_t*
get_ebpf_program_type(bpf_prog_type_t bpf_program_type)
{
    for (auto const& [key, val] : _windows_program_information) {
        if (val.program_type_descriptor.bpf_prog_type == (uint32_t)bpf_program_type) {
            return &key;
        }
    }

    return nullptr;
}

_Ret_maybenull_ const ebpf_attach_type_t*
get_ebpf_attach_type(bpf_attach_type_t bpf_attach_type)
{
    for (const auto& definition : _windows_section_definitions) {
        if (definition.bpf_attach_type == bpf_attach_type) {
            return definition.attach_type;
        }
    }

    return nullptr;
}

bpf_prog_type_t
get_bpf_program_type(_In_ const ebpf_program_type_t* ebpf_program_type)
{
    for (auto const& [key, val] : _windows_program_information) {
        if (IsEqualGUID(*ebpf_program_type, key)) {
            return (bpf_prog_type_t)val.program_type_descriptor.bpf_prog_type;
        }
    }

    return BPF_PROG_TYPE_UNSPEC;
}

bpf_attach_type_t
get_bpf_attach_type(_In_ const ebpf_attach_type_t* ebpf_attach_type)
{
    for (const auto& definition : _windows_section_definitions) {
        if (IsEqualGUID(*ebpf_attach_type, *definition.attach_type)) {
            return definition.bpf_attach_type;
        }
    }

    return BPF_ATTACH_TYPE_UNSPEC;
}

ebpf_result_t
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

ebpf_result_t
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
    for (const ebpf_section_definition_t& t : _windows_section_definitions) {
        if (section.find(t.section_prefix) == 0)
            return t.attach_type;
    }

    return &EBPF_ATTACH_TYPE_UNSPECIFIED;
}

_Ret_maybenull_z_ const char*
get_attach_type_name(_In_ const ebpf_attach_type_t* attach_type)
{
    for (const ebpf_section_definition_t& t : _windows_section_definitions) {
        if (IsEqualGUID(*t.attach_type, *attach_type)) {
            return t.section_prefix;
        }
    }

    return nullptr;
}

static ebpf_result_t
_load_section_data_information(HKEY section_data_key, _In_z_ const wchar_t* section_name) noexcept
{
    int32_t status;
    ebpf_result_t result = EBPF_SUCCESS;
    HKEY section_info_key = nullptr;
    ebpf_program_type_t* program_type = nullptr;
    ebpf_attach_type_t* attach_type = nullptr;
    ebpf_section_definition_t section_definition;
    bpf_prog_type_t bpf_program_type;
    bpf_attach_type_t bpf_attach_type;
    char* section_prefix = nullptr;

    try {
        status = open_registry_key(section_data_key, section_name, KEY_READ, &section_info_key);
        if (status != ERROR_SUCCESS) {
            // Registry path is not present.
            result = EBPF_FILE_NOT_FOUND;
            goto Exit;
        }

        program_type = (ebpf_program_type_t*)ebpf_allocate(sizeof(ebpf_program_type_t));
        if (program_type == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }

        attach_type = (ebpf_attach_type_t*)ebpf_allocate(sizeof(ebpf_attach_type_t));
        if (attach_type == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }

        // Read program type.
        status = read_registry_value_binary(
            section_info_key, EBPF_SECTION_DATA_PROGRAM_TYPE, (uint8_t*)program_type, sizeof(ebpf_program_type_t));
        if (status != ERROR_SUCCESS) {
            result = win32_error_code_to_ebpf_result(status);
            goto Exit;
        }

        // Read attach type.
        status = read_registry_value_binary(
            section_info_key, EBPF_SECTION_DATA_ATTACH_TYPE, (uint8_t*)attach_type, sizeof(ebpf_attach_type_t));
        if (status != ERROR_SUCCESS) {
            result = win32_error_code_to_ebpf_result(status);
            goto Exit;
        }

        // Read bpf program type.
        status =
            read_registry_value_dword(section_info_key, EBPF_PROGRAM_DATA_BPF_PROG_TYPE, (uint32_t*)&bpf_program_type);
        if (status != ERROR_SUCCESS) {
            bpf_program_type = BPF_PROG_TYPE_UNSPEC;
            result = EBPF_SUCCESS;
        }

        // Read bpf attach type.
        status =
            read_registry_value_dword(section_info_key, EBPF_PROGRAM_DATA_BPF_PROG_TYPE, (uint32_t*)&bpf_attach_type);
        if (status != ERROR_SUCCESS) {
            bpf_attach_type = BPF_ATTACH_TYPE_UNSPEC;
            result = EBPF_SUCCESS;
        }

        section_prefix = _strdup(ebpf_down_cast_from_wstring(section_name).c_str());
        if (section_prefix == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }

        // We have read all the required data. Populate section definition in the global array.
        section_definition.program_type = program_type;
        section_definition.attach_type = attach_type;
        section_definition.bpf_prog_type = bpf_program_type;
        section_definition.bpf_attach_type = bpf_attach_type;
        section_definition.section_prefix = section_prefix;

        _windows_section_definitions.emplace_back(section_definition);
    } catch (...) {
        result = EBPF_FAILED;
        goto Exit;
    }

Exit:
    if (result != EBPF_SUCCESS) {
        if (program_type) {
            ebpf_free(program_type);
        }
        if (attach_type) {
            ebpf_free(attach_type);
        }
        if (section_prefix) {
            ebpf_free(section_prefix);
        }
    }
    if (section_info_key) {
        close_registry_key(section_info_key);
    }
    return result;
}

static ebpf_result_t
_load_helper_prototype(
    HKEY helper_store_key,
    _In_z_ const wchar_t* helper_name,
    _Out_ ebpf_helper_function_prototype_t* helper_prototype) noexcept
{
    int32_t status;
    ebpf_result_t result = EBPF_SUCCESS;
    HKEY helper_info_key = nullptr;

    try {
        status = RegOpenKeyEx(helper_store_key, helper_name, 0, KEY_READ, &helper_info_key);
        if (status != ERROR_SUCCESS) {
            // Registry path is not present.
            result = EBPF_FILE_NOT_FOUND;
            goto Exit;
        }

        // Read serialized helper prototype information.
        char serialized_data[sizeof(ebpf_helper_function_prototype_t)] = {0};
        size_t expected_size = sizeof(helper_prototype->helper_id) + sizeof(helper_prototype->return_type) +
                               sizeof(helper_prototype->arguments);

        status = read_registry_value_binary(
            helper_info_key, EBPF_HELPER_DATA_PROTOTYPE, (uint8_t*)serialized_data, expected_size);
        if (status != ERROR_SUCCESS) {
            result = win32_error_code_to_ebpf_result(status);
            __analysis_assume(result != EBPF_SUCCESS);
            goto Exit;
        }

        uint32_t offset = 0;
        memcpy(&(helper_prototype->helper_id), serialized_data, sizeof(helper_prototype->helper_id));
        offset += sizeof(helper_prototype->helper_id);

        memcpy(&helper_prototype->return_type, serialized_data + offset, sizeof(helper_prototype->return_type));
        offset += sizeof(helper_prototype->return_type);

        memcpy(&helper_prototype->arguments, serialized_data + offset, sizeof(helper_prototype->arguments));
        offset += sizeof(helper_prototype->arguments);

        helper_prototype->name = _strdup(ebpf_down_cast_from_wstring(std::wstring(helper_name)).c_str());
        if (helper_prototype->name == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }
    } catch (...) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

Exit:
    if (helper_info_key) {
        close_registry_key(helper_info_key);
    }
    return result;
}

static ebpf_result_t
_get_program_type_guid_from_string(_In_ const wchar_t* program_type_string, _Out_ ebpf_program_type_t* program_type)
{
    ebpf_result_t result = EBPF_SUCCESS;

    // The UUID string read from registry also contains the opening and closing braces.
    // Remove those before converting to UUID.
    wchar_t truncated_string[GUID_STRING_LENGTH + 1] = {0};
    memcpy(truncated_string, program_type_string + 1, (wcslen(program_type_string) - 2) * sizeof(wchar_t));
    // Convert program type string to GUID
    auto rpc_status = UuidFromString((RPC_WSTR)truncated_string, program_type);
    if (rpc_status != RPC_S_OK) {
        result = EBPF_INVALID_ARGUMENT;
    }

    return result;
}

static ebpf_result_t
_load_program_data_information(HKEY program_data_key, _In_z_ const wchar_t* program_type_string) noexcept
{
    int32_t status;
    ebpf_result_t result = EBPF_SUCCESS;
    HKEY program_info_key = nullptr;
    HKEY helper_key = nullptr;
    wchar_t* program_type_name = nullptr;
    ebpf_context_descriptor_t* descriptor = nullptr;
    uint32_t is_privileged;
    uint32_t bpf_program_type;
    ebpf_program_type_t* program_type = nullptr;
    EbpfProgramType program_data;
    ebpf_program_info_t program_information = {0};
    uint32_t helper_count;

    try {
        status = open_registry_key(program_data_key, program_type_string, KEY_READ, &program_info_key);
        if (status != ERROR_SUCCESS) {
            // Registry path is not present.
            result = EBPF_FILE_NOT_FOUND;
            goto Exit;
        }

        program_type = (ebpf_program_type_t*)ebpf_allocate(sizeof(ebpf_program_type_t));
        if (program_type == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }

        result = _get_program_type_guid_from_string(program_type_string, program_type);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        // Read the friendly program type name.
        status = read_registry_value_string(program_info_key, EBPF_PROGRAM_DATA_NAME, &program_type_name);
        if (status != ERROR_SUCCESS) {
            result = win32_error_code_to_ebpf_result(status);
            goto Exit;
        }

        // Read context descriptor.
        descriptor = (ebpf_context_descriptor_t*)ebpf_allocate(sizeof(ebpf_context_descriptor_t));
        if (descriptor == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }
        status = read_registry_value_binary(
            program_info_key,
            EBPF_PROGRAM_DATA_CONTEXT_DESCRIPTOR,
            (uint8_t*)descriptor,
            sizeof(ebpf_context_descriptor_t));
        if (status != ERROR_SUCCESS) {
            result = win32_error_code_to_ebpf_result(status);
            goto Exit;
        }

        // Read "is_privileged".
        status = read_registry_value_dword(program_info_key, EBPF_PROGRAM_DATA_PRIVELEGED, &is_privileged);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        // Read bpf program type.
        status = read_registry_value_dword(program_info_key, EBPF_PROGRAM_DATA_BPF_PROG_TYPE, &bpf_program_type);
        if (status != ERROR_SUCCESS) {
            result = win32_error_code_to_ebpf_result(status);
            goto Exit;
        }

        // Read helper count
        status = read_registry_value_dword(program_info_key, EBPF_PROGRAM_DATA_HELPER_COUNT, &helper_count);
        if (status != ERROR_SUCCESS) {
            result = win32_error_code_to_ebpf_result(status);
            goto Exit;
        }

        auto program_type_name_string = ebpf_down_cast_from_wstring(std::wstring(program_type_name));
        program_data.context_descriptor = descriptor;
        program_data.name = program_type_name_string;
        program_data.platform_specific_data = (uint64_t)program_type;
        program_data.is_privileged = !!is_privileged;

        program_information.program_type_descriptor.name = _strdup(program_type_name_string.c_str());
        if (program_information.program_type_descriptor.name == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }
        program_information.program_type_descriptor.context_descriptor = descriptor;
        program_information.program_type_descriptor.is_privileged = !!is_privileged;
        program_information.program_type_descriptor.bpf_prog_type = bpf_program_type;
        program_information.program_type_descriptor.program_type = *program_type;

        if (helper_count > 0) {
            // Read the helper functions prototypes.
            status = RegOpenKeyEx(program_info_key, EBPF_PROGRAM_DATA_HELPERS_REGISTRY_PATH, 0, KEY_READ, &helper_key);
            if (status != ERROR_SUCCESS) {
                // Registry path is not present.
                result = EBPF_FILE_NOT_FOUND;
                goto Exit;
            }

            uint32_t max_helper_name_size;
            uint32_t max_helpers_count;
            uint32_t key_size;
            // Get the size of the largest subkey.
            status = RegQueryInfoKey(
                helper_key,
                nullptr,
                nullptr,
                nullptr,
                (LPDWORD)&max_helpers_count,
                (LPDWORD)&max_helper_name_size,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr);
            if (status != ERROR_SUCCESS) {
                result = EBPF_FILE_NOT_FOUND;
                goto Exit;
            }

            if (max_helpers_count != helper_count) {
                result = EBPF_INVALID_ARGUMENT;
                goto Exit;
            }
            if (max_helper_name_size == 0) {
                result = EBPF_INVALID_ARGUMENT;
                goto Exit;
            }

            program_information.helper_prototype = (ebpf_helper_function_prototype_t*)ebpf_allocate(
                helper_count * sizeof(ebpf_helper_function_prototype_t));
            if (program_information.helper_prototype == nullptr) {
                goto Exit;
            }

            // Add space for null terminator.
            max_helper_name_size += 1;

            wchar_t* helper_name = (wchar_t*)ebpf_allocate(max_helper_name_size * sizeof(wchar_t));
            if (helper_name == nullptr) {
                result = EBPF_NO_MEMORY;
                goto Exit;
            }

            for (uint32_t index = 0; index < max_helpers_count; index++) {
                memset(helper_name, 0, (max_helper_name_size) * sizeof(wchar_t));
                key_size = (max_helper_name_size - 1) * sizeof(wchar_t);
                status = RegEnumKeyEx(
                    helper_key, index, helper_name, (LPDWORD)&key_size, nullptr, nullptr, nullptr, nullptr);
                if (status != ERROR_SUCCESS) {
                    result = win32_error_code_to_ebpf_result(status);
                    goto Exit;
                }

                result = _load_helper_prototype(helper_key, helper_name, &program_information.helper_prototype[index]);
                if (result != EBPF_SUCCESS) {
                    goto Exit;
                }
            }

            program_information.count_of_helpers = helper_count;
        }

        _windows_program_types.insert(std::pair<ebpf_program_type_t, EbpfProgramType>(*program_type, program_data));
        _windows_program_information.insert(
            std::pair<ebpf_program_type_t, ebpf_program_info_t>(*program_type, program_information));
    } catch (...) {
        result = EBPF_FAILED;
        goto Exit;
    }

Exit:
    if (result != EBPF_SUCCESS) {
        if (descriptor) {
            ebpf_free(descriptor);
        }
        if (program_type_name) {
            ebpf_free(program_type_name);
        }
        if (program_type) {
            ebpf_free(program_type);
        }
    }
    if (program_info_key) {
        close_registry_key(program_info_key);
    }
    if (helper_key) {
        close_registry_key(helper_key);
    }
    return result;
}

static void
_update_global_helpers_for_program_information(
    _In_reads_(global_helper_count) const ebpf_helper_function_prototype_t* global_helpers, uint32_t global_helper_count)
{
    // Iterate over all the program information and append the global
    // helper functions to each of the program information.
    for (auto& iterator : _windows_program_information) {
        ebpf_program_info_t& program_info = iterator.second;
        uint32_t total_helper_count = global_helper_count + program_info.count_of_helpers;
        ebpf_helper_function_prototype_t* new_helpers = (ebpf_helper_function_prototype_t*)ebpf_allocate(
            total_helper_count * sizeof(ebpf_helper_function_prototype_t));
        if (new_helpers == nullptr) {
            continue;
        }

        // Copy the global helpers to the new helpers.
        uint32_t global_helper_size = global_helper_count * sizeof(ebpf_helper_function_prototype_t);
        memcpy(new_helpers, global_helpers, global_helper_size);

        if (program_info.count_of_helpers > 0) {
            memcpy(
                new_helpers + global_helper_count,
                program_info.helper_prototype,
                (program_info.count_of_helpers * sizeof(ebpf_helper_function_prototype_t)));
            ebpf_free(program_info.helper_prototype);
        }

        program_info.helper_prototype = new_helpers;
        program_info.count_of_helpers = total_helper_count;
    }
}

static ebpf_result_t
_load_all_global_helper_information(HKEY store_key)
{
    int32_t status;
    ebpf_result_t result = EBPF_SUCCESS;
    HKEY global_helpers_key = nullptr;
    wchar_t* helper_name = nullptr;
    DWORD key_size = 0;
    uint32_t max_helper_name_size = 0;
    uint32_t max_helpers_count = 0;
    ebpf_helper_function_prototype_t* helper_prototype = nullptr;

    try {
        // Open program data registry path.
        status = open_registry_key(store_key, EBPF_GLOBAL_HELPERS_REGISTRY_PATH, KEY_READ, &global_helpers_key);
        if (status != ERROR_SUCCESS) {
            // Registry path is not present.
            result = EBPF_FILE_NOT_FOUND;
            goto Exit;
        }

        // Get the size of the largest subkey.
        status = RegQueryInfoKey(
            global_helpers_key,
            nullptr,
            nullptr,
            nullptr,
            (LPDWORD)&max_helpers_count,
            (LPDWORD)&max_helper_name_size,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr);
        if (status != ERROR_SUCCESS) {
            result = EBPF_FILE_NOT_FOUND;
            goto Exit;
        }

        if (max_helpers_count == 0) {
            goto Exit;
        }
        if (max_helper_name_size == 0) {
            result = EBPF_FILE_NOT_FOUND;
            goto Exit;
        }

        // Add space for null terminator.
        max_helper_name_size += 1;

        helper_name = (wchar_t*)ebpf_allocate(max_helper_name_size * sizeof(wchar_t));
        if (helper_name == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }

        helper_prototype = (ebpf_helper_function_prototype_t*)ebpf_allocate(
            max_helpers_count * sizeof(ebpf_helper_function_prototype_t));
        if (helper_prototype == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }

        for (uint32_t index = 0; index < max_helpers_count; index++) {
            memset(helper_name, 0, max_helper_name_size * sizeof(wchar_t));
            key_size = max_helper_name_size;
            status =
                RegEnumKeyEx(global_helpers_key, index, helper_name, &key_size, nullptr, nullptr, nullptr, nullptr);
            if (status != ERROR_SUCCESS) {
                result = win32_error_code_to_ebpf_result(status);
                goto Exit;
            }

            result = _load_helper_prototype(global_helpers_key, helper_name, &(helper_prototype[index]));
            if (result != EBPF_SUCCESS) {
                goto Exit;
            }
        }

        _update_global_helpers_for_program_information(helper_prototype, max_helpers_count);
    } catch (...) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

Exit:
    if (global_helpers_key) {
        close_registry_key(global_helpers_key);
    }
    ebpf_free(helper_prototype);
    return result;
}

static ebpf_result_t
_load_all_program_data_information(HKEY store_key)
{
    int32_t status;
    ebpf_result_t result = EBPF_SUCCESS;
    HKEY program_data_key = nullptr;
    wchar_t program_type_key[GUID_STRING_LENGTH + 1];
    DWORD key_size = 0;
    uint32_t index = 0;

    try {
        // Open program data registry path.
        status = open_registry_key(store_key, EBPF_PROGRAM_DATA_REGISTRY_PATH, KEY_READ, &program_data_key);
        if (status != ERROR_SUCCESS) {
            // Registry path is not present.
            result = EBPF_FILE_NOT_FOUND;
            goto Exit;
        }

        while (true) {
            key_size = GUID_STRING_LENGTH + 1;
            memset(program_type_key, 0, key_size);
            status =
                RegEnumKeyEx(program_data_key, index, program_type_key, &key_size, nullptr, nullptr, nullptr, nullptr);
            index++;
            if (status == ERROR_NO_MORE_ITEMS) {
                // Exhausted all the entries.
                break;
            } else if (status == ERROR_MORE_DATA) {
                // This looks like an invalid entry in the registry.
                // Ignore this entry and continue.
                continue;
            } else if (status != ERROR_SUCCESS) {
                break;
            }

            _load_program_data_information(program_data_key, program_type_key);
        }
    } catch (...) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

Exit:
    return result;
}

static ebpf_result_t
_load_all_section_data_information(HKEY store_key)
{
    uint32_t status;
    ebpf_result_t result = EBPF_SUCCESS;
    HKEY section_data_key = nullptr;
    wchar_t section_name_key[MAX_PATH];
    DWORD key_size = 0;
    uint32_t index = 0;

    try {
        status = RegOpenKeyEx(store_key, EBPF_SECTIONS_REGISTRY_PATH, 0, KEY_READ, &section_data_key);
        if (status != ERROR_SUCCESS) {
            // Registry path is not present.
            result = EBPF_FILE_NOT_FOUND;
            goto Exit;
        }

        index = 0;
        while (true) {
            key_size = GUID_STRING_LENGTH;
            status =
                RegEnumKeyEx(section_data_key, index, section_name_key, &key_size, nullptr, nullptr, nullptr, nullptr);
            index++;
            if (status == ERROR_NO_MORE_ITEMS) {
                // Exhausted all the entries.
                break;
            } else if (status == ERROR_MORE_DATA) {
                // This looks like an invalid entry in the registry.
                // Ignore this entry and continue.
                continue;
            } else if (status != ERROR_SUCCESS) {
                break;
            }

            _load_section_data_information(section_data_key, section_name_key);
        }
    } catch (...) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

Exit:
    if (section_data_key) {
        close_registry_key(section_data_key);
    }
    return result;
}

static ebpf_result_t
_load_all_provider_data_information(HKEY store_key)
{
    ebpf_result_t result;

    result = _load_all_program_data_information(store_key);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    result = _load_all_section_data_information(store_key);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    result = _load_all_global_helper_information(store_key);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

Exit:
    return result;
}

ebpf_result_t
load_ebpf_provider_data()
{
    HKEY store_key = nullptr;
    int32_t status;
    ebpf_result_t result = EBPF_SUCCESS;

    // Open root registry path.
    status = open_registry_key(_root_registry_key, EBPF_STORE_REGISTRY_PATH, KEY_READ, &store_key);
    if (status != ERROR_SUCCESS) {
        // Registry path is not present.
        result = EBPF_FILE_NOT_FOUND;
        goto Exit;
    }

    _load_all_provider_data_information(store_key);

Exit:
    return result;
}

void
clear_ebpf_provider_data()
{
    try {
#pragma warning(push)
#pragma warning(disable : 6001) // Using uninitialized memory 't.second.context_descriptor'
        for (auto& [context_descriptor, platform_specific_data] : _windows_program_types) {
            ebpf_free((void*)context_descriptor);
            ebpf_free((void*)platform_specific_data);
        }
#pragma warning(pop)

        for (const ebpf_section_definition_t& section : _windows_section_definitions) {
            ebpf_free(section.program_type);
            ebpf_free(section.attach_type);
            ebpf_free((void*)section.section_prefix);
        }

        _windows_program_types.clear();
        _windows_section_definitions.resize(0);
        _windows_program_information.clear();
    } catch (...) {
        // Do nothing.
    }
}

const ebpf_program_info_t*
get_static_program_info(_In_ const ebpf_program_type_t* program_type)
{
    for (auto& iterator : _windows_program_information) {
        if (IsEqualGUID(*program_type, iterator.first)) {
            return &iterator.second;
        }
    }

    return nullptr;
}

ebpf_result_t
get_program_type_info(_Outptr_ const ebpf_program_info_t** info)
{
    const GUID* program_type = reinterpret_cast<const GUID*>(global_program_info.type.platform_specific_data);
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
        *info = get_static_program_info(program_type);
        if (info == nullptr) {
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
