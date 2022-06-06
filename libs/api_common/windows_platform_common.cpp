// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#include <cassert>
#include <codecvt>
#include <stdexcept>
#include "api_internal.h"
#include "api_common.hpp"
#include "crab_verifier_wrapper.hpp"
#include "ebpf_api.h"
#include "ebpf_nethooks.h"
#include "helpers.hpp"
#include "map_descriptors.hpp"
#include "platform.hpp"
#include "spec_type_descriptors.hpp"
#include "utilities.hpp"
#include "windows_program_type.h"
#include "windows_platform.hpp"
#include "registry_helper.hpp"

#define SOFTWARE_REGISTRY_PATH L"Software"
#define EBPF_STORE_PATH L"Software\\eBPF\\Providers"
#define EBPF_PROGRAM_DATA_PATH L"ProgramData"
#define EBPF_SECTION_DATA_PATH L"SectionData"
#define EBPF_PROGRAM_DATA_HELPERS_PATH L"Helpers"
#define EBPF_GLOBAL_HELPERS_PATH L"GlobalHelpers"

#define EBPF_PROGRAM_DATA_NAME L"Name"
#define EBPF_PROGRAM_DATA_CONTEXT_DESCRIPTOR L"ContextDescriptor"
#define EBPF_PROGRAM_DATA_PLATFORM_SPECIFIC_DATA L"PlatformSpecificData"
#define EBPF_PROGRAM_DATA_PRIVELEGED L"IsPrivileged"
#define EBPF_PROGRAM_DATA_BPF_PROG_TYPE L"BpfProgType"
#define EBPF_PROGRAM_DATA_HELPER_COUNT L"HelperCount"

#define EBPF_SECTION_DATA_PROGRAM_TYPE L"ProgramType"
#define EBPF_SECTION_DATA_ATTACH_TYPE L"AttachType"

#define EBPF_HELPER_DATA_PROTOTYPE L"Prototype"

#define GUID_STRING_LENGTH 38

static HKEY _root_registry_key = HKEY_LOCAL_MACHINE;

struct guid_compare
{
    bool
    operator()(const GUID& a, const GUID& b) const
    {
        return (memcmp(&a, &b, sizeof(GUID)) < 0);
    }
};

// TODO: Merge EbpfProgramType and ebpf_program_info_t to create a common struct so we dont have to duplicate stuff.
static std::map<ebpf_program_type_t, EbpfProgramType, guid_compare> _windows_program_types;
static std::vector<ebpf_section_definition_t> _windows_section_definitions;
static std::map<ebpf_program_type_t, ebpf_program_info_t, guid_compare> _windows_program_information;

static std::string
_down_cast_from_wstring(const std::wstring& wide_string)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
    return converter.to_bytes(wide_string);
}

const EbpfProgramType&
get_program_type_windows(const GUID& program_type)
{
    std::map<ebpf_program_type_t, EbpfProgramType>::iterator it;
    it = _windows_program_types.find(program_type);
    if (it != _windows_program_types.end()) {
        return it->second;
    }

    // Entry not found. Return the default program type "unspecified".
    it = _windows_program_types.find(EBPF_PROGRAM_TYPE_UNSPECIFIED);
    ebpf_assert(it != _windows_program_types.end());

    return it->second;
}

EbpfProgramType
get_program_type_windows(const std::string& section, const std::string&)
{
    // Check if a global program type is set.
    const ebpf_program_type_t* program_type = get_global_program_type();
    if (program_type != nullptr) {
        return get_program_type_windows(*program_type);
    }

    // Program type is not set. Find the program type from the section prefixes.
    // Find the longest matching section prefix.
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

    // ebpf_program_type_t* program_type = nullptr;
    if (match_index >= 0) {
        program_type = _windows_section_definitions[match_index].prog_type;
    } else {
        program_type = &EBPF_PROGRAM_TYPE_UNSPECIFIED;
    }

    return get_program_type_windows(*program_type);
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
    // TODO: (Issue #223) Read the registry to fetch all the section
    //       prefixes and corresponding program and attach types.

    for (const ebpf_section_definition_t& t : _windows_section_definitions) {
        if (section.find(t.section_prefix) == 0)
            return t.attach_type;
    }

    return &EBPF_ATTACH_TYPE_UNSPECIFIED;
}

_Ret_maybenull_z_ const char*
get_attach_type_name(_In_ const ebpf_attach_type_t* attach_type)
{
    // TODO: (Issue #223) Read the registry to fetch attach types.
    auto it = windows_section_names.find(*attach_type);
    if (it != windows_section_names.end())
        return it->second;

    return nullptr;
}

static ebpf_result_t
_load_section_data_information(HKEY section_data_key, _In_ const wchar_t* section_name) noexcept
{
    int32_t status;
    ebpf_result_t result = EBPF_SUCCESS;
    HKEY section_info_key = nullptr;
    ebpf_program_type_t* program_type = nullptr;
    ebpf_attach_type_t* attach_type = nullptr;
    ebpf_section_definition_t section_definition;

    try {
        status = RegOpenKeyEx(section_data_key, section_name, 0, KEY_READ, &section_info_key);
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
        result = read_registry_value_binary(
            section_info_key, EBPF_SECTION_DATA_PROGRAM_TYPE, (uint8_t*)program_type, sizeof(ebpf_program_type_t));
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        // Read attach type.
        result = read_registry_value_binary(
            section_info_key, EBPF_SECTION_DATA_ATTACH_TYPE, (uint8_t*)attach_type, sizeof(ebpf_attach_type_t));
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        // We have read all the required data. Populate section definition in the global array.
        section_definition.prog_type = program_type;
        section_definition.attach_type = attach_type;
        section_definition.section_prefix = _strdup(_down_cast_from_wstring(section_name).c_str());

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
    }
    if (section_info_key) {
        RegCloseKey(section_info_key);
    }
    return result;
}

static ebpf_result_t
_load_helper_prototype(
    HKEY helper_store_key,
    _In_ const wchar_t* helper_name,
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

        result = read_registry_value_binary(
            helper_info_key, EBPF_HELPER_DATA_PROTOTYPE, (uint8_t*)serialized_data, expected_size);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        uint32_t offset = 0;
        memcpy(&(helper_prototype->helper_id), serialized_data, sizeof(helper_prototype->helper_id));
        offset += sizeof(helper_prototype->helper_id);

        memcpy(&helper_prototype->return_type, serialized_data + offset, sizeof(helper_prototype->return_type));
        offset += sizeof(helper_prototype->return_type);

        memcpy(&helper_prototype->arguments, serialized_data + offset, sizeof(helper_prototype->arguments));
        offset += sizeof(helper_prototype->arguments);

        helper_prototype->name = _strdup(_down_cast_from_wstring(std::wstring(helper_name)).c_str());
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
        RegCloseKey(helper_info_key);
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
_load_program_data_information(HKEY program_data_key, _In_ const wchar_t* program_type_string) noexcept
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
        status = RegOpenKeyEx(program_data_key, program_type_string, 0, KEY_READ, &program_info_key);
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
        result = read_registry_value_string(program_info_key, EBPF_PROGRAM_DATA_NAME, &program_type_name);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        // Read context descriptor.
        descriptor = (ebpf_context_descriptor_t*)ebpf_allocate(sizeof(ebpf_context_descriptor_t));
        if (descriptor == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }
        result = read_registry_value_binary(
            program_info_key,
            EBPF_PROGRAM_DATA_CONTEXT_DESCRIPTOR,
            (uint8_t*)descriptor,
            sizeof(ebpf_context_descriptor_t));
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        // Read "is_privileged".
        result = read_registry_value_dword(program_info_key, EBPF_PROGRAM_DATA_PRIVELEGED, &is_privileged);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        // Read bpf program type.
        result = read_registry_value_dword(program_info_key, EBPF_PROGRAM_DATA_BPF_PROG_TYPE, &bpf_program_type);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        // Read helper count
        result = read_registry_value_dword(program_info_key, EBPF_PROGRAM_DATA_HELPER_COUNT, &helper_count);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        auto program_type_name_string = _down_cast_from_wstring(std::wstring(program_type_name));
        program_data.context_descriptor = descriptor;
        program_data.name = program_type_name_string;
        program_data.platform_specific_data = (uint64_t)program_type;
        program_data.is_privileged = !!is_privileged;

        program_information.program_type_descriptor.context_descriptor = descriptor;
        program_information.program_type_descriptor.is_privileged = !!is_privileged;
        program_information.program_type_descriptor.bpf_prog_type = bpf_program_type;
        program_information.program_type_descriptor.name = program_type_name_string.c_str();
        program_information.program_type_descriptor.program_type = *program_type;

        if (helper_count > 0) {
            // Read the helper functions prototypes.
            status = RegOpenKeyEx(program_info_key, EBPF_PROGRAM_DATA_HELPERS_PATH, 0, KEY_READ, &helper_key);
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

#pragma warning(push)
#pragma warning(disable : 26495) // EbpfProgramType does not initialize member variables.
        _windows_program_types.insert(std::pair<ebpf_program_type_t, EbpfProgramType>(*program_type, program_data));
#pragma warning(pop)

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
        RegCloseKey(program_info_key);
    }
    if (helper_key) {
        RegCloseKey(helper_key);
    }
    return result;
}

static void
_update_global_helpers_for_program_information(
    _In_ const ebpf_helper_function_prototype_t* global_helpers, uint32_t global_helper_count)
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
        status = RegOpenKeyEx(store_key, EBPF_GLOBAL_HELPERS_PATH, 0, KEY_READ, &global_helpers_key);
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
            // key_size = (max_helper_name_size - 1) * sizeof(wchar_t);
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
        RegCloseKey(global_helpers_key);
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
    // wchar_t program_type_key[MAX_PATH + 1];
    DWORD key_size = 0;
    uint32_t index = 0;

    try {
        // Add a default entry in windows_program_types.
        EbpfProgramType unspecified = PTYPE("unspecified", {0}, (uint64_t)&EBPF_PROGRAM_TYPE_UNSPECIFIED, {});
#pragma warning(push)
#pragma warning(disable : 26495) // EbpfProgramType does not initialize member variables.
        _windows_program_types.insert(
            std::pair<ebpf_program_type_t, EbpfProgramType>(EBPF_PROGRAM_TYPE_UNSPECIFIED, unspecified));
#pragma warning(pop)

        // Open program data registry path.
        status = RegOpenKeyEx(store_key, EBPF_PROGRAM_DATA_PATH, 0, KEY_READ, &program_data_key);
        if (status != ERROR_SUCCESS) {
            // Registry path is not present.
            result = EBPF_FILE_NOT_FOUND;
            goto Exit;
        }

        while (true) {
            key_size = GUID_STRING_LENGTH + 1;
            // key_size = MAX_PATH + 1;
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
                // TODO: Add a trace that we failed with an unexpected error.
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
        status = RegOpenKeyEx(store_key, EBPF_SECTION_DATA_PATH, 0, KEY_READ, &section_data_key);
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
                // TODO: Add a trace that we failed with an unexpected error.
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
        RegCloseKey(section_data_key);
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

static uint32_t
_set_root_registry_path()
{
    // Try opening HKEY_LOCAL_MACHINE.
    HKEY key = nullptr;
    uint32_t status;

    status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, SOFTWARE_REGISTRY_PATH, 0, KEY_READ, &key);
    if (status == ERROR_SUCCESS) {
        goto Exit;
    }

    _root_registry_key = HKEY_CURRENT_USER;

Exit:
    if (key) {
        RegCloseKey(key);
    }

    return status;
}

ebpf_result_t
load_ebpf_provider_data()
{
    HKEY store_key = nullptr;
    int32_t status;
    ebpf_result_t result = EBPF_SUCCESS;

    _set_root_registry_path();

    // Open root registry path.
    status = RegOpenKeyEx(_root_registry_key, EBPF_STORE_PATH, 0, KEY_READ, &store_key);
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
        for (auto& t : _windows_program_types) {
            ebpf_free((void*)t.second.context_descriptor);
            ebpf_free((void*)t.second.platform_specific_data);
        }

        for (const ebpf_section_definition_t& section : _windows_section_definitions) {
            ebpf_free(section.prog_type);
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

const ebpf_program_type_t*
get_ebpf_program_type(enum bpf_prog_type type)
{
    for (auto& iterator : _windows_program_information) {
        ebpf_program_info_t& program_info = iterator.second;
        if (program_info.program_type_descriptor.bpf_prog_type == (uint32_t)type) {
            return &iterator.first;
        }
    }

    return &EBPF_PROGRAM_TYPE_UNSPECIFIED;
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