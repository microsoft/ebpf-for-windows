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

#define EBPF_STORE_PATH L"Software\\eBPF\\Providers"
#define EBPF_PROGRAM_DATA_PATH L"ProgramData"
#define EBPF_SECTION_DATA_PATH L"SectionData"

#define EBPF_PROGRAM_DATA_NAME L"Name"
#define EBPF_PROGRAM_DATA_CONTEXT_DESCRIPTOR L"ContextDescriptor"
#define EBPF_PROGRAM_DATA_PLATFORM_SPECIFIC_DATA L"PlatformSpecificData"
#define EBPF_PROGRAM_DATA_PRIVELEGED L"IsPrivileged"

#define EBPF_SECTION_DATA_PROGRAM_TYPE L"ProgramType"
#define EBPF_SECTION_DATA_ATTACH_TYPE L"AttachType"

#define GUID_STRING_LENGTH 37

std::vector<EbpfProgramType> windows_program_types1;
std::vector<ebpf_section_definition_t> windows_section_definitions;

static std::string
_down_cast_from_wstring(const std::wstring& wide_string)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
    return converter.to_bytes(wide_string);
}

const EbpfProgramType&
get_program_type_windows(const GUID& program_type)
{
    // TODO: (Issue #67) Make an IOCTL call to fetch the program context
    //       info and then fill the EbpfProgramType struct.
    for (const EbpfProgramType& t : windows_program_types1) {
        if (t.platform_specific_data != 0) {
            ebpf_program_type_t* program_type_uuid = (ebpf_program_type_t*)t.platform_specific_data;
            if (IsEqualGUID(*program_type_uuid, program_type)) {
                return t;
            }
        }
    }

    auto guid_string = guid_to_string(&program_type);
    throw std::runtime_error(std::string("ProgramType not found for GUID ") + guid_string);
}

EbpfProgramType
get_program_type_windows(const std::string& section, const std::string&)
{
    // Check if a global program type is set.
    const ebpf_program_type_t* program_type = get_global_program_type();

    // TODO: (Issue #223) Read the registry to fetch all the section
    //       prefixes and corresponding program and attach types.
    for (const EbpfProgramType& t : windows_program_types) {
        if (program_type != nullptr) {
            if (t.platform_specific_data != (uint64_t)&EBPF_PROGRAM_TYPE_UNSPECIFIED) {
                ebpf_program_type_t* program_type_uuid = (ebpf_program_type_t*)t.platform_specific_data;
                if (IsEqualGUID(*program_type_uuid, *program_type)) {
                    return t;
                }
            }
        } else {
            for (const std::string prefix : t.section_prefixes) {
                if (section.find(prefix) == 0)
                    return t;
            }
        }
    }

    // Note: Ideally this function should throw an exception whenever a matching ProgramType is not found,
    // but that causes a problem in the following scenario:
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
    if (get_verification_in_progress()) {
        if (program_type != nullptr) {
            auto guid_string = guid_to_string(program_type);
            throw std::runtime_error(std::string("ProgramType not found for GUID ") + guid_string);
        } else {
            throw std::runtime_error(std::string("ProgramType not found for section " + section));
        }
    }

    return windows_unspecified_program_type;
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

    for (const ebpf_section_definition_t& t : windows_section_definitions) {
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

        windows_section_definitions.emplace_back(section_definition);
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
    return result;
}

static ebpf_result_t
_load_program_data_information(HKEY program_data_key, _In_ const wchar_t* program_type_string) noexcept
{
    int32_t status;
    ebpf_result_t result = EBPF_SUCCESS;
    HKEY program_info_key = nullptr;
    wchar_t* program_type_name = nullptr;
    // uint64_t platform_specific_data = 0;
    ebpf_context_descriptor_t* descriptor = nullptr;
    uint32_t is_privileged;
    ebpf_program_type_t* program_type = nullptr;
    EbpfProgramType program_data; //  = { 0 };

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

        // Convert program type string to GUID
        auto rpc_status = UuidFromString((RPC_WSTR)program_type_string, program_type);
        if (rpc_status != RPC_S_OK) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        // Read the friendly program type name.
        result = read_registry_value_string(program_info_key, EBPF_PROGRAM_DATA_NAME, &program_type_name);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        /*
        // Read integer program type.
        result = read_registry_value_qword(program_info_key, EBPF_PROGRAM_DATA_PLATFORM_SPECIFIC_DATA,
        &platform_specific_data); if (result != EBPF_SUCCESS) { goto Exit;
        }
        */

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

        // We have read all the required data. Populate program data in the global array.
        program_data.context_descriptor = descriptor;
        program_data.name = _down_cast_from_wstring(std::wstring(program_type_name));
        program_data.platform_specific_data = (uint64_t)program_type;
        program_data.is_privileged = !!is_privileged;

        windows_program_types1.emplace_back(program_data);
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
    return result;
}

static ebpf_result_t
_load_all_program_data_information(HKEY store_key)
{
    int32_t status;
    ebpf_result_t result = EBPF_SUCCESS;
    HKEY program_data_key = nullptr;
    HKEY section_data_key = nullptr;
    wchar_t program_type_key[GUID_STRING_LENGTH];
    wchar_t section_name_key[MAX_PATH];
    DWORD key_size = 0;
    uint32_t index = 0;

    try {
        // Add a default entry in windows_program_types1.
        EbpfProgramType unspecified = PTYPE("unspecified", {0}, 0, {});
        windows_program_types1.emplace_back(unspecified);

        // First read all the program data.
        status = RegOpenKeyEx(store_key, EBPF_PROGRAM_DATA_PATH, 0, KEY_READ, &program_data_key);
        if (status != ERROR_SUCCESS) {
            // Registry path is not present.
            result = EBPF_FILE_NOT_FOUND;
            goto Exit;
        }

        while (true) {
            key_size = GUID_STRING_LENGTH;
            status =
                RegEnumKeyEx(program_data_key, index, program_type_key, &key_size, nullptr, nullptr, nullptr, nullptr);
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

        // Next read all the section data.
        status = RegOpenKeyEx(store_key, EBPF_SECTION_DATA_PATH, 0, KEY_READ, &section_data_key);
        if (status != ERROR_SUCCESS) {
            // Registry path is not present.
            result = EBPF_FILE_NOT_FOUND;
            goto Exit;
        }

        while (true) {
            key_size = GUID_STRING_LENGTH;
            status =
                RegEnumKeyEx(section_data_key, index, section_name_key, &key_size, nullptr, nullptr, nullptr, nullptr);
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

        /*
        // First read all the program information.
        for (uint32_t index = 0, KeyLen = (MAX_PATH + 1);
            (RegEnumKeyEx(store_key, Index, KeyName, &KeyLen,
            NULL, NULL, NULL, NULL) == NO_ERROR);
            Index++, KeyLen = (MAX_PATH + 1))
        {
            LoadRoutingDomainAndTunnelConfig(StoreKey, KeyName);
        }
        */
    } catch (...) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

Exit:
    return result;
}

ebpf_result_t
load_provider_data_from_registry()
{
    HKEY store_key = nullptr;
    int32_t status;
    ebpf_result_t result = EBPF_SUCCESS;

    // Open root registry path.
    // status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, EBPF_STORE_PATH, 0, KEY_WRITE | DELETE | KEY_READ, &store_key);
    status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, EBPF_STORE_PATH, 0, KEY_READ, &store_key);
    if (status != ERROR_SUCCESS) {
        // Registry path is not present.
        result = EBPF_FILE_NOT_FOUND;
        goto Exit;
    }

    _load_all_program_data_information(store_key);

Exit:
    return result;
}

void
clean_up_provider_data()
{
    try {
        for (const EbpfProgramType& t : windows_program_types1) {
            ebpf_free((void*)t.context_descriptor);
            ebpf_free((void*)t.platform_specific_data);
        }

        for (const ebpf_section_definition_t& section : windows_section_definitions) {
            ebpf_free(section.prog_type);
            ebpf_free(section.attach_type);
            ebpf_free((void*)section.section_prefix);
        }

        windows_program_types1.resize(0);
        windows_section_definitions.resize(0);
    } catch (...) {
        // Do nothing.
    }
}