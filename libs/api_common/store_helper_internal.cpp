// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "..\libs\store_helper\user\ebpf_registry_helper.h"
#include "ebpf_program_attach_type_guids.h"
#include "ebpf_serialize.h"
#include "ebpf_shared_framework.h"
#include "ebpf_store_helper.h"
#include "ebpf_tracelog.h"
#include "ebpf_utilities.h"
#include "store_helper_internal.h"
#include "utilities.hpp"

ebpf_store_key_t root_registry_key_current_user = HKEY_CURRENT_USER;

static ebpf_result_t
_open_ebpf_store_key(_Out_ ebpf_store_key_t* store_key)
{
    EBPF_LOG_ENTRY();

    // Open root registry path.
    *store_key = nullptr;

    // Open the HKCU registry key.
    ebpf_result_t result =
        ebpf_open_registry_key(root_registry_key_current_user, EBPF_STORE_REGISTRY_PATH, KEY_READ, store_key);

    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_load_extension_header(HKEY data_key, _Out_ ebpf_extension_header_t* extension_header)
{
    uint32_t version, size;

    EBPF_LOG_ENTRY();

    ebpf_result_t result = ebpf_read_registry_value_dword(data_key, EBPF_EXTENSION_HEADER_VERSION, &version);
    if (result != EBPF_SUCCESS) {
        EBPF_RETURN_RESULT(result);
    }
    result = ebpf_read_registry_value_dword(data_key, EBPF_EXTENSION_HEADER_SIZE, &size);
    if (result != EBPF_SUCCESS) {
        EBPF_RETURN_RESULT(result);
    }

    extension_header->version = static_cast<uint16_t>(version);
    extension_header->size = size;

    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_store_load_helper_prototype(
    HKEY helper_store_key,
    _In_z_ const wchar_t* helper_name,
    _Out_ ebpf_helper_function_prototype_t* helper_prototype) noexcept
{
    int32_t status;
    ebpf_result_t result = EBPF_SUCCESS;
    HKEY helper_info_key = nullptr;
    uint32_t offset = 0;
    char serialized_data[sizeof(ebpf_helper_function_prototype_t)] = {0};
    size_t expected_size = sizeof(helper_prototype->helper_id) + sizeof(helper_prototype->return_type) +
                           sizeof(helper_prototype->arguments);
    uint32_t reallocate_packet_value = 0;

    EBPF_LOG_ENTRY();

    status = RegOpenKeyEx(helper_store_key, helper_name, 0, KEY_READ, &helper_info_key);
    if (status != ERROR_SUCCESS) {
        // Registry path is not present.
        result = EBPF_FILE_NOT_FOUND;
        goto Exit;
    }

    // Load extension header.
    result = _load_extension_header(helper_info_key, &helper_prototype->header);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    // Read serialized helper prototype information.
    result = ebpf_read_registry_value_binary(
        helper_info_key, EBPF_HELPER_DATA_PROTOTYPE, (uint8_t*)serialized_data, expected_size);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }

    memcpy(&(helper_prototype->helper_id), serialized_data, sizeof(helper_prototype->helper_id));
    offset += sizeof(helper_prototype->helper_id);

    memcpy(&helper_prototype->return_type, serialized_data + offset, sizeof(helper_prototype->return_type));
    offset += sizeof(helper_prototype->return_type);

    memcpy(&helper_prototype->arguments, serialized_data + offset, sizeof(helper_prototype->arguments));
    offset += sizeof(helper_prototype->arguments);

    (void)ebpf_read_registry_value_dword(helper_info_key, EBPF_HELPER_DATA_REALLOCATE_PACKET, &reallocate_packet_value);
    helper_prototype->flags.reallocate_packet = !!reallocate_packet_value;

    try {
        helper_prototype->name =
            cxplat_duplicate_string(ebpf_down_cast_from_wstring(std::wstring(helper_name)).c_str());
        if (helper_prototype->name == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }

    } catch (std::exception& e) {
        EBPF_LOG_MESSAGE_STRING(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_BASE,
            "Failed to convert helper name to string:",
            e.what());
        result = EBPF_FAILED;
        goto Exit;
    }

Exit:
    if (helper_info_key) {
        ebpf_close_registry_key(static_cast<ebpf_store_key_t>(helper_info_key));
    }
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_store_load_program_type_descriptor(
    HKEY program_info_key,
    _In_ const ebpf_program_type_t* program_type,
    _Out_ ebpf_program_type_descriptor_t** program_type_descriptor) noexcept
{
    ebpf_result_t result = EBPF_SUCCESS;
    HKEY program_type_descriptor_key = nullptr;
    wchar_t* program_type_name = nullptr;
    ebpf_context_descriptor_t* context_descriptor = nullptr;
    uint32_t is_privileged = false;
    uint32_t bpf_program_type = 0;
    ebpf_program_type_descriptor_t* local_program_type_descriptor = nullptr;
    std::string program_type_name_string;

    EBPF_LOG_ENTRY();

    result = ebpf_open_registry_key(
        program_info_key,
        EBPF_PROGRAM_TYPE_DESCRIPTOR_REGISTRY_KEY,
        KEY_READ,
        (ebpf_store_key_t*)&program_type_descriptor_key);
    if (result != EBPF_SUCCESS) {
        // Registry path is not present.
        result = EBPF_FILE_NOT_FOUND;
        goto Exit;
    }

    // Allocate the program type descriptor.
    local_program_type_descriptor =
        (ebpf_program_type_descriptor_t*)ebpf_allocate(sizeof(ebpf_program_type_descriptor_t));
    if (local_program_type_descriptor == nullptr) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    // Load extension header.
    result = _load_extension_header(program_type_descriptor_key, &local_program_type_descriptor->header);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    // Read the friendly program type name.
    result = ebpf_read_registry_value_string(program_type_descriptor_key, EBPF_PROGRAM_DATA_NAME, &program_type_name);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    try {
        program_type_name_string = (program_type_name != nullptr)
                                       ? ebpf_down_cast_from_wstring(std::wstring(program_type_name))
                                       : ebpf_down_cast_from_wstring(std::wstring(L""));
    } catch (const std::exception& e) {
        EBPF_LOG_MESSAGE_STRING(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_BASE,
            "Failed to convert program type name to string:",
            e.what());
        result = EBPF_FAILED;
        goto Exit;
    }

    // Allocate and read context descriptor.
    context_descriptor = (ebpf_context_descriptor_t*)ebpf_allocate(sizeof(ebpf_context_descriptor_t));
    if (context_descriptor == nullptr) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    result = ebpf_read_registry_value_binary(
        program_type_descriptor_key,
        EBPF_PROGRAM_DATA_CONTEXT_DESCRIPTOR,
        (uint8_t*)context_descriptor,
        sizeof(ebpf_context_descriptor_t));
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    // Read "is_privileged".
    result = ebpf_read_registry_value_dword(program_type_descriptor_key, EBPF_PROGRAM_DATA_PRIVILEGED, &is_privileged);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    // Read bpf program type.
    result = ebpf_read_registry_value_dword(program_type_descriptor_key, EBPF_DATA_BPF_PROG_TYPE, &bpf_program_type);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    // Populate the fields.
    local_program_type_descriptor->name = cxplat_duplicate_string(program_type_name_string.c_str());
    if (local_program_type_descriptor->name == nullptr) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    local_program_type_descriptor->context_descriptor = context_descriptor;
    context_descriptor = nullptr;
    local_program_type_descriptor->is_privileged = !!is_privileged;
    local_program_type_descriptor->bpf_prog_type = bpf_program_type;
    local_program_type_descriptor->program_type = *program_type;

    *program_type_descriptor = local_program_type_descriptor;
    local_program_type_descriptor = nullptr;
Exit:
    ebpf_free(program_type_name);
    ebpf_free(context_descriptor);
    ebpf_free(local_program_type_descriptor);
    if (program_type_descriptor_key) {
        ebpf_close_registry_key(program_type_descriptor_key);
    }
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_store_load_program_information(
    HKEY program_data_key,
    _In_z_ const wchar_t* program_type_string,
    _Outptr_ ebpf_program_info_t** program_info) noexcept
{
    uint32_t status;
    ebpf_result_t result = EBPF_SUCCESS;
    HKEY program_info_key = nullptr;
    HKEY helper_key = nullptr;
    ebpf_program_type_t* program_type = nullptr;
    ebpf_program_info_t* program_information = nullptr;
    ebpf_program_type_descriptor_t* program_type_descriptor = nullptr;
    uint32_t helper_count;
    wchar_t* helper_name = nullptr;

    EBPF_LOG_ENTRY();

    *program_info = nullptr;

    result =
        ebpf_open_registry_key(program_data_key, program_type_string, KEY_READ, (ebpf_store_key_t*)&program_info_key);
    if (result != EBPF_SUCCESS) {
        // Registry path is not present.
        result = EBPF_FILE_NOT_FOUND;
        goto Exit;
    }

    // Allocate the program information struct.
    program_information = (ebpf_program_info_t*)ebpf_allocate(sizeof(ebpf_program_info_t));
    if (program_information == nullptr) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    // Load extension header.
    result = _load_extension_header(program_info_key, &program_information->header);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    // Allocate and read the program type GUID.
    program_type = (ebpf_program_type_t*)ebpf_allocate(sizeof(ebpf_program_type_t));
    if (program_type == nullptr) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    result = ebpf_convert_string_to_guid(program_type_string, program_type);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    // Load program type descriptor.
    result = _ebpf_store_load_program_type_descriptor(program_info_key, program_type, &program_type_descriptor);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }
    program_information->program_type_descriptor = const_cast<ebpf_program_type_descriptor_t*>(program_type_descriptor);

    // Read helper count.
    result = ebpf_read_registry_value_dword(program_info_key, EBPF_PROGRAM_DATA_HELPER_COUNT, &helper_count);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    if (helper_count > 0) {
        // Read the helper functions prototypes.
        status = RegOpenKeyEx(program_info_key, EBPF_PROGRAM_DATA_HELPERS_REGISTRY_KEY, 0, KEY_READ, &helper_key);
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
            (unsigned long*)&max_helpers_count,
            (unsigned long*)&max_helper_name_size,
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

        ebpf_helper_function_prototype_t* helper_prototype =
            (ebpf_helper_function_prototype_t*)ebpf_allocate(helper_count * sizeof(ebpf_helper_function_prototype_t));
        if (helper_prototype == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }
        program_information->program_type_specific_helper_prototype = helper_prototype;

        // Add space for null terminator.
        max_helper_name_size += 1;

        helper_name = (wchar_t*)ebpf_allocate(max_helper_name_size * sizeof(wchar_t));
        if (helper_name == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }

        for (uint32_t index = 0; index < max_helpers_count; index++) {
            memset(helper_name, 0, (max_helper_name_size) * sizeof(wchar_t));
            key_size = (max_helper_name_size - 1) * sizeof(wchar_t);
            status = RegEnumKeyEx(
                helper_key, index, helper_name, (unsigned long*)&key_size, nullptr, nullptr, nullptr, nullptr);
            if (status != ERROR_SUCCESS) {
                result = win32_error_code_to_ebpf_result(status);
                goto Exit;
            }

            result = _ebpf_store_load_helper_prototype(helper_key, helper_name, &helper_prototype[index]);
            if (result != EBPF_SUCCESS) {
                goto Exit;
            }
        }

        program_information->count_of_program_type_specific_helpers = helper_count;
    }

    // Validate the program information struct.
    if (!ebpf_validate_program_info((const ebpf_program_info_t*)program_information)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    *program_info = program_information;
    program_information = nullptr;

Exit:
    ebpf_free(helper_name);
    if (result != EBPF_SUCCESS) {
        ebpf_program_info_free(program_information);
    }
    if (program_info_key) {
        ebpf_close_registry_key(program_info_key);
    }
    ebpf_free(program_type);

    if (helper_key) {
        ebpf_close_registry_key(helper_key);
    }
    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_store_load_program_data(
    _Outptr_result_buffer_maybenull_(*program_info_count) ebpf_program_info_t*** program_info,
    _Out_ uint32_t* program_info_count)
{
    uint32_t status;
    ebpf_result_t result = EBPF_SUCCESS;
    HKEY program_data_key = nullptr;
    wchar_t program_type_key[GUID_STRING_LENGTH + 1];
    unsigned long key_size = 0;
    uint32_t index = 0;
    ebpf_store_key_t store_key = nullptr;
    std::vector<ebpf_program_info_t*> program_info_array;

    EBPF_LOG_ENTRY();

    *program_info = nullptr;
    *program_info_count = 0;

    result = _open_ebpf_store_key(&store_key);
    if (result != EBPF_SUCCESS) {
        if (result == EBPF_FILE_NOT_FOUND) {
            result = EBPF_SUCCESS;
        }
        goto Exit;
    }

    // Open program data registry path.
    result = ebpf_open_registry_key(
        store_key, EBPF_PROGRAM_DATA_REGISTRY_KEY, KEY_READ, (ebpf_store_key_t*)&program_data_key);
    if (result != EBPF_SUCCESS) {
        if (result == EBPF_FILE_NOT_FOUND) {
            result = EBPF_SUCCESS;
        }
        goto Exit;
    }

    try {
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
                result = EBPF_FAILED;
                break;
            }

            ebpf_program_info_t* local_program_info = nullptr;
            result = _ebpf_store_load_program_information(program_data_key, program_type_key, &local_program_info);
            if (result != EBPF_SUCCESS) {
                EBPF_LOG_MESSAGE_WSTRING(
                    EBPF_TRACELOG_LEVEL_ERROR,
                    EBPF_TRACELOG_KEYWORD_BASE,
                    "Failed to load program data from store.",
                    program_type_key);
            } else {
                program_info_array.push_back(local_program_info);
            }
            result = EBPF_SUCCESS;
        }

        if (program_info_array.size() > 0) {
            // Copy the vector data to a new array.
            auto size = program_info_array.size() * sizeof(ebpf_program_info_t*);
            *program_info = (ebpf_program_info_t**)ebpf_allocate(size);
            if (*program_info == nullptr) {
                result = EBPF_NO_MEMORY;
                goto Exit;
            }

            memcpy(*program_info, program_info_array.data(), size);
            *program_info_count = (uint32_t)program_info_array.size();
        }
    } catch (...) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

Exit:
    if (result != EBPF_SUCCESS) {
        ebpf_free(*program_info);

        // Deallocate the dynamic memory in the program_info_array vector.
        if (program_info_array.size() > 0) {
            for (auto program_data : program_info_array) {
                ebpf_program_info_free(program_data);
            }
        }
    }

    if (program_data_key) {
        ebpf_close_registry_key(program_data_key);
    }

    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_load_section_data_information(
    HKEY section_data_key,
    _In_z_ const wchar_t* section_name,
    _Outptr_ ebpf_section_definition_t** section_info) noexcept
{
    ebpf_result_t result = EBPF_SUCCESS;
    HKEY section_info_key = nullptr;
    ebpf_program_type_t* program_type = nullptr;
    ebpf_attach_type_t* attach_type = nullptr;
    bpf_prog_type_t bpf_program_type;
    bpf_attach_type_t bpf_attach_type;
    char* section_prefix = nullptr;
    ebpf_section_definition_t* section_information = nullptr;

    EBPF_LOG_ENTRY();

    try {
        result = ebpf_open_registry_key(section_data_key, section_name, KEY_READ, (ebpf_store_key_t*)&section_info_key);
        if (result != EBPF_SUCCESS) {
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
        result = ebpf_read_registry_value_binary(
            section_info_key, EBPF_SECTION_DATA_PROGRAM_TYPE, (uint8_t*)program_type, sizeof(ebpf_program_type_t));
        if (result != EBPF_SUCCESS) {
            __analysis_assume(result != EBPF_SUCCESS);
            goto Exit;
        }

        // Read attach type.
        result = ebpf_read_registry_value_binary(
            section_info_key, EBPF_SECTION_DATA_ATTACH_TYPE, (uint8_t*)attach_type, sizeof(ebpf_attach_type_t));
        if (result != EBPF_SUCCESS) {
            __analysis_assume(result != EBPF_SUCCESS);
            goto Exit;
        }

        // Read bpf program type.
        result =
            ebpf_read_registry_value_dword(section_info_key, EBPF_DATA_BPF_PROG_TYPE, (uint32_t*)&bpf_program_type);
        if (result != EBPF_SUCCESS) {
            bpf_program_type = BPF_PROG_TYPE_UNSPEC;
            result = EBPF_SUCCESS;
        }

        // Read bpf attach type.
        result =
            ebpf_read_registry_value_dword(section_info_key, EBPF_DATA_BPF_ATTACH_TYPE, (uint32_t*)&bpf_attach_type);
        if (result != EBPF_SUCCESS) {
            bpf_attach_type = BPF_ATTACH_TYPE_UNSPEC;
            result = EBPF_SUCCESS;
        }

        section_prefix = cxplat_duplicate_string(ebpf_down_cast_from_wstring(section_name).c_str());
        if (section_prefix == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }

        section_information = (ebpf_section_definition_t*)ebpf_allocate(sizeof(ebpf_section_definition_t));
        if (section_information == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }

        // We have read all the required data. Populate section definition in the global array.
        section_information->program_type = program_type;
        section_information->attach_type = attach_type;
        section_information->bpf_prog_type = bpf_program_type;
        section_information->bpf_attach_type = bpf_attach_type;
        section_information->section_prefix = section_prefix;

        *section_info = section_information;
    } catch (...) {
        result = EBPF_FAILED;
        goto Exit;
    }

Exit:
    if (result != EBPF_SUCCESS) {
        ebpf_free(program_type);
        ebpf_free(attach_type);
        ebpf_free(section_prefix);
        ebpf_free(section_information);
    }
    if (section_info_key) {
        ebpf_close_registry_key(section_info_key);
    }
    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_store_load_section_information(
    _Outptr_result_buffer_maybenull_(*section_info_count) ebpf_section_definition_t*** section_info,
    _Out_ uint32_t* section_info_count)
{
    uint32_t status;
    ebpf_result_t result = EBPF_SUCCESS;
    HKEY section_data_key = nullptr;
    wchar_t section_name_key[MAX_PATH];
    unsigned long key_size = 0;
    uint32_t index = 0;
    ebpf_store_key_t store_key = nullptr;
    std::vector<ebpf_section_definition_t*> section_info_array;

    EBPF_LOG_ENTRY();

    *section_info = nullptr;
    *section_info_count = 0;

    result = _open_ebpf_store_key(&store_key);
    if (result != EBPF_SUCCESS) {
        if (result == EBPF_FILE_NOT_FOUND) {
            result = EBPF_SUCCESS;
        }
        goto Exit;
    }

    status = RegOpenKeyEx(static_cast<HKEY>(store_key), EBPF_SECTIONS_REGISTRY_KEY, 0, KEY_READ, &section_data_key);
    if (status != ERROR_SUCCESS) {
        if (status != ERROR_FILE_NOT_FOUND) {
            result = win32_error_code_to_ebpf_result(status);
            __analysis_assume(result != EBPF_SUCCESS);
        }
        goto Exit;
    }

    try {
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

            ebpf_section_definition_t* local_section_info = nullptr;
            result = _load_section_data_information(section_data_key, section_name_key, &local_section_info);
            if (result == EBPF_SUCCESS) {
                section_info_array.push_back(local_section_info);
            }
            result = EBPF_SUCCESS;
        }

        if (section_info_array.size() > 0) {
            // Copy the vector data to a new array.
            auto size = section_info_array.size() * sizeof(ebpf_section_definition_t*);
            *section_info = (ebpf_section_definition_t**)ebpf_allocate(size);
            if (*section_info == nullptr) {
                result = EBPF_NO_MEMORY;
                goto Exit;
            }

            memcpy(*section_info, section_info_array.data(), size);
            *section_info_count = (uint32_t)section_info_array.size();
        }
    } catch (...) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

Exit:
    if (result != EBPF_SUCCESS) {
        ebpf_free(*section_info);
        // Deallocate the dynamic memory in the section_info_array vector.
        if (section_info_array.size() > 0) {
            for (auto section_data : section_info_array) {
                ebpf_free(section_data->program_type);
                ebpf_free(section_data->attach_type);
                ebpf_free(const_cast<char*>(section_data->section_prefix));
                ebpf_free(section_data);
            }
        }
    }
    if (section_data_key) {
        ebpf_close_registry_key(section_data_key);
    }
    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_store_load_global_helper_information(
    _Outptr_result_buffer_maybenull_(*global_helper_info_count) ebpf_helper_function_prototype_t** global_helper_info,
    _Out_ uint32_t* global_helper_info_count)
{
    int32_t status;
    ebpf_result_t result = EBPF_SUCCESS;
    HKEY global_helpers_key = nullptr;
    wchar_t* helper_name = nullptr;
    unsigned long key_size = 0;
    uint32_t max_helper_name_size = 0;
    uint32_t max_helpers_count = 0;
    ebpf_helper_function_prototype_t* helper_prototype = nullptr;
    uint32_t index = 0;
    ebpf_store_key_t store_key = nullptr;

    EBPF_LOG_ENTRY();

    *global_helper_info = nullptr;
    *global_helper_info_count = 0;

    result = _open_ebpf_store_key(&store_key);
    if (result != EBPF_SUCCESS) {
        if (result == EBPF_FILE_NOT_FOUND) {
            result = EBPF_SUCCESS;
        }
        goto Exit;
    }

    // Open program data registry path.
    result = ebpf_open_registry_key(
        store_key, EBPF_GLOBAL_HELPERS_REGISTRY_KEY, KEY_READ, (ebpf_store_key_t*)&global_helpers_key);
    if (result != EBPF_SUCCESS) {
        if (result == EBPF_FILE_NOT_FOUND) {
            result = EBPF_SUCCESS;
        }
        goto Exit;
    }

    // Get the size of the largest subkey.
    status = RegQueryInfoKey(
        global_helpers_key,
        nullptr,
        nullptr,
        nullptr,
        (unsigned long*)&max_helpers_count,
        (unsigned long*)&max_helper_name_size,
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

    helper_prototype =
        (ebpf_helper_function_prototype_t*)ebpf_allocate(max_helpers_count * sizeof(ebpf_helper_function_prototype_t));
    if (helper_prototype == nullptr) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    memset(helper_prototype, 0, max_helpers_count * sizeof(ebpf_helper_function_prototype_t));

    for (index = 0; index < max_helpers_count; index++) {
        memset(helper_name, 0, max_helper_name_size * sizeof(wchar_t));
        key_size = max_helper_name_size;
        status = RegEnumKeyEx(global_helpers_key, index, helper_name, &key_size, nullptr, nullptr, nullptr, nullptr);
        if (status != ERROR_SUCCESS) {
            result = win32_error_code_to_ebpf_result(status);
            __analysis_assume(result != EBPF_SUCCESS);
            goto Exit;
        }

        result = _ebpf_store_load_helper_prototype(global_helpers_key, helper_name, &(helper_prototype[index]));
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }
    }

    *global_helper_info = helper_prototype;
    *global_helper_info_count = max_helpers_count;

Exit:
    if (global_helpers_key) {
        ebpf_close_registry_key(global_helpers_key);
    }
    if (result != EBPF_SUCCESS) {
        if (helper_prototype) {
            for (uint32_t i = 0; i < index; i++) {
                ebpf_free((void*)helper_prototype[i].name);
            }
            ebpf_free(helper_prototype);
        }
    }
    ebpf_free(helper_name);
    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_store_clear(_In_ const ebpf_store_key_t root_key_path)
{
    ebpf_store_key_t root_handle = {0};
    ebpf_store_key_t provider_handle = {0};
    ebpf_result_t result = EBPF_FAILED;

    EBPF_LOG_ENTRY();

    // Open root registry key.
    result = ebpf_open_registry_key(root_key_path, EBPF_ROOT_RELATIVE_PATH, REG_CREATE_FLAGS, &root_handle);
    if (result != EBPF_SUCCESS) {
        if (result == EBPF_FILE_NOT_FOUND) {
            result = EBPF_SUCCESS;
        }
        goto Exit;
    }

    // Open "providers" registry key.
    result = ebpf_open_registry_key(root_handle, EBPF_PROVIDERS_REGISTRY_KEY, REG_CREATE_FLAGS, &provider_handle);
    if (result != EBPF_SUCCESS) {
        if (result == EBPF_FILE_NOT_FOUND) {
            result = EBPF_SUCCESS;
        }
        goto Exit;
    }

    // Delete subtree of provider reg key.
    result = ebpf_delete_registry_tree(provider_handle, NULL);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }
    ebpf_close_registry_key(provider_handle);
    provider_handle = nullptr;

    result = ebpf_delete_registry_key(root_handle, EBPF_PROVIDERS_REGISTRY_KEY);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    result = EBPF_SUCCESS;

Exit:
    if (provider_handle) {
        ebpf_close_registry_key(provider_handle);
    }
    if (root_handle) {
        ebpf_close_registry_key(root_handle);
    }

    EBPF_RETURN_RESULT(result);
}

ebpf_result_t
ebpf_store_delete_global_helper_information(_In_ ebpf_helper_function_prototype_t* helper_info)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_store_key_t root_key = NULL;
    ebpf_store_key_t provider_key = NULL;
    ebpf_store_key_t helper_info_key = NULL;
    wchar_t* helper_name = ebpf_get_wstring_from_string(helper_info->name);

    EBPF_LOG_ENTRY();

    if (helper_name == nullptr) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    // Open root registry key.
    result = ebpf_open_registry_key(ebpf_store_root_key, EBPF_ROOT_RELATIVE_PATH, REG_CREATE_FLAGS, &root_key);
    if (result != EBPF_SUCCESS) {
        if (result == EBPF_FILE_NOT_FOUND) {
            result = EBPF_SUCCESS;
        }
        goto Exit;
    }

    // Open "providers" registry key.
    result = ebpf_open_registry_key(root_key, EBPF_PROVIDERS_REGISTRY_KEY, REG_CREATE_FLAGS, &provider_key);
    if (result != EBPF_SUCCESS) {
        if (result == EBPF_FILE_NOT_FOUND) {
            result = EBPF_SUCCESS;
        }
        goto Exit;
    }

    // Open (or create) global helpers key.
    result = ebpf_open_registry_key(provider_key, EBPF_GLOBAL_HELPERS_REGISTRY_KEY, REG_DELETE_FLAGS, &helper_info_key);
    if (result != EBPF_SUCCESS) {
        if (result == EBPF_FILE_NOT_FOUND) {
            result = EBPF_SUCCESS;
        }
        goto Exit;
    }

    result = ebpf_delete_registry_tree(helper_info_key, helper_name);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

Exit:
    ebpf_free(helper_name);
    ebpf_close_registry_key(helper_info_key);
    ebpf_close_registry_key(provider_key);

    EBPF_RETURN_RESULT(result);
}