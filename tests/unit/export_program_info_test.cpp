// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include "..\..\libs\shared\ebpf_shared_framework.h"
#include "..\..\libs\store_helper\user\ebpf_registry_helper.h"
#include "catch_wrapper.hpp"
#include "export_program_info.cpp"

#include <cstring>
#include <string>

#ifndef __CGUID_H__
static const GUID GUID_NULL = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};
#endif

static const GUID _btf_test_module_guid = {
    0x9bf4af4c, 0xe7d5, 0x4fd9, {0x92, 0x55, 0x20, 0x06, 0x6c, 0x61, 0xaf, 0xe3}};

static const ebpf_btf_resolved_function_prototype_t _btf_test_function_prototypes[] = {
    {EBPF_BTF_RESOLVED_FUNCTION_PROTOTYPE_HEADER,
     "my_driver_lookup",
     "int my_driver_lookup(uint64_t, void*, uint32_t)",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_ANYTHING,
      EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
      EBPF_ARGUMENT_TYPE_CONST_SIZE,
      EBPF_ARGUMENT_TYPE_DONTCARE,
      EBPF_ARGUMENT_TYPE_DONTCARE},
     1},
    {EBPF_BTF_RESOLVED_FUNCTION_PROTOTYPE_HEADER,
     "my_driver_update",
     "int my_driver_update(void*, uint64_t)",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
      EBPF_ARGUMENT_TYPE_ANYTHING,
      EBPF_ARGUMENT_TYPE_DONTCARE,
      EBPF_ARGUMENT_TYPE_DONTCARE,
      EBPF_ARGUMENT_TYPE_DONTCARE},
     2},
};

static const ebpf_btf_resolved_function_provider_info_t _btf_test_provider_info = {
    EBPF_BTF_RESOLVED_FUNCTION_PROVIDER_INFO_HEADER,
    _btf_test_module_guid,
    EBPF_COUNT_OF(_btf_test_function_prototypes),
    _btf_test_function_prototypes};

static const uint64_t _btf_test_function_addresses[] = {1, 2};

static std::wstring
_get_btf_store_relative_path()
{
    return std::wstring(ebpf_store_root_sub_key) + L"\\" + EBPF_PROVIDERS_REGISTRY_KEY + L"\\" +
           EBPF_BTF_RESOLVED_FUNCTIONS_REGISTRY_KEY;
}

static std::wstring
_get_btf_provider_relative_path()
{
    wchar_t guid_string[GUID_STRING_LENGTH + 1] = {};
    REQUIRE(ebpf_convert_guid_to_string(&_btf_test_module_guid, guid_string, GUID_STRING_LENGTH + 1) == EBPF_SUCCESS);

    return _get_btf_store_relative_path() + L"\\" + guid_string;
}

static ebpf_result_t
_clear_btf_store()
{
    ebpf_result_t result = ebpf_delete_registry_tree(ebpf_store_hkcu_root_key, _get_btf_store_relative_path().c_str());
    if (result != EBPF_SUCCESS && result != EBPF_FILE_NOT_FOUND) {
        return result;
    }

    result = ebpf_delete_registry_tree(ebpf_store_hklm_root_key, _get_btf_store_relative_path().c_str());
    if (result == EBPF_ACCESS_DENIED || result == EBPF_FILE_NOT_FOUND) {
        result = EBPF_SUCCESS;
    }

    return result;
}

static ebpf_store_key_t
_open_registry_key_or_require_success(_In_ ebpf_store_key_t root_key, _In_ const std::wstring& path)
{
    ebpf_store_key_t key = nullptr;
    REQUIRE(ebpf_open_registry_key(root_key, path.c_str(), KEY_READ, &key) == EBPF_SUCCESS);
    return key;
}

static void
_require_btf_function_metadata(
    _In_ ebpf_store_key_t function_collection_key,
    _In_ const ebpf_btf_resolved_function_prototype_t* function_prototype)
{
    ebpf_store_key_t function_key = nullptr;
    wchar_t* prototype = nullptr;
    wchar_t* function_name = nullptr;
    wchar_t* expected_prototype = nullptr;
    uint32_t return_type = MAXUINT32;
    ebpf_argument_type_t arguments[5] = {};
    uint32_t flags = MAXUINT32;

    function_name = ebpf_get_wstring_from_string(function_prototype->name);
    REQUIRE(function_name != nullptr);
    expected_prototype = ebpf_get_wstring_from_string(function_prototype->prototype);
    REQUIRE(expected_prototype != nullptr);

    REQUIRE(ebpf_open_registry_key(function_collection_key, function_name, KEY_READ, &function_key) == EBPF_SUCCESS);
    REQUIRE(
        ebpf_read_registry_value_string(function_key, EBPF_BTF_FUNCTION_DATA_PROTOTYPE, &prototype) == EBPF_SUCCESS);
    REQUIRE(prototype != nullptr);
    REQUIRE(std::wstring(prototype) == std::wstring(expected_prototype));
    ebpf_free(prototype);
    prototype = nullptr;

    REQUIRE(
        ebpf_read_registry_value_dword(function_key, EBPF_BTF_FUNCTION_DATA_RETURN_TYPE, &return_type) == EBPF_SUCCESS);
    REQUIRE(return_type == static_cast<uint32_t>(function_prototype->return_type));

    REQUIRE(
        ebpf_read_registry_value_binary(
            function_key, EBPF_BTF_FUNCTION_DATA_ARGUMENTS, (uint8_t*)arguments, sizeof(arguments)) == EBPF_SUCCESS);
    REQUIRE(memcmp(arguments, function_prototype->arguments, sizeof(arguments)) == 0);

    REQUIRE(ebpf_read_registry_value_dword(function_key, EBPF_BTF_FUNCTION_DATA_FLAGS, &flags) == EBPF_SUCCESS);
    REQUIRE(flags == function_prototype->flags);

    ebpf_close_registry_key(function_key);
    ebpf_free_wstring(expected_prototype);
    ebpf_free_wstring(function_name);
}

static void
_populate_ebpf_store()
{
    REQUIRE(export_all_program_information() == 0);
    REQUIRE(export_all_section_information() == 0);
    REQUIRE(export_global_helper_information() == 0);
}

TEST_CASE("export_program_info", "[end_to_end]")
{
    REQUIRE(clear_ebpf_store() == 0);

    // Re-populate the ebpf store.
    _populate_ebpf_store();
}

TEST_CASE("export_btf_resolved_function_provider_information", "[store_helper]")
{
    ebpf_store_key_t provider_key = nullptr;
    ebpf_store_key_t function_collection_key = nullptr;
    uint32_t version = MAXUINT32;
    uint32_t size = MAXUINT32;

    REQUIRE(_clear_btf_store() == EBPF_SUCCESS);
    REQUIRE(ebpf_store_update_btf_resolved_function_provider_information(&_btf_test_provider_info) == EBPF_SUCCESS);

    provider_key = _open_registry_key_or_require_success(ebpf_store_hkcu_root_key, _get_btf_provider_relative_path());
    REQUIRE(ebpf_read_registry_value_dword(provider_key, EBPF_EXTENSION_HEADER_VERSION, &version) == EBPF_SUCCESS);
    REQUIRE(version == EBPF_BTF_RESOLVED_FUNCTION_PROVIDER_INFO_CURRENT_VERSION);
    REQUIRE(ebpf_read_registry_value_dword(provider_key, EBPF_EXTENSION_HEADER_SIZE, &size) == EBPF_SUCCESS);
    REQUIRE(size == EBPF_BTF_RESOLVED_FUNCTION_PROVIDER_INFO_CURRENT_VERSION_SIZE);

    function_collection_key =
        _open_registry_key_or_require_success(provider_key, std::wstring(EBPF_BTF_FUNCTIONS_REGISTRY_KEY));
    for (const auto& function_prototype : _btf_test_function_prototypes) {
        _require_btf_function_metadata(function_collection_key, &function_prototype);
    }

    ebpf_close_registry_key(function_collection_key);
    ebpf_close_registry_key(provider_key);
    REQUIRE(_clear_btf_store() == EBPF_SUCCESS);
}

TEST_CASE("delete_btf_resolved_function_provider_information", "[store_helper]")
{
    REQUIRE(_clear_btf_store() == EBPF_SUCCESS);
    REQUIRE(ebpf_store_update_btf_resolved_function_provider_information(&_btf_test_provider_info) == EBPF_SUCCESS);

    REQUIRE(ebpf_store_delete_btf_resolved_function_provider_information(&_btf_test_provider_info) == EBPF_SUCCESS);

    ebpf_store_key_t provider_key = nullptr;
    REQUIRE(
        ebpf_open_registry_key(
            ebpf_store_hkcu_root_key, _get_btf_provider_relative_path().c_str(), KEY_READ, &provider_key) ==
        EBPF_FILE_NOT_FOUND);

    REQUIRE(_clear_btf_store() == EBPF_SUCCESS);
}

TEST_CASE("export_btf_resolved_function_provider_information rejects invalid input", "[store_helper]")
{
    ebpf_btf_resolved_function_provider_info_t provider_info = _btf_test_provider_info;
    ebpf_btf_resolved_function_prototype_t function_prototypes[EBPF_COUNT_OF(_btf_test_function_prototypes)] = {};

    memcpy(function_prototypes, _btf_test_function_prototypes, sizeof(function_prototypes));
    provider_info.btf_resolved_function_prototypes = function_prototypes;

#pragma warning(suppress : 6387) // Intentional invalid-input test of the nullptr provider_info path.
    REQUIRE(ebpf_store_update_btf_resolved_function_provider_information(nullptr) == EBPF_INVALID_ARGUMENT);

    provider_info.btf_resolved_function_count = 0;
    REQUIRE(ebpf_store_update_btf_resolved_function_provider_information(&provider_info) == EBPF_INVALID_ARGUMENT);
    provider_info.btf_resolved_function_count = EBPF_COUNT_OF(_btf_test_function_prototypes);

    provider_info.btf_resolved_function_prototypes = nullptr;
    REQUIRE(ebpf_store_update_btf_resolved_function_provider_information(&provider_info) == EBPF_INVALID_ARGUMENT);
    provider_info.btf_resolved_function_prototypes = function_prototypes;

    provider_info.module_guid = GUID_NULL;
    REQUIRE(ebpf_store_update_btf_resolved_function_provider_information(&provider_info) == EBPF_INVALID_ARGUMENT);
    provider_info.module_guid = _btf_test_module_guid;

    function_prototypes[0].name = nullptr;
    REQUIRE(ebpf_store_update_btf_resolved_function_provider_information(&provider_info) == EBPF_INVALID_ARGUMENT);
    function_prototypes[0].name = _btf_test_function_prototypes[0].name;

    function_prototypes[0].prototype = nullptr;
    REQUIRE(ebpf_store_update_btf_resolved_function_provider_information(&provider_info) == EBPF_INVALID_ARGUMENT);
}

TEST_CASE("validate_btf_resolved_function_provider_data", "[shared]")
{
    ebpf_btf_resolved_function_provider_data_t provider_data = {
        EBPF_BTF_RESOLVED_FUNCTION_PROVIDER_DATA_HEADER,
        EBPF_COUNT_OF(_btf_test_function_prototypes),
        _btf_test_function_prototypes,
        _btf_test_function_addresses};

    REQUIRE(ebpf_validate_btf_resolved_function_prototype_array(
        _btf_test_function_prototypes, EBPF_COUNT_OF(_btf_test_function_prototypes)));
    REQUIRE(ebpf_validate_btf_resolved_function_provider_data(&provider_data));

    provider_data.btf_resolved_function_count = 0;
    REQUIRE_FALSE(ebpf_validate_btf_resolved_function_provider_data(&provider_data));
    provider_data.btf_resolved_function_count = EBPF_COUNT_OF(_btf_test_function_prototypes);

    provider_data.btf_resolved_function_addresses = nullptr;
    REQUIRE_FALSE(ebpf_validate_btf_resolved_function_provider_data(&provider_data));
    provider_data.btf_resolved_function_addresses = _btf_test_function_addresses;

    ebpf_btf_resolved_function_prototype_t invalid_prototypes[EBPF_COUNT_OF(_btf_test_function_prototypes)] = {};
    memcpy(invalid_prototypes, _btf_test_function_prototypes, sizeof(invalid_prototypes));
    invalid_prototypes[0].name = nullptr;
    REQUIRE_FALSE(
        ebpf_validate_btf_resolved_function_prototype_array(invalid_prototypes, EBPF_COUNT_OF(invalid_prototypes)));

    provider_data.btf_resolved_function_prototypes = invalid_prototypes;
    REQUIRE_FALSE(ebpf_validate_btf_resolved_function_provider_data(&provider_data));
}
