// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "..\..\libs\store_helper\user\ebpf_registry_helper.h"
#include "catch_wrapper.hpp"
#include "ebpf_store_helper.h"
#include "platform.hpp"
#include "windows_platform_common.hpp"

#pragma warning(push)
#pragma warning(disable : 26495) // Always initialize a member variable
#define ebpf_inst ebpf_inst_btf
#include "libbtf/libbtf/btf_type_data.h"
#undef ebpf_inst
#pragma warning(pop)

#include <limits>
#include <string>
#include <vector>

#ifndef __CGUID_H__
static const GUID GUID_NULL = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};
#endif

static const GUID _btf_test_module_guid = {
    0x12345678, 0x1234, 0x1234, {0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}};
static const GUID _btf_test_module_guid_2 = {
    0x87654321, 0x4321, 0x4321, {0x43, 0x21, 0x43, 0x21, 0xba, 0x98, 0x76, 0x54}};

static const ebpf_btf_resolved_function_prototype_t _supported_btf_function = {
    EBPF_BTF_RESOLVED_FUNCTION_PROTOTYPE_HEADER,
    "my_driver_lookup",
    "int my_driver_lookup(uint64_t, void*, uint32_t)",
    EBPF_RETURN_TYPE_INTEGER,
    {EBPF_ARGUMENT_TYPE_ANYTHING,
     EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
     EBPF_ARGUMENT_TYPE_CONST_SIZE,
     EBPF_ARGUMENT_TYPE_DONTCARE,
     EBPF_ARGUMENT_TYPE_DONTCARE},
    0};

typedef struct _btf_test_function_definition
{
    const char* function_name;
    const char* module_tag;
    bool add_decl_tag;
} btf_test_function_definition_t;

static std::wstring
_get_btf_store_relative_path()
{
    return std::wstring(ebpf_store_root_sub_key) + L"\\" + EBPF_PROVIDERS_REGISTRY_KEY + L"\\" +
           EBPF_BTF_RESOLVED_FUNCTIONS_REGISTRY_KEY;
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

static std::string
_wide_to_utf8(_In_z_ const wchar_t* string)
{
    int required_size = WideCharToMultiByte(CP_UTF8, 0, string, -1, nullptr, 0, nullptr, nullptr);
    REQUIRE(required_size > 0);

    std::string converted(static_cast<size_t>(required_size) - 1, '\0');
    REQUIRE(
        WideCharToMultiByte(CP_UTF8, 0, string, -1, converted.data(), required_size, nullptr, nullptr) ==
        required_size);
    return converted;
}

static std::string
_guid_to_decl_tag_string(_In_ const GUID* module_guid)
{
    wchar_t guid_string[GUID_STRING_LENGTH + 1] = {};
    REQUIRE(
        ebpf_convert_guid_to_string(module_guid, guid_string, sizeof(guid_string) / sizeof(guid_string[0])) ==
        EBPF_SUCCESS);
    return std::string("module_id:") + _wide_to_utf8(guid_string);
}

static void
_publish_btf_provider(
    _In_ const GUID* module_guid,
    _In_reads_(prototype_count) const ebpf_btf_resolved_function_prototype_t* prototypes,
    uint32_t prototype_count)
{
    ebpf_btf_resolved_function_provider_info_t provider_info = {
        EBPF_BTF_RESOLVED_FUNCTION_PROVIDER_INFO_HEADER, *module_guid, prototype_count, prototypes};
    REQUIRE(ebpf_store_update_btf_resolved_function_provider_information(&provider_info) == EBPF_SUCCESS);
}

static libbtf::btf_type_data
_create_btf_resolved_function_btf(const std::vector<btf_test_function_definition_t>& functions)
{
    libbtf::btf_type_data btf_data;
    const auto int_id = btf_data.append(libbtf::btf_kind_int{"int", 4, 0, 32, true, false, false});
    std::vector<libbtf::btf_kind_data_member> ksym_members;
    uint32_t offset = 0;

    for (const auto& function : functions) {
        const auto function_prototype_id = btf_data.append(
            libbtf::btf_kind_function_prototype{{libbtf::btf_kind_function_parameter{"value", int_id}}, int_id});
        const auto function_id = btf_data.append(
            libbtf::btf_kind_function{function.function_name, libbtf::BTF_LINKAGE_EXTERN, function_prototype_id});
        ksym_members.push_back(libbtf::btf_kind_data_member{function_id, offset, 8});
        offset += 8;

        if (function.add_decl_tag) {
            btf_data.append(
                libbtf::btf_kind_decl_tag{function.module_tag, function_id, std::numeric_limits<uint32_t>::max()});
        }
    }

    btf_data.append(libbtf::btf_kind_data_section{".ksyms", ksym_members, offset});
    return btf_data;
}

static prevail::EbpfProgramType
_create_test_program_type()
{
    prevail::EbpfProgramType program_type;
    program_type.name = "test";
    program_type.is_privileged = true;
    return program_type;
}

TEST_CASE("btf verifier resolves published function metadata", "[verifier][btf]")
{
    const std::string module_tag = _guid_to_decl_tag_string(&_btf_test_module_guid);
    libbtf::btf_type_data btf_data =
        _create_btf_resolved_function_btf({{_supported_btf_function.name, module_tag.c_str(), true}});
    prevail::EbpfProgramType program_type = _create_test_program_type();
    std::string why_not;

    REQUIRE(_clear_btf_store() == EBPF_SUCCESS);
    clear_program_info_cache();
    _publish_btf_provider(&_btf_test_module_guid, &_supported_btf_function, 1);

    REQUIRE_NOTHROW(cache_btf_resolved_functions(btf_data));

    const auto resolved_symbol = resolve_ksym_btf_id_windows(_supported_btf_function.name);
    REQUIRE(resolved_symbol.has_value());
    REQUIRE(resolved_symbol->btf_id == 1);
    REQUIRE(resolved_symbol->module == 0);

    const auto resolved_call =
        resolve_kfunc_call_windows(resolved_symbol->btf_id, resolved_symbol->module, program_type, &why_not);
    REQUIRE(resolved_call.has_value());
    REQUIRE(why_not.empty());
    REQUIRE(resolved_call->name == _supported_btf_function.name);
    REQUIRE(!resolved_call->contract.return_ptr_type.has_value());
    REQUIRE(!resolved_call->contract.return_nullable);
    REQUIRE(!resolved_call->contract.is_map_lookup);
    REQUIRE(resolved_call->contract.singles.size() == 1);
    REQUIRE(resolved_call->contract.singles[0].kind == prevail::ArgSingle::Kind::ANYTHING);
    REQUIRE(resolved_call->contract.pairs.size() == 1);
    REQUIRE(resolved_call->contract.pairs[0].kind == prevail::ArgPair::Kind::PTR_TO_READABLE_MEM);

    clear_program_info_cache();
    REQUIRE(_clear_btf_store() == EBPF_SUCCESS);
}

TEST_CASE("btf verifier rejects published function flags without verifier semantics", "[verifier][btf]")
{
    ebpf_btf_resolved_function_prototype_t prototype = _supported_btf_function;
    const std::string module_tag = _guid_to_decl_tag_string(&_btf_test_module_guid);
    libbtf::btf_type_data btf_data = _create_btf_resolved_function_btf({{prototype.name, module_tag.c_str(), true}});
    prevail::EbpfProgramType program_type = _create_test_program_type();
    std::string why_not;

    prototype.flags = 1;

    REQUIRE(_clear_btf_store() == EBPF_SUCCESS);
    clear_program_info_cache();
    _publish_btf_provider(&_btf_test_module_guid, &prototype, 1);

    REQUIRE_NOTHROW(cache_btf_resolved_functions(btf_data));
    const auto resolved_symbol = resolve_ksym_btf_id_windows(prototype.name);
    REQUIRE(resolved_symbol.has_value());

    const auto resolved_call =
        resolve_kfunc_call_windows(resolved_symbol->btf_id, resolved_symbol->module, program_type, &why_not);
    REQUIRE(!resolved_call.has_value());
    REQUIRE(why_not.find("unsupported flags") != std::string::npos);

    clear_program_info_cache();
    REQUIRE(_clear_btf_store() == EBPF_SUCCESS);
}

TEST_CASE("btf verifier keeps unresolved symbols when published metadata is missing", "[verifier][btf]")
{
    const std::string module_tag = _guid_to_decl_tag_string(&_btf_test_module_guid);
    libbtf::btf_type_data btf_data =
        _create_btf_resolved_function_btf({{_supported_btf_function.name, module_tag.c_str(), true}});
    prevail::EbpfProgramType program_type = _create_test_program_type();
    std::string why_not;

    REQUIRE(_clear_btf_store() == EBPF_SUCCESS);
    clear_program_info_cache();

    REQUIRE_NOTHROW(cache_btf_resolved_functions(btf_data));
    const auto resolved_symbol = resolve_ksym_btf_id_windows(_supported_btf_function.name);
    REQUIRE(resolved_symbol.has_value());
    const auto resolved_call =
        resolve_kfunc_call_windows(resolved_symbol->btf_id, resolved_symbol->module, program_type, &why_not);
    REQUIRE(!resolved_call.has_value());
    REQUIRE(why_not.find("prototype lookup failed") != std::string::npos);

    clear_program_info_cache();
    REQUIRE(_clear_btf_store() == EBPF_SUCCESS);
}

TEST_CASE("btf verifier preprocessing requires module decl tags for .ksyms functions", "[verifier][btf]")
{
    libbtf::btf_type_data btf_data = _create_btf_resolved_function_btf({{_supported_btf_function.name, "", false}});

    clear_program_info_cache();
    REQUIRE_THROWS_WITH(
        cache_btf_resolved_functions(btf_data),
        Catch::Matchers::ContainsSubstring("Missing module_id decl_tag for BTF-resolved function"));
    clear_program_info_cache();
}

TEST_CASE("btf verifier preprocessing rejects ambiguous duplicate .ksyms names", "[verifier][btf]")
{
    const std::string module_tag_1 = _guid_to_decl_tag_string(&_btf_test_module_guid);
    const std::string module_tag_2 = _guid_to_decl_tag_string(&_btf_test_module_guid_2);
    libbtf::btf_type_data btf_data = _create_btf_resolved_function_btf(
        {{_supported_btf_function.name, module_tag_1.c_str(), true},
         {_supported_btf_function.name, module_tag_2.c_str(), true}});

    clear_program_info_cache();
    REQUIRE_THROWS_WITH(
        cache_btf_resolved_functions(btf_data),
        Catch::Matchers::ContainsSubstring("Ambiguous BTF-resolved function name across multiple module GUIDs"));
    clear_program_info_cache();
}

TEST_CASE("btf verifier preprocessing ignores unrelated top-level decl tags", "[verifier][btf]")
{
    const std::string module_tag = _guid_to_decl_tag_string(&_btf_test_module_guid);
    libbtf::btf_type_data btf_data =
        _create_btf_resolved_function_btf({{_supported_btf_function.name, module_tag.c_str(), true}});
    prevail::EbpfProgramType program_type = _create_test_program_type();
    std::string why_not;

    btf_data.append(
        libbtf::btf_kind_decl_tag{"preserve_access_index", 1, std::numeric_limits<uint32_t>::max()});

    REQUIRE(_clear_btf_store() == EBPF_SUCCESS);
    clear_program_info_cache();
    _publish_btf_provider(&_btf_test_module_guid, &_supported_btf_function, 1);

    REQUIRE_NOTHROW(cache_btf_resolved_functions(btf_data));

    const auto resolved_symbol = resolve_ksym_btf_id_windows(_supported_btf_function.name);
    REQUIRE(resolved_symbol.has_value());

    const auto resolved_call =
        resolve_kfunc_call_windows(resolved_symbol->btf_id, resolved_symbol->module, program_type, &why_not);
    REQUIRE(resolved_call.has_value());
    REQUIRE(why_not.empty());

    clear_program_info_cache();
    REQUIRE(_clear_btf_store() == EBPF_SUCCESS);
}
