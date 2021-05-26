/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#define CATCH_CONFIG_MAIN
// Windows build system requires include of Windows.h before other Windows
// headers.
#include <Windows.h>

#include <chrono>
#include <mutex>
#include <thread>
#include <sddl.h>

#include "catch2\catch.hpp"
#include "ebpf_bind_program_data.h"
#include "ebpf_epoch.h"
#include "ebpf_nethooks.h"
#include "ebpf_platform.h"
#include "ebpf_pinning_table.h"
#include "ebpf_program_types.h"
#include "ebpf_xdp_program_data.h"

class _test_helper
{
  public:
    _test_helper()
    {
        ebpf_object_tracking_initiate();
        REQUIRE(ebpf_platform_initiate() == EBPF_SUCCESS);
        platform_initiated = true;
        REQUIRE(ebpf_epoch_initiate() == EBPF_SUCCESS);
        epoch_initated = true;
    }
    ~_test_helper()
    {
        if (epoch_initated)
            ebpf_epoch_terminate();
        if (platform_initiated)
            ebpf_platform_terminate();
        ebpf_object_tracking_terminate();
    }

  private:
    bool platform_initiated = false;
    bool epoch_initated = false;
};

TEST_CASE("pinning_test", "[pinning_test]")
{
    _test_helper test_helper;

    typedef struct _some_object
    {
        ebpf_object_t object;
        std::string name;
    } some_object_t;

    some_object_t an_object;
    some_object_t another_object;
    some_object_t* some_object = nullptr;
    ebpf_utf8_string_t foo = EBPF_UTF8_STRING_FROM_CONST_STRING("foo");
    ebpf_utf8_string_t bar = EBPF_UTF8_STRING_FROM_CONST_STRING("bar");

    ebpf_object_initialize(&an_object.object, EBPF_OBJECT_MAP, [](ebpf_object_t*) {});
    ebpf_object_initialize(&another_object.object, EBPF_OBJECT_MAP, [](ebpf_object_t*) {});

    ebpf_pinning_table_t* pinning_table = nullptr;
    REQUIRE(ebpf_pinning_table_allocate(&pinning_table) == EBPF_SUCCESS);

    REQUIRE(ebpf_pinning_table_insert(pinning_table, &foo, &an_object.object) == EBPF_SUCCESS);
    REQUIRE(an_object.object.reference_count == 2);
    REQUIRE(ebpf_pinning_table_insert(pinning_table, &bar, &another_object.object) == EBPF_SUCCESS);
    REQUIRE(another_object.object.reference_count == 2);
    REQUIRE(ebpf_pinning_table_find(pinning_table, &foo, (ebpf_object_t**)&some_object) == EBPF_SUCCESS);
    REQUIRE(an_object.object.reference_count == 3);
    REQUIRE(some_object == &an_object);
    ebpf_object_release_reference(&some_object->object);
    REQUIRE(ebpf_pinning_table_delete(pinning_table, &foo) == EBPF_SUCCESS);
    REQUIRE(another_object.object.reference_count == 2);

    ebpf_pinning_table_free(pinning_table);
    REQUIRE(an_object.object.reference_count == 1);
    REQUIRE(another_object.object.reference_count == 1);

    ebpf_object_release_reference(&an_object.object);
    ebpf_object_release_reference(&another_object.object);
}

TEST_CASE("epoch_test_single_epoch", "[epoch_test_single_epoch]")
{
    _test_helper test_helper;

    REQUIRE(ebpf_epoch_enter() == EBPF_SUCCESS);
    void* memory = ebpf_epoch_allocate(10);
    ebpf_epoch_free(memory);
    ebpf_epoch_exit();
    ebpf_epoch_flush();
}

TEST_CASE("epoch_test_two_threads", "[epoch_test_two_threads]")
{
    _test_helper test_helper;

    auto epoch = []() {
        ebpf_epoch_enter();
        void* memory = ebpf_epoch_allocate(10);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        ebpf_epoch_free(memory);
        ebpf_epoch_exit();
        ebpf_epoch_flush();
    };

    std::thread thread_1(epoch);
    std::thread thread_2(epoch);
    thread_1.join();
    thread_2.join();
}

TEST_CASE("extension_test", "[extension_test]")
{
    _test_helper test_helper;

    auto client_function = []() { return EBPF_SUCCESS; };
    auto provider_function = []() { return EBPF_SUCCESS; };
    auto provider_attach = [](void* context,
                              const GUID* client_id,
                              void* client_binding_context,
                              const ebpf_extension_data_t* client_data,
                              const ebpf_extension_dispatch_table_t* client_dispatch_table) {
        UNREFERENCED_PARAMETER(context);
        UNREFERENCED_PARAMETER(client_id);
        UNREFERENCED_PARAMETER(client_data);
        UNREFERENCED_PARAMETER(client_dispatch_table);
        UNREFERENCED_PARAMETER(client_binding_context);
        return EBPF_SUCCESS;
    };
    auto provider_detach = [](void* context, const GUID* client_id) {
        UNREFERENCED_PARAMETER(context);
        UNREFERENCED_PARAMETER(client_id);
        return EBPF_SUCCESS;
    };
    ebpf_extension_dispatch_table_t client_dispatch_table = {
        0, sizeof(ebpf_extension_dispatch_table_t), client_function};
    ebpf_extension_dispatch_table_t provider_dispatch_table = {
        0, sizeof(ebpf_extension_dispatch_table_t), provider_function};
    ebpf_extension_data_t client_data;
    ebpf_extension_data_t provider_data;
    GUID interface_id;

    const ebpf_extension_dispatch_table_t* returned_provider_dispatch_table;
    const ebpf_extension_data_t* returned_provider_data;

    ebpf_extension_provider_t* provider_context = nullptr;
    ebpf_extension_client_t* client_context = nullptr;
    void* provider_binding_context = nullptr;

    ebpf_guid_create(&interface_id);

    REQUIRE(
        ebpf_provider_load(
            &provider_context,
            &interface_id,
            nullptr,
            &provider_data,
            &provider_dispatch_table,
            nullptr,
            provider_attach,
            provider_detach) == EBPF_SUCCESS);

    REQUIRE(
        ebpf_extension_load(
            &client_context,
            &interface_id,
            nullptr,
            &client_data,
            &client_dispatch_table,
            &provider_binding_context,
            &returned_provider_data,
            &returned_provider_dispatch_table,
            nullptr) == EBPF_SUCCESS);

    REQUIRE(returned_provider_data == &provider_data);
    REQUIRE(returned_provider_dispatch_table == &provider_dispatch_table);

    ebpf_extension_unload(client_context);
    ebpf_provider_unload(provider_context);
}

TEST_CASE("trampoline_test", "[trampoline_test]")
{
    _test_helper test_helper;

    size_t count = 0;
    ebpf_trampoline_table_t* table = NULL;
    ebpf_result_t (*test_function)();
    auto provider_function1 = []() { return EBPF_SUCCESS; };
    auto provider_function2 = []() { return EBPF_OBJECT_ALREADY_EXISTS; };

    ebpf_extension_dispatch_table_t provider_dispatch_table1 = {
        0, sizeof(ebpf_extension_dispatch_table_t), provider_function1};
    ebpf_extension_dispatch_table_t provider_dispatch_table2 = {
        0, sizeof(ebpf_extension_dispatch_table_t), provider_function2};

    REQUIRE(ebpf_allocate_trampoline_table(1, &table) == EBPF_SUCCESS);
    REQUIRE(ebpf_update_trampoline_table(table, &provider_dispatch_table1) == EBPF_SUCCESS);
    REQUIRE(ebpf_get_trampoline_function(table, 0, reinterpret_cast<void**>(&test_function)) == EBPF_SUCCESS);

    // Verify that the trampoline function invokes the provider function
    REQUIRE(test_function() == EBPF_SUCCESS);

    REQUIRE(ebpf_update_trampoline_table(table, &provider_dispatch_table2) == EBPF_SUCCESS);

    // Verify that the trampoline function now invokes the new provider function
    REQUIRE(test_function() == EBPF_OBJECT_ALREADY_EXISTS);
    ebpf_free_trampoline_table(table);
}

TEST_CASE("program_type_info", "[program_type_info]")
{
    _test_helper test_helper;

    ebpf_helper_function_prototype_t helper_functions[] = {
        {1,
         "ebpf_map_lookup_element",
         EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
         {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY}},
        {2,
         "ebpf_map_update_element",
         EBPF_RETURN_TYPE_INTEGER,
         {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE}},
        {3,
         "ebpf_map_delete_element",
         EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
         {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY}},
    };
    ebpf_context_descriptor_t context_descriptor{sizeof(xdp_md_t),
                                                 EBPF_OFFSET_OF(xdp_md_t, data),
                                                 EBPF_OFFSET_OF(xdp_md_t, data_end),
                                                 EBPF_OFFSET_OF(xdp_md_t, data_meta)};
    ebpf_program_type_descriptor_t program_type{"xdp", &context_descriptor};
    ebpf_program_information_t program_information{program_type, _countof(helper_functions), helper_functions};
    ebpf_program_information_t* new_program_information = nullptr;
    uint8_t* buffer = nullptr;
    unsigned long buffer_size;
    REQUIRE(ebpf_program_information_encode(&program_information, &buffer, &buffer_size) == EBPF_SUCCESS);
    REQUIRE(ebpf_program_information_decode(&new_program_information, buffer, buffer_size) == EBPF_SUCCESS);
    ebpf_free(new_program_information);
}

TEST_CASE("program_type_info_stored", "[program_type_info_stored]")
{
    _test_helper test_helper;
    ebpf_program_information_t* xdp_program_information = nullptr;
    ebpf_program_information_t* bind_program_information = nullptr;
    REQUIRE(
        ebpf_program_information_decode(
            &xdp_program_information,
            _ebpf_encoded_xdp_program_information_data,
            sizeof(_ebpf_encoded_xdp_program_information_data)) == EBPF_SUCCESS);
    REQUIRE(xdp_program_information->count_of_helpers == 3);
    REQUIRE(strcmp(xdp_program_information->program_type_descriptor.name, "xdp") == 0);
    ebpf_free(xdp_program_information);

    REQUIRE(
        ebpf_program_information_decode(
            &bind_program_information,
            _ebpf_encoded_bind_program_information_data,
            sizeof(_ebpf_encoded_bind_program_information_data)) == EBPF_SUCCESS);
    REQUIRE(strcmp(xdp_program_information->program_type_descriptor.name, "bind") == 0);
    REQUIRE(bind_program_information->count_of_helpers == 3);
    ebpf_free(bind_program_information);
}

TEST_CASE("access_check", "[access_check]")
{
    _test_helper test_helper;
    ebpf_security_descriptor_t* sd = NULL;
    DWORD sd_size = 0;
    ebpf_security_generic_mapping_t generic_mapping{1, 1, 1};
    ebpf_result_t result;
    auto allow_sddl = L"O:COG:BUD:(A;;FA;;;WD)";
    auto deny_sddl = L"O:COG:BUD:(D;;FA;;;WD)";
    REQUIRE(ConvertStringSecurityDescriptorToSecurityDescriptor(
        allow_sddl, SDDL_REVISION_1, (PSECURITY_DESCRIPTOR*)&sd, &sd_size));

    REQUIRE(ebpf_validate_security_descriptor(sd, sd_size) == EBPF_SUCCESS);

    REQUIRE((result = ebpf_access_check(sd, 1, &generic_mapping), LocalFree(sd), result == EBPF_SUCCESS));

    REQUIRE(ConvertStringSecurityDescriptorToSecurityDescriptor(
        deny_sddl, SDDL_REVISION_1, (PSECURITY_DESCRIPTOR*)&sd, &sd_size));

    REQUIRE(ebpf_validate_security_descriptor(sd, sd_size) == EBPF_SUCCESS);

    REQUIRE((result = ebpf_access_check(sd, 1, &generic_mapping), LocalFree(sd), result == EBPF_ERROR_ACCESS_DENIED));
}

TEST_CASE("memory_map_test", "[memory_map_test]")
{
    ebpf_result_t result;
    ebpf_memory_descriptor_t* memory_descriptor = nullptr;
    REQUIRE((memory_descriptor = ebpf_map_memory(100)) != nullptr);
    REQUIRE(
        (result = ebpf_protect_memory(memory_descriptor, EBPF_PAGE_PROTECT_READ_WRITE),
         result != EBPF_SUCCESS ? ebpf_unmap_memory(memory_descriptor) : (void)0,
         result == EBPF_SUCCESS));
    memset(ebpf_memory_descriptor_get_base_address(memory_descriptor), 0xCC, 100);
    REQUIRE(ebpf_protect_memory(memory_descriptor, EBPF_PAGE_PROTECT_READ_ONLY) == EBPF_SUCCESS);
    ebpf_unmap_memory(memory_descriptor);
}