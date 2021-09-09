// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Windows build system requires include of Windows.h before other Windows
// headers.
#include <Windows.h>

#include <chrono>
#include <mutex>
#include <thread>
#include <sddl.h>

#include "catch_wrapper.hpp"
#include "ebpf_bind_program_data.h"
#include "ebpf_epoch.h"
#include "ebpf_nethooks.h"
#include "ebpf_platform.h"
#include "ebpf_pinning_table.h"
#include "ebpf_program_types.h"
#include "ebpf_serialize.h"
#include "ebpf_xdp_program_data.h"
#include "ebpf_state.h"
#include "encode_program_info.h"

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

TEST_CASE("hash_table_test", "[platform]")
{
    ebpf_hash_table_t* table = nullptr;
    std::vector<uint8_t> key_1(13);
    std::vector<uint8_t> key_2(13);
    std::vector<uint8_t> data_1(37);
    std::vector<uint8_t> data_2(37);
    uint8_t* returned_value = nullptr;
    std::vector<uint8_t> returned_key(13);

    for (auto& v : key_1) {
        v = static_cast<uint8_t>(ebpf_random_uint32());
    }
    for (auto& v : key_2) {
        v = static_cast<uint8_t>(ebpf_random_uint32());
    }
    for (auto& v : data_1) {
        v = static_cast<uint8_t>(ebpf_random_uint32());
    }
    for (auto& v : data_2) {
        v = static_cast<uint8_t>(ebpf_random_uint32());
    }

    REQUIRE(
        ebpf_hash_table_create(&table, ebpf_allocate, ebpf_free, key_1.size(), data_1.size(), 1, NULL) == EBPF_SUCCESS);

    // Insert first
    REQUIRE(
        ebpf_hash_table_update(table, key_1.data(), data_1.data(), EBPF_HASH_TABLE_OPERATION_INSERT) == EBPF_SUCCESS);

    // Insert second
    REQUIRE(ebpf_hash_table_update(table, key_2.data(), data_2.data(), EBPF_HASH_TABLE_OPERATION_ANY) == EBPF_SUCCESS);

    // Find the first
    REQUIRE(ebpf_hash_table_find(table, key_1.data(), &returned_value) == EBPF_SUCCESS);
    REQUIRE(memcmp(returned_value, data_1.data(), data_1.size()) == 0);

    // Find the second
    REQUIRE(ebpf_hash_table_find(table, key_2.data(), &returned_value) == EBPF_SUCCESS);
    REQUIRE(memcmp(returned_value, data_2.data(), data_2.size()) == 0);

    // Replace
    memset(data_1.data(), '0x55', data_1.size());
    REQUIRE(
        ebpf_hash_table_update(table, key_1.data(), data_1.data(), EBPF_HASH_TABLE_OPERATION_REPLACE) == EBPF_SUCCESS);

    // Find the first
    REQUIRE(ebpf_hash_table_find(table, key_1.data(), &returned_value) == EBPF_SUCCESS);
    REQUIRE(memcmp(returned_value, data_1.data(), data_1.size()) == 0);

    // Next key
    REQUIRE(ebpf_hash_table_next_key(table, nullptr, returned_key.data()) == EBPF_SUCCESS);
    REQUIRE((returned_key == key_1 || returned_key == key_2));

    REQUIRE(ebpf_hash_table_next_key(table, returned_key.data(), returned_key.data()) == EBPF_SUCCESS);
    REQUIRE((returned_key == key_1 || returned_key == key_2));

    REQUIRE(ebpf_hash_table_next_key(table, returned_key.data(), returned_key.data()) == EBPF_NO_MORE_KEYS);
    REQUIRE((returned_key == key_1 || returned_key == key_2));

    // Delete found
    REQUIRE(ebpf_hash_table_delete(table, key_1.data()) == EBPF_SUCCESS);

    // Delete not found
    REQUIRE(ebpf_hash_table_delete(table, key_1.data()) == EBPF_KEY_NOT_FOUND);

    // Find not found
    REQUIRE(ebpf_hash_table_find(table, key_1.data(), &returned_value) == EBPF_KEY_NOT_FOUND);

    ebpf_hash_table_destroy(table);
}

void
run_in_epoch(std::function<void()> function)
{
    if (ebpf_epoch_enter() == EBPF_SUCCESS) {
        function();
        ebpf_epoch_exit();
    }
}

TEST_CASE("hash_table_stress_test", "[platform]")
{
    _test_helper test_helper;

    ebpf_hash_table_t* table = nullptr;
    const size_t iterations = 1000;
    uint32_t worker_threads = ebpf_get_cpu_count();
    uint32_t key_count = 4;
    uint32_t load_factor = 4;
    int32_t cpu_id = 0;
    REQUIRE(
        ebpf_hash_table_create(
            &table,
            ebpf_epoch_allocate,
            ebpf_epoch_free,
            sizeof(uint32_t),
            sizeof(uint64_t),
            static_cast<size_t>(worker_threads) * static_cast<size_t>(key_count),
            NULL) == EBPF_SUCCESS);
    auto worker = [table, iterations, key_count, load_factor, &cpu_id]() {
        uint32_t next_key = 0;
        uint64_t value = 11;
        uint64_t** returned_value = nullptr;
        std::vector<uint32_t> keys(static_cast<size_t>(key_count) * static_cast<size_t>(load_factor));

        uint32_t local_cpu_id = ebpf_interlocked_increment_int32(&cpu_id) - 1;
        uintptr_t thread_mask = local_cpu_id;
        thread_mask = static_cast<uintptr_t>(1) << thread_mask;
        SetThreadAffinityMask(GetCurrentThread(), thread_mask);

        for (auto& key : keys) {
            key = ebpf_random_uint32();
        }
        for (size_t i = 0; i < iterations; i++) {
            for (auto& key : keys) {
                run_in_epoch([&]() {
                    ebpf_hash_table_update(
                        table,
                        reinterpret_cast<const uint8_t*>(&key),
                        reinterpret_cast<const uint8_t*>(&value),
                        EBPF_HASH_TABLE_OPERATION_ANY);
                });
            }
            for (auto& key : keys)
                run_in_epoch([&]() {
                    ebpf_hash_table_find(
                        table, reinterpret_cast<const uint8_t*>(&key), reinterpret_cast<uint8_t**>(&returned_value));
                });
            for (auto& key : keys)
                run_in_epoch([&]() {
                    ebpf_hash_table_next_key(
                        table, reinterpret_cast<const uint8_t*>(&key), reinterpret_cast<uint8_t*>(&next_key));
                });

            for (auto& key : keys)
                run_in_epoch([&]() { ebpf_hash_table_delete(table, reinterpret_cast<const uint8_t*>(&key)); });
        }
    };

    std::vector<std::thread> threads;
    for (size_t i = 0; i < worker_threads; i++) {
        threads.emplace_back(std::thread(worker));
    }

    for (auto& thread : threads) {
        thread.join();
    }

    ebpf_hash_table_destroy(table);
}

TEST_CASE("pinning_test", "[platform]")
{
    _test_helper test_helper;

    typedef struct _some_object
    {
        ebpf_object_t object{};
        std::string name;
    } some_object_t;

    some_object_t an_object;
    some_object_t another_object;
    some_object_t* some_object = nullptr;
    ebpf_utf8_string_t foo = EBPF_UTF8_STRING_FROM_CONST_STRING("foo");
    ebpf_utf8_string_t bar = EBPF_UTF8_STRING_FROM_CONST_STRING("bar");

    REQUIRE(
        ebpf_object_initialize(
            &an_object.object, EBPF_OBJECT_MAP, [](ebpf_object_t*) {}, NULL) == EBPF_SUCCESS);
    REQUIRE(
        ebpf_object_initialize(
            &another_object.object, EBPF_OBJECT_MAP, [](ebpf_object_t*) {}, NULL) == EBPF_SUCCESS);

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

TEST_CASE("epoch_test_single_epoch", "[platform]")
{
    _test_helper test_helper;

    REQUIRE(ebpf_epoch_enter() == EBPF_SUCCESS);
    void* memory = ebpf_epoch_allocate(10);
    ebpf_epoch_free(memory);
    ebpf_epoch_exit();
    ebpf_epoch_flush();
}

TEST_CASE("epoch_test_two_threads", "[platform]")
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

TEST_CASE("extension_test", "[platform]")
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
    ebpf_extension_data_t client_data{};
    ebpf_extension_data_t provider_data{};
    GUID interface_id;

    const ebpf_extension_dispatch_table_t* returned_provider_dispatch_table;
    const ebpf_extension_data_t* returned_provider_data;

    ebpf_extension_provider_t* provider_context = nullptr;
    ebpf_extension_client_t* client_context = nullptr;
    void* provider_binding_context = nullptr;

    ebpf_guid_create(&interface_id);
    int callback_context = 0;
    int client_binding_context = 0;
    REQUIRE(
        ebpf_provider_load(
            &provider_context,
            &interface_id,
            nullptr,
            &provider_data,
            &provider_dispatch_table,
            &callback_context,
            provider_attach,
            provider_detach) == EBPF_SUCCESS);

    REQUIRE(
        ebpf_extension_load(
            &client_context,
            &interface_id,
            &client_binding_context,
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

TEST_CASE("trampoline_test", "[platform]")
{
    _test_helper test_helper;

    ebpf_trampoline_table_t* table = NULL;
    ebpf_result_t (*test_function)();
    auto provider_function1 = []() { return EBPF_SUCCESS; };
    ebpf_result_t (*function_pointer1)() = provider_function1;
    const void* helper_functions1[] = {(void*)function_pointer1};
    const uint32_t provider_helper_function_ids[] = {(uint32_t)(EBPF_MAX_GENERAL_HELPER_FUNCTION + 1)};
    ebpf_helper_function_addresses_t helper_function_addresses1 = {
        EBPF_COUNT_OF(helper_functions1), (uint64_t*)helper_functions1};

    auto provider_function2 = []() { return EBPF_OBJECT_ALREADY_EXISTS; };
    ebpf_result_t (*function_pointer2)() = provider_function2;
    const void* helper_functions2[] = {(void*)function_pointer2};
    ebpf_helper_function_addresses_t helper_function_addresses2 = {
        EBPF_COUNT_OF(helper_functions1), (uint64_t*)helper_functions2};

    REQUIRE(ebpf_allocate_trampoline_table(1, &table) == EBPF_SUCCESS);
    REQUIRE(
        ebpf_update_trampoline_table(
            table,
            EBPF_COUNT_OF(provider_helper_function_ids),
            provider_helper_function_ids,
            &helper_function_addresses1) == EBPF_SUCCESS);
    REQUIRE(ebpf_get_trampoline_function(table, 0, reinterpret_cast<void**>(&test_function)) == EBPF_SUCCESS);

    // Verify that the trampoline function invokes the provider function
    REQUIRE(test_function() == EBPF_SUCCESS);

    REQUIRE(
        ebpf_update_trampoline_table(
            table,
            EBPF_COUNT_OF(provider_helper_function_ids),
            provider_helper_function_ids,
            &helper_function_addresses2) == EBPF_SUCCESS);

    // Verify that the trampoline function now invokes the new provider function
    REQUIRE(test_function() == EBPF_OBJECT_ALREADY_EXISTS);
    ebpf_free_trampoline_table(table);
}

TEST_CASE("program_type_info", "[platform]")
{
    _test_helper test_helper;

    ebpf_context_descriptor_t context_descriptor{
        sizeof(xdp_md_t),
        EBPF_OFFSET_OF(xdp_md_t, data),
        EBPF_OFFSET_OF(xdp_md_t, data_end),
        EBPF_OFFSET_OF(xdp_md_t, data_meta)};
    ebpf_program_type_descriptor_t program_type{"xdp", &context_descriptor};
    ebpf_program_info_t program_info{
        program_type, ebpf_core_helper_functions_count, ebpf_core_helper_function_prototype};
    ebpf_program_info_t* new_program_info = nullptr;
    uint8_t* buffer = nullptr;
    unsigned long buffer_size;
    REQUIRE(ebpf_program_info_encode(&program_info, &buffer, &buffer_size) == EBPF_SUCCESS);
    REQUIRE(ebpf_program_info_decode(&new_program_info, buffer, buffer_size) == EBPF_SUCCESS);
    ebpf_free(new_program_info);
}

TEST_CASE("program_type_info_stored", "[platform]")
{
    _test_helper test_helper;
    ebpf_program_info_t* xdp_program_info = nullptr;
    ebpf_program_info_t* bind_program_info = nullptr;
    REQUIRE(
        ebpf_program_info_decode(
            &xdp_program_info, _ebpf_encoded_xdp_program_info_data, sizeof(_ebpf_encoded_xdp_program_info_data)) ==
        EBPF_SUCCESS);
    REQUIRE(xdp_program_info->count_of_helpers == ebpf_core_helper_functions_count);
    REQUIRE(strcmp(xdp_program_info->program_type_descriptor.name, "xdp") == 0);
    ebpf_free(xdp_program_info);

    REQUIRE(
        ebpf_program_info_decode(
            &bind_program_info, _ebpf_encoded_bind_program_info_data, sizeof(_ebpf_encoded_bind_program_info_data)) ==
        EBPF_SUCCESS);
    REQUIRE(strcmp(bind_program_info->program_type_descriptor.name, "bind") == 0);
    REQUIRE(bind_program_info->count_of_helpers == ebpf_core_helper_functions_count);
    ebpf_free(bind_program_info);
}

struct ebpf_security_descriptor_t_free
{
    void
    operator()(_Frees_ptr_opt_ ebpf_security_descriptor_t* p)
    {
        LocalFree(p);
    }
};
typedef std::unique_ptr<ebpf_security_descriptor_t, ebpf_security_descriptor_t_free> ebpf_security_generic_mapping_ptr;

TEST_CASE("access_check", "[platform]")
{
    _test_helper test_helper;
    ebpf_security_generic_mapping_ptr sd_ptr;
    ebpf_security_descriptor_t* sd = NULL;
    DWORD sd_size = 0;
    ebpf_security_generic_mapping_t generic_mapping{1, 1, 1};
    auto allow_sddl = L"O:COG:BUD:(A;;FA;;;WD)";
    auto deny_sddl = L"O:COG:BUD:(D;;FA;;;WD)";
    REQUIRE(ConvertStringSecurityDescriptorToSecurityDescriptor(
        allow_sddl, SDDL_REVISION_1, (PSECURITY_DESCRIPTOR*)&sd, &sd_size));
    sd_ptr.reset(sd);
    sd = nullptr;

    REQUIRE(ebpf_validate_security_descriptor(sd_ptr.get(), sd_size) == EBPF_SUCCESS);

    REQUIRE(ebpf_access_check(sd_ptr.get(), 1, &generic_mapping) == EBPF_SUCCESS);

    REQUIRE(ConvertStringSecurityDescriptorToSecurityDescriptor(
        deny_sddl, SDDL_REVISION_1, (PSECURITY_DESCRIPTOR*)&sd, &sd_size));

    sd_ptr.reset(sd);
    sd = nullptr;

    REQUIRE(ebpf_validate_security_descriptor(sd_ptr.get(), sd_size) == EBPF_SUCCESS);

    REQUIRE(ebpf_access_check(sd_ptr.get(), 1, &generic_mapping) == EBPF_ACCESS_DENIED);
}

struct ebpf_memory_descriptor_t_free
{
    void
    operator()(_Frees_ptr_opt_ ebpf_memory_descriptor_t* p)
    {
        ebpf_unmap_memory(p);
    }
};
typedef std::unique_ptr<ebpf_memory_descriptor_t, ebpf_memory_descriptor_t_free> ebpf_memory_descriptor_ptr;

TEST_CASE("memory_map_test", "[platform]")
{
    ebpf_memory_descriptor_ptr memory_descriptor;
    memory_descriptor.reset(ebpf_map_memory(100));
    REQUIRE(memory_descriptor);
    REQUIRE(ebpf_protect_memory(memory_descriptor.get(), EBPF_PAGE_PROTECT_READ_WRITE) == EBPF_SUCCESS);
    memset(ebpf_memory_descriptor_get_base_address(memory_descriptor.get()), 0xCC, 100);
    REQUIRE(ebpf_protect_memory(memory_descriptor.get(), EBPF_PAGE_PROTECT_READ_ONLY) == EBPF_SUCCESS);
}

TEST_CASE("serialize_map_test", "[platform]")
{
    _test_helper test_helper;

    const int map_count = 10;
    ebpf_map_info_internal_t internal_map_info_array[map_count] = {};
    std::string pin_path_prefix = "\\ebpf\\map\\";
    std::vector<std::string> pin_paths;
    size_t buffer_length = 0;
    uint8_t* buffer = nullptr;
    size_t required_length;
    size_t serialized_length;
    ebpf_map_info_t* map_info_array;

    // Construct the array of ebpf_map_info_internal_t to be serialized.
    for (int i = 0; i < map_count; i++) {
        pin_paths.push_back(pin_path_prefix + std::to_string(i));
    }

    for (int i = 0; i < map_count; i++) {
        ebpf_map_info_internal_t* map_info = &internal_map_info_array[i];
        map_info->definition.size = (i + 1) * 32;
        map_info->definition.type = static_cast<ebpf_map_type_t>(i % (BPF_MAP_TYPE_ARRAY + 1));
        map_info->definition.key_size = i + 1;
        map_info->definition.value_size = (i + 1) * (i + 1);
        map_info->definition.max_entries = (i + 1) * 128;

        map_info->pin_path.length = pin_paths[i].size();
        map_info->pin_path.value = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(pin_paths[i].c_str()));
    }

    // Serialize.
    ebpf_result_t result = ebpf_serialize_internal_map_info_array(
        map_count, internal_map_info_array, buffer, buffer_length, &serialized_length, &required_length);
    REQUIRE(result == EBPF_INSUFFICIENT_BUFFER);

    buffer = static_cast<uint8_t*>(calloc(required_length, 1));
    REQUIRE(buffer != nullptr);
    if (!buffer) {
        return;
    }
    buffer_length = required_length;

    result = ebpf_serialize_internal_map_info_array(
        map_count, internal_map_info_array, buffer, buffer_length, &serialized_length, &required_length);
    REQUIRE(result == EBPF_SUCCESS);

    // Deserialize.
    result = ebpf_deserialize_map_info_array(serialized_length, buffer, map_count, &map_info_array);
    REQUIRE(result == EBPF_SUCCESS);
    _Analysis_assume_(map_info_array != nullptr);
    // Verify de-serialized map info array matches input.
    for (int i = 0; i < map_count; i++) {
        ebpf_map_info_internal_t* input_map_info = &internal_map_info_array[i];
        ebpf_map_info_t* map_info = &map_info_array[i];
        REQUIRE(
            memcmp(&map_info->definition, &input_map_info->definition, sizeof(ebpf_map_definition_in_memory_t)) == 0);
        REQUIRE(strnlen_s(map_info->pin_path, EBPF_MAX_PIN_PATH_LENGTH) == input_map_info->pin_path.length);
        REQUIRE(memcmp(map_info->pin_path, input_map_info->pin_path.value, input_map_info->pin_path.length) == 0);
    }

    // Free de-serialized map info array.
    ebpf_map_info_array_free(map_count, map_info_array);

    free(buffer);
}

TEST_CASE("serialize_program_info_test", "[platform]")
{
    _test_helper test_helper;

    ebpf_helper_function_prototype_t helper_prototype[] = {
        {1000,
         "helper_0",
         EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
         {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY}},
        {1001,
         "helper_1",
         EBPF_RETURN_TYPE_INTEGER,
         {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE}}};
    // The values of the fields in the context_descriptor variable are completely arbitrary
    // and have no effect on the test.
    ebpf_context_descriptor_t context_descriptor = {32, 0, 8, -1};
    GUID program_type_test = {0x7ebe418c, 0x76dd, 0x4c2c, {0x99, 0xbc, 0x5c, 0x48, 0xa2, 0x30, 0x4b, 0x90}};
    ebpf_program_type_descriptor_t program_type = {"unit_test_program", &context_descriptor, program_type_test};
    ebpf_program_info_t in_program_info = {program_type, EBPF_COUNT_OF(helper_prototype), helper_prototype};

    size_t buffer_length = 0;
    uint8_t* buffer = nullptr;
    size_t required_length;
    size_t serialized_length;

    ebpf_program_info_t* out_program_info;

    // Serialize.
    ebpf_result_t result =
        ebpf_serialize_program_info(&in_program_info, buffer, buffer_length, &serialized_length, &required_length);
    REQUIRE(result == EBPF_INSUFFICIENT_BUFFER);

    buffer = static_cast<uint8_t*>(calloc(required_length, 1));
    _Analysis_assume_(buffer != nullptr);
    buffer_length = required_length;

    result = ebpf_serialize_program_info(&in_program_info, buffer, buffer_length, &serialized_length, &required_length);
    REQUIRE(result == EBPF_SUCCESS);

    // Deserialize.
    result = ebpf_deserialize_program_info(serialized_length, buffer, &out_program_info);
    REQUIRE(result == EBPF_SUCCESS);

    // Verify de-serialized program info matches input.
    REQUIRE(
        in_program_info.program_type_descriptor.program_type == out_program_info->program_type_descriptor.program_type);
    REQUIRE(
        in_program_info.program_type_descriptor.is_privileged ==
        out_program_info->program_type_descriptor.is_privileged);
    REQUIRE(in_program_info.program_type_descriptor.context_descriptor != nullptr);
    REQUIRE(
        memcmp(
            in_program_info.program_type_descriptor.context_descriptor,
            out_program_info->program_type_descriptor.context_descriptor,
            sizeof(ebpf_context_descriptor_t)) == 0);
    REQUIRE(
        strncmp(
            in_program_info.program_type_descriptor.name,
            out_program_info->program_type_descriptor.name,
            EBPF_MAX_PROGRAM_DESCRIPTOR_NAME_LENGTH) == 0);
    REQUIRE(in_program_info.count_of_helpers == out_program_info->count_of_helpers);
    REQUIRE(out_program_info->helper_prototype != nullptr);
    for (uint32_t i = 0; i < in_program_info.count_of_helpers; i++) {
        ebpf_helper_function_prototype_t* in_prototype = &in_program_info.helper_prototype[i];
        ebpf_helper_function_prototype_t* out_prototype = &out_program_info->helper_prototype[i];
        REQUIRE(in_prototype->helper_id == out_prototype->helper_id);
        REQUIRE(in_prototype->return_type == out_prototype->return_type);
        for (int j = 0; j < _countof(in_prototype->arguments); j++)
            REQUIRE(in_prototype->arguments[j] == out_prototype->arguments[j]);
        REQUIRE(out_prototype->name != nullptr);
        REQUIRE(strncmp(in_prototype->name, out_prototype->name, EBPF_MAX_HELPER_FUNCTION_NAME_LENGTH) == 0);
    }

    // Free de-serialized program info.
    ebpf_program_info_free(out_program_info);

    free(buffer);
}

TEST_CASE("state_test", "[state]")
{
    size_t allocated_index_1 = 0;
    size_t allocated_index_2 = 0;
    struct
    {
        uint32_t some_value;
    } foo;
    uintptr_t retreived_value = 0;
    REQUIRE(ebpf_state_initiate() == EBPF_SUCCESS);
    REQUIRE(ebpf_state_allocate_index(&allocated_index_1) == EBPF_SUCCESS);
    REQUIRE(ebpf_state_allocate_index(&allocated_index_2) == EBPF_SUCCESS);
    REQUIRE(allocated_index_2 != allocated_index_1);
    REQUIRE(ebpf_state_store(allocated_index_1, reinterpret_cast<uintptr_t>(&foo)) == EBPF_SUCCESS);
    REQUIRE(ebpf_state_load(allocated_index_1, &retreived_value) == EBPF_SUCCESS);
    REQUIRE(retreived_value == reinterpret_cast<uintptr_t>(&foo));
    ebpf_state_terminate();
}