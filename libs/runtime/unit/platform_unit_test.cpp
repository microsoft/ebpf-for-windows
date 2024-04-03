// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_PLATFORM_UNIT_TESTS

#include "api_common.hpp"
#include "catch_wrapper.hpp"
#include "ebpf_async.h"
#include "ebpf_bitmap.h"
#include "ebpf_epoch.h"
#include "ebpf_hash_table.h"
#include "ebpf_nethooks.h"
#include "ebpf_pinning_table.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_random.h"
#include "ebpf_ring_buffer.h"
#include "ebpf_serialize.h"
#include "ebpf_state.h"
#include "ebpf_work_queue.h"
#include "helpers.h"
#include "kissfft.hh"

#include <winsock2.h>
#include <Windows.h>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <complex>
#include <condition_variable>
#include <fstream>
#include <mutex>
#include <numeric>
#include <sddl.h>
#include <thread>
#include <vector>

extern ebpf_helper_function_prototype_t* ebpf_core_helper_function_prototype;
extern uint32_t ebpf_core_helper_functions_count;

typedef struct _free_ebpf_pinning_table
{
    void
    operator()(_In_opt_ _Post_invalid_ ebpf_pinning_table_t* table)
    {
        if (table != nullptr) {
            ebpf_pinning_table_free(table);
        }
    }
} free_ebpf_pinning_table_t;

typedef std::unique_ptr<ebpf_pinning_table_t, free_ebpf_pinning_table_t> ebpf_pinning_table_ptr;

typedef struct _free_trampoline_table
{
    void
    operator()(_In_opt_ _Post_invalid_ ebpf_trampoline_table_t* table)
    {
        if (table != nullptr) {
            ebpf_free_trampoline_table(table);
        }
    }
} free_trampoline_table_t;

typedef std::unique_ptr<ebpf_trampoline_table_t, free_trampoline_table_t> ebpf_trampoline_table_ptr;

typedef class _signal
{
  public:
    void
    wait()
    {
        std::unique_lock l(lock);
        condition_variable.wait(l, [&]() { return signaled; });
    }
    void
    signal()
    {
        std::unique_lock l(lock);
        signaled = true;
        condition_variable.notify_all();
    }

  private:
    std::mutex lock;
    std::condition_variable condition_variable;
    bool signaled = false;
} signal_t;

class _test_helper
{
  public:
    _test_helper() {}
    void
    initialize()
    {
        REQUIRE(ebpf_platform_initiate() == EBPF_SUCCESS);
        platform_initiated = true;
        REQUIRE(ebpf_random_initiate() == EBPF_SUCCESS);
        REQUIRE(ebpf_epoch_initiate() == EBPF_SUCCESS);
        epoch_initiated = true;
        REQUIRE(ebpf_object_tracking_initiate() == EBPF_SUCCESS);
        object_tracking_initiated = true;
        REQUIRE(ebpf_async_initiate() == EBPF_SUCCESS);
        async_initiated = true;
        REQUIRE(ebpf_state_initiate() == EBPF_SUCCESS);
        state_initiated = true;
    }
    ~_test_helper()
    {
        if (state_initiated) {
            ebpf_state_terminate();
        }
        if (async_initiated) {
            ebpf_async_terminate();
        }
        if (object_tracking_initiated) {
            ebpf_object_tracking_terminate();
        }
        if (epoch_initiated) {
            ebpf_epoch_synchronize();
            ebpf_epoch_terminate();
        }
        ebpf_random_terminate();
        if (platform_initiated) {
            ebpf_platform_terminate();
        }
    }

  private:
    bool platform_initiated = false;
    bool epoch_initiated = false;
    bool async_initiated = false;
    bool state_initiated = false;
    bool object_tracking_initiated = false;
};

struct ebpf_hash_table_destroyer_t
{
    void
    operator()(_In_opt_ _Post_invalid_ ebpf_hash_table_t* table)
    {
        ebpf_hash_table_destroy(table);
    }
};

using ebpf_hash_table_ptr = std::unique_ptr<ebpf_hash_table_t, ebpf_hash_table_destroyer_t>;

/**
 * @brief A RAII class to enter and exit epoch.
 */
typedef class _ebpf_epoch_scope
{
  public:
    /**
     * @brief Construct a new ebpf epoch scope object and enter epoch.
     */
    _ebpf_epoch_scope() : in_epoch(false) { enter(); }

    /**
     * @brief Leave epoch if entered.
     */
    ~_ebpf_epoch_scope()
    {
        if (in_epoch) {
            exit();
        }
    }

    /**
     * @brief Enter epoch.
     */
    void
    enter()
    {
        if (in_epoch) {
            throw std::runtime_error("Already in epoch.");
        }
        memset(&epoch_state, 0, sizeof(epoch_state));
        ebpf_epoch_enter(&epoch_state);
        in_epoch = true;
    }

    /**
     * @brief Exit epoch.
     */
    void
    exit()
    {
        if (!in_epoch) {
            throw std::runtime_error("Not in epoch.");
        }
        ebpf_epoch_exit(&epoch_state);
        in_epoch = false;
    }

  private:
    ebpf_epoch_state_t epoch_state;
    bool in_epoch;
} ebpf_epoch_scope_t;

TEST_CASE("hash_table_test", "[platform]")
{
    std::vector<uint8_t> key_1(13);
    std::vector<uint8_t> key_2(13);
    std::vector<uint8_t> key_3(13);
    std::vector<uint8_t> data_1(37);
    std::vector<uint8_t> data_2(37);
    std::vector<uint8_t> data_3(37);
    uint8_t* returned_value = nullptr;
    std::vector<uint8_t> returned_key(13);

    _test_helper test_helper;
    test_helper.initialize();

    for (auto& v : key_1) {
        v = static_cast<uint8_t>(ebpf_random_uint32());
    }
    for (auto& v : key_2) {
        v = static_cast<uint8_t>(ebpf_random_uint32());
    }
    for (auto& v : key_3) {
        v = static_cast<uint8_t>(ebpf_random_uint32());
    }
    for (auto& v : data_1) {
        v = static_cast<uint8_t>(ebpf_random_uint32());
    }
    for (auto& v : data_2) {
        v = static_cast<uint8_t>(ebpf_random_uint32());
    }
    for (auto& v : data_3) {
        v = static_cast<uint8_t>(ebpf_random_uint32());
    }

    const ebpf_hash_table_creation_options_t options = {
        .key_size = key_1.size(),
        .value_size = data_1.size(),
        .allocate = ebpf_allocate,
        .free = ebpf_free,
        .minimum_bucket_count = 1,
    };

    ebpf_hash_table_t* raw_ptr = nullptr;
    REQUIRE(ebpf_hash_table_create(&raw_ptr, &options) == EBPF_SUCCESS);
    ebpf_hash_table_ptr table(raw_ptr);

    // Insert first
    // Empty bucket case
    REQUIRE(
        ebpf_hash_table_update(table.get(), key_1.data(), data_1.data(), EBPF_HASH_TABLE_OPERATION_INSERT) ==
        EBPF_SUCCESS);
    REQUIRE(ebpf_hash_table_key_count(table.get()) == 1);

    // Insert second
    // Existing bucket, no backup.
    REQUIRE(
        ebpf_hash_table_update(table.get(), key_2.data(), data_2.data(), EBPF_HASH_TABLE_OPERATION_ANY) ==
        EBPF_SUCCESS);
    REQUIRE(ebpf_hash_table_key_count(table.get()) == 2);

    // Insert third
    // Existing bucket, with backup.
    REQUIRE(
        ebpf_hash_table_update(table.get(), key_3.data(), data_3.data(), EBPF_HASH_TABLE_OPERATION_ANY) ==
        EBPF_SUCCESS);
    REQUIRE(ebpf_hash_table_key_count(table.get()) == 3);

    // Iterate through all keys.
    uint64_t cookie = 0;
    uint8_t keys_found = 0;
    std::vector<const uint8_t*> keys;
    std::vector<const uint8_t*> values;
    size_t count = 2;
    keys.resize(count);
    values.resize(count);
    // Bucket contains 3 keys, but we only have space for 2.
    // Should fail with insufficient buffer.
    REQUIRE(
        ebpf_hash_table_iterate(table.get(), &cookie, &count, keys.data(), values.data()) == EBPF_INSUFFICIENT_BUFFER);
    REQUIRE(count == 3);
    keys.resize(count);
    values.resize(count);
    // Bucket contains 3 keys, and we have space for 3.
    // Should succeed.
    REQUIRE(ebpf_hash_table_iterate(table.get(), &cookie, &count, keys.data(), values.data()) == EBPF_SUCCESS);

    // Verify that all keys are found.
    for (size_t index = 0; index < 3; index++) {
        if (memcmp(keys[index], key_1.data(), key_1.size()) == 0) {
            REQUIRE(memcmp(values[index], data_1.data(), data_1.size()) == 0);
            keys_found |= 1 << 0;
        } else if (memcmp(keys[index], key_2.data(), key_2.size()) == 0) {
            REQUIRE(memcmp(values[index], data_2.data(), data_2.size()) == 0);
            keys_found |= 1 << 1;
        } else if (memcmp(keys[index], key_3.data(), key_3.size()) == 0) {
            REQUIRE(memcmp(values[index], data_3.data(), data_3.size()) == 0);
            keys_found |= 1 << 2;
        } else {
            REQUIRE(false);
        }
    }
    // Verify that there are no more keys.
    REQUIRE(ebpf_hash_table_iterate(table.get(), &cookie, &count, keys.data(), values.data()) == EBPF_NO_MORE_KEYS);
    REQUIRE(keys_found == 0x7);

    // Find the first
    REQUIRE(ebpf_hash_table_find(table.get(), key_1.data(), &returned_value) == EBPF_SUCCESS);
    REQUIRE(memcmp(returned_value, data_1.data(), data_1.size()) == 0);

    // Find the second
    REQUIRE(ebpf_hash_table_find(table.get(), key_2.data(), &returned_value) == EBPF_SUCCESS);
    REQUIRE(memcmp(returned_value, data_2.data(), data_2.size()) == 0);

    // Find the third
    REQUIRE(ebpf_hash_table_find(table.get(), key_2.data(), &returned_value) == EBPF_SUCCESS);
    REQUIRE(memcmp(returned_value, data_2.data(), data_2.size()) == 0);

    // Replace the second
    memset(data_2.data(), '0x55', data_2.size());
    REQUIRE(
        ebpf_hash_table_update(table.get(), key_2.data(), data_2.data(), EBPF_HASH_TABLE_OPERATION_REPLACE) ==
        EBPF_SUCCESS);
    REQUIRE(ebpf_hash_table_key_count(table.get()) == 3);

    // Find the first
    REQUIRE(ebpf_hash_table_find(table.get(), key_1.data(), &returned_value) == EBPF_SUCCESS);
    REQUIRE(memcmp(returned_value, data_1.data(), data_1.size()) == 0);

    // Next key
    REQUIRE(ebpf_hash_table_next_key(table.get(), nullptr, returned_key.data()) == EBPF_SUCCESS);
    REQUIRE(returned_key == key_1);

    REQUIRE(ebpf_hash_table_next_key(table.get(), returned_key.data(), returned_key.data()) == EBPF_SUCCESS);
    REQUIRE(returned_key == key_2);

    REQUIRE(ebpf_hash_table_next_key(table.get(), returned_key.data(), returned_key.data()) == EBPF_SUCCESS);
    REQUIRE(returned_key == key_3);

    REQUIRE(ebpf_hash_table_next_key(table.get(), returned_key.data(), returned_key.data()) == EBPF_NO_MORE_KEYS);
    REQUIRE(returned_key == key_3);

    // Delete middle key
    REQUIRE(ebpf_hash_table_delete(table.get(), key_2.data()) == EBPF_SUCCESS);
    REQUIRE(ebpf_hash_table_key_count(table.get()) == 2);

    // Delete not found
    REQUIRE(ebpf_hash_table_delete(table.get(), key_2.data()) == EBPF_KEY_NOT_FOUND);
    REQUIRE(ebpf_hash_table_key_count(table.get()) == 2);

    // Find not found
    REQUIRE(ebpf_hash_table_find(table.get(), key_2.data(), &returned_value) == EBPF_KEY_NOT_FOUND);

    // Delete first key
    REQUIRE(ebpf_hash_table_delete(table.get(), key_1.data()) == EBPF_SUCCESS);
    REQUIRE(ebpf_hash_table_key_count(table.get()) == 1);

    // Delete last key
    REQUIRE(ebpf_hash_table_delete(table.get(), key_3.data()) == EBPF_SUCCESS);
    REQUIRE(ebpf_hash_table_key_count(table.get()) == 0);
}

void
run_in_epoch(std::function<void()> function)
{
    ebpf_epoch_scope_t epoch_scope;
    function();
}

TEST_CASE("hash_table_stress_test", "[platform]")
{
    _test_helper test_helper;
    test_helper.initialize();

    ebpf_hash_table_t* table = nullptr;
    const size_t iterations = 1000;
    uint32_t worker_threads = ebpf_get_cpu_count();
    uint32_t key_count = 4;
    uint32_t load_factor = 4;
    int32_t cpu_id = 0;
    const ebpf_hash_table_creation_options_t options = {
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(uint64_t),
        .minimum_bucket_count = static_cast<size_t>(worker_threads) * static_cast<size_t>(key_count),
    };
    REQUIRE(ebpf_hash_table_create(&table, &options) == EBPF_SUCCESS);
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
                    (void)ebpf_hash_table_update(
                        table,
                        reinterpret_cast<const uint8_t*>(&key),
                        reinterpret_cast<const uint8_t*>(&value),
                        EBPF_HASH_TABLE_OPERATION_ANY);
                });
            }
            for (auto& key : keys) {
                run_in_epoch([&]() {
                    (void)ebpf_hash_table_find(
                        table, reinterpret_cast<const uint8_t*>(&key), reinterpret_cast<uint8_t**>(&returned_value));
                });
            }
            for (auto& key : keys) {
                run_in_epoch([&]() {
                    (void)ebpf_hash_table_next_key(
                        table, reinterpret_cast<const uint8_t*>(&key), reinterpret_cast<uint8_t*>(&next_key));
                });
            }

            for (auto& key : keys) {
                run_in_epoch([&]() { (void)ebpf_hash_table_delete(table, reinterpret_cast<const uint8_t*>(&key)); });
            }
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
    test_helper.initialize();

    typedef struct _some_object
    {
        ebpf_core_object_t object{};
        std::string name;
        bool finalized = true;
        signal_t signal;
        ebpf_result_t
        initialize()
        {
            ebpf_result_t return_value = EBPF_OBJECT_INITIALIZE(
                &object,
                EBPF_OBJECT_MAP,
                [](ebpf_core_object_t* object) {
                    auto some_object = reinterpret_cast<_some_object*>(object);
                    some_object->signal.signal();
                },
                NULL,
                NULL);
            if (return_value == EBPF_SUCCESS) {
                finalized = false;
            }
            return return_value;
        }

        void
        finalize()
        {
            if (!finalized) {
                EBPF_OBJECT_RELEASE_REFERENCE(&object);
                finalized = true;
            }
        }

        ~_some_object() { finalize(); }
    } some_object_t;

    some_object_t an_object;
    some_object_t another_object;
    some_object_t* some_object = nullptr;
    cxplat_utf8_string_t foo = CXPLAT_UTF8_STRING_FROM_CONST_STRING("foo");
    cxplat_utf8_string_t bar = CXPLAT_UTF8_STRING_FROM_CONST_STRING("bar");

    REQUIRE(an_object.initialize() == EBPF_SUCCESS);
    REQUIRE(another_object.initialize() == EBPF_SUCCESS);

    ebpf_pinning_table_ptr pinning_table;
    {
        ebpf_pinning_table_t* local_pinning_table = nullptr;
        REQUIRE(ebpf_pinning_table_allocate(&local_pinning_table) == EBPF_SUCCESS);
        pinning_table.reset(local_pinning_table);
    }

    REQUIRE(ebpf_pinning_table_insert(pinning_table.get(), &foo, &an_object.object) == EBPF_SUCCESS);
    REQUIRE(an_object.object.base.reference_count == 2);
    REQUIRE(ebpf_pinning_table_insert(pinning_table.get(), &bar, &another_object.object) == EBPF_SUCCESS);
    REQUIRE(another_object.object.base.reference_count == 2);
    REQUIRE(ebpf_pinning_table_find(pinning_table.get(), &foo, (ebpf_core_object_t**)&some_object) == EBPF_SUCCESS);
    REQUIRE(an_object.object.base.reference_count == 3);
    REQUIRE(some_object == &an_object);
    EBPF_OBJECT_RELEASE_REFERENCE(&some_object->object);
    REQUIRE(ebpf_pinning_table_delete(pinning_table.get(), &foo) == EBPF_SUCCESS);
    REQUIRE(another_object.object.base.reference_count == 2);

    ebpf_pinning_table_free(pinning_table.release());
    REQUIRE(an_object.object.base.reference_count == 1);
    REQUIRE(another_object.object.base.reference_count == 1);

    an_object.finalize();
    another_object.finalize();

    an_object.signal.wait();
    another_object.signal.wait();
}

TEST_CASE("epoch_test_single_epoch", "[platform]")
{
    _test_helper test_helper;
    test_helper.initialize();

    ebpf_epoch_scope_t epoch_scope;
    void* memory = ebpf_epoch_allocate(10);
    ebpf_epoch_free(memory);
    epoch_scope.exit();
    ebpf_epoch_synchronize();
}

TEST_CASE("epoch_test_two_threads", "[platform]")
{
    _test_helper test_helper;
    test_helper.initialize();

    auto epoch = []() {
        ebpf_epoch_scope_t epoch_scope;
        void* memory = ebpf_epoch_allocate(10);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        ebpf_epoch_free(memory);
        epoch_scope.exit();
        ebpf_epoch_synchronize();
    };

    std::thread thread_1(epoch);
    std::thread thread_2(epoch);
    thread_1.join();
    thread_2.join();
}

/**
 * @brief Verify that the stale item worker runs.
 * Epoch free can leave items on a CPU's free list until the next epoch exit.
 * To avoid holding onto freed items indefinitely, epoch schedules a work item
 * to call epoch_enter/epoch_exit on a CPU to releasing the free list.
 */
TEST_CASE("epoch_test_stale_items", "[platform]")
{
    _test_helper test_helper;
    test_helper.initialize();
    _signal signal_1;
    _signal signal_2;

    if (ebpf_get_cpu_count() < 2) {
        return;
    }

    size_t const test_iterations = 100;
    for (size_t test_iteration = 0; test_iteration < test_iterations; test_iteration++) {

        auto t1 = [&]() {
            uintptr_t old_thread_affinity;
            ebpf_assert_success(ebpf_set_current_thread_affinity(1, &old_thread_affinity));
            ebpf_epoch_scope_t epoch_scope;
            void* memory = ebpf_epoch_allocate(10);
            signal_2.signal();
            signal_1.wait();
            ebpf_epoch_free(memory);
            epoch_scope.exit();
        };
        auto t2 = [&]() {
            uintptr_t old_thread_affinity;
            ebpf_assert_success(ebpf_set_current_thread_affinity(2, &old_thread_affinity));
            signal_2.wait();
            ebpf_epoch_scope_t epoch_scope;
            void* memory = ebpf_epoch_allocate(10);
            ebpf_epoch_free(memory);
            epoch_scope.exit();
            signal_1.signal();
        };

        std::thread thread_1(t1);
        std::thread thread_2(t2);

        thread_1.join();
        thread_2.join();
        for (size_t retry = 0; retry < 100; retry++) {
            if (ebpf_epoch_is_free_list_empty(0) && ebpf_epoch_is_free_list_empty(1)) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        REQUIRE(ebpf_epoch_is_free_list_empty(0));
        REQUIRE(ebpf_epoch_is_free_list_empty(1));
    }
}

static auto provider_function = []() { return EBPF_SUCCESS; };

TEST_CASE("trampoline_test", "[platform]")
{
    _test_helper test_helper;
    test_helper.initialize();

    ebpf_trampoline_table_ptr table;
    ebpf_result_t (*test_function)();
    auto provider_function1 = []() { return EBPF_SUCCESS; };
    ebpf_result_t (*function_pointer1)() = provider_function1;
    const void* helper_functions1[] = {(void*)function_pointer1};
    const uint32_t provider_helper_function_ids[] = {(uint32_t)(EBPF_MAX_GENERAL_HELPER_FUNCTION + 1)};
    ebpf_helper_function_addresses_t helper_function_addresses1 = {
        {EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION, EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION_SIZE},
        EBPF_COUNT_OF(helper_functions1),
        (uint64_t*)helper_functions1};

    auto provider_function2 = []() { return EBPF_OBJECT_ALREADY_EXISTS; };
    ebpf_result_t (*function_pointer2)() = provider_function2;
    const void* helper_functions2[] = {(void*)function_pointer2};
    ebpf_helper_function_addresses_t helper_function_addresses2 = {
        {EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION, EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION_SIZE},
        EBPF_COUNT_OF(helper_functions1),
        (uint64_t*)helper_functions2};
    ebpf_trampoline_table_t* local_table = nullptr;

    REQUIRE(ebpf_allocate_trampoline_table(1, &local_table) == EBPF_SUCCESS);
    table.reset(local_table);

    REQUIRE(
        ebpf_update_trampoline_table(
            table.get(),
            EBPF_COUNT_OF(provider_helper_function_ids),
            provider_helper_function_ids,
            &helper_function_addresses1) == EBPF_SUCCESS);
    REQUIRE(
        ebpf_get_trampoline_function(
            table.get(), EBPF_MAX_GENERAL_HELPER_FUNCTION + 1, reinterpret_cast<void**>(&test_function)) ==
        EBPF_SUCCESS);

    // Verify that the trampoline function invokes the provider function.
    REQUIRE(test_function() == EBPF_SUCCESS);

    REQUIRE(
        ebpf_update_trampoline_table(
            table.get(),
            EBPF_COUNT_OF(provider_helper_function_ids),
            provider_helper_function_ids,
            &helper_function_addresses2) == EBPF_SUCCESS);

    // Verify that the trampoline function now invokes the new provider function.
    REQUIRE(test_function() == EBPF_OBJECT_ALREADY_EXISTS);
    ebpf_free_trampoline_table(table.release());
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
    test_helper.initialize();
    ebpf_security_generic_mapping_ptr sd_ptr;
    ebpf_security_descriptor_t* sd = NULL;
    unsigned long sd_size = 0;
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
    operator()(_Frees_ptr_opt_ MDL* p)
    {
        ebpf_unmap_memory(p);
    }
};
typedef std::unique_ptr<MDL, ebpf_memory_descriptor_t_free> ebpf_memory_descriptor_ptr;

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
    test_helper.initialize();

    const int map_count = 10;
    ebpf_map_info_internal_t internal_map_info_array[map_count] = {};
    std::string pin_path_prefix = "\\ebpf\\map\\";
    std::vector<std::string> pin_paths;
    size_t buffer_length = 0;
    size_t required_length;
    size_t serialized_length;
    ebpf_map_info_t* map_info_array;
    ebpf_memory_t unique_buffer;

    // Construct the array of ebpf_map_info_internal_t to be serialized.
    for (int i = 0; i < map_count; i++) {
        pin_paths.push_back(pin_path_prefix + std::to_string(i));
    }

    for (int i = 0; i < map_count; i++) {
        ebpf_map_info_internal_t* map_info = &internal_map_info_array[i];
        map_info->definition.type = static_cast<ebpf_map_type_t>(i % (BPF_MAP_TYPE_ARRAY + 1));
        map_info->definition.key_size = i + 1;
        map_info->definition.value_size = (i + 1) * (i + 1);
        map_info->definition.max_entries = (i + 1) * 128;

        map_info->pin_path.length = pin_paths[i].size();
        map_info->pin_path.value = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(pin_paths[i].c_str()));
    }

    // Serialize.
    REQUIRE(
        ebpf_serialize_internal_map_info_array(
            map_count, internal_map_info_array, nullptr, buffer_length, &serialized_length, &required_length) ==
        EBPF_INSUFFICIENT_BUFFER);

    {
        uint8_t* buffer = static_cast<uint8_t*>(ebpf_allocate(required_length));
        if (buffer == nullptr) {
            REQUIRE(false);
        }
        unique_buffer.reset(buffer);
    }
    buffer_length = required_length;

    REQUIRE(
        ebpf_serialize_internal_map_info_array(
            map_count,
            internal_map_info_array,
            unique_buffer.get(),
            buffer_length,
            &serialized_length,
            &required_length) == EBPF_SUCCESS);

    // Deserialize.
    REQUIRE(
        ebpf_deserialize_map_info_array(serialized_length, unique_buffer.get(), map_count, &map_info_array) ==
        EBPF_SUCCESS);
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
}

TEST_CASE("serialize_program_info_test", "[platform]")
{
    _test_helper test_helper;
    test_helper.initialize();

    ebpf_helper_function_prototype_t helper_prototype[] = {
        {{EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION, EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION_SIZE},
         1000,
         "helper_0",
         EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
         {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY}},
        {{EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION, EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION_SIZE},
         1001,
         "helper_1",
         EBPF_RETURN_TYPE_INTEGER,
         {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE}}};
    // The values of the fields in the context_descriptor variable are completely arbitrary
    // and have no effect on the test.
    ebpf_context_descriptor_t context_descriptor = {32, 0, 8, -1};
    GUID program_type_test = {0x7ebe418c, 0x76dd, 0x4c2c, {0x99, 0xbc, 0x5c, 0x48, 0xa2, 0x30, 0x4b, 0x90}};
    ebpf_program_type_descriptor_t program_type = {
        {EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION, EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION_SIZE},
        "unit_test_program",
        &context_descriptor,
        program_type_test};
    ebpf_program_info_t in_program_info = {
        {EBPF_PROGRAM_INFORMATION_CURRENT_VERSION, EBPF_PROGRAM_INFORMATION_CURRENT_VERSION_SIZE},
        &program_type,
        EBPF_COUNT_OF(helper_prototype),
        helper_prototype};

    size_t buffer_length = 0;
    size_t required_length;
    size_t serialized_length;
    ebpf_memory_t unique_buffer;

    ebpf_program_info_t* out_program_info;

    // Serialize.
    REQUIRE(
        ebpf_serialize_program_info(&in_program_info, nullptr, buffer_length, &serialized_length, &required_length));

    {
        uint8_t* buffer = static_cast<uint8_t*>(ebpf_allocate(required_length));
        if (buffer == nullptr) {
            REQUIRE(false);
        }
        unique_buffer.reset(buffer);
    }
    buffer_length = required_length;

    REQUIRE(
        ebpf_serialize_program_info(
            &in_program_info, unique_buffer.get(), buffer_length, &serialized_length, &required_length) ==
        EBPF_SUCCESS);

    // Deserialize.
    REQUIRE(ebpf_deserialize_program_info(serialized_length, unique_buffer.get(), &out_program_info) == EBPF_SUCCESS);

    // Verify de-serialized program info matches input.
    REQUIRE(in_program_info.program_type_descriptor != nullptr);
    REQUIRE(
        in_program_info.program_type_descriptor->program_type ==
        out_program_info->program_type_descriptor->program_type);
    REQUIRE(
        in_program_info.program_type_descriptor->is_privileged ==
        out_program_info->program_type_descriptor->is_privileged);
    REQUIRE(in_program_info.program_type_descriptor->context_descriptor != nullptr);
    REQUIRE(
        memcmp(
            in_program_info.program_type_descriptor->context_descriptor,
            out_program_info->program_type_descriptor->context_descriptor,
            sizeof(ebpf_context_descriptor_t)) == 0);
    REQUIRE(
        strncmp(
            in_program_info.program_type_descriptor->name,
            out_program_info->program_type_descriptor->name,
            EBPF_MAX_PROGRAM_DESCRIPTOR_NAME_LENGTH) == 0);
    REQUIRE(
        in_program_info.count_of_program_type_specific_helpers ==
        out_program_info->count_of_program_type_specific_helpers);
    REQUIRE(out_program_info->program_type_specific_helper_prototype != nullptr);
    for (uint32_t i = 0; i < in_program_info.count_of_program_type_specific_helpers; i++) {
        const ebpf_helper_function_prototype_t* in_prototype =
            &in_program_info.program_type_specific_helper_prototype[i];
        const ebpf_helper_function_prototype_t* out_prototype =
            &out_program_info->program_type_specific_helper_prototype[i];
        REQUIRE(in_prototype->helper_id == out_prototype->helper_id);
        REQUIRE(in_prototype->return_type == out_prototype->return_type);
        for (int j = 0; j < _countof(in_prototype->arguments); j++) {
            REQUIRE(in_prototype->arguments[j] == out_prototype->arguments[j]);
        }
        REQUIRE(out_prototype->name != nullptr);
        REQUIRE(strncmp(in_prototype->name, out_prototype->name, EBPF_MAX_HELPER_FUNCTION_NAME_LENGTH) == 0);
    }

    // Free de-serialized program info.
    ebpf_program_info_free(out_program_info);
}

TEST_CASE("state_test", "[state]")
{
    _test_helper test_helper;
    test_helper.initialize();
    size_t allocated_index_1 = 0;
    size_t allocated_index_2 = 0;
    struct
    {
        uint32_t some_value;
    } foo;
    uintptr_t retrieved_value = 0;
    REQUIRE(ebpf_state_allocate_index(&allocated_index_1) == EBPF_SUCCESS);
    REQUIRE(ebpf_state_allocate_index(&allocated_index_2) == EBPF_SUCCESS);
    REQUIRE(allocated_index_2 != allocated_index_1);
    ebpf_execution_context_state_t state{};
    ebpf_get_execution_context_state(&state);
    REQUIRE(ebpf_state_store(allocated_index_1, reinterpret_cast<uintptr_t>(&foo), &state) == EBPF_SUCCESS);
    REQUIRE(ebpf_state_load(allocated_index_1, &retrieved_value) == EBPF_SUCCESS);
    REQUIRE(retrieved_value == reinterpret_cast<uintptr_t>(&foo));
}

template <size_t bit_count, bool interlocked>
void
bitmap_test()
{
    std::vector<uint8_t> data(ebpf_bitmap_size(bit_count));

    ebpf_bitmap_t* bitmap = reinterpret_cast<ebpf_bitmap_t*>(data.data());
    ebpf_bitmap_initialize(bitmap, bit_count);

    // Set every bit.
    for (size_t i = 0; i < bit_count; i++) {
        ebpf_bitmap_set_bit(bitmap, i, interlocked);
    }

    // Clear odd bits.
    for (size_t i = 1; i < bit_count; i += 2) {
        ebpf_bitmap_reset_bit(bitmap, i, interlocked);
    }

    // Verify every even bit is set via ebpf_bitmap_test_bit.
    for (size_t i = 0; i < bit_count; i += 2) {
        REQUIRE(ebpf_bitmap_test_bit(bitmap, i));
    }

    // Verify every even bit is set via ebpf_bitmap_forward_search_next_bit.
    ebpf_bitmap_cursor_t cursor;
    ebpf_bitmap_start_forward_search(bitmap, &cursor);

    for (size_t i = 0; i < bit_count; i += 2) {
        REQUIRE(ebpf_bitmap_forward_search_next_bit(&cursor) == i);
    }
    REQUIRE(ebpf_bitmap_forward_search_next_bit(&cursor) == MAXSIZE_T);

    ebpf_bitmap_start_reverse_search(bitmap, &cursor);
    for (size_t i = 0; i < bit_count; i += 2) {
        REQUIRE(ebpf_bitmap_reverse_search_next_bit(&cursor) == bit_count - i - 1);
    }
    REQUIRE(ebpf_bitmap_reverse_search_next_bit(&cursor) == MAXSIZE_T);
}

#define BIT_MASK_TEST(X, Y) \
    TEST_CASE("bitmap_test:" #X, "[platform]") { bitmap_test<X, Y>(); }

BIT_MASK_TEST(33, true);
BIT_MASK_TEST(65, false);
BIT_MASK_TEST(129, true);
BIT_MASK_TEST(1025, false);

TEST_CASE("async", "[platform]")
{
    _test_helper test_helper;
    test_helper.initialize();

    auto test = [](bool complete) {
        ebpf_epoch_scope_t epoch_scope;
        struct _async_context
        {
            ebpf_result_t result;
        } async_context = {EBPF_PENDING};

        struct _cancellation_context
        {
            bool canceled;
        } cancellation_context = {false};

        REQUIRE(
            ebpf_async_set_completion_callback(
                &async_context, [](_Inout_ void* context, size_t output_buffer_length, ebpf_result_t result) {
                    UNREFERENCED_PARAMETER(output_buffer_length);
                    auto async_context = reinterpret_cast<_async_context*>(context);
                    async_context->result = result;
                }) == EBPF_SUCCESS);

        REQUIRE(ebpf_async_set_cancel_callback(&async_context, &cancellation_context, [](void* context) {
                    auto cancellation_context = reinterpret_cast<_cancellation_context*>(context);
                    cancellation_context->canceled = true;
                }) == EBPF_SUCCESS);
        REQUIRE(async_context.result == EBPF_PENDING);
        REQUIRE(!cancellation_context.canceled);

        if (complete) {
            ebpf_async_complete(&async_context, 0, EBPF_SUCCESS);
            REQUIRE(async_context.result == EBPF_SUCCESS);
            REQUIRE(!cancellation_context.canceled);
            REQUIRE(!ebpf_async_cancel(&async_context));
        } else {
            REQUIRE(ebpf_async_cancel(&async_context));
            REQUIRE(async_context.result == EBPF_PENDING);
            REQUIRE(cancellation_context.canceled);
            ebpf_async_complete(&async_context, 0, EBPF_SUCCESS);
        }
    };

    // Run the test with complete before cancel.
    test(true);

    // Run the test with cancel before complete.
    test(false);
}

TEST_CASE("ring_buffer_output", "[platform]")
{
    _test_helper test_helper;
    test_helper.initialize();
    size_t consumer;
    size_t producer;
    ebpf_ring_buffer_t* ring_buffer;

    uint8_t* buffer;
    std::vector<uint8_t> data(10);
    size_t size = 64 * 1024;

    REQUIRE(ebpf_ring_buffer_create(&ring_buffer, size) == EBPF_SUCCESS);
    REQUIRE(ebpf_ring_buffer_map_buffer(ring_buffer, &buffer) == EBPF_SUCCESS);

    ebpf_ring_buffer_query(ring_buffer, &consumer, &producer);

    // Ring is empty
    REQUIRE(producer == consumer);
    REQUIRE(consumer == 0);

    REQUIRE(ebpf_ring_buffer_output(ring_buffer, data.data(), data.size()) == EBPF_SUCCESS);
    ebpf_ring_buffer_query(ring_buffer, &consumer, &producer);

    // Ring is not empty
    REQUIRE(producer != consumer);
    REQUIRE(producer == data.size() + EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data));
    REQUIRE(consumer == 0);

    auto record = ebpf_ring_buffer_next_record(buffer, size, consumer, producer);
    REQUIRE(record != nullptr);
    REQUIRE(record->header.length == data.size() + EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data));

    REQUIRE(ebpf_ring_buffer_return(ring_buffer, record->header.length) == EBPF_SUCCESS);
    ebpf_ring_buffer_query(ring_buffer, &consumer, &producer);

    record = ebpf_ring_buffer_next_record(buffer, size, consumer, producer);
    REQUIRE(record == nullptr);
    REQUIRE(consumer == producer);
    REQUIRE(producer == data.size() + EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data));
    REQUIRE(consumer == data.size() + EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data));

    data.resize(1023);
    while (ebpf_ring_buffer_output(ring_buffer, data.data(), data.size()) == EBPF_SUCCESS) {
    }

    ebpf_ring_buffer_query(ring_buffer, &consumer, &producer);
    REQUIRE(ebpf_ring_buffer_return(ring_buffer, (producer - consumer) % size) == EBPF_SUCCESS);

    data.resize(size - EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data) - 1);
    // Fill ring
    REQUIRE(ebpf_ring_buffer_output(ring_buffer, data.data(), data.size()) == EBPF_SUCCESS);

    ebpf_ring_buffer_destroy(ring_buffer);
    ring_buffer = nullptr;
}

TEST_CASE("ring_buffer_reserve_submit_discard", "[platform]")
{
    _test_helper test_helper;
    test_helper.initialize();
    size_t consumer;
    size_t producer;
    ebpf_ring_buffer_t* ring_buffer;

    uint8_t* buffer;
    std::vector<uint8_t> data(10);
    size_t size = 64 * 1024;

    REQUIRE(ebpf_ring_buffer_create(&ring_buffer, size) == EBPF_SUCCESS);
    REQUIRE(ebpf_ring_buffer_map_buffer(ring_buffer, &buffer) == EBPF_SUCCESS);

    ebpf_ring_buffer_query(ring_buffer, &consumer, &producer);

    // Ring is empty.
    REQUIRE(producer == consumer);
    REQUIRE(consumer == 0);

    uint8_t* mem1 = nullptr;
    REQUIRE(ebpf_ring_buffer_reserve(ring_buffer, &mem1, 10) == EBPF_SUCCESS);
    REQUIRE(mem1 != nullptr);
    // Wrapping ebpf_ring_buffer_submit in a REQUIRE macro causes code analysis
    // to fail with error warning C6001: Using uninitialized memory 'mem1'.
    ebpf_result_t result = ebpf_ring_buffer_submit(mem1);
    // Workaround for code analysis failure:
    // C28193: 'result' holds a value that must be examined.
    if (result != EBPF_SUCCESS) {
        REQUIRE(result == EBPF_SUCCESS);
    }

    uint8_t* mem2 = nullptr;
    REQUIRE(ebpf_ring_buffer_reserve(ring_buffer, &mem2, 10) == EBPF_SUCCESS);
    REQUIRE(mem2 != nullptr);
    // Wrapping ebpf_ring_buffer_submit in a REQUIRE macro causes code analysis
    // to fail with error warning C6001: Using uninitialized memory 'mem1'.
    result = ebpf_ring_buffer_discard(mem2);
    // Workaround for code analysis failure:
    // C28193: 'result' holds a value that must be examined.
    if (result != EBPF_SUCCESS) {
        REQUIRE(result == EBPF_SUCCESS);
    }

    uint8_t* mem3 = nullptr;
    REQUIRE(ebpf_ring_buffer_reserve(ring_buffer, &mem3, size + 1) == EBPF_INVALID_ARGUMENT);

    ebpf_ring_buffer_query(ring_buffer, &consumer, &producer);

    // Ring is not empty.
    REQUIRE(producer != consumer);
    REQUIRE(consumer == 0);

    ebpf_ring_buffer_destroy(ring_buffer);
    ring_buffer = nullptr;
}

TEST_CASE("error codes", "[platform]")
{
    for (ebpf_result_t result = EBPF_SUCCESS; result < EBPF_RESULT_COUNT; result = (ebpf_result_t)(result + 1)) {
        uint32_t error = ebpf_result_to_win32_error_code(result);
        ebpf_result_t result2 = win32_error_code_to_ebpf_result(error);
        REQUIRE(result2 == result);
    }
}

TEST_CASE("interlocked operations", "[platform]")
{
    volatile int32_t value32 = 0;
    ebpf_interlocked_or_int32(&value32, 0xffff);
    REQUIRE(value32 == 0xffff);
    ebpf_interlocked_and_int32(&value32, 0xff);
    REQUIRE(value32 == 0xff);
    ebpf_interlocked_xor_int32(&value32, 0xff);
    REQUIRE(value32 == 0);
    volatile int64_t value64 = 0;
    ebpf_interlocked_or_int64(&value64, 0xffff);
    REQUIRE(value64 == 0xffff);
    ebpf_interlocked_and_int64(&value64, 0xff);
    REQUIRE(value64 == 0xff);
    ebpf_interlocked_xor_int64(&value64, 0xff);
    REQUIRE(value64 == 0);

    value32 = 1;
    REQUIRE(ebpf_interlocked_compare_exchange_int32(&value32, 2, 1) == 1);
    REQUIRE(ebpf_interlocked_compare_exchange_int32(&value32, 2, 1) == 2);

    int a = 0;
    int b = 0;
    void* p = &a;
    REQUIRE(ebpf_interlocked_compare_exchange_pointer(&p, &b, &a) == &a);
    REQUIRE(ebpf_interlocked_compare_exchange_pointer(&p, &b, &a) == &b);
}

TEST_CASE("get_authentication_id", "[platform]")
{
    _test_helper test_helper;
    test_helper.initialize();
    uint64_t authentication_id = 0;

    REQUIRE(ebpf_platform_get_authentication_id(&authentication_id) == EBPF_SUCCESS);
}

// ISSUE: https://github.com/microsoft/ebpf-for-windows/issues/2958
// Replace these test with a more robust test like TESTU01 or PractRand once licensing issues are resolved.

#define SEQUENCE_LENGTH 1024 * 128
#define CHI_SQUARED_STATISTIC_THRESHOLD \
    9.210 // Critical value for Chi-squared test with 2 degrees of freedom with significance level of 0.01.

/**
 * @brief Verify that the random number generator passes the chi-squared test.
 *
 * @param[in] sequence_length The number of random numbers to generate.
 * @param[in] random_number_generator The random number generator.
 * @return true The random number generator passes the chi-squared test.
 * @return false The random number generator fails the chi-squared test.
 */
bool
passes_chi_squared_test(size_t sequence_length, std::function<uint32_t()> random_number_generator)
{
    // Hypothesis is that the random number generator produces a uniform distribution.
    // There are two degrees of freedom: 0 and 1 for each bit in the random number.
    // The expected population count for each degree of freedom is half the sequence length.
    // The critical value for a chi-squared test with 2 degrees of freedom and a significance level of 0.05 is 3.841.
    // See https://en.wikipedia.org/wiki/Chi-squared_test for details.
    // The chi-squared statistic is the sum of the squared difference between the observed and expected values
    // divided by the expected value. If the chi-squared statistic is less than the critical value, the hypothesis
    // is accepted.

    double zero_count = 0;
    double one_count = 0;
    double expected_value = static_cast<double>(sequence_length) * sizeof(uint32_t) * 8 / 2;

    // Treat each bit in the random number as degree of freedom.
    for (size_t i = 0; i < sequence_length; i++) {
        unsigned long value = static_cast<int>(random_number_generator());
        size_t bit_count = __popcnt(value);
        zero_count += static_cast<double>(32 - bit_count);
        one_count += static_cast<double>(bit_count);
    }

    double chi_squared_statistic = std::pow(zero_count - expected_value, 2) / expected_value;
    chi_squared_statistic += std::pow(one_count - expected_value, 2) / expected_value;

    std::cout << "Zero count: " << zero_count << std::endl;
    std::cout << "One count: " << one_count << std::endl;

    // Weaken the test due to the fact that the random number generator is not perfect.
    double critical_value = CHI_SQUARED_STATISTIC_THRESHOLD * 2;
    std::cout << chi_squared_statistic << std::endl;
    return chi_squared_statistic < critical_value;
}

/**
 * @brief Determine if the provided random number generator has a dominant frequency in its output.
 *
 * @param[in] sequence_length The number of random numbers to examine. Must be a power of 2.
 * @param[in] random_number_generator The random number generator.
 * @return true The highest frequency in the random number generator's output is more than 6 standard deviations from
 * the mean.
 * @return false The highest frequency in the random number generator's output is less than 6 standard deviations from
 * the mean.
 */
bool
has_dominant_frequency(size_t sequence_length, std::function<uint32_t()> random_number_generator)
{
    kissfft<double> fft(sequence_length, false);

    std::vector<kissfft<double>::cpx_t> test_values;

    for (size_t k = 0; k < sequence_length / (sizeof(uint32_t) * 8); k++) {
        uint32_t r = random_number_generator();
        for (size_t i = 0; i < sizeof(uint32_t) * 8; i++) {
            test_values.push_back((r & (1 << i)) ? 1.0 : -1.0);
        }
    }
    std::vector<kissfft<double>::cpx_t> output_values(sequence_length);

    fft.transform(test_values.data(), output_values.data());

    std::vector<std::pair<double, size_t>> frequencies;
    for (size_t i = 0; i < sequence_length; i++) {
        frequencies.push_back({std::abs(output_values[i]), i});
    }

    std::sort(frequencies.begin(), frequencies.end(), [](std::pair<double, size_t> a, std::pair<double, size_t> b) {
        return a.first > b.first;
    });

    kissfft<double>::cpx_t c;

    auto max_frequency = *std::max_element(
        output_values.begin(), output_values.end(), [](kissfft<double>::cpx_t a, kissfft<double>::cpx_t b) {
            return std::abs(a) < std::abs(b);
        });

    auto average_frequency = std::abs(std::accumulate(
                                 output_values.begin(),
                                 output_values.end(),
                                 0.0,
                                 [](double a, kissfft<double>::cpx_t b) { return a + std::abs(b); })) /
                             sequence_length;

    auto std_dev_frequency = std::sqrt(
        std::accumulate(
            output_values.begin(),
            output_values.end(),
            0.0,
            [&](double a, kissfft<double>::cpx_t b) { return a + std::pow(std::abs(b) - average_frequency, 2); }) /
        sequence_length);

    std::cout << "Average frequency: " << average_frequency << std::endl;
    std::cout << "Std dev frequency: " << std_dev_frequency << std::endl;
    std::cout << "Max frequency: " << std::abs(max_frequency) << std::endl;
    std::cout << "Ratio of (max-average) to std:dev: "
              << (std::abs(max_frequency) - average_frequency) / std_dev_frequency << ":1" << std::endl;
    return (std::abs(max_frequency) - average_frequency) > 10 * std_dev_frequency;
}

class _raise_irql_to_dpc_helper
{
  public:
    _raise_irql_to_dpc_helper() { old_irql = KeRaiseIrqlToDpcLevel(); }
    ~_raise_irql_to_dpc_helper() { KeLowerIrql(old_irql); }

  private:
    KIRQL old_irql{0};
};

TEST_CASE("verify random", "[platform]")
{
    _test_helper test_helper;
    test_helper.initialize();

    _raise_irql_to_dpc_helper irql_helper;

    bool odd = false;
    std::function<uint32_t()> ebpf_random_uint32_biased = [&odd]() {
        uint32_t value = ebpf_random_uint32();
        if (odd) {
            value |= 1;
        } else {
            value &= ~1;
        }
        odd = !odd;

        return value;
    };

    std::cout << "ebpf_random_uint32" << std::endl;
    // Verify that the random number generators pass the chi-squared test.
    REQUIRE(passes_chi_squared_test(SEQUENCE_LENGTH, ebpf_random_uint32));

    // Verify that the random number generators do not have a dominant frequency.
    std::cout << "ebpf_random_uint32" << std::endl;
    REQUIRE(!has_dominant_frequency(SEQUENCE_LENGTH, ebpf_random_uint32));

    // Verify that has_dominant_frequency fails for the biased random number generator.
    std::cout << "ebpf_random_uint32_biased" << std::endl;
    REQUIRE(has_dominant_frequency(SEQUENCE_LENGTH, ebpf_random_uint32_biased));

    // Dump a thousand bits from the random number generator for visual inspection.
    std::cout << "ebpf_random_uint32" << std::endl;
    for (size_t mask = 0; mask < 32; mask++) {
        for (size_t i = 0; i < 1000; i++) {
            uint32_t value = ebpf_random_uint32();
            uint32_t test_mask = 1 << mask;
            if ((value & test_mask) != 0) {
                std::cout << "1";
            } else {
                std::cout << "0";
            }
            if (i % 40 == 39)
                std::cout << std::endl;
        }
        std::cout << std::endl;
    }
}

TEST_CASE("work_queue", "[platform]")
{
    _test_helper test_helper;
    test_helper.initialize();
    struct _work_item_context
    {
        LIST_ENTRY list_entry;
        KEVENT completion_event;
    } work_item_context;

    ebpf_list_initialize(&work_item_context.list_entry);

    KeInitializeEvent(&work_item_context.completion_event, NotificationEvent, FALSE);

    ebpf_timed_work_queue_t* work_queue;
    LARGE_INTEGER interval;

    interval.QuadPart = 10 * 1000 * 100; // 100ms
    int context = 1;
    REQUIRE(
        ebpf_timed_work_queue_create(
            &work_queue,
            0,
            &interval,
            [](_Inout_ void* context, uint32_t cpu_id, _Inout_ ebpf_list_entry_t* entry) {
                UNREFERENCED_PARAMETER(context);
                UNREFERENCED_PARAMETER(cpu_id);
                auto work_item_context = reinterpret_cast<_work_item_context*>(entry);
                KeSetEvent(&work_item_context->completion_event, 0, FALSE);
            },
            &context) == EBPF_SUCCESS);

    // Unique ptr that will call ebpf_timed_work_queue_destroy when it goes out of scope.
    std::unique_ptr<ebpf_timed_work_queue_t, decltype(&ebpf_timed_work_queue_destroy)> work_queue_ptr(
        work_queue, &ebpf_timed_work_queue_destroy);

    // Queue a work item without flush.
    ebpf_timed_work_queue_insert(work_queue, &work_item_context.list_entry, EBPF_WORK_QUEUE_WAKEUP_ON_TIMER);

    LARGE_INTEGER timeout = {0};

    // Verify that the work item is not signaled immediately.
    REQUIRE(
        KeWaitForSingleObject(&work_item_context.completion_event, Executive, KernelMode, FALSE, &timeout) ==
        STATUS_TIMEOUT);

    // Verify the queue is not empty.
    REQUIRE(ebpf_timed_work_queue_is_empty(work_queue) == false);

    timeout.QuadPart = -10 * 1000 * 1000; // 1s

    // Verify that the work item is signaled after 100ms.
    REQUIRE(
        KeWaitForSingleObject(&work_item_context.completion_event, Executive, KernelMode, FALSE, &timeout) ==
        STATUS_SUCCESS);

    // Queue a work item with flush.
    ebpf_timed_work_queue_insert(work_queue, &work_item_context.list_entry, EBPF_WORK_QUEUE_WAKEUP_ON_INSERT);

    // Wait for active DPCs to complete.
    KeFlushQueuedDpcs();

    // Verify the queue is now empty.
    REQUIRE(ebpf_timed_work_queue_is_empty(work_queue) == true);

    // Queue a work item without flush.
    ebpf_timed_work_queue_insert(work_queue, &work_item_context.list_entry, EBPF_WORK_QUEUE_WAKEUP_ON_TIMER);

    // Verify the queue is not empty.
    REQUIRE(ebpf_timed_work_queue_is_empty(work_queue) == false);

    // Process the work queue.
    ebpf_timed_work_queued_flush(work_queue);

    // Verify the queue is now empty.
    REQUIRE(ebpf_timed_work_queue_is_empty(work_queue) == true);
}
