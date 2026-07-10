// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "native_helper.hpp"
#include "netsh_test_helper.h"
#include "program_helper.h"
#include "sample_ext_app.h"
#include "sample_ext_helper.h"
#include "service_helper.h"
#include "watchdog.h"

#include <chrono>
#include <mutex>
#include <thread>

CATCH_REGISTER_LISTENER(_watchdog)

#define SAMPLE_PATH ""

#define EBPF_CORE_DRIVER_BINARY_NAME L"ebpfcore.sys"
#define EBPF_CORE_DRIVER_NAME L"ebpfcore"

#define EBPF_EXTENSION_DRIVER_BINARY_NAME L"sample_ebpf_ext.sys"

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
#define EBPF_SERVICE_BINARY_NAME L"ebpfsvc.exe"
#define EBPF_SERVICE_NAME L"ebpfsvc"
#endif

static service_install_helper
    _ebpf_core_driver_helper(EBPF_CORE_DRIVER_NAME, EBPF_CORE_DRIVER_BINARY_NAME, SERVICE_KERNEL_DRIVER);

static service_install_helper
    _ebpf_extension_driver_helper(SAMPLE_EBPF_EXT_NAME_W, EBPF_EXTENSION_DRIVER_BINARY_NAME, SERVICE_KERNEL_DRIVER);

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
static service_install_helper
    _ebpf_service_helper(EBPF_SERVICE_NAME, EBPF_SERVICE_BINARY_NAME, SERVICE_WIN32_OWN_PROCESS);
#endif

void
sample_ebpf_ext_test(_In_ const struct bpf_object* object)
{
    struct bpf_map* map = nullptr;
    fd_t map_fd;
    const char* strings[] = {"rainy", "sunny"};
    std::vector<std::vector<char>> map_entry_buffers(EBPF_COUNT_OF(strings), std::vector<char>(32));
    const char* input_string = "Seattle is a rainy city";
    std::vector<char> input_buffer(input_string, input_string + strlen(input_string));
    const char* expected_output = "Seattle is a sunny city";
    std::vector<char> output_buffer(256);
    _sample_extension_helper extension;

    // Get map and insert data.
    map = bpf_object__find_map_by_name(object, "test_map");
    REQUIRE(map != nullptr);
    map_fd = bpf_map__fd(map);
    REQUIRE(map_fd > 0);

    for (uint32_t key = 0; key < EBPF_COUNT_OF(strings); key++) {
        std::copy(strings[key], strings[key] + strlen(strings[key]), map_entry_buffers[key].begin());
        REQUIRE(bpf_map_update_elem(map_fd, &key, map_entry_buffers[key].data(), EBPF_ANY) == EBPF_SUCCESS);
    }

    extension.invoke(input_buffer, output_buffer);

    REQUIRE(memcmp(output_buffer.data(), expected_output, strlen(expected_output)) == 0);
}

void
sample_ebpf_ext_test_prog_test_run(_In_ const struct bpf_object* object)
{
    struct bpf_map* map = nullptr;
    fd_t map_fd;
    fd_t program_fd;
    struct bpf_program* program = nullptr;
    const char* strings[] = {"rainy", "sunny"};
    std::vector<std::vector<char>> map_entry_buffers(EBPF_COUNT_OF(strings), std::vector<char>(32));
    const char* input_string = "Seattle is a rainy city";
    std::vector<char> input_buffer(input_string, input_string + strlen(input_string));
    const char* expected_output = "Seattle is a sunny city";
    std::vector<char> output_buffer(256);

    // Build test run opts.
    bpf_test_run_opts opts{};
    sample_program_context_t in_ctx{};
    sample_program_context_t out_ctx{};
    opts.repeat = 1;
    opts.ctx_in = reinterpret_cast<uint8_t*>(&in_ctx);
    opts.ctx_size_in = sizeof(in_ctx);
    opts.ctx_out = reinterpret_cast<uint8_t*>(&out_ctx);
    opts.ctx_size_out = sizeof(out_ctx);
    opts.data_in = reinterpret_cast<const uint8_t*>(input_buffer.data());
    opts.data_size_in = static_cast<uint32_t>(input_buffer.size());
    opts.data_out = reinterpret_cast<uint8_t*>(output_buffer.data());
    opts.data_size_out = static_cast<uint32_t>(output_buffer.size());

    // Get map and insert data.
    map = bpf_object__find_map_by_name(object, "test_map");
    REQUIRE(map != nullptr);
    map_fd = bpf_map__fd(map);
    REQUIRE(map_fd > 0);

    for (uint32_t key = 0; key < EBPF_COUNT_OF(strings); key++) {
        std::copy(strings[key], strings[key] + strlen(strings[key]), map_entry_buffers[key].begin());
        REQUIRE(bpf_map_update_elem(map_fd, &key, map_entry_buffers[key].data(), EBPF_ANY) == EBPF_SUCCESS);
    }

    // Get the program fd.
    program = bpf_object__find_program_by_name(object, "test_program_entry");
    program_fd = bpf_program__fd(program);
    REQUIRE(bpf_prog_test_run_opts(program_fd, &opts) == 0);

    // Validate data_out.
    REQUIRE(memcmp(output_buffer.data(), expected_output, strlen(expected_output)) == 0);

    // NULL opts.data_in.
    opts.data_in = nullptr;
    opts.data_size_in = 0;
    opts.data_out = reinterpret_cast<uint8_t*>(output_buffer.data());
    opts.data_size_out = static_cast<uint32_t>(output_buffer.size());
    REQUIRE(bpf_prog_test_run_opts(program_fd, &opts) == 0);
}

void
sample_ebpf_ext_test_batch(_In_ const struct bpf_object* object)
{
    struct bpf_map* map = nullptr;
    fd_t map_fd;
    const char* strings[] = {"rainy", "sunny"};
    std::vector<std::vector<char>> map_entry_buffers(EBPF_COUNT_OF(strings), std::vector<char>(32));
    const char* input_string = "rainy rainy rainy rainy rainy";
    size_t input_string_length = strlen(input_string);
    std::vector<char> input_buffer(EBPF_OFFSET_OF(sample_ebpf_ext_batch_run_request_t, data) + input_string_length);
    const char* expected_output = "sunny sunny sunny sunny rainy";
    std::vector<char> output_buffer(256);

    sample_ebpf_ext_batch_run_request_t* request = (sample_ebpf_ext_batch_run_request_t*)input_buffer.data();
    request->count = 4;
    memcpy(request->data, input_string, input_string_length);
    sample_ebpf_ext_batch_run_reply_t* reply = (sample_ebpf_ext_batch_run_reply_t*)output_buffer.data();
    _sample_extension_helper extension;

    // Get map and insert data.
    map = bpf_object__find_map_by_name(object, "test_map");
    REQUIRE(map != nullptr);
    map_fd = bpf_map__fd(map);
    REQUIRE(map_fd > 0);

    for (uint32_t key = 0; key < EBPF_COUNT_OF(strings); key++) {
        std::copy(strings[key], strings[key] + strlen(strings[key]), map_entry_buffers[key].begin());
        REQUIRE(bpf_map_update_elem(map_fd, &key, map_entry_buffers[key].data(), EBPF_ANY) == EBPF_SUCCESS);
    }

    extension.invoke_batch(input_buffer, output_buffer);

    REQUIRE(memcmp(reply->data, expected_output, strlen(expected_output)) == 0);
}

void
sample_ebpf_ext_invoke_and_validate(
    _In_ const struct bpf_object* object,
    _In_ _sample_extension_helper* extension,
    uint8_t attach_data,
    _In_z_ const char* map_value0,
    _In_z_ const char* map_value1,
    _In_z_ const char* input_string,
    _In_z_ const char* expected_output)
{
    struct bpf_map* map;
    fd_t map_fd;
    const int VALUE_SIZE = 32;
    std::vector<char> map_entry_buffer(VALUE_SIZE);
    std::vector<char> input_buffer(input_string, input_string + strlen(input_string));
    std::vector<char> output_buffer(256);
    uint32_t key = 0;

    map = bpf_object__find_map_by_name(object, "test_map");
    REQUIRE(map != nullptr);
    map_fd = bpf_map__fd(map);
    REQUIRE(map_fd > 0);

    memset(map_entry_buffer.data(), 0, map_entry_buffer.size());
    memcpy(map_entry_buffer.data(), map_value0, strlen(map_value0));
    REQUIRE(bpf_map_update_elem(map_fd, &key, map_entry_buffer.data(), EBPF_ANY) == EBPF_SUCCESS);

    key = 1;
    memset(map_entry_buffer.data(), 0, map_entry_buffer.size());
    memcpy(map_entry_buffer.data(), map_value1, strlen(map_value1));
    REQUIRE(bpf_map_update_elem(map_fd, &key, map_entry_buffer.data(), EBPF_ANY) == EBPF_SUCCESS);

    extension->invoke_by_attach_parameter(&attach_data, sizeof(attach_data), input_buffer, output_buffer);
    REQUIRE(memcmp(output_buffer.data(), expected_output, strlen(expected_output)) == 0);
}

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("jit_test", "[sample_ext_test]")
{
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_SAMPLE);
    program_load_attach_helper_t _helper;
    _helper.initialize(
        "test_sample_ebpf.o", BPF_PROG_TYPE_SAMPLE, "test_program_entry", EBPF_EXECUTION_JIT, nullptr, 0, hook);

    object = _helper.get_object();

    sample_ebpf_ext_test(object);
}
#endif

#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("interpret_test", "[sample_ext_test]")
{
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_SAMPLE);
    program_load_attach_helper_t _helper;
    _helper.initialize(
        "test_sample_ebpf.o", BPF_PROG_TYPE_SAMPLE, "test_program_entry", EBPF_EXECUTION_INTERPRET, nullptr, 0, hook);

    object = _helper.get_object();

    sample_ebpf_ext_test(object);
}
#endif

TEST_CASE("native_test", "[sample_ext_test]")
{
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_SAMPLE);
    program_load_attach_helper_t _helper;
    _helper.initialize(
        "test_sample_ebpf.sys", BPF_PROG_TYPE_SAMPLE, "test_program_entry", EBPF_EXECUTION_ANY, nullptr, 0, hook);

    object = _helper.get_object();

    sample_ebpf_ext_test(object);
}

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("jit_test_data", "[sample_ext_test]")
{
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_SAMPLE);
    program_load_attach_helper_t _helper;
    _helper.initialize(
        "test_sample_ebpf.o", BPF_PROG_TYPE_SAMPLE, "test_program_entry", EBPF_EXECUTION_JIT, nullptr, 0, hook);

    object = _helper.get_object();

    sample_ebpf_ext_test_prog_test_run(object);
}
#endif

#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("interpret_test_data", "[sample_ext_test]")
{
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_SAMPLE);
    program_load_attach_helper_t _helper;
    _helper.initialize(
        "test_sample_ebpf.o", BPF_PROG_TYPE_SAMPLE, "test_program_entry", EBPF_EXECUTION_INTERPRET, nullptr, 0, hook);

    object = _helper.get_object();

    sample_ebpf_ext_test_prog_test_run(object);
}
#endif

TEST_CASE("native_test_data", "[sample_ext_test]")
{
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_SAMPLE);
    program_load_attach_helper_t _helper;
    native_module_helper_t _native_helper;
    _native_helper.initialize("test_sample_ebpf", EBPF_EXECUTION_NATIVE);
    _helper.initialize(
        _native_helper.get_file_name().c_str(),
        BPF_PROG_TYPE_SAMPLE,
        "test_program_entry",
        EBPF_EXECUTION_NATIVE,
        nullptr,
        0,
        hook);

    object = _helper.get_object();

    sample_ebpf_ext_test_prog_test_run(object);
}

TEST_CASE("native_multi_attach_by_parameter", "[sample_ext_test]")
{
    struct bpf_object* object1 = nullptr;
    struct bpf_object* object2 = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_SAMPLE);
    program_load_attach_helper_t helper1;
    program_load_attach_helper_t helper2;
    native_module_helper_t native_helper1;
    native_module_helper_t native_helper2;
    _sample_extension_helper extension;
    uint8_t attach_data0 = 0;
    uint8_t attach_data1 = 1;

    native_helper1.initialize("test_sample_ebpf", EBPF_EXECUTION_NATIVE);
    native_helper2.initialize("test_sample_ebpf", EBPF_EXECUTION_NATIVE);
    helper1.initialize(
        native_helper1.get_file_name().c_str(),
        BPF_PROG_TYPE_SAMPLE,
        "test_program_entry",
        EBPF_EXECUTION_NATIVE,
        &attach_data0,
        sizeof(attach_data0),
        hook);
    helper2.initialize(
        native_helper2.get_file_name().c_str(),
        BPF_PROG_TYPE_SAMPLE,
        "test_program_entry",
        EBPF_EXECUTION_NATIVE,
        &attach_data1,
        sizeof(attach_data1),
        hook);

    object1 = helper1.get_object();
    object2 = helper2.get_object();
    sample_ebpf_ext_invoke_and_validate(
        object1, &extension, attach_data0, "rainy", "sunny", "Seattle is a rainy city", "Seattle is a sunny city");
    sample_ebpf_ext_invoke_and_validate(
        object2, &extension, attach_data1, "frowny", "smiley", "Seattle is a frowny city", "Seattle is a smiley city");
}

TEST_CASE("ebpf_program_attach_with_attach_data_race_native", "[sample_ext_test]")
{
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_SAMPLE);
    program_load_attach_helper_t helper;
    native_module_helper_t native_helper;
    uint8_t attach_data = 0;
    constexpr int value_size = 32;
    std::vector<char> map_entry_buffer(value_size);
    _sample_extension_helper extension;
    std::vector<char> input_buffer = {'r', 'a', 'i', 'n', 'y'};
    std::vector<char> output_buffer(256);
    std::atomic<bool> stop{false};

    native_helper.initialize("test_sample_ebpf", EBPF_EXECUTION_NATIVE);
    helper.initialize(
        native_helper.get_file_name().c_str(),
        BPF_PROG_TYPE_SAMPLE,
        "test_program_entry",
        EBPF_EXECUTION_NATIVE,
        &attach_data,
        sizeof(attach_data),
        hook);
    object = helper.get_object();

    struct bpf_map* map = bpf_object__find_map_by_name(object, "test_map");
    REQUIRE(map != nullptr);
    fd_t map_fd = bpf_map__fd(map);
    REQUIRE(map_fd > 0);
    uint32_t key = 0;
    memset(map_entry_buffer.data(), 0, map_entry_buffer.size());
    memcpy(map_entry_buffer.data(), "rainy", 5);
    REQUIRE(bpf_map_update_elem(map_fd, &key, map_entry_buffer.data(), EBPF_ANY) == EBPF_SUCCESS);
    key = 1;
    memset(map_entry_buffer.data(), 0, map_entry_buffer.size());
    memcpy(map_entry_buffer.data(), "sunny", 5);
    REQUIRE(bpf_map_update_elem(map_fd, &key, map_entry_buffer.data(), EBPF_ANY) == EBPF_SUCCESS);

    bpf_program* program = bpf_object__find_program_by_name(object, "test_program_entry");
    REQUIRE(program != nullptr);
    fd_t program_fd = bpf_program__fd(program);
    REQUIRE(program_fd > 0);

    std::thread fire_thread([&]() {
        while (!stop) {
            (void)extension.try_invoke_by_attach_parameter(
                &attach_data, sizeof(attach_data), input_buffer, output_buffer);
        }
    });

    std::thread detach_thread([&]() {
        while (!stop) {
            (void)hook.detach(program_fd, &attach_data, sizeof(attach_data));
            (void)hook.attach(program, &attach_data, sizeof(attach_data));
        }
    });

    Sleep(1000);
    stop = true;
    fire_thread.join();
    detach_thread.join();

    (void)hook.detach(program_fd, &attach_data, sizeof(attach_data));
}

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("batch_test", "[sample_ext_test]")
{
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_SAMPLE);
    program_load_attach_helper_t _helper;
    _helper.initialize(
        "test_sample_ebpf.o", BPF_PROG_TYPE_SAMPLE, "test_program_entry", EBPF_EXECUTION_ANY, nullptr, 0, hook);

    object = _helper.get_object();

    sample_ebpf_ext_test_batch(object);
}
#endif

void
utility_helpers_test(ebpf_execution_type_t execution_type)
{
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_SAMPLE);
    native_module_helper_t native_module_helper;
    native_module_helper.initialize("test_utility_helpers", execution_type);
    program_load_attach_helper_t _helper;
    _helper.initialize(
        native_module_helper.get_file_name().c_str(),
        BPF_PROG_TYPE_SAMPLE,
        "test_utility_helpers",
        execution_type,
        nullptr,
        0,
        hook);
    object = _helper.get_object();

    std::vector<char> dummy(1);
    _sample_extension_helper extension;

    extension.invoke(dummy, dummy);

    verify_utility_helper_results(object, true);
}

#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("utility_helpers_test_interpret", "[sample_ext_test]") { utility_helpers_test(EBPF_EXECUTION_INTERPRET); }
#endif
#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("utility_helpers_test_jit", "[sample_ext_test]") { utility_helpers_test(EBPF_EXECUTION_JIT); }
#endif
TEST_CASE("utility_helpers_test_native", "[sample_ext_test]") { utility_helpers_test(EBPF_EXECUTION_NATIVE); }

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("netsh_add_program_test_sample_ebpf", "[sample_ext_test]")
{
    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_add_program, L"test_sample_ebpf.o", L"pinned=none", nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output.starts_with("Loaded with"));
}
#endif
