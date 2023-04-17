// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "netsh_test_helper.h"
#include "program_helper.h"
#include "sample_ext_app.h"
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

#define EBPF_SERVICE_BINARY_NAME L"ebpfsvc.exe"
#define EBPF_SERVICE_NAME L"ebpfsvc"

static service_install_helper
    _ebpf_core_driver_helper(EBPF_CORE_DRIVER_NAME, EBPF_CORE_DRIVER_BINARY_NAME, SERVICE_KERNEL_DRIVER);

static service_install_helper
    _ebpf_extension_driver_helper(SAMPLE_EBPF_EXT_NAME_W, EBPF_EXTENSION_DRIVER_BINARY_NAME, SERVICE_KERNEL_DRIVER);

static service_install_helper
    _ebpf_service_helper(EBPF_SERVICE_NAME, EBPF_SERVICE_BINARY_NAME, SERVICE_WIN32_OWN_PROCESS);

struct _sample_extension_helper
{
  public:
    _sample_extension_helper() : device_handle(INVALID_HANDLE_VALUE)
    {
        // Open handle to test eBPF extension device.
        REQUIRE(
            (device_handle = ::CreateFileW(
                 SAMPLE_EBPF_EXT_DEVICE_WIN32_NAME,
                 GENERIC_READ | GENERIC_WRITE,
                 0,
                 nullptr,
                 CREATE_ALWAYS,
                 FILE_ATTRIBUTE_NORMAL,
                 nullptr)) != INVALID_HANDLE_VALUE);
    }

    ~_sample_extension_helper()
    {
        if (device_handle != INVALID_HANDLE_VALUE) {
            ::CloseHandle(device_handle);
        }
    }

    void
    invoke(std::vector<char>& input_buffer, std::vector<char>& output_buffer)
    {
        uint32_t count_of_bytes_returned;

        // Issue IOCTL.
        REQUIRE(
            ::DeviceIoControl(
                device_handle,
                IOCTL_SAMPLE_EBPF_EXT_CTL_RUN,
                input_buffer.data(),
                static_cast<uint32_t>(input_buffer.size()),
                output_buffer.data(),
                static_cast<uint32_t>(output_buffer.size()),
                (unsigned long*)&count_of_bytes_returned,
                nullptr) == TRUE);
    }

  private:
    HANDLE device_handle;
};

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

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("jit_test", "[sample_ext_test]")
{
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_SAMPLE);
    program_load_attach_helper_t _helper(
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
    program_load_attach_helper_t _helper(
        "test_sample_ebpf.o", BPF_PROG_TYPE_SAMPLE, "test_program_entry", EBPF_EXECUTION_INTERPRET, nullptr, 0, hook);

    object = _helper.get_object();

    sample_ebpf_ext_test(object);
}
#endif

void
utility_helpers_test(ebpf_execution_type_t execution_type)
{
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_SAMPLE);
    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE) ? "test_sample_ebpf.sys" : "test_sample_ebpf.o";
    program_load_attach_helper_t _helper(
        file_name, BPF_PROG_TYPE_SAMPLE, "test_utility_helpers", execution_type, nullptr, 0, hook);
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
TEST_CASE("netsh_add_program_test_sample_ebpf", "[sample_ext_test]")
{
    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_add_program, L"test_sample_ebpf.o", L"pinned=none", nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output.starts_with("Loaded with"));
}
