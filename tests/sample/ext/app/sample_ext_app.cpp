// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include <chrono>
#include <mutex>
#include <thread>

#include "catch_wrapper.hpp"
#include "libbpf.h"
#include "service_helper.h"
#include "sample_ext_app.h"

#define SAMPLE_PATH ""

#define EBPF_CORE_DRIVER_BINARY_NAME L"ebpfcore.sys"
#define EBPF_CORE_DRIVER_NAME L"ebpfcore"

#define EBPF_EXTENSION_DRIVER_BINARY_NAME L"sample_ebpf_ext.sys"
#define EBPF_EXTENSION_DRIVER_NAME L"SampleEbpfExt"

#define EBPF_SERVICE_BINARY_NAME L"ebpfsvc.exe"
#define EBPF_SERVICE_NAME L"ebpfsvc"

static service_install_helper
    _ebpf_core_driver_helper(EBPF_CORE_DRIVER_NAME, EBPF_CORE_DRIVER_BINARY_NAME, SERVICE_KERNEL_DRIVER);

static service_install_helper
    _ebpf_extension_driver_helper(EBPF_EXTENSION_DRIVER_NAME, EBPF_EXTENSION_DRIVER_BINARY_NAME, SERVICE_KERNEL_DRIVER);

static service_install_helper
    _ebpf_service_helper(EBPF_SERVICE_NAME, EBPF_SERVICE_BINARY_NAME, SERVICE_WIN32_OWN_PROCESS);

static ebpf_result_t
_program_load_helper(
    _In_z_ const char* file_name,
    _In_ const ebpf_program_type_t* program_type,
    ebpf_execution_type_t execution_type,
    _Outptr_ struct bpf_object** object,
    _Out_ fd_t* program_fd)
{
    ebpf_result_t result;
    const char* log_buffer = nullptr;
    result = ebpf_program_load(file_name, program_type, nullptr, execution_type, object, program_fd, &log_buffer);

    ebpf_free_string(log_buffer);
    return result;
}

TEST_CASE("test_test", "[test_test]")
{
    ebpf_result_t result;
    struct bpf_object* object = nullptr;
    fd_t program_fd;
    ebpf_handle_t program_handle = INVALID_HANDLE_VALUE;
    ebpf_handle_t next_program_handle = INVALID_HANDLE_VALUE;
    struct bpf_map* map = nullptr;
    ebpf_handle_t map_handle = INVALID_HANDLE_VALUE;
    const char* strings[2] = {"rainy", "sunny"};
    std::vector<std::vector<char>> map_entry_buffers(2, std::vector<char>(32));
    HANDLE device_handle = INVALID_HANDLE_VALUE;
    const char* input_string = "Seattle is a rainy city";
    std::vector<char> input_buffer(input_string, input_string + strlen(input_string));
    const char* expected_output = "Seattle is a sunny city";
    std::vector<char> output_buffer(256);
    uint32_t count_of_bytes_returned;

    REQUIRE(ebpf_api_initiate() == EBPF_SUCCESS);

    result =
        _program_load_helper("test_sample_ebpf.o", &EBPF_PROGRAM_TYPE_SAMPLE, EBPF_EXECUTION_JIT, &object, &program_fd);

    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(program_fd > 0);

    // Query loaded programs to verify this program is loaded.
    REQUIRE(ebpf_api_get_next_program(program_handle, &next_program_handle) == ERROR_SUCCESS);
    REQUIRE(next_program_handle != INVALID_HANDLE_VALUE);

    program_handle = next_program_handle;

    // Get map and insert data.
    map = bpf_map__next(nullptr, object);
    REQUIRE(map != nullptr);
    // TODO: Change to APIs using FD once #81 is resolved.
    map_handle = map->map_handle;
    for (uint32_t key = 0; key < map_entry_buffers.size(); key++) {
        std::copy(strings[key], strings[key] + strlen(strings[key]), map_entry_buffers[key].begin());
        REQUIRE(
            ebpf_api_map_update_element(
                map_handle,
                sizeof(key),
                reinterpret_cast<uint8_t*>(&key),
                static_cast<uint32_t>(map_entry_buffers[key].size()),
                reinterpret_cast<uint8_t*>(map_entry_buffers[key].data())) == EBPF_SUCCESS);
    }

    // Attach to link.
    ebpf_handle_t link_handle = INVALID_HANDLE_VALUE;
    REQUIRE(ebpf_api_link_program(program_handle, EBPF_ATTACH_TYPE_SAMPLE, &link_handle) == ERROR_SUCCESS);

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

    // Issue IOCTL.
    REQUIRE(
        ::DeviceIoControl(
            device_handle,
            IOCTL_SAMPLE_EBPF_EXT_CTL,
            input_buffer.data(),
            static_cast<uint32_t>(input_buffer.size()),
            output_buffer.data(),
            static_cast<uint32_t>(output_buffer.size()),
            (DWORD*)&count_of_bytes_returned,
            nullptr) == TRUE);

    REQUIRE(memcmp(output_buffer.data(), expected_output, strlen(expected_output)) == 0);

    ebpf_api_close_handle(program_handle);
    bpf_object__close(object);
    if (device_handle != INVALID_HANDLE_VALUE)
        ::CloseHandle(device_handle);

    ebpf_api_terminate();
}
