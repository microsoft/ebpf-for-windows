// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include <chrono>
#include <mutex>
#include <thread>

#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "service_helper.h"
#include "test_ext_app.h"

namespace api_test {
#pragma warning(push)
#pragma warning(disable : 4201) // nonstandard extension used : nameless struct/union
#include "../../sample/ebpf.h"
#pragma warning(pop)
}; // namespace api_test

#define SAMPLE_PATH ""

#define EBPF_CORE_DRIVER_BINARY_NAME L"ebpfcore.sys"
#define EBPF_CORE_DRIVER_NAME L"ebpfcore"

#define EBPF_EXTENSION_DRIVER_BINARY_NAME L"test_ebpf_ext.sys"
#define EBPF_EXTENSION_DRIVER_NAME L"testebpfext"

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
    const char* file_name,
    const ebpf_program_type_t* program_type,
    ebpf_execution_type_t execution_type,
    struct _ebpf_object** object,
    fd_t* program_fd)
{
    ebpf_result_t result;
    const char* log_buffer = nullptr;
    result = ebpf_program_load(file_name, program_type, nullptr, execution_type, object, program_fd, &log_buffer);
    printf("Logbuffer: %s\n", log_buffer);

    ebpf_free_string(log_buffer);
    return result;
}

TEST_CASE("test_test", "[test_test]")
{
    ebpf_result_t result;
    struct _ebpf_object* object = nullptr;
    fd_t program_fd;
    ebpf_handle_t program_handle = INVALID_HANDLE_VALUE;
    ebpf_handle_t next_program_handle = INVALID_HANDLE_VALUE;
    HANDLE device_handle = INVALID_HANDLE_VALUE;
    GUID input_guid = {0};
    uint32_t count_of_bytes_returned;

    REQUIRE(ebpf_api_initiate() == EBPF_SUCCESS);

    result = _program_load_helper("test_ebpf.o", &EBPF_PROGRAM_TYPE_TEST, EBPF_EXECUTION_JIT, &object, &program_fd);

    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(program_fd > 0);

    // Query loaded programs to verify this program is loaded.
    REQUIRE(ebpf_api_get_next_program(program_handle, &next_program_handle) == ERROR_SUCCESS);
    REQUIRE(next_program_handle != INVALID_HANDLE_VALUE);

    program_handle = next_program_handle;

    // Attach to link.
    ebpf_handle_t link_handle = INVALID_HANDLE_VALUE;
    REQUIRE(ebpf_api_link_program(program_handle, EBPF_ATTACH_TYPE_TEST, &link_handle) == ERROR_SUCCESS);

    REQUIRE(UuidCreate(&input_guid) == RPC_S_OK);

    // Open handle to test eBPF extension device.
    REQUIRE(
        (device_handle = ::CreateFileW(
             TEST_EBPF_EXT_DEVICE_WIN32_NAME,
             GENERIC_READ | GENERIC_WRITE,
             0,
             nullptr,
             CREATE_ALWAYS,
             FILE_ATTRIBUTE_NORMAL,
             nullptr)) != INVALID_HANDLE_VALUE);

    // Issue IOCTL
    REQUIRE(
        ::DeviceIoControl(
            device_handle,
            IOCTL_TEST_EBPF_EXT_CTL,
            &input_guid,
            sizeof(input_guid),
            NULL,
            0,
            (DWORD*)&count_of_bytes_returned,
            nullptr) == TRUE);

    ebpf_api_close_handle(program_handle);
    ebpf_object_close(object);
    if (device_handle != INVALID_HANDLE_VALUE)
        ::CloseHandle(device_handle);

    ebpf_api_terminate();
}