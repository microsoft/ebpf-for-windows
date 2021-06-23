// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include <chrono>
#include <mutex>
#include <thread>

#include "api_test.h"
#include "catch2\catch.hpp"
#include "common_tests.h"
#include "service_helper.h"

namespace api_test {
#pragma warning(push)
#pragma warning(disable : 4201) // nonstandard extension used : nameless struct/union
#include "../sample/ebpf.h"
#pragma warning(pop)
}; // namespace api_test

#define SAMPLE_PATH ""

#define EBPF_CORE_DRIVER_BINARY_NAME L"ebpfcore.sys"
#define EBPF_CORE_DRIVER_NAME L"ebpfcore"

#define EBPF_EXTENSION_DRIVER_BINARY_NAME L"netebpfext.sys"
#define EBPF_EXTENSION_DRIVER_NAME L"netebpfext"

#define EBPF_SERVICE_BINARY_NAME L"ebpfsvc.exe"
#define EBPF_SERVICE_NAME L"ebpfsvc"

#define DROP_PACKET_PROGRAM_COUNT 1
#define BIND_MONITOR_PROGRAM_COUNT 1

#define DROP_PACKET_MAP_COUNT 1
#define BIND_MONITOR_MAP_COUNT 2

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

    ebpf_free_string(log_buffer);
    return result;
}

static void
_test_program_load(
    const char* file_name,
    ebpf_program_type_t* program_type,
    ebpf_execution_type_t execution_type,
    bool expected_to_load)
{
    ebpf_result_t result;
    struct _ebpf_object* object = nullptr;
    fd_t program_fd;
    ebpf_handle_t program_handle = INVALID_HANDLE_VALUE;
    ebpf_handle_t next_program_handle = INVALID_HANDLE_VALUE;
    result = _program_load_helper(file_name, program_type, execution_type, &object, &program_fd);

    if (expected_to_load) {
        REQUIRE(result == EBPF_SUCCESS);
        REQUIRE(program_fd > 0);
    } else {
        REQUIRE(result == EBPF_VERIFICATION_FAILED);
        return;
    }

    // Query loaded programs to verify this program is loaded.
    REQUIRE(ebpf_api_get_next_program(program_handle, &next_program_handle) == ERROR_SUCCESS);
    REQUIRE(next_program_handle != INVALID_HANDLE_VALUE);

    program_handle = next_program_handle;

    const char* program_file_name;
    const char* program_section_name;
    ebpf_execution_type_t program_execution_type;
    REQUIRE(
        ebpf_api_program_query_information(
            program_handle, &program_execution_type, &program_file_name, &program_section_name) == ERROR_SUCCESS);

    if (execution_type == EBPF_EXECUTION_ANY) {
        execution_type = EBPF_EXECUTION_JIT;
    }
    REQUIRE(program_execution_type == execution_type);
    REQUIRE(strcmp(program_file_name, file_name) == 0);

    // Next program should not be present.
    REQUIRE(ebpf_api_get_next_program(program_handle, &next_program_handle) == ERROR_SUCCESS);
    REQUIRE(next_program_handle == INVALID_HANDLE_VALUE);

    ebpf_api_close_handle(program_handle);
    program_handle = INVALID_HANDLE_VALUE;
    ebpf_object_close(object);

    // We have closed both handles to the program. Program should be unloaded now.
    REQUIRE(ebpf_api_get_next_program(program_handle, &next_program_handle) == ERROR_SUCCESS);
    REQUIRE(next_program_handle == INVALID_HANDLE_VALUE);
}

static void
_test_map_next_previous(const char* file_name, int expected_map_count)
{
    ebpf_result_t result;
    struct _ebpf_object* object = nullptr;
    fd_t program_fd;
    int map_count = 0;
    struct _ebpf_map* previous = nullptr;
    struct _ebpf_map* next = nullptr;
    result = _program_load_helper(file_name, nullptr, EBPF_EXECUTION_ANY, &object, &program_fd);
    REQUIRE(result == EBPF_SUCCESS);

    next = ebpf_map_next(previous, object);
    while (next != nullptr) {
        map_count++;
        previous = next;
        next = ebpf_map_next(previous, object);
    }
    REQUIRE(map_count == expected_map_count);

    map_count = 0;
    previous = next = nullptr;

    previous = ebpf_map_previous(next, object);
    while (previous != nullptr) {
        map_count++;
        next = previous;
        previous = ebpf_map_previous(next, object);
    }
    REQUIRE(map_count == expected_map_count);

    ebpf_object_close(object);
}

static void
_test_program_next_previous(const char* file_name, int expected_program_count)
{
    ebpf_result_t result;
    struct _ebpf_object* object = nullptr;
    fd_t program_fd;
    int program_count = 0;
    struct _ebpf_program* previous = nullptr;
    struct _ebpf_program* next = nullptr;
    result = _program_load_helper(file_name, nullptr, EBPF_EXECUTION_ANY, &object, &program_fd);
    REQUIRE(result == EBPF_SUCCESS);

    next = ebpf_program_next(previous, object);
    while (next != nullptr) {
        program_count++;
        previous = next;
        next = ebpf_program_next(previous, object);
    }
    REQUIRE(program_count == expected_program_count);

    program_count = 0;
    previous = next = nullptr;

    previous = ebpf_program_previous(next, object);
    while (previous != nullptr) {
        program_count++;
        next = previous;
        previous = ebpf_program_previous(next, object);
    }
    REQUIRE(program_count == expected_program_count);

    ebpf_object_close(object);
}

TEST_CASE("pinned_map_enum", "[pinned_map_enum]")
{
    REQUIRE(ebpf_api_initiate() == EBPF_SUCCESS);

    ebpf_test_pinned_map_enum();
    ebpf_api_terminate();
}

TEST_CASE("test_ebpf_program_load", "[test_ebpf_program_load]")
{
    REQUIRE(ebpf_api_initiate() == EBPF_SUCCESS);

    // Load droppacket (JIT) without providing expected program type.
    _test_program_load("droppacket.o", nullptr, EBPF_EXECUTION_JIT, true);

    // Load droppacket (ANY) without providing expected program type.
    _test_program_load("droppacket.o", nullptr, EBPF_EXECUTION_ANY, true);

    // Load droppacket (INTERPRET) without providing expected program type.
    _test_program_load("droppacket.o", nullptr, EBPF_EXECUTION_INTERPRET, true);

    // Load droppacket with providing expected program type.
    _test_program_load("droppacket.o", &EBPF_PROGRAM_TYPE_XDP, EBPF_EXECUTION_INTERPRET, true);

    // Load bindmonitor (JIT) without providing expected program type.
    _test_program_load("bindmonitor.o", nullptr, EBPF_EXECUTION_JIT, true);

    // Load bindmonitor (INTERPRET) without providing expected program type.
    _test_program_load("bindmonitor.o", nullptr, EBPF_EXECUTION_INTERPRET, true);

    // Load bindmonitor with providing expected program type.
    _test_program_load("bindmonitor.o", &EBPF_PROGRAM_TYPE_BIND, EBPF_EXECUTION_JIT, true);

    // Try to load bindmonitor with providing wrong program type.
    _test_program_load("bindmonitor.o", &EBPF_PROGRAM_TYPE_XDP, EBPF_EXECUTION_ANY, false);

    // Try to load an unsafe program.
    _test_program_load("droppacket_unsafe.o", nullptr, EBPF_EXECUTION_ANY, false);

    ebpf_api_terminate();
}

TEST_CASE("test_ebpf_program_next_previous", "[test_ebpf_program_next_previous]")
{
    REQUIRE(ebpf_api_initiate() == EBPF_SUCCESS);

    _test_program_next_previous("droppacket.o", DROP_PACKET_PROGRAM_COUNT);
    _test_program_next_previous("bindmonitor.o", BIND_MONITOR_PROGRAM_COUNT);

    ebpf_api_terminate();
}

TEST_CASE("test_ebpf_map_next_previous", "[test_ebpf_map_next_previous]")
{
    REQUIRE(ebpf_api_initiate() == EBPF_SUCCESS);

    _test_map_next_previous("droppacket.o", DROP_PACKET_MAP_COUNT);
    _test_map_next_previous("bindmonitor.o", BIND_MONITOR_MAP_COUNT);

    ebpf_api_terminate();
}
