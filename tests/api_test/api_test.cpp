// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include <chrono>
#include <mutex>
#include <thread>
#include "api_test.h"
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "service_helper.h"
#include "libbpf.h"
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
    struct bpf_object** object,
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
    struct bpf_object* object = nullptr;
    fd_t program_fd;
    fd_t previous_fd = ebpf_fd_invalid;
    fd_t next_fd = ebpf_fd_invalid;

    printf(
        "_test_program_load: file_name=%s, execution_type=%d, expected_to_load=%d\n",
        file_name,
        execution_type,
        expected_to_load);

    result = _program_load_helper(file_name, program_type, execution_type, &object, &program_fd);

    if (expected_to_load) {
        REQUIRE(result == EBPF_SUCCESS);
        REQUIRE(program_fd > 0);
    } else {
        REQUIRE(result == EBPF_VERIFICATION_FAILED);
        return;
    }

    // Query loaded programs to verify this program is loaded.
    REQUIRE(ebpf_get_next_program(previous_fd, &next_fd) == EBPF_SUCCESS);
    REQUIRE(next_fd != ebpf_fd_invalid);

    const char* program_file_name;
    const char* program_section_name;
    ebpf_execution_type_t program_execution_type;
    REQUIRE(
        ebpf_program_query_info(program_fd, &program_execution_type, &program_file_name, &program_section_name) ==
        EBPF_SUCCESS);

    // Set the default execution type to JIT. This will eventually
    // be decided by a system-wide policy. TODO(Issue #288): Configure
    // system-wide execution type.
    if (execution_type == EBPF_EXECUTION_ANY) {
        execution_type = EBPF_EXECUTION_JIT;
    }
    REQUIRE(program_execution_type == execution_type);
    REQUIRE(strcmp(program_file_name, file_name) == 0);

    // Next program should not be present.
    previous_fd = next_fd;
    REQUIRE(ebpf_get_next_program(previous_fd, &next_fd) == EBPF_SUCCESS);
    REQUIRE(next_fd == ebpf_fd_invalid);

    ebpf_close_fd(previous_fd);
    previous_fd = ebpf_fd_invalid;
    bpf_object__close(object);

    // We have closed both handles to the program. Program should be unloaded now.
    REQUIRE(ebpf_get_next_program(previous_fd, &next_fd) == ERROR_SUCCESS);
    REQUIRE(next_fd == ebpf_fd_invalid);
}

static void
_test_map_next_previous(const char* file_name, int expected_map_count)
{
    ebpf_result_t result;
    struct bpf_object* object = nullptr;
    fd_t program_fd;
    int map_count = 0;
    struct bpf_map* previous = nullptr;
    struct bpf_map* next = nullptr;
    result = _program_load_helper(file_name, nullptr, EBPF_EXECUTION_ANY, &object, &program_fd);
    REQUIRE(result == EBPF_SUCCESS);

    next = bpf_map__next(previous, object);
    while (next != nullptr) {
        map_count++;
        previous = next;
        next = bpf_map__next(previous, object);
    }
    REQUIRE(map_count == expected_map_count);

    map_count = 0;
    previous = next = nullptr;

    previous = bpf_map__prev(next, object);
    while (previous != nullptr) {
        map_count++;
        next = previous;
        previous = bpf_map__prev(next, object);
    }
    REQUIRE(map_count == expected_map_count);

    bpf_object__close(object);
}

static void
_test_program_next_previous(const char* file_name, int expected_program_count)
{
    ebpf_result_t result;
    struct bpf_object* object = nullptr;
    fd_t program_fd;
    int program_count = 0;
    struct bpf_program* previous = nullptr;
    struct bpf_program* next = nullptr;
    result = _program_load_helper(file_name, nullptr, EBPF_EXECUTION_ANY, &object, &program_fd);
    REQUIRE(result == EBPF_SUCCESS);

    next = bpf_program__next(previous, object);
    while (next != nullptr) {
        program_count++;
        previous = next;
        next = bpf_program__next(previous, object);
    }
    REQUIRE(program_count == expected_program_count);

    program_count = 0;
    previous = next = nullptr;

    previous = bpf_program__prev(next, object);
    while (previous != nullptr) {
        program_count++;
        next = previous;
        previous = bpf_program__prev(next, object);
    }
    REQUIRE(program_count == expected_program_count);

    bpf_object__close(object);
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
