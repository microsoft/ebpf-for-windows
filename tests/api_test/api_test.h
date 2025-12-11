// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once
#include "api_internal.h"
#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "ebpf_api.h"
#include "ebpf_result.h"
#include "ebpf_structs.h"
#include "native_helper.hpp"
#include "service_helper.h"

static bool
_is_native_program(_In_z_ const char* file_name)
{
    std::string file_name_string(file_name);
    std::string file_extension = file_name_string.substr(file_name_string.find_last_of(".") + 1);
    if (file_extension == "sys") {
        return true;
    }

    return false;
}

static std::string
_get_file_name_without_extension(_In_z_ const char* file_name)
{
    std::string file_name_without_extension = file_name;
    size_t last_dot = file_name_without_extension.find_last_of('.');
    if (last_dot != std::string::npos) {
        file_name_without_extension = file_name_without_extension.substr(0, last_dot);
    }
    size_t last_slash = file_name_without_extension.find_last_of("/\\");
    if (last_slash != std::string::npos) {
        file_name_without_extension = file_name_without_extension.substr(last_slash + 1);
    }
    return file_name_without_extension;
}

inline _Success_(return == 0) int program_load_helper(
    _In_z_ const char* file_name,
    bpf_prog_type prog_type,
    ebpf_execution_type_t execution_type,
    _Outptr_ struct bpf_object** object,
    _Out_ fd_t* program_fd, // File descriptor of first program in the object.
    bool copy_file = true)
{
    *program_fd = ebpf_fd_invalid;
    *object = nullptr;
    native_module_helper_t _native_helper;
    std::string actual_file_name_string;
    const char* actual_file_name = nullptr;

    if (copy_file && _is_native_program(file_name)) {
        std::string file_name_without_extension = _get_file_name_without_extension(file_name);
        _native_helper.initialize(file_name_without_extension.c_str(), execution_type);
        actual_file_name_string = _native_helper.get_file_name();
        actual_file_name = actual_file_name_string.c_str();
    } else {
        actual_file_name = file_name;
    }

    struct bpf_object* new_object = bpf_object__open(actual_file_name);
    if (new_object == nullptr) {
        return -EINVAL;
    }

    REQUIRE(ebpf_object_set_execution_type(new_object, execution_type) == EBPF_SUCCESS);

    struct bpf_program* program = bpf_object__next_program(new_object, nullptr);

    if (prog_type != BPF_PROG_TYPE_UNSPEC) {
        bpf_program__set_type(program, prog_type);
    }

    int error = bpf_object__load(new_object);
    if (error < 0) {
        bpf_object__close(new_object);
        return error;
    }

    if (program != nullptr) {
        *program_fd = bpf_program__fd(program);
    }
    *object = new_object;
    return 0;
}

inline void
test_program_next_previous(const char* file_name, int expected_program_count)
{
    int result;
    struct bpf_object* object = nullptr;
    fd_t program_fd;
    int program_count = 0;
    struct bpf_program* previous = nullptr;
    struct bpf_program* next = nullptr;
    result = program_load_helper(file_name, BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_ANY, &object, &program_fd);
    REQUIRE(result == 0);

    next = bpf_object__next_program(object, previous);
    while (next != nullptr) {
        program_count++;
        previous = next;
        next = bpf_object__next_program(object, previous);
    }
    REQUIRE(program_count == expected_program_count);

    program_count = 0;
    previous = next = nullptr;

    previous = bpf_object__prev_program(object, next);
    while (previous != nullptr) {
        program_count++;
        next = previous;
        previous = bpf_object__prev_program(object, next);
    }
    REQUIRE(program_count == expected_program_count);

    bpf_object__close(object);
}

inline void
test_map_next_previous(const char* file_name, int expected_map_count)
{
    int result;
    struct bpf_object* object = nullptr;
    fd_t program_fd;
    int map_count = 0;
    struct bpf_map* previous = nullptr;
    struct bpf_map* next = nullptr;
    result = program_load_helper(file_name, BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_ANY, &object, &program_fd);
    REQUIRE(result == 0);

    next = bpf_object__next_map(object, previous);
    while (next != nullptr) {
        map_count++;
        previous = next;
        next = bpf_object__next_map(object, previous);
    }
    REQUIRE(map_count == expected_map_count);

    map_count = 0;
    previous = next = nullptr;

    previous = bpf_object__prev_map(object, next);
    while (previous != nullptr) {
        map_count++;
        next = previous;
        previous = bpf_object__prev_map(object, next);
    }
    REQUIRE(map_count == expected_map_count);

    bpf_object__close(object);
}

void
tailcall_load_test(_In_z_ const char* file_name);

void
bpf_user_helpers_test(ebpf_execution_type_t execution_type);