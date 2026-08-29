// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "sample_ext_test_common.h"

#include <array>
#include <cstring>

int
sample_stress_initialize_test_map(fd_t map_fd)
{
    if (map_fd <= 0) {
        return -1;
    }

    std::array<char, 32> map_entry_buffer = {};
    uint32_t key = 0;

    std::memcpy(map_entry_buffer.data(), "rainy", 5);
    if (bpf_map_update_elem(map_fd, &key, map_entry_buffer.data(), EBPF_ANY) != 0) {
        return -1;
    }

    key = 1;
    map_entry_buffer = {};
    std::memcpy(map_entry_buffer.data(), "sunny", 5);
    if (bpf_map_update_elem(map_fd, &key, map_entry_buffer.data(), EBPF_ANY) != 0) {
        return -1;
    }

    return 0;
}

int
sample_stress_load_program(
    const char* file_name,
    bpf_prog_type program_type,
    bpf_object** object,
    bpf_program** program,
    fd_t* program_fd,
    fd_t* map_fd)
{
    if (file_name == nullptr || object == nullptr || program == nullptr || program_fd == nullptr || map_fd == nullptr) {
        return -1;
    }

    *object = nullptr;
    *program = nullptr;
    *program_fd = -1;
    *map_fd = -1;

    *object = bpf_object__open(file_name);
    if (*object == nullptr) {
        return -1;
    }

    if (ebpf_object_set_execution_type(*object, EBPF_EXECUTION_NATIVE) != EBPF_SUCCESS) {
        sample_stress_close_program(*object);
        *object = nullptr;
        return -1;
    }

    *program = bpf_object__next_program(*object, nullptr);
    if (*program == nullptr) {
        sample_stress_close_program(*object);
        *object = nullptr;
        return -1;
    }

    bpf_program__set_type(*program, program_type);

    if (bpf_object__load(*object) != 0) {
        sample_stress_close_program(*object);
        *object = nullptr;
        return -1;
    }

    *program_fd = bpf_program__fd(*program);
    if (*program_fd <= 0) {
        sample_stress_close_program(*object);
        *object = nullptr;
        return -1;
    }

    *map_fd = bpf_object__find_map_fd_by_name(*object, "test_map");
    if (*map_fd <= 0) {
        sample_stress_close_program(*object);
        *object = nullptr;
        *program_fd = -1;
        return -1;
    }

    if (sample_stress_initialize_test_map(*map_fd) != 0) {
        sample_stress_close_program(*object);
        *object = nullptr;
        *program_fd = -1;
        *map_fd = -1;
        return -1;
    }

    return 0;
}

void
sample_stress_close_program(bpf_object* object)
{
    if (object != nullptr) {
        bpf_object__close(object);
    }
}
