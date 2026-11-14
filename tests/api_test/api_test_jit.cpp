// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "api_internal.h"
#include "api_test.h"
#include "api_test_jit.h"
#include "bpf/libbpf.h"
#include "common_tests.h"
#include "native_helper.hpp"
#include "program_helper.h"
#include "service_helper.h"
#include "socket_helper.h"

void
tailcall_load_test(_In_z_ const char* file_name)
{
    int result;
    struct bpf_object* object = nullptr;
    fd_t program_fd;

    result = program_load_helper(file_name, BPF_PROG_TYPE_SAMPLE, EBPF_EXECUTION_ANY, &object, &program_fd);
    REQUIRE(result == 0);

    REQUIRE(program_fd > 0);

    // Set up tail calls.
    struct bpf_program* callee0 = bpf_object__find_program_by_name(object, "callee0");
    REQUIRE(callee0 != nullptr);
    fd_t callee0_fd = bpf_program__fd(callee0);
    REQUIRE(callee0_fd > 0);

    struct bpf_program* callee1 = bpf_object__find_program_by_name(object, "callee1");
    REQUIRE(callee1 != nullptr);
    fd_t callee1_fd = bpf_program__fd(callee1);
    REQUIRE(callee1_fd > 0);

    // Test a legacy libbpf api alias.
    REQUIRE(bpf_program__get_type(callee0) == BPF_PROG_TYPE_SAMPLE);

    fd_t prog_map_fd = bpf_object__find_map_fd_by_name(object, "map");
    REQUIRE(prog_map_fd > 0);

    uint32_t index = 0;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee0_fd, 0) == 0);
    index = 1;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    // Cleanup tail calls.
    index = 0;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
    index = 1;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);

    bpf_object__close(object);
}

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("test_ebpf_program_next_previous_jit", "[test_ebpf_program_next_previous]")
{
    test_program_next_previous("test_sample_ebpf.o", SAMPLE_PROGRAM_COUNT);
}

TEST_CASE("test_ebpf_map_next_previous_jit", "[test_ebpf_map_next_previous]")
{
    test_map_next_previous("test_sample_ebpf.o", SAMPLE_MAP_COUNT);
}

TEST_CASE("ringbuf_api_jit", "[test_ringbuf_api][ring_buffer]") { ring_buffer_api_test(EBPF_EXECUTION_JIT); }
TEST_CASE("divide_by_zero_jit", "[divide_by_zero]") { divide_by_zero_test_km(EBPF_EXECUTION_JIT); }

TEST_CASE("tailcall_load_test_jit", "[tailcall_load_test]") { tailcall_load_test("tail_call_multiple.o"); }
#endif

#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("ringbuf_api_interpret", "[test_ringbuf_api][ring_buffer]")
{
    ring_buffer_api_test(EBPF_EXECUTION_INTERPRET);
}
TEST_CASE("divide_by_zero_interpret", "[divide_by_zero]") { divide_by_zero_test_km(EBPF_EXECUTION_INTERPRET); }
#endif