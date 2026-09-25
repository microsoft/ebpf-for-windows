// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "api_test.h"
#include "api_test_jit.h"
#include "bpf/bpf.h"
#include "bpf/libbpf.h"

#include <io.h>
#include <vector>

static void
_test_program_load(
    const char* file_name, bpf_prog_type program_type, ebpf_execution_type_t execution_type, int expected_load_result)
{
    struct bpf_object* object = nullptr;
    fd_t program_fd;

    int result = program_load_helper(file_name, program_type, execution_type, &object, &program_fd);
    REQUIRE(result == expected_load_result);
    if (expected_load_result != 0) {
        return;
    }

    REQUIRE(program_fd > 0);
    uint32_t next_id;
    REQUIRE(bpf_prog_get_next_id(0, &next_id) == 0);

    program_fd = bpf_prog_get_fd_by_id(next_id);
    REQUIRE(program_fd > 0);

    const char* program_file_name = nullptr;
    const char* program_section_name = nullptr;
    ebpf_execution_type_t program_execution_type;
    REQUIRE(
        ebpf_program_query_info(program_fd, &program_execution_type, &program_file_name, &program_section_name) ==
        EBPF_SUCCESS);
    _close(program_fd);

    if (execution_type == EBPF_EXECUTION_ANY) {
        execution_type = EBPF_EXECUTION_JIT;
    }
    REQUIRE(program_execution_type == execution_type);
    if (execution_type != EBPF_EXECUTION_NATIVE) {
        REQUIRE(strcmp(program_file_name, file_name) == 0);
    }

    ebpf_free_string(program_file_name);
    ebpf_free_string(program_section_name);
    uint32_t previous_id = next_id;
    REQUIRE(bpf_prog_get_next_id(previous_id, &next_id) == -ENOENT);

    bpf_object__close(object);
    REQUIRE(bpf_prog_get_next_id(0, &next_id) == -ENOENT);
}

#define DECLARE_LOAD_TEST_CASE(file, program_type, execution_type, expected_result)  \
    TEST_CASE("test_ebpf_program_load-" #file "-" #program_type "-" #execution_type) \
    {                                                                                \
        _test_program_load(file, program_type, execution_type, expected_result);     \
    }

#if defined(CONFIG_BPF_INTERPRETER_DISABLED)
#define INTERPRET_LOAD_RESULT -ENOTSUP
#else
#define INTERPRET_LOAD_RESULT 0
#endif

DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_JIT, JIT_LOAD_RESULT);
DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_INTERPRET, INTERPRET_LOAD_RESULT);
DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_BIND, EBPF_EXECUTION_JIT, JIT_LOAD_RESULT);
DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_SAMPLE, EBPF_EXECUTION_ANY, get_expected_jit_result(-EACCES));

struct _ebpf_program_load_test_parameters
{
    _Field_z_ const char* file_name;
    bpf_prog_type prog_type;
};

static void
_test_multiple_programs_load(
    int program_count,
    _In_reads_(program_count) const struct _ebpf_program_load_test_parameters* parameters,
    ebpf_execution_type_t execution_type,
    int expected_load_result)
{
    int result;
    std::vector<struct bpf_object*> objects;

    for (int i = 0; i < program_count; i++) {
        const char* file_name = parameters[i].file_name;
        bpf_prog_type program_type = parameters[i].prog_type;
        struct bpf_object* object;
        fd_t program_fd;

        result = program_load_helper(file_name, program_type, execution_type, &object, &program_fd);
        CAPTURE(file_name);
        REQUIRE(expected_load_result == result);
        if (expected_load_result == 0) {
            REQUIRE(program_fd > 0);
        } else {
            continue;
        }

        objects.push_back(object);
    }

    if (expected_load_result != 0) {
        return;
    }

    for (int i = 0; i < program_count; i++) {
        bpf_object__close(objects[i]);
    }
}

TEST_CASE("native_load_retry_after_insufficient_buffers", "[native_tests]")
{
    native_module_helper_t native_helper;
    native_helper.initialize("bindmonitor", EBPF_EXECUTION_NATIVE);

    std::vector<fd_t> map_fds(3, ebpf_fd_invalid);
    std::vector<fd_t> program_fds(1, ebpf_fd_invalid);
    size_t count_of_maps = 0;
    size_t count_of_programs = 0;

    ebpf_result_t result = ebpf_object_load_native_by_fds(
        native_helper.get_file_name().c_str(), &count_of_maps, nullptr, &count_of_programs, nullptr);

    REQUIRE(result == EBPF_NO_MEMORY);
    REQUIRE(count_of_maps == map_fds.size());
    REQUIRE(count_of_programs == program_fds.size());

    result = ebpf_object_load_native_by_fds(
        native_helper.get_file_name().c_str(), &count_of_maps, map_fds.data(), &count_of_programs, program_fds.data());

    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(count_of_maps == map_fds.size());
    REQUIRE(count_of_programs == program_fds.size());

    for (auto fd : map_fds) {
        REQUIRE(fd != ebpf_fd_invalid);
        _close(fd);
    }
    for (auto fd : program_fds) {
        REQUIRE(fd != ebpf_fd_invalid);
        _close(fd);
    }
}

TEST_CASE("load_all_sample_programs", "[native_tests]")
{
    struct _ebpf_program_load_test_parameters test_parameters[] = {
        {"bindmonitor.sys", BPF_PROG_TYPE_UNSPEC},
        {"bindmonitor_bpf2bpf.sys", BPF_PROG_TYPE_UNSPEC},
        {"bindmonitor_mt_tailcall.sys", BPF_PROG_TYPE_UNSPEC},
        {"bindmonitor_perf_event_array.sys", BPF_PROG_TYPE_UNSPEC},
        {"bindmonitor_ringbuf.sys", BPF_PROG_TYPE_UNSPEC},
        {"bindmonitor_tailcall.sys", BPF_PROG_TYPE_UNSPEC},
        {"cgroup_count_connect4.sys", BPF_PROG_TYPE_UNSPEC},
        {"cgroup_count_connect6.sys", BPF_PROG_TYPE_UNSPEC},
        {"cgroup_mt_connect4.sys", BPF_PROG_TYPE_UNSPEC},
        {"cgroup_mt_connect6.sys", BPF_PROG_TYPE_UNSPEC},
        {"cgroup_sock_addr.sys", BPF_PROG_TYPE_UNSPEC},
        {"cgroup_sock_addr2.sys", BPF_PROG_TYPE_UNSPEC},
        {"multiple_programs.sys", BPF_PROG_TYPE_UNSPEC},
        {"pidtgid.sys", BPF_PROG_TYPE_UNSPEC},
        {"printk.sys", BPF_PROG_TYPE_UNSPEC},
        {"printk_legacy.sys", BPF_PROG_TYPE_UNSPEC},
        {"process_start_key.sys", BPF_PROG_TYPE_UNSPEC},
        {"sockops.sys", BPF_PROG_TYPE_UNSPEC},
        {"strings.sys", BPF_PROG_TYPE_UNSPEC},
        {"tail_call_max_exceed.sys", BPF_PROG_TYPE_UNSPEC},
        {"thread_start_time.sys", BPF_PROG_TYPE_UNSPEC},
        {"utility.sys", BPF_PROG_TYPE_UNSPEC}};

    _test_multiple_programs_load(_countof(test_parameters), test_parameters, EBPF_EXECUTION_NATIVE, 0);
}
