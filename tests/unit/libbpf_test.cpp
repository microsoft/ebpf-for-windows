// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#pragma warning(push)
#pragma warning(disable : 4200)
#include "bpf/libbpf.h"
#pragma warning(pop)
#include "capture_helper.hpp"
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "ebpf_platform.h"
#include "ebpf_tracelog.h"
#include "ebpf_vm_isa.hpp"
#include "helpers.h"
#include "libbpf_test_jit.h"
#include "platform.h"
#include "program_helper.h"
#include "test_helper.hpp"

#include <chrono>
#include <fstream>
#include <stop_token>
#include <thread>

// Pulling in the prevail namespace to get the definitions in ebpf_vm_isa.h.
// See: https://github.com/vbpf/prevail/issues/876
using namespace prevail;

// libbpf.h uses enum types and generates the
// following warning whenever an enum type is used below:
// "The enum type 'bpf_attach_type' is unscoped.
// Prefer 'enum class' over 'enum'"
#pragma warning(disable : 26812)

// Set of all attach_types defined in ebpfcore. This must be updated any time a new bpf_attach_type is added.
static const std::set<bpf_attach_type> ebpf_core_attach_types = {
    BPF_ATTACH_TYPE_UNSPEC,
    BPF_ATTACH_TYPE_BIND,
    BPF_CGROUP_INET4_CONNECT,
    BPF_CGROUP_INET6_CONNECT,
    BPF_CGROUP_INET4_RECV_ACCEPT,
    BPF_CGROUP_INET6_RECV_ACCEPT,
    BPF_CGROUP_SOCK_OPS,
    BPF_ATTACH_TYPE_SAMPLE,
    BPF_XDP_TEST,
};

std::vector<uint8_t>
prepare_udp_packet(uint16_t udp_length, uint16_t ethernet_type);

TEST_CASE("empty bpf_load_program", "[libbpf][deprecated]")
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    // An empty set of instructions is invalid.
#pragma warning(suppress : 4996) // deprecated
    int program_fd = bpf_load_program(BPF_PROG_TYPE_SAMPLE, nullptr, 0, nullptr, 0, nullptr, 0);
    REQUIRE(program_fd < 0);
    REQUIRE(errno == EINVAL);
}

TEST_CASE("empty bpf_prog_load", "[libbpf]")
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    // An empty set of instructions is invalid.
    int program_fd = bpf_prog_load(BPF_PROG_TYPE_SAMPLE, "name", "license", nullptr, 0, nullptr);
    REQUIRE(program_fd < 0);
    REQUIRE(errno == EINVAL);
}

TEST_CASE("too big bpf_prog_load", "[libbpf]")
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    // An empty set of instructions is invalid.
    int program_fd = bpf_prog_load(BPF_PROG_TYPE_SAMPLE, "name", "license", nullptr, UINT32_MAX, nullptr);
    REQUIRE(program_fd < 0);
    REQUIRE(errno == EINVAL);
}

TEST_CASE("invalid bpf_load_program", "[libbpf][deprecated]")
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    // Try with an invalid set of instructions.
    prevail::EbpfInst instructions[] = {
        {INST_OP_EXIT}, // return r0
    };

    // Try to load and verify the eBPF program.
    char log_buffer[1024];
#pragma warning(suppress : 4996) // deprecated
    int program_fd = bpf_load_program(
        BPF_PROG_TYPE_SAMPLE,
        (struct bpf_insn*)instructions,
        _countof(instructions),
        nullptr,
        0,
        log_buffer,
        sizeof(log_buffer));
    REQUIRE(program_fd < 0);
    test_invalid_bpf_action(log_buffer);
}

TEST_CASE("invalid bpf_prog_load", "[libbpf]")
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    // Try with an invalid set of instructions.
    prevail::EbpfInst instructions[] = {
        {INST_OP_EXIT}, // return r0
    };

    // Try to load and verify the eBPF program.
    char log_buffer[1024] = "";
    struct bpf_prog_load_opts opts = {.sz = sizeof(opts), .log_size = sizeof(log_buffer), .log_buf = log_buffer};
    int program_fd = bpf_prog_load(
        BPF_PROG_TYPE_SAMPLE, "name", "license", (struct bpf_insn*)instructions, _countof(instructions), &opts);
    REQUIRE(program_fd < 0);
    test_invalid_bpf_action(log_buffer);
}

TEST_CASE("invalid bpf_load_program - wrong type", "[libbpf][deprecated]")
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    // Try with a valid set of instructions.
    prevail::EbpfInst instructions[] = {
        {0xb7, R0_RETURN_VALUE, 0}, // r0 = 0
        {INST_OP_EXIT},             // return r0
    };

    // Load and verify the eBPF program.
#pragma warning(suppress : 4996) // deprecated
    int program_fd = bpf_load_program(
        (bpf_prog_type)-1, (struct bpf_insn*)instructions, _countof(instructions), nullptr, 0, nullptr, 0);
    REQUIRE(program_fd < 0);
    REQUIRE(errno == EINVAL);
}

TEST_CASE("invalid bpf_prog_load - wrong type", "[libbpf]")
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    // Try with a valid set of instructions.
    prevail::EbpfInst instructions[] = {
        {0xb7, R0_RETURN_VALUE, 0}, // r0 = 0
        {INST_OP_EXIT},             // return r0
    };

    // Load and verify the eBPF program.
    int program_fd = bpf_prog_load(
        (bpf_prog_type)-1, "name", "license", (struct bpf_insn*)instructions, _countof(instructions), nullptr);
    REQUIRE(program_fd < 0);
    REQUIRE(errno == EINVAL);
}

// This is a set of tests which utilize the libbpf XDP APIs.
// The XDP extension is built outside of the ebpf-for-windows repo
// and therefore these APIs are expected to gracefully fail.
TEST_CASE("libbpf xdp negative", "[libbpf]")
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    uint32_t program_id;
    REQUIRE(bpf_xdp_query_id(TEST_IFINDEX, 0, &program_id) < 0);

    REQUIRE(bpf_xdp_attach(TEST_IFINDEX, 0, 0, nullptr) < 0);

    REQUIRE(bpf_xdp_detach(TEST_IFINDEX, 0, nullptr) == 0);

#pragma warning(suppress : 4996) // deprecated
    REQUIRE(bpf_set_link_xdp_fd(TEST_IFINDEX, 0, 0) < 0);

#pragma warning(suppress : 4996) // deprecated
    REQUIRE(bpf_program__attach_xdp(nullptr, TEST_IFINDEX) == nullptr);
}

TEST_CASE("libbpf create queue", "[libbpf]")
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    bpf_map_create_opts opts = {0};
    const uint32_t max_entries = 2;
    const uint32_t value_size = sizeof(uint32_t);
    int map_fd = bpf_map_create(BPF_MAP_TYPE_QUEUE, "MapName", sizeof(uint32_t), value_size, max_entries, &opts);
    REQUIRE(map_fd < 0);

    map_fd = bpf_map_create(BPF_MAP_TYPE_QUEUE, "MapName", 0, value_size, max_entries, &opts);
    REQUIRE(map_fd > 0);

    bpf_map_info info;
    uint32_t info_size = sizeof(info);
    REQUIRE(bpf_obj_get_info_by_fd(map_fd, &info, &info_size) == 0);

    REQUIRE(info.type == BPF_MAP_TYPE_QUEUE);
    REQUIRE(info.key_size == 0);
    REQUIRE(info.value_size == value_size);
    REQUIRE(info.max_entries == max_entries);
    REQUIRE(info.map_flags == 0);
    REQUIRE(info.inner_map_id == EBPF_ID_NONE);
    REQUIRE(info.pinned_path_count == 0);
    REQUIRE(info.id > 0);
    REQUIRE(strcmp(info.name, "MapName") == 0);

    uint32_t next_key;
    int err = bpf_map_get_next_key(map_fd, NULL, &next_key);
    REQUIRE(err == -ENOTSUP);

    // Push 2 elements.
    uint32_t value = 1;
    REQUIRE(bpf_map_update_elem(map_fd, nullptr, &value, 0) == 0);
    value = 2;
    REQUIRE(bpf_map_update_elem(map_fd, nullptr, &value, 0) == 0);

    // Pop elements.
    REQUIRE(bpf_map_lookup_elem(map_fd, nullptr, &value) == 0);
    REQUIRE(value == 1);
    REQUIRE(bpf_map_lookup_and_delete_elem(map_fd, nullptr, &value) == 0);
    REQUIRE(value == 1);
    REQUIRE(bpf_map_lookup_elem(map_fd, nullptr, &value) == 0);
    REQUIRE(value == 2);
    REQUIRE(bpf_map_lookup_and_delete_elem(map_fd, nullptr, &value) == 0);
    REQUIRE(value == 2);
    REQUIRE(bpf_map_lookup_elem(map_fd, nullptr, &value) == -ENOENT);
    REQUIRE(bpf_map_lookup_and_delete_elem(map_fd, nullptr, &value) == -ENOENT);

    Platform::_close(map_fd);
}

TEST_CASE("libbpf create ringbuf", "[libbpf]")
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    bpf_map_create_opts opts = {0};
    const uint32_t max_entries = 128 * 1024;
    const uint32_t value_size = sizeof(uint32_t);

    // Wrong key and value size.
    int map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "MapName", sizeof(uint32_t), value_size, max_entries, &opts);
    REQUIRE(map_fd < 0);

    // Max_entries too small.
    map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "MapName", 0, 0, 1024, &opts);
    REQUIRE(map_fd < 0);

    map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "MapName", 0, 0, max_entries, &opts);
    REQUIRE(map_fd > 0);

    bpf_map_info info;
    uint32_t info_size = sizeof(info);
    REQUIRE(bpf_obj_get_info_by_fd(map_fd, &info, &info_size) == 0);

    REQUIRE(info.type == BPF_MAP_TYPE_RINGBUF);
    REQUIRE(info.key_size == 0);
    REQUIRE(info.value_size == 0);
    REQUIRE(info.max_entries == max_entries);
    REQUIRE(info.map_flags == 0);
    REQUIRE(info.inner_map_id == EBPF_ID_NONE);
    REQUIRE(info.pinned_path_count == 0);
    REQUIRE(info.id > 0);
    REQUIRE(strcmp(info.name, "MapName") == 0);

    int key;
    int value;
    int result = bpf_map_lookup_elem(map_fd, &key, &value);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);
    result = bpf_map_update_elem(map_fd, &key, &value, 0);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);
    result = bpf_map_delete_elem(map_fd, &key);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    result = bpf_map_get_next_key(map_fd, &key, &value);
    REQUIRE(result < 0);
    REQUIRE(errno == ENOTSUP);

    Platform::_close(map_fd);
}

TEST_CASE("good_tail_call-native", "[libbpf]")
{
    // Verify that 42 is returned, which is done by the callee.
    ebpf_test_tail_call("tail_call_um.dll", 42);
}

TEST_CASE("good_tail_call_same_section-native", "[libbpf]")
{
    // Verify that 42 is returned, which is done by the callee.
    ebpf_test_tail_call("tail_call_same_section_um.dll", 42);
}

TEST_CASE("bad_tail_call-native", "[libbpf]")
{
    ebpf_test_tail_call("tail_call_bad_um.dll", (uint32_t)(-EBPF_INVALID_ARGUMENT));
}

static void
_multiple_tail_calls_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    const char* file_name =
        (execution_type == EBPF_EXECUTION_NATIVE ? "tail_call_multiple_um.dll" : "tail_call_multiple.o");

    struct bpf_object* object = bpf_object__open(file_name);
    REQUIRE(object != nullptr);

    // Load the program(s).
    REQUIRE(bpf_object__load(object) == 0);

    struct bpf_program* caller = bpf_object__find_program_by_name(object, "caller");
    REQUIRE(caller != nullptr);

    struct bpf_program* callee0 = bpf_object__find_program_by_name(object, "callee0");
    REQUIRE(callee0 != nullptr);

    struct bpf_program* callee1 = bpf_object__find_program_by_name(object, "callee1");
    REQUIRE(callee1 != nullptr);

    struct bpf_map* map = bpf_object__next_map(object, nullptr);
    REQUIRE(map != nullptr);

    int callee0_fd = bpf_program__fd(callee0);
    REQUIRE(callee0_fd >= 0);

    int callee1_fd = bpf_program__fd(callee1);
    REQUIRE(callee1_fd >= 0);

    int map_fd = bpf_map__fd(map);
    REQUIRE(map_fd >= 0);

    // Store callee0 at index 0.
    int index = 0;
    int error = bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&callee0_fd, 0);
    REQUIRE(error == 0);

    // Store callee1 at index 9.
    index = 9;
    error = bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&callee1_fd, 0);
    REQUIRE(error == 0);

    ebpf_id_t callee_id;
    // Verify that we can read the values back.
    index = 0;
    REQUIRE(bpf_map_lookup_elem(map_fd, &index, &callee_id) == 0);

    // Verify that we can convert the ID to a new fd, so we know it is actually
    // a valid program ID.
    int callee0_fd2 = bpf_prog_get_fd_by_id(callee_id);
    REQUIRE(callee0_fd2 > 0);
    Platform::_close(callee0_fd2);

    index = 9;
    REQUIRE(bpf_map_lookup_elem(map_fd, &index, &callee_id) == 0);

    // Verify that we can convert the ID to a new fd, so we know it is actually
    // a valid program ID.
    int callee1_fd2 = bpf_prog_get_fd_by_id(callee_id);
    REQUIRE(callee1_fd2 > 0);
    Platform::_close(callee1_fd2);

    bpf_link_ptr link(bpf_program__attach(caller));
    REQUIRE(link != nullptr);

    auto packet = prepare_udp_packet(0, ETHERNET_TYPE_IPV4);
    INITIALIZE_SAMPLE_CONTEXT
    uint32_t result;
    REQUIRE(hook.fire(ctx, &result) == EBPF_SUCCESS);
    REQUIRE(result == 3);

    // Clear the prog array map entries. This is needed to release reference on the
    // programs which are inserted in the prog array.
    index = 0;
    REQUIRE(bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&ebpf_fd_invalid, 0) == 0);
    REQUIRE(error == 0);

    index = 9;
    REQUIRE(bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&ebpf_fd_invalid, 0) == 0);
    REQUIRE(error == 0);

    result = bpf_link__destroy(link.release());
    REQUIRE(result == 0);
    bpf_object__close(object);
}

DECLARE_JIT_TEST_CASES("multiple tail calls", "[libbpf]", _multiple_tail_calls_test);

static void
_test_bind_fd_to_prog_array(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    program_info_provider_t bind_program_info;
    REQUIRE(bind_program_info.initialize(EBPF_PROGRAM_TYPE_BIND) == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "tail_call_um.dll" : "tail_call.o");
    struct bpf_object* sample_object = bpf_object__open(file_name);
    REQUIRE(sample_object != nullptr);

    // Load the program(s).
    REQUIRE(bpf_object__load(sample_object) == 0);

    struct bpf_map* map = bpf_object__find_map_by_name(sample_object, "map");
    REQUIRE(map != nullptr);

    // Load a program of any other type.
    // Note: We are deliberately using "bindmonitor_um.dll" here as we want the programs to be loaded from
    // the individual dll, instead of the combined DLL. This helps in testing the DLL stub which is generated
    // bpf2c.exe tool.
    const char* another_file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "bindmonitor_um.dll" : "bindmonitor.o");
    struct bpf_object* bind_object = bpf_object__open(another_file_name);
    REQUIRE(bind_object != nullptr);
    // Load the program(s).
    REQUIRE(bpf_object__load(bind_object) == 0);

    struct bpf_program* callee = bpf_object__find_program_by_name(bind_object, "BindMonitor");
    REQUIRE(callee != nullptr);

    int callee_fd = bpf_program__fd(callee);
    REQUIRE(callee_fd >= 0);

    int map_fd = bpf_map__fd(map);
    REQUIRE(map_fd >= 0);

    bpf_prog_info program_info = {};
    uint32_t program_info_size = sizeof(program_info);
    REQUIRE(bpf_obj_get_info_by_fd(callee_fd, &program_info, &program_info_size) == 0);
    REQUIRE(program_info_size == sizeof(program_info));
    REQUIRE(strcmp(program_info.name, "BindMonitor") == 0);
    REQUIRE(program_info.type == BPF_PROG_TYPE_BIND);

    // Verify that we cannot add a BIND program fd to a prog_array map already
    // associated with a SAMPLE program.
    int index = 0;
    int error = bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&callee_fd, 0);
    REQUIRE(error < 0);
    REQUIRE(errno == EBADF);

    bpf_object__close(bind_object);
    bpf_object__close(sample_object);
}

DECLARE_ALL_TEST_CASES("disallow setting bind fd in sample prog array", "[libbpf]", _test_bind_fd_to_prog_array);

static void
_load_inner_map(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "inner_map_um.dll" : "inner_map.o");
    struct bpf_object* sample_object = bpf_object__open(file_name);
    REQUIRE(sample_object != nullptr);

    // Load the program(s).
    REQUIRE(bpf_object__load(sample_object) == 0);

    struct bpf_map* map = bpf_object__find_map_by_name(sample_object, "outer_map");
    REQUIRE(map != nullptr);
    REQUIRE(bpf_map__type(map) == BPF_MAP_TYPE_HASH_OF_MAPS);

    bpf_object__close(sample_object);
}

DECLARE_ALL_TEST_CASES("Test loading BPF program with anonymous inner map", "[libbpf]", _load_inner_map);

static void
_enumerate_program_ids_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    // Verify the enumeration is empty.
    uint32_t id1;
    REQUIRE(bpf_prog_get_next_id(0, &id1) < 0);
    REQUIRE(errno == ENOENT);

    REQUIRE(bpf_prog_get_next_id(EBPF_ID_NONE, &id1) < 0);
    REQUIRE(errno == ENOENT);

    // Load a file with multiple programs.
    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "tail_call_um.dll" : "tail_call.o");
    struct bpf_object* sample_object = bpf_object__open(file_name);
    REQUIRE(sample_object != nullptr);

    // Load the program(s).
    REQUIRE(bpf_object__load(sample_object) == 0);

    // Now enumerate the IDs.
    REQUIRE(bpf_prog_get_next_id(0, &id1) == 0);
    fd_t fd1 = bpf_prog_get_fd_by_id(id1);
    REQUIRE(fd1 >= 0);
    Platform::_close(fd1);

    uint32_t id2;
    REQUIRE(bpf_prog_get_next_id(id1, &id2) == 0);
    fd_t fd2 = bpf_prog_get_fd_by_id(id2);
    REQUIRE(fd2 >= 0);
    Platform::_close(fd2);

    uint32_t id3;
    REQUIRE(bpf_prog_get_next_id(id2, &id3) < 0);
    REQUIRE(errno == ENOENT);

    bpf_object__close(sample_object);
}

DECLARE_JIT_TEST_CASES("enumerate program IDs", "[libbpf]", _enumerate_program_ids_test);

static uint32_t
_ebpf_test_count_entries_map_in_map(int outer_map_fd)
{
    uint32_t entries_count = 0;
    uint32_t outer_key = 0;
    void* old_key = nullptr;
    void* key = &outer_key;

    while (bpf_map_get_next_key(outer_map_fd, old_key, key) == 0) {
        old_key = key;
        entries_count++;
    }
    return entries_count;
}

static void
_ebpf_test_map_in_map(ebpf_map_type_t type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    // Create an inner map that we'll use both as a template and as an actual entry.
    int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "inner_map", sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(inner_map_fd > 0);

    // Verify that we cannot simply create an outer map without a template.
    REQUIRE(bpf_map_create(type, "array_map_of_maps", sizeof(__u32), sizeof(__u32), 2, nullptr) < 0);
    REQUIRE(errno == EBADF);

    // Verify that we cannot create an outer map with an invalid fd for the inner map.
    bpf_map_create_opts opts = {.inner_map_fd = (uint32_t)ebpf_fd_invalid};
    REQUIRE(bpf_map_create(type, "array_map_of_maps", sizeof(__u32), sizeof(fd_t), 2, &opts) < 0);
    REQUIRE(errno == EBADF);

    // Verify we can create an outer map with a template.
    opts.inner_map_fd = inner_map_fd;
    int outer_map_fd = bpf_map_create(type, "array_map_of_maps", sizeof(__u32), sizeof(fd_t), 2, &opts);
    REQUIRE(outer_map_fd > 0);

    // Verify that lookup of an empty slot in the map returns ENOENT.
    ebpf_id_t inner_map_id;
    __u32 outer_key = 0;
    REQUIRE(bpf_map_lookup_elem(outer_map_fd, &outer_key, &inner_map_id) == -ENOENT);
    REQUIRE(errno == ENOENT);

    // Verify we can insert the inner map into the outer map.
    int error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error == 0);

    uint32_t count = _ebpf_test_count_entries_map_in_map(outer_map_fd);
    // Verify the number of elements in the outer map.
    if (type == BPF_MAP_TYPE_HASH_OF_MAPS) {
        REQUIRE(count == 1);
    } else {
        // For ARRAY_OF_MAPS, the count is max_entries.
        REQUIRE(count == 2);
    }

    // Verify that we can read it back.
    REQUIRE(bpf_map_lookup_elem(outer_map_fd, &outer_key, &inner_map_id) == 0);

    // Verify that we can convert the ID to a new fd, so we know it is actually
    // a valid map ID.
    int inner_map_fd2 = bpf_map_get_fd_by_id(inner_map_id);
    REQUIRE(inner_map_fd2 > 0);
    Platform::_close(inner_map_fd2);

    // Verify we can't insert an integer into the outer map.
    __u32 bad_value = 12345678;
    outer_key = 1;
    error = bpf_map_update_elem(outer_map_fd, &outer_key, &bad_value, 0);
    REQUIRE(error < 0);
    REQUIRE(errno == EBADF);

    if (type == BPF_MAP_TYPE_HASH_OF_MAPS) {
        // Try deleting outer key that doesn't exist.
        error = bpf_map_delete_elem(outer_map_fd, &outer_key);
        REQUIRE(error < 0);
        REQUIRE(errno == ENOENT);
    }

    // Try deleting outer key that does exist.
    outer_key = 0;
    error = bpf_map_delete_elem(outer_map_fd, &outer_key);
    REQUIRE(error == 0);

    // Verify the number of elements in the outer map is 0.
    if (type == BPF_MAP_TYPE_HASH_OF_MAPS) {
        REQUIRE(_ebpf_test_count_entries_map_in_map(outer_map_fd) == 0);
    } else {
        // For ARRAY_OF_MAPS, the count is max_entries.
        REQUIRE(_ebpf_test_count_entries_map_in_map(outer_map_fd) == 2);
    }

    Platform::_close(inner_map_fd);
    Platform::_close(outer_map_fd);

    // Verify that all maps were successfully removed.
    uint32_t id;
    REQUIRE(bpf_map_get_next_id(0, &id) < 0);
    REQUIRE(errno == ENOENT);
}

// Verify libbpf can create and update arrays of maps.
TEST_CASE("simple array of maps", "[libbpf]") { _ebpf_test_map_in_map(BPF_MAP_TYPE_ARRAY_OF_MAPS); }

// Verify libbpf can create and update hash tables of maps.
TEST_CASE("simple hash of maps", "[libbpf]") { _ebpf_test_map_in_map(BPF_MAP_TYPE_HASH_OF_MAPS); }

// Verify an app can communicate with an eBPF program via an array of maps.
static void
_array_of_maps_test(ebpf_execution_type_t execution_type, _In_ PCSTR dll_name, _In_ PCSTR obj_name)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? dll_name : obj_name);
    struct bpf_object* sample_object = bpf_object__open(file_name);
    REQUIRE(sample_object != nullptr);

    // Load the program(s).
    REQUIRE(bpf_object__load(sample_object) == 0);

    struct bpf_program* caller = bpf_object__find_program_by_name(sample_object, "lookup");
    REQUIRE(caller != nullptr);

    struct bpf_map* outer_map = bpf_object__find_map_by_name(sample_object, "outer_map");
    REQUIRE(outer_map != nullptr);

    int outer_map_fd = bpf_map__fd(outer_map);
    REQUIRE(outer_map_fd > 0);

    // Create an inner map.
    int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(inner_map_fd > 0);

    // Add a value to the inner map.
    uint32_t inner_value = 42;
    uint32_t inner_key = 0;
    int error = bpf_map_update_elem(inner_map_fd, &inner_key, &inner_value, 0);
    REQUIRE(error == 0);

    // Add inner map to outer map.
    __u32 outer_key = 0;
    error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error == 0);

    bpf_link_ptr link(bpf_program__attach(caller));
    REQUIRE(link != nullptr);

    // Now run the ebpf program.
    INITIALIZE_SAMPLE_CONTEXT
    uint32_t result;
    REQUIRE(hook.fire(ctx, &result) == EBPF_SUCCESS);

    // Verify the return value is what we saved in the inner map.
    REQUIRE(result == inner_value);

    Platform::_close(inner_map_fd);
    result = bpf_link__destroy(link.release());
    REQUIRE(result == 0);
    bpf_object__close(sample_object);
}

// Create a map-in-map using BTF ids.
static void
_array_of_btf_maps_test(ebpf_execution_type_t execution_type)
{
    _array_of_maps_test(execution_type, "map_in_map_btf_um.dll", "map_in_map_btf.o");
}

DECLARE_JIT_TEST_CASES("array of btf maps", "[libbpf]", _array_of_btf_maps_test);

// Create a map-in-map using id and inner_id.
static void
_array_of_id_maps_test(ebpf_execution_type_t execution_type)
{
    _array_of_maps_test(execution_type, "map_in_map_legacy_id_um.dll", "map_in_map_legacy_id.o");
}

DECLARE_JIT_TEST_CASES("array of id maps", "[libbpf]", _array_of_id_maps_test);

// Create a map-in-map using map indices.
static void
_array_of_idx_maps_test(ebpf_execution_type_t execution_type)
{
    _array_of_maps_test(execution_type, "map_in_map_legacy_idx_um.dll", "map_in_map_legacy_idx.o");
}

DECLARE_JIT_TEST_CASES("array of idx maps", "[libbpf]", _array_of_idx_maps_test);

static void
_wrong_inner_map_types_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "map_in_map_btf_um.dll" : "map_in_map_btf.o");
    struct bpf_object* sample_object = bpf_object__open(file_name);
    REQUIRE(sample_object != nullptr);

    // Load the program(s).
    REQUIRE(bpf_object__load(sample_object) == 0);

    struct bpf_map* outer_map = bpf_object__find_map_by_name(sample_object, "outer_map");
    REQUIRE(outer_map != nullptr);

    int outer_map_fd = bpf_map__fd(outer_map);
    REQUIRE(outer_map_fd > 0);

    // Create an inner map of the wrong type.
    int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(inner_map_fd > 0);

    // Try to add the array map to the outer map.
    __u32 outer_key = 0;
    int error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error < 0);
    REQUIRE(errno == EINVAL);

    Platform::_close(inner_map_fd);

    // Try an inner map with wrong key_size.
    inner_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, nullptr, sizeof(__u64), sizeof(__u32), 1, nullptr);
    REQUIRE(inner_map_fd > 0);
    error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error < 0);
    REQUIRE(errno == EINVAL);
    Platform::_close(inner_map_fd);

    // Try an inner map of the wrong value size.
    inner_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, nullptr, sizeof(__u32), sizeof(__u64), 1, nullptr);
    REQUIRE(inner_map_fd > 0);
    error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error < 0);
    REQUIRE(errno == EINVAL);
    Platform::_close(inner_map_fd);

    // Try an inner map with wrong max_entries.
    inner_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, nullptr, sizeof(__u32), sizeof(__u32), 2, nullptr);
    REQUIRE(inner_map_fd > 0);
    error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error < 0);
    REQUIRE(errno == EINVAL);
    Platform::_close(inner_map_fd);

    bpf_object__close(sample_object);
}

DECLARE_JIT_TEST_CASES("disallow wrong inner map types", "[libbpf]", _wrong_inner_map_types_test);

TEST_CASE("create map with name", "[libbpf]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    // Create a map with a given name.
    PCSTR name = "mymapname";
    int map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, name, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(map_fd > 0);

    // Make sure the name matches what we set.
    bpf_map_info info;
    uint32_t info_size = sizeof(info);
    REQUIRE(bpf_obj_get_info_by_fd(map_fd, &info, &info_size) == 0);
    REQUIRE(strcmp(info.name, name) == 0);

    Platform::_close(map_fd);
}

TEST_CASE("enumerate map IDs", "[libbpf]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    // Verify the enumeration is empty.
    uint32_t id1;
    REQUIRE(bpf_map_get_next_id(0, &id1) < 0);
    REQUIRE(errno == ENOENT);

    REQUIRE(bpf_map_get_next_id(EBPF_ID_NONE, &id1) < 0);
    REQUIRE(errno == ENOENT);

    // Create two maps.
    int map1_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(map1_fd > 0);

    int map2_fd = bpf_map_create(BPF_MAP_TYPE_HASH, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(map2_fd > 0);

    // Now enumerate the IDs.
    REQUIRE(bpf_map_get_next_id(0, &id1) == 0);
    fd_t fd1 = bpf_map_get_fd_by_id(id1);
    REQUIRE(fd1 >= 0);
    Platform::_close(fd1);

    uint32_t id2;
    REQUIRE(bpf_map_get_next_id(id1, &id2) == 0);
    fd_t fd2 = bpf_map_get_fd_by_id(id2);
    REQUIRE(fd2 >= 0);
    Platform::_close(fd2);

    uint32_t id3;
    REQUIRE(bpf_map_get_next_id(id2, &id3) < 0);
    REQUIRE(errno == ENOENT);

    Platform::_close(map1_fd);
    Platform::_close(map2_fd);
    Platform::_close(fd1);
    Platform::_close(fd2);
}

TEST_CASE("libbpf_prog_type_by_name_test", "[libbpf]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    bpf_prog_type prog_type;
    bpf_attach_type expected_attach_type;

    // Try a cross-platform type.
    REQUIRE(libbpf_prog_type_by_name("xdp", &prog_type, &expected_attach_type) == 0);
    REQUIRE(prog_type == BPF_PROG_TYPE_XDP);
    REQUIRE(expected_attach_type == BPF_XDP);

    // Try a Windows-specific type.
    REQUIRE(libbpf_prog_type_by_name("bind", &prog_type, &expected_attach_type) == 0);
    REQUIRE(prog_type == BPF_PROG_TYPE_BIND);
    REQUIRE(expected_attach_type == BPF_ATTACH_TYPE_BIND);

    // Try a random name. This should fail.
    REQUIRE(libbpf_prog_type_by_name("default", &prog_type, &expected_attach_type) == -ESRCH);
    REQUIRE(errno == ESRCH);

    REQUIRE(libbpf_prog_type_by_name(nullptr, &prog_type, &expected_attach_type) == -EINVAL);
    REQUIRE(errno == EINVAL);
}

TEST_CASE("libbpf_bpf_prog_type_str", "[libbpf]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    const char* prog_type_str_sample = libbpf_bpf_prog_type_str(BPF_PROG_TYPE_SAMPLE);
    REQUIRE(prog_type_str_sample);
    REQUIRE(strcmp(prog_type_str_sample, "sample") == 0);
    const char* prog_type_str_unspec = libbpf_bpf_prog_type_str(BPF_PROG_TYPE_UNSPEC);
    REQUIRE(prog_type_str_unspec);
    REQUIRE(strcmp(prog_type_str_unspec, "unspec") == 0);
    REQUIRE(libbpf_bpf_prog_type_str((bpf_prog_type)123) == nullptr);
}

TEST_CASE("libbpf_get_error", "[libbpf]")
{
    errno = 123;
    REQUIRE(libbpf_get_error(nullptr) == -123);

    char buffer[80];
    REQUIRE(libbpf_strerror(errno, buffer, sizeof(buffer)) == -ENOENT);
    REQUIRE(strcmp(buffer, "Unknown libbpf error 123") == 0);
}

TEST_CASE("libbpf attach type names", "[libbpf]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    enum bpf_attach_type attach_type;
    for (int i = 1; i < __MAX_BPF_ATTACH_TYPE; i++) {
        // Skip types that are not defined in ebpfcore.
        if (ebpf_core_attach_types.find(static_cast<bpf_attach_type>(i)) == ebpf_core_attach_types.end())
            continue;
        const char* type_str = libbpf_bpf_attach_type_str((enum bpf_attach_type)i);

        REQUIRE(libbpf_attach_type_by_name(type_str, &attach_type) == 0);
        REQUIRE(attach_type == i);
    }
    REQUIRE(strcmp(libbpf_bpf_attach_type_str(BPF_ATTACH_TYPE_UNSPEC), "unspec") == 0);
    REQUIRE(libbpf_bpf_attach_type_str((bpf_attach_type)123) == nullptr);
    REQUIRE(libbpf_attach_type_by_name("other", &attach_type) == -ESRCH);
    REQUIRE(libbpf_attach_type_by_name(nullptr, &attach_type) == -EINVAL);
}

TEST_CASE("libbpf link type names", "[libbpf]")
{
    REQUIRE(strcmp(libbpf_bpf_link_type_str(BPF_LINK_TYPE_PLAIN), "plain") == 0);
    REQUIRE(strcmp(libbpf_bpf_link_type_str(BPF_LINK_TYPE_UNSPEC), "unspec") == 0);
    REQUIRE(strcmp(libbpf_bpf_link_type_str(BPF_LINK_TYPE_CGROUP), "cgroup") == 0);
    REQUIRE(strcmp(libbpf_bpf_link_type_str(BPF_LINK_TYPE_XDP), "xdp") == 0);
    REQUIRE(libbpf_bpf_link_type_str((bpf_link_type)123) == nullptr);
}

TEST_CASE("libbpf map type names", "[libbpf]")
{
    REQUIRE(strcmp(libbpf_bpf_map_type_str(BPF_MAP_TYPE_UNSPEC), "unspec") == 0);
    REQUIRE(strcmp(libbpf_bpf_map_type_str(BPF_MAP_TYPE_HASH), "hash") == 0);
    REQUIRE(strcmp(libbpf_bpf_map_type_str(BPF_MAP_TYPE_ARRAY), "array") == 0);
    REQUIRE(strcmp(libbpf_bpf_map_type_str(BPF_MAP_TYPE_PROG_ARRAY), "prog_array") == 0);
    REQUIRE(strcmp(libbpf_bpf_map_type_str(BPF_MAP_TYPE_PERCPU_HASH), "percpu_hash") == 0);
    REQUIRE(strcmp(libbpf_bpf_map_type_str(BPF_MAP_TYPE_PERCPU_ARRAY), "percpu_array") == 0);
    REQUIRE(strcmp(libbpf_bpf_map_type_str(BPF_MAP_TYPE_HASH_OF_MAPS), "hash_of_maps") == 0);
    REQUIRE(strcmp(libbpf_bpf_map_type_str(BPF_MAP_TYPE_ARRAY_OF_MAPS), "array_of_maps") == 0);
    REQUIRE(strcmp(libbpf_bpf_map_type_str(BPF_MAP_TYPE_LRU_HASH), "lru_hash") == 0);
    REQUIRE(strcmp(libbpf_bpf_map_type_str(BPF_MAP_TYPE_LPM_TRIE), "lpm_trie") == 0);
    REQUIRE(strcmp(libbpf_bpf_map_type_str(BPF_MAP_TYPE_QUEUE), "queue") == 0);
    REQUIRE(strcmp(libbpf_bpf_map_type_str(BPF_MAP_TYPE_LRU_PERCPU_HASH), "lru_percpu_hash") == 0);
    REQUIRE(strcmp(libbpf_bpf_map_type_str(BPF_MAP_TYPE_STACK), "stack") == 0);
    REQUIRE(strcmp(libbpf_bpf_map_type_str(BPF_MAP_TYPE_RINGBUF), "ringbuf") == 0);
    REQUIRE(strcmp(libbpf_bpf_map_type_str(BPF_MAP_TYPE_PERF_EVENT_ARRAY), "perf_event_array") == 0);
    REQUIRE(libbpf_bpf_map_type_str((bpf_map_type)123) == nullptr);
}

TEST_CASE("bpf_object__open with .dll", "[libbpf]")
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    struct bpf_object* object = bpf_object__open("test_sample_ebpf_um.dll");
    REQUIRE(object != nullptr);

    struct bpf_program* program = bpf_object__next_program(object, nullptr);
    REQUIRE(program != nullptr);
    REQUIRE(bpf_program__type(program) == BPF_PROG_TYPE_SAMPLE);
    REQUIRE(bpf_program__get_expected_attach_type(program) == BPF_ATTACH_TYPE_SAMPLE);

    REQUIRE(bpf_object__next_program(object, program) == nullptr);

    // Trying to attach the program should fail since it's not loaded yet.
    bpf_link_ptr link(bpf_program__attach(program));
    REQUIRE(link == nullptr);
    REQUIRE(libbpf_get_error(link.get()) == -EINVAL);

    // Load the program.
    REQUIRE(bpf_object__load(object) == 0);

    // Attach should now succeed.
    link.reset(bpf_program__attach(program));
    REQUIRE(link != nullptr);

    REQUIRE(bpf_link__destroy(link.release()) == 0);

    bpf_object__close(object);
}

TEST_CASE("bpf_object__open_file with .dll", "[libbpf]")
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    const char* my_object_name = "my_object_name";
    struct bpf_object_open_opts opts = {0};
    opts.object_name = my_object_name;
    struct bpf_object* object = bpf_object__open_file("test_sample_ebpf_um.dll", &opts);
    REQUIRE(object != nullptr);

    REQUIRE(strcmp(bpf_object__name(object), my_object_name) == 0);

    struct bpf_program* program = bpf_object__next_program(object, nullptr);
    REQUIRE(program != nullptr);
    REQUIRE(bpf_program__type(program) == BPF_PROG_TYPE_SAMPLE);
    REQUIRE(bpf_program__get_expected_attach_type(program) == BPF_ATTACH_TYPE_SAMPLE);

    REQUIRE(bpf_object__next_program(object, program) == nullptr);

    struct bpf_map* map = bpf_object__next_map(object, nullptr);
    REQUIRE(map != nullptr);
    REQUIRE(strcmp(bpf_map__name(map), "test_map") == 0);
    REQUIRE(bpf_map__fd(map) == ebpf_fd_invalid);
    map = bpf_object__next_map(object, map);
    REQUIRE(map == nullptr);

    // Trying to attach the program should fail since it's not loaded yet.
    bpf_link_ptr link(bpf_program__attach(program));
    REQUIRE(link == nullptr);
    REQUIRE(libbpf_get_error(link.get()) == -EINVAL);

    // Load the program.
    REQUIRE(bpf_object__load(object) == 0);

    // The maps should now have FDs.
    map = bpf_object__next_map(object, nullptr);
    REQUIRE(map != nullptr);
    REQUIRE(strcmp(bpf_map__name(map), "test_map") == 0);
    REQUIRE(bpf_map__fd(map) != ebpf_fd_invalid);
    map = bpf_object__next_map(object, map);
    REQUIRE(map == nullptr);

    // Attach should now succeed.
    link.reset(bpf_program__attach(program));
    REQUIRE(link != nullptr);

    REQUIRE(bpf_link__destroy(link.release()) == 0);

    bpf_object__close(object);
}

TEST_CASE("bpf_object__load with .dll", "[libbpf]")
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    const char* my_object_name = "my_object_name";
    struct bpf_object_open_opts opts = {0};
    opts.object_name = my_object_name;
    struct bpf_object* object = bpf_object__open_file("droppacket_um.dll", &opts);
    REQUIRE(object != nullptr);

    REQUIRE(strcmp(bpf_object__name(object), my_object_name) == 0);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "DropPacket");
    REQUIRE(program != nullptr);

    REQUIRE(bpf_program__fd(program) == ebpf_fd_invalid);
    REQUIRE(bpf_program__type(program) == BPF_PROG_TYPE_XDP);

    // Make sure we cannot override the program type, since this is a native program.
    REQUIRE(bpf_program__set_type(program, BPF_PROG_TYPE_BIND) < 0);
    REQUIRE(errno == EINVAL);
    REQUIRE(bpf_program__type(program) == BPF_PROG_TYPE_XDP);

    struct bpf_map* map = bpf_object__next_map(object, nullptr);
    REQUIRE(map != nullptr);
    REQUIRE(strcmp(bpf_map__name(map), "interface_index_map") == 0);
    REQUIRE(bpf_map__fd(map) == ebpf_fd_invalid);
    map = bpf_object__next_map(object, map);
    REQUIRE(strcmp(bpf_map__name(map), "dropped_packet_map") == 0);
    REQUIRE(bpf_map__fd(map) == ebpf_fd_invalid);
    map = bpf_object__next_map(object, map);
    REQUIRE(map == nullptr);

    // Trying to attach the program should fail since it's not loaded yet.
    bpf_link_ptr link(bpf_program__attach(program));
    REQUIRE(link == nullptr);
    REQUIRE(libbpf_get_error(link.get()) == -EINVAL);

    // Load the program.
    REQUIRE(bpf_object__load(object) == 0);

    // Attach should now succeed.
    link.reset(bpf_program__attach(program));
    REQUIRE(link != nullptr);

    // The maps should now have FDs.
    map = bpf_object__next_map(object, nullptr);
    REQUIRE(map != nullptr);
    REQUIRE(strcmp(bpf_map__name(map), "interface_index_map") == 0);
    REQUIRE(bpf_map__fd(map) != ebpf_fd_invalid);
    map = bpf_object__next_map(object, map);
    REQUIRE(strcmp(bpf_map__name(map), "dropped_packet_map") == 0);
    REQUIRE(bpf_map__fd(map) != ebpf_fd_invalid);
    map = bpf_object__next_map(object, map);
    REQUIRE(map == nullptr);

    REQUIRE(bpf_link__destroy(link.release()) == 0);
    bpf_object__close(object);
}

// Test bpf() with the following command ids:
// BPF_MAP_CREATE, BPF_MAP_UPDATE_ELEM, BPF_MAP_LOOKUP_ELEM,
// BPF_MAP_GET_NEXT_KEY, BPF_MAP_LOOKUP_AND_DELETE_ELEM, and BPF_MAP_DELETE_ELEM.
TEST_CASE("BPF_MAP_GET_NEXT_KEY etc.", "[libbpf][bpf]")
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    // Create a hash map.
    union bpf_attr attr = {};
    attr.map_create.map_type = BPF_MAP_TYPE_HASH;
    attr.map_create.key_size = sizeof(uint32_t);
    attr.map_create.value_size = sizeof(uint32_t);
    attr.map_create.max_entries = 3;
    attr.map_create.map_flags = 0;
    int map_fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
    REQUIRE(map_fd > 0);

    // Add an entry.
    uint64_t value = 12345;
    uint32_t key = 42;
    memset(&attr, 0, sizeof(attr));
    attr.map_update.map_fd = map_fd;
    attr.map_update.key = (uintptr_t)&key;
    attr.map_update.value = (uintptr_t)&value;
    attr.map_update.flags = 0;
    REQUIRE(bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) == 0);

    // Look up the entry.
    value = 0;
    memset(&attr, 0, sizeof(attr));
    attr.map_lookup.map_fd = map_fd;
    attr.map_lookup.key = (uintptr_t)&key;
    attr.map_lookup.value = (uintptr_t)&value;
    REQUIRE(bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) == 0);
    REQUIRE(value == 12345);

    // Enumerate the entry.
    uint32_t next_key;
    memset(&attr, 0, sizeof(attr));
    attr.map_get_next_key.map_fd = map_fd;
    attr.map_get_next_key.key = 0;
    attr.map_get_next_key.next_key = (uintptr_t)&next_key;
    REQUIRE(bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr)) == 0);
    REQUIRE(next_key == key);

    // Verify the entry is the last entry.
    memset(&attr, 0, sizeof(attr));
    attr.map_get_next_key.map_fd = map_fd;
    attr.map_get_next_key.key = (uintptr_t)&key;
    attr.map_get_next_key.next_key = (uintptr_t)&next_key;
    REQUIRE(bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr)) < 0);
    REQUIRE(errno == ENOENT);

    // Delete the entry.
    memset(&attr, 0, sizeof(attr));
    attr.map_delete.map_fd = map_fd;
    attr.map_delete.key = (uintptr_t)&key;
    REQUIRE(bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr)) == 0);

    // Look up and delete the entry.
    memset(&attr, 0, sizeof(attr));
    value = 0;
    key = 42;
    attr.map_lookup.map_fd = map_fd;
    attr.map_lookup.key = (uintptr_t)&key;
    attr.map_lookup.value = (uintptr_t)&value;

    // Add the element back to the entry after the previous test entry deletion.
    bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
    REQUIRE(bpf(BPF_MAP_LOOKUP_AND_DELETE_ELEM, &attr, sizeof(attr)) == 0);

    // Test the API again and verify looking up and deleting fails.
    REQUIRE(bpf(BPF_MAP_LOOKUP_AND_DELETE_ELEM, &attr, sizeof(attr)) < 0);
    REQUIRE(errno == ENOENT);

    // Verify that no entries exist.
    memset(&attr, 0, sizeof(attr));
    attr.map_get_next_key.map_fd = map_fd;
    attr.map_get_next_key.key = 0;
    attr.map_get_next_key.next_key = (uintptr_t)&next_key;
    REQUIRE(bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr)) < 0);
    REQUIRE(errno == ENOENT);

    // Test that the bpf_map_get_next_key returns the first key of the map if the previous key is not found.
    // Add 3 entries into the now empty map.
    for (key = 100; key < 400; key += 100) {
        value = 0;
        memset(&attr, 0, sizeof(attr));
        attr.map_update.map_fd = map_fd;
        attr.map_update.key = (uintptr_t)&key;
        attr.map_update.value = (uintptr_t)&value;
        REQUIRE(bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) == 0);
    }

    // Look up the first key in the map, so we can check that it's returned later.
    memset(&attr, 0, sizeof(attr));
    attr.map_get_next_key.map_fd = map_fd;
    attr.map_get_next_key.key = NULL;
    attr.map_get_next_key.next_key = (uintptr_t)&next_key;
    REQUIRE(bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr)) == 0);
    uint64_t first_key = next_key;

    // Look up a key that is not present in the map, and check that the first key is returned.
    key = 123;
    memset(&attr, 0, sizeof(attr));
    attr.map_get_next_key.map_fd = map_fd;
    attr.map_get_next_key.key = (uintptr_t)&key;
    attr.map_get_next_key.next_key = (uintptr_t)&next_key;
    REQUIRE(bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr)) == 0);
    REQUIRE(next_key == first_key);

    Platform::_close(map_fd);
}

TEST_CASE("Map and program information", "[libbpf][bpf]")
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    // Create a map.
    sys_bpf_map_create_attr_t map_create = {};
    map_create.map_type = BPF_MAP_TYPE_ARRAY;
    map_create.key_size = sizeof(uint32_t);
    map_create.value_size = sizeof(uint32_t);
    map_create.max_entries = 2;
    strncpy_s(map_create.map_name, "testing", sizeof(map_create.map_name));
    int map_fd = bpf(BPF_MAP_CREATE, (union bpf_attr*)&map_create, sizeof(map_create));
    REQUIRE(map_fd > 0);

    // Retrieve a prefix of map info.
    sys_bpf_map_info_t map_info = {};
    union bpf_attr attr = {};
    attr.info.bpf_fd = map_fd;
    attr.info.info = (uintptr_t)&map_info;
    attr.info.info_len = offsetof(map_info, key_size);
    REQUIRE(bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0);
    REQUIRE(attr.info.info_len == offsetof(map_info, key_size));
    REQUIRE(map_info.type == map_create.map_type);
    REQUIRE(map_info.id != 0);
    REQUIRE(map_info.key_size == 0);

    // Retrieve the map info.
    attr = {};
    attr.info.bpf_fd = map_fd;
    attr.info.info = (uintptr_t)&map_info;
    attr.info.info_len = sizeof(map_info);
    REQUIRE(bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0);
    REQUIRE(attr.info.info_len == sizeof(map_info));
    REQUIRE(map_info.type == map_create.map_type);
    REQUIRE(map_info.id != 0);
    REQUIRE(map_info.key_size == map_create.key_size);
    REQUIRE(map_info.value_size == map_create.value_size);
    REQUIRE(map_info.max_entries == map_create.max_entries);
    REQUIRE(map_info.map_flags == map_create.map_flags);
    REQUIRE(strncmp(map_info.name, map_create.map_name, sizeof(map_info.name)) == 0);

#if !defined(CONFIG_BPF_JIT_DISABLED)
    prevail::EbpfInst instructions[] = {
        {INST_ALU_OP_MOV | INST_CLS_ALU64, R0_RETURN_VALUE, 0}, // r0 = 0
        {INST_OP_EXIT},                                         // return r0
    };

    // Load and verify the eBPF program.
    attr = {};
    attr.prog_load.prog_type = BPF_PROG_TYPE_SAMPLE;
    attr.prog_load.insns = (uintptr_t)instructions;
    attr.prog_load.insn_cnt = _countof(instructions);
    strncpy_s(attr.prog_load.prog_name, "testing", sizeof(attr.prog_load.prog_name));
    int program_fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    REQUIRE(program_fd >= 0);

    // Bind map to the program so that the ID is returned in the info.
    attr = {};
    attr.prog_bind_map.prog_fd = program_fd;
    attr.prog_bind_map.map_fd = map_fd;
    REQUIRE(bpf(BPF_PROG_BIND_MAP, &attr, sizeof(attr)) == 0);

    // Verify that we can query a prefix of fields.
    sys_bpf_prog_info_t program_info = {};
    attr = {};
    attr.info.bpf_fd = program_fd;
    attr.info.info = (uintptr_t)&program_info;
    attr.info.info_len = offsetof(program_info, tag);
    REQUIRE(bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0);
    REQUIRE(attr.info.info_len == offsetof(program_info, tag));
    REQUIRE(program_info.id != 0);
    REQUIRE(program_info.nr_map_ids == 0);
    REQUIRE(strnlen(program_info.name, sizeof(program_info.name)) == 0);

    // Query the full program info.
    ebpf_id_t map_ids[2] = {};
    attr.info.info_len = sizeof(program_info);
    program_info.nr_map_ids = sizeof(map_ids) / sizeof(map_ids[0]);
    program_info.map_ids = (uintptr_t)map_ids;
    REQUIRE(bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0);
    REQUIRE(attr.info.info_len == sizeof(program_info));
    REQUIRE(program_info.tag[0] == 0);
    REQUIRE(program_info.jited_prog_len == 0);
    REQUIRE(program_info.xlated_prog_len == 0);
    REQUIRE(program_info.jited_prog_insns == 0);
    REQUIRE(program_info.xlated_prog_insns == 0);
    REQUIRE(program_info.load_time == 0);
    REQUIRE(program_info.created_by_uid == 0);
    REQUIRE(program_info.nr_map_ids == 1);
    REQUIRE(map_ids[0] == map_info.id);
    REQUIRE(strncmp(program_info.name, "testing", sizeof(program_info.name)) == 0);
#endif
}

TEST_CASE("libbpf_num_possible_cpus", "[libbpf]")
{
    int cpu_count = libbpf_num_possible_cpus();
    REQUIRE(cpu_count > 0);
}

void
_test_nested_maps(bpf_map_type map_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    // First, create an inner map.
    fd_t inner_map_fd1 =
        bpf_map_create(BPF_MAP_TYPE_ARRAY, "inner_map1", sizeof(uint32_t), sizeof(uint32_t), 1, nullptr);
    REQUIRE(inner_map_fd1 > 0);

    // Create outer map with the inner map handle in options.
    bpf_map_create_opts opts = {.inner_map_fd = (uint32_t)inner_map_fd1};
    fd_t outer_map_fd = bpf_map_create(map_type, "outer_map", sizeof(uint32_t), sizeof(fd_t), 10, &opts);
    REQUIRE(outer_map_fd > 0);

    // Create second inner map.
    fd_t inner_map_fd2 =
        bpf_map_create(BPF_MAP_TYPE_ARRAY, "inner_map2", sizeof(uint32_t), sizeof(uint32_t), 1, nullptr);
    REQUIRE(inner_map_fd2 > 0);

    // Insert both inner maps in outer map.
    uint32_t key = 1;
    uint32_t result = bpf_map_update_elem(outer_map_fd, &key, &inner_map_fd1, 0);
    REQUIRE(result == ERROR_SUCCESS);

    key = 2;
    result = bpf_map_update_elem(outer_map_fd, &key, &inner_map_fd2, 0);
    REQUIRE(result == ERROR_SUCCESS);

    // Remove the inner maps from outer map.
    key = 1;
    result = bpf_map_delete_elem(outer_map_fd, &key);
    REQUIRE(result == ERROR_SUCCESS);

    key = 2;
    result = bpf_map_delete_elem(outer_map_fd, &key);
    REQUIRE(result == ERROR_SUCCESS);

    Platform::_close(inner_map_fd2);
    Platform::_close(inner_map_fd1);
    Platform::_close(outer_map_fd);
}

TEST_CASE("array_map_of_maps", "[libbpf]") { _test_nested_maps(BPF_MAP_TYPE_ARRAY_OF_MAPS); }
TEST_CASE("hash_map_of_maps", "[libbpf]") { _test_nested_maps(BPF_MAP_TYPE_HASH_OF_MAPS); }

TEST_CASE("libbpf_load_stress", "[libbpf]")
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    std::vector<std::jthread> threads;
    // Schedule 4 threads per CPU to force contention.
    for (size_t i = 0; i < static_cast<size_t>(ebpf_get_cpu_count()) * 4; i++) {
        // Initialize thread object with lambda plus stop token
        threads.emplace_back([i](std::stop_token stop_token) {
            while (!stop_token.stop_requested()) {
                struct bpf_object* object = bpf_object__open("test_sample_ebpf_um.dll");
                if (!object) {
                    break;
                }
                // Enumerate maps and programs.
                bpf_program* program;
                bpf_object__for_each_program(program, object) {}
                bpf_map* map;
                bpf_object__for_each_map(map, object) {}
                bpf_object__close(object);
            }
        });
    }

    // Wait for 10 seconds.
    std::this_thread::sleep_for(std::chrono::seconds(10));

    // Stop all threads.
    for (auto& thread : threads) {
        thread.request_stop();
    }

    // Wait for all threads to stop.
    for (auto& thread : threads) {
        thread.join();
    }
}

TEST_CASE("recursive_tail_call", "[libbpf]")
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();
    struct bpf_object* object = bpf_object__open("tail_call_recursive_um.dll");
    REQUIRE(object != nullptr);

    // Load the BPF program.
    REQUIRE(bpf_object__load(object) == 0);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "recurse");
    REQUIRE(program != nullptr);

    // Get the map used to store the next program to call.
    struct bpf_map* map = bpf_object__find_map_by_name(object, "map");
    REQUIRE(map != nullptr);

    // Get the map used to record the number of times the program was called.
    struct bpf_map* canary_map = bpf_object__find_map_by_name(object, "canary");
    REQUIRE(canary_map != nullptr);

    // Get the fd for the program.
    fd_t program_fd = bpf_program__fd(program);
    REQUIRE(program_fd > 0);

    // Get the fd of the map.
    fd_t map_fd = bpf_map__fd(map);
    REQUIRE(map_fd > 0);

    // Get the fd of the canary map.
    fd_t canary_map_fd = bpf_map__fd(canary_map);
    REQUIRE(canary_map_fd > 0);

    uint32_t key = 0;
    uint32_t value = 0;
    REQUIRE(bpf_map_update_elem(canary_map_fd, &key, &value, 0) == 0);

    bpf_test_run_opts opts = {};
    sample_program_context_t in_ctx{0};
    sample_program_context_t out_ctx{0};
    opts.repeat = 1;
    opts.ctx_in = reinterpret_cast<uint8_t*>(&in_ctx);
    opts.ctx_size_in = sizeof(in_ctx);
    opts.ctx_out = reinterpret_cast<uint8_t*>(&out_ctx);
    opts.ctx_size_out = sizeof(out_ctx);

    capture_helper_t capture;
    std::vector<std::string> output;
    errno_t error = capture.begin_capture();
    if (error == NO_ERROR) {
        // Run the program.
        usersim_trace_logging_set_enabled(true, EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_PRINTK);
        int result = bpf_prog_test_run_opts(program_fd, &opts);
        usersim_trace_logging_set_enabled(false, 0, 0);

        output = capture.buffer_to_printk_vector(capture.get_stdout_contents());
        REQUIRE(result == 0);
    }

    // Verify that the printk output is correct.
    // In 'recurse' ebpf program, the printk is added even to the caller.
    // Hence the printk count is called MAX_TAIL_CALL_CNT + 1 times.
    REQUIRE(output.size() == MAX_TAIL_CALL_CNT + 1);
    for (size_t i = 0; i < MAX_TAIL_CALL_CNT + 1; i++) {
        REQUIRE(output[i] == std::format("recurse: *value={}", i));
    }

    // The program should have returned -EBPF_NO_MORE_TAIL_CALLS.
    REQUIRE(opts.retval == -EBPF_NO_MORE_TAIL_CALLS);

    // Read the map to determine how many times the program was called.
    REQUIRE(bpf_map_lookup_elem(canary_map_fd, &key, &value) == 0);

    // The program should have been called MAX_TAIL_CALL_CNT + 1 times.
    REQUIRE(value == MAX_TAIL_CALL_CNT + 1);

    // Close the map and programs.
    bpf_object__close(object);
}

TEST_CASE("sequential_tail_call", "[libbpf]")
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();
    struct bpf_object* object = bpf_object__open("tail_call_sequential_um.dll");
    REQUIRE(object != nullptr);

    // Load the BPF program.
    REQUIRE(bpf_object__load(object) == 0);

    // Get the map used to store the next program to call.
    struct bpf_map* map = bpf_object__find_map_by_name(object, "map");
    REQUIRE(map != nullptr);

    // Get the map used to record the number of times the program was called.
    struct bpf_map* canary_map = bpf_object__find_map_by_name(object, "canary");
    REQUIRE(canary_map != nullptr);

    // Get the fd of the map.
    fd_t map_fd = bpf_map__fd(map);
    REQUIRE(map_fd > 0);

    // Get the fd of the canary map.
    fd_t canary_map_fd = bpf_map__fd(canary_map);
    REQUIRE(canary_map_fd > 0);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "sequential0");
    REQUIRE(program);
    // Get the fd for the program.
    fd_t program_fd = bpf_program__fd(program);
    REQUIRE(program_fd > 0);

    // Invoke the first program in the chain.
    bpf_test_run_opts opts = {};
    sample_program_context_t in_ctx{0};
    sample_program_context_t out_ctx{0};
    opts.repeat = 1;
    opts.ctx_in = reinterpret_cast<uint8_t*>(&in_ctx);
    opts.ctx_size_in = sizeof(in_ctx);
    opts.ctx_out = reinterpret_cast<uint8_t*>(&out_ctx);
    opts.ctx_size_out = sizeof(out_ctx);

    capture_helper_t capture;
    std::vector<std::string> output;
    errno_t error = capture.begin_capture();
    if (error == NO_ERROR) {
        // Run the program.
        usersim_trace_logging_set_enabled(true, EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_PRINTK);
        int result = bpf_prog_test_run_opts(program_fd, &opts);
        usersim_trace_logging_set_enabled(false, 0, 0);

        output = capture.buffer_to_printk_vector(capture.get_stdout_contents());
        REQUIRE(result == 0);
    }

    // Verify that the printk output is correct.
    // In 'sequential' ebpf program, the printk is added even to the caller.
    // Hence the printk count is called MAX_TAIL_CALL_CNT + 1 times.
    REQUIRE(output.size() == MAX_TAIL_CALL_CNT + 1);
    for (size_t i = 0; i < MAX_TAIL_CALL_CNT + 1; i++) {
        REQUIRE(output[i] == std::format("sequential{}: *value={}", i, i));
    }

    // Read the map to determine how many times the program was called.
    uint32_t key = 0;
    uint32_t value = 0;
    REQUIRE(bpf_map_lookup_elem(canary_map_fd, &key, &value) == 0);

    // The program should have been called MAX_TAIL_CALL_CNT times.
    REQUIRE(value == MAX_TAIL_CALL_CNT + 1);

    // The last program should have returned -EBPF_NO_MORE_TAIL_CALLS.
    REQUIRE(opts.retval == -EBPF_NO_MORE_TAIL_CALLS);
}

bind_action_t
emulate_bind_tail_call(std::function<ebpf_result_t(void*, uint32_t*)>& invoke, uint64_t pid, const char* appid)
{
    uint32_t result;
    std::string app_id = appid;
    INITIALIZE_BIND_CONTEXT
    ctx->app_id_start = (uint8_t*)app_id.c_str();
    ctx->app_id_end = (uint8_t*)(app_id.c_str()) + app_id.size();
    ctx->process_id = pid;
    ctx->operation = BIND_OPERATION_BIND;

    REQUIRE(invoke(reinterpret_cast<void*>(ctx), &result) == EBPF_SUCCESS);

    return static_cast<bind_action_t>(result);
}

TEST_CASE("bind_tail_call_max_exceed", "[libbpf]")
{
    const int TOTAL_TAIL_CALL = MAX_TAIL_CALL_CNT + 2;

    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    program_info_provider_t bind_program_info;
    REQUIRE(bind_program_info.initialize(EBPF_PROGRAM_TYPE_BIND) == EBPF_SUCCESS);

    struct bpf_object* object = bpf_object__open("tail_call_max_exceed_um.dll");
    REQUIRE(object != nullptr);

    // Load the BPF program.
    REQUIRE(bpf_object__load(object) == 0);

    // Get the map used to store the next program to call.
    struct bpf_map* map = bpf_object__find_map_by_name(object, "bind_tail_call_map");
    REQUIRE(map != nullptr);

    // Get the fd of the prog array map.
    fd_t map_fd = bpf_map__fd(map);
    REQUIRE(map_fd > 0);

    std::string first_program_name{"bind_test_caller"};
    struct bpf_program* first_program = bpf_object__find_program_by_name(object, first_program_name.c_str());
    REQUIRE(first_program != nullptr);

    fd_t first_program_fd = bpf_program__fd(first_program);
    REQUIRE(first_program_fd > 0);

    // Verify that the prog_array map contains the correct number of TOTAL_TAIL_CALL programs.
    uint32_t key = 0;
    uint32_t val = 0;
    bpf_map_lookup_elem(map_fd, &key, &val);
    for (int x = 0; x < TOTAL_TAIL_CALL - 1; x++) {
        REQUIRE(bpf_map_get_next_key(map_fd, &key, &key) == 0);
        uint32_t value = 0;
        bpf_map_lookup_elem(map_fd, &key, &value);
        REQUIRE(key != 0);
    }
    REQUIRE(bpf_map_get_next_key(map_fd, &key, &key) < 0);
    REQUIRE(errno == ENOENT);

    // Create a hook for the bind program.
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);

    // Attach the hook.
    bpf_link_ptr link;
    uint32_t ifindex = 0;
    uint64_t fake_pid = 123456;
    REQUIRE(hook.attach_link(first_program_fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

    std::function<ebpf_result_t(void*, uint32_t*)> invoke =
        [&hook](_Inout_ void* context, _Out_ uint32_t* result) -> ebpf_result_t { return hook.fire(context, result); };

    // Binding to the port should be denied because the number of tail call programs exceeds MAX_TAIL_CALL_COUNT.
    REQUIRE(emulate_bind_tail_call(invoke, fake_pid, "fake_app_1") == BIND_DENY);

    hook.detach_and_close_link(&link);
}

void
_test_batch_iteration_maps(
    fd_t& map_fd, uint32_t batch_size, bpf_map_batch_opts* opts, size_t value_size, int num_of_cpus)
{
    // Retrieve in batches.
    const uint8_t batch_size_divisor = 10;
    uint32_t* in_batch = nullptr;
    uint32_t out_batch = 0;
    std::vector<uint32_t> returned_keys(0);
    std::vector<uint64_t> returned_values(0);
    int32_t requested_batch_size = (batch_size / batch_size_divisor) - 2;
    uint32_t batch_size_count = 0;
    int result = 0;

    if (requested_batch_size <= 0) {
        requested_batch_size = 1;
    }

    for (;;) {
        std::vector<uint32_t> batch_keys(requested_batch_size, 0);
        std::vector<uint64_t> batch_values(requested_batch_size * value_size, 0);

        batch_size_count = static_cast<uint32_t>(batch_keys.size());
        result = bpf_map_lookup_batch(
            map_fd, in_batch, &out_batch, batch_keys.data(), batch_values.data(), &batch_size_count, opts);
        if (result == -ENOENT) {
            printf("No more entries. End of map reached.\n");
            break;
        }

        REQUIRE(result == 0);
        // Number of entries retrieved (batch_size_count) should be less than or equal to requested_batch_size.
        REQUIRE(batch_size_count <= static_cast<uint32_t>(batch_keys.size()));
        REQUIRE(batch_size_count <= static_cast<uint32_t>(batch_values.size()) / value_size);

        batch_keys.resize(batch_size_count);
        batch_values.resize(batch_size_count * value_size);
        returned_keys.insert(returned_keys.end(), batch_keys.begin(), batch_keys.end());
        returned_values.insert(returned_values.end(), batch_values.begin(), batch_values.end());

        in_batch = &out_batch;
    }

    REQUIRE(returned_keys.size() == batch_size);
    REQUIRE(returned_values.size() == batch_size * value_size);

    // Verify the returned keys and values.
    uint32_t key = 0;
    for (uint32_t i = 0; i < batch_size; i++) {
        key = returned_keys[i];
        for (int cpu = 0; cpu < num_of_cpus; cpu++) {
            REQUIRE(returned_values[(i * value_size) + cpu] == static_cast<uint64_t>(key) * 2ul);
        }
    }
    // Hash maps do not guarantee order of keys.
    // The keys in the returned_keys vector should be in the range [0, batch_size-1].
    std::sort(returned_keys.begin(), returned_keys.end());
    for (uint32_t i = 0; i < batch_size; i++) {
        REQUIRE(returned_keys[i] == i);
    }
}

void
_test_maps_batch(bpf_map_type map_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    int num_of_cpus = 1;
    size_t value_size = 1;

    if (BPF_MAP_TYPE_PER_CPU(map_type)) {
        // Get the number of possible CPUs that the host kernel supports and expects.
        num_of_cpus = libbpf_num_possible_cpus();
        REQUIRE(num_of_cpus > 0);

        // The value size is the size of the value multiplied by the number of CPUs.
        // Also, the value size should be closest 8-byte aligned.
        //       value_size = EBPF_PAD_8(sizeof(uint8_t)) * num_of_cpus
        //
        // If you use vector<uint8_t> to initialize the values, then use
        //       value_size = EBPF_PAD_8(sizeof(uint8_t)) * num_of_cpus
        //       vector<uint8_t> values(batch_size * value_size);
        //
        // In this test case, we use vector<uint64_t> to initialize the values, which is already 8-byte aligned.
        value_size = num_of_cpus;
    }

    // Create a hash map.
    union bpf_attr attr = {};
    attr.map_create.map_type = map_type;
    attr.map_create.key_size = sizeof(uint32_t);
    attr.map_create.value_size = sizeof(uint64_t);
    attr.map_create.max_entries = 1024 * 1024;

    fd_t map_fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
    REQUIRE(map_fd > 0);

    uint32_t batch_size = 20000;
    std::vector<uint32_t> keys(batch_size);
    std::vector<uint64_t> values(batch_size * value_size);
    for (uint32_t i = 0; i < batch_size; i++) {
        keys[i] = i;
        // Populate the value.
        for (int cpu = 0; cpu < num_of_cpus; cpu++) {
            values[(i * value_size) + cpu] = static_cast<uint64_t>(i) * 2ul;
        }
    }

    // Update the map with the batch.
    bpf_map_batch_opts opts = {.elem_flags = BPF_NOEXIST};

    uint32_t update_batch_size = batch_size;

    // Insert keys in batch.
    REQUIRE(bpf_map_update_batch(map_fd, keys.data(), values.data(), &update_batch_size, &opts) == 0);
    REQUIRE(update_batch_size == batch_size);

    // Fetch the batch.
    uint32_t fetched_batch_size = batch_size;
    std::vector<uint32_t> fetched_keys(batch_size);
    std::vector<uint64_t> fetched_values(batch_size * value_size);
    uint32_t next_key = 0;
    opts.elem_flags = 0;

    // Fetch all keys in one batch.
    REQUIRE(
        bpf_map_lookup_batch(
            map_fd, nullptr, &next_key, fetched_keys.data(), fetched_values.data(), &fetched_batch_size, &opts) == 0);
    REQUIRE(fetched_batch_size == batch_size);
    _test_batch_iteration_maps(map_fd, batch_size, &opts, value_size, num_of_cpus);

    // Request more keys than present.
    uint32_t large_fetched_batch_size = fetched_batch_size * 2;
    REQUIRE(
        bpf_map_lookup_batch(
            map_fd, nullptr, &next_key, fetched_keys.data(), fetched_values.data(), &large_fetched_batch_size, &opts) ==
        0);
    REQUIRE(large_fetched_batch_size == batch_size);

    // Search at end of map.
    REQUIRE(
        bpf_map_lookup_batch(
            map_fd,
            &next_key,
            &next_key,
            fetched_keys.data(),
            fetched_values.data(),
            &large_fetched_batch_size,
            &opts) == -ENOENT);

    // Verify all keys and values in batches.
    _test_batch_iteration_maps(map_fd, batch_size, &opts, value_size, num_of_cpus);

    // Delete all keys in one batch.
    uint32_t delete_batch_size = batch_size;
    opts.elem_flags = 0;
    REQUIRE(bpf_map_delete_batch(map_fd, keys.data(), &delete_batch_size, &opts) == 0);
    REQUIRE(delete_batch_size == batch_size);

    // Verify there are no entries, after deletion.
    REQUIRE(
        bpf_map_lookup_batch(
            map_fd, nullptr, &next_key, fetched_keys.data(), fetched_values.data(), &fetched_batch_size, &opts) ==
        -ENOENT);

    // Lookup and Delete batch operation.
    opts.elem_flags = BPF_NOEXIST;
    update_batch_size = batch_size;

    // Populate the map with the keys and values.
    REQUIRE(bpf_map_update_batch(map_fd, keys.data(), values.data(), &update_batch_size, &opts) == 0);
    REQUIRE(update_batch_size == batch_size);

    next_key = 0;
    opts.elem_flags = BPF_ANY;
    fetched_batch_size = batch_size;
    REQUIRE(
        bpf_map_lookup_batch(
            map_fd, nullptr, &next_key, fetched_keys.data(), fetched_values.data(), &fetched_batch_size, &opts) == 0);
    REQUIRE(fetched_batch_size == batch_size);
    _test_batch_iteration_maps(map_fd, batch_size, &opts, value_size, num_of_cpus);
    // Verify the fetched_keys and fetched_values are returned correctly.
    std::sort(fetched_keys.begin(), fetched_keys.end());
    REQUIRE(fetched_keys == keys);
    std::sort(fetched_values.begin(), fetched_values.end());
    REQUIRE(fetched_values == values);

    next_key = 0;
    REQUIRE(
        bpf_map_lookup_and_delete_batch(
            map_fd, nullptr, &next_key, fetched_keys.data(), fetched_values.data(), &fetched_batch_size, &opts) == 0);
    REQUIRE(fetched_batch_size == batch_size);
    REQUIRE(next_key == 0);
    // Verify the fetched_keys and fetched_values are returned correctly.
    std::sort(fetched_keys.begin(), fetched_keys.end());
    REQUIRE(fetched_keys == keys);
    std::sort(fetched_values.begin(), fetched_values.end());
    REQUIRE(fetched_values == values);

    // Verify there are no entries, after deletion.
    REQUIRE(
        bpf_map_lookup_batch(
            map_fd, nullptr, &next_key, fetched_keys.data(), fetched_values.data(), &fetched_batch_size, &opts) ==
        -ENOENT);

    // Negative tests.
    // Batch size 0

    update_batch_size = 0;
    REQUIRE(bpf_map_update_batch(map_fd, keys.data(), values.data(), &update_batch_size, &opts) == -EINVAL);

    fetched_batch_size = 0;
    REQUIRE(
        bpf_map_lookup_batch(
            map_fd, nullptr, &next_key, fetched_keys.data(), fetched_values.data(), &fetched_batch_size, &opts) ==
        -EINVAL);

    delete_batch_size = 0;
    REQUIRE(bpf_map_delete_batch(map_fd, keys.data(), &delete_batch_size, &opts) == -EINVAL);

    // opts.flags has invalid value.
    opts.flags = 0x100;
    update_batch_size = batch_size;
    REQUIRE(bpf_map_update_batch(map_fd, keys.data(), values.data(), &update_batch_size, &opts) == -EINVAL);

    fetched_batch_size = batch_size;
    REQUIRE(
        bpf_map_lookup_batch(
            map_fd, nullptr, &next_key, fetched_keys.data(), fetched_values.data(), &fetched_batch_size, &opts) ==
        -EINVAL);

    delete_batch_size = batch_size;
    REQUIRE(bpf_map_delete_batch(map_fd, keys.data(), &delete_batch_size, &opts) == -EINVAL);

    // opts.elem_flags has invalid value.
    opts.elem_flags = 0x100;
    opts.flags = 0;
    update_batch_size = batch_size;
    REQUIRE(bpf_map_update_batch(map_fd, keys.data(), values.data(), &update_batch_size, &opts) == -EINVAL);

    fetched_batch_size = batch_size;
    REQUIRE(
        bpf_map_lookup_batch(
            map_fd, nullptr, &next_key, fetched_keys.data(), fetched_values.data(), &fetched_batch_size, &opts) ==
        -EINVAL);

    delete_batch_size = batch_size;
    REQUIRE(bpf_map_delete_batch(map_fd, keys.data(), &delete_batch_size, &opts) == -EINVAL);

    // invalid map fd.
    fd_t invalid_map_fd = 0x10000000;

    opts.flags = 0;
    opts.elem_flags = 0;
    update_batch_size = batch_size;

    REQUIRE(bpf_map_update_batch(invalid_map_fd, keys.data(), values.data(), &update_batch_size, &opts) == -EBADF);

    fetched_batch_size = batch_size;
    REQUIRE(
        bpf_map_lookup_batch(
            invalid_map_fd,
            nullptr,
            &next_key,
            fetched_keys.data(),
            fetched_values.data(),
            &fetched_batch_size,
            &opts) == -EBADF);

    delete_batch_size = batch_size;
    REQUIRE(bpf_map_delete_batch(invalid_map_fd, keys.data(), &delete_batch_size, &opts) == -EBADF);
}

TEST_CASE("libbpf hash map batch", "[libbpf]") { _test_maps_batch(BPF_MAP_TYPE_HASH); }

TEST_CASE("libbpf lru hash map batch", "[libbpf]") { _test_maps_batch(BPF_MAP_TYPE_LRU_HASH); }

TEST_CASE("libbpf percpu hash map batch", "[libbpf]") { _test_maps_batch(BPF_MAP_TYPE_PERCPU_HASH); }

TEST_CASE("libbpf lru percpu hash map batch", "[libbpf]") { _test_maps_batch(BPF_MAP_TYPE_LRU_PERCPU_HASH); }

void
_hash_of_map_initial_value_test(ebpf_execution_type_t execution_type)
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    std::string file_name = std::format("hash_of_map{}", execution_type == EBPF_EXECUTION_NATIVE ? "_um.dll" : ".o");

    bpf_object_ptr object(bpf_object__open(file_name.c_str()));
    REQUIRE(object != nullptr);

    REQUIRE(ebpf_object_set_execution_type(object.get(), execution_type) == EBPF_SUCCESS);

    // Load the BPF program.
    REQUIRE(bpf_object__load(object.get()) == 0);

    // Get the outer map.
    bpf_map* outer_map = bpf_object__find_map_by_name(object.get(), "outer_map");
    REQUIRE(outer_map != nullptr);

    bpf_map* inner_map = bpf_object__find_map_by_name(object.get(), "inner_map");
    REQUIRE(inner_map != nullptr);

    fd_t outer_map_fd = bpf_map__fd(outer_map);
    REQUIRE(outer_map_fd > 0);

    fd_t inner_map_fd = bpf_map__fd(inner_map);
    REQUIRE(inner_map_fd > 0);

    // Issue: https://github.com/microsoft/ebpf-for-windows/issues/3210
    // Only native execution supports map of maps with static initializers.
    if (execution_type != EBPF_EXECUTION_NATIVE) {
        return;
    }

    uint32_t key = 0;
    uint32_t inner_map_id = 0;

    // Get the map at index 0.
    REQUIRE(bpf_map_lookup_elem(outer_map_fd, &key, &inner_map_id) == 0);

    // Get id of the inner map.
    bpf_map_info info;
    uint32_t info_length = sizeof(info);
    memset(&info, 0, sizeof(info));
    REQUIRE(bpf_obj_get_info_by_fd(inner_map_fd, &info, &info_length) == 0);

    // Verify that the id of the inner map matches the id in the outer map.
    REQUIRE(inner_map_id == info.id);

    // Lookup in the inner map with a non-zero key should fail.
    uint32_t non_zero_key = 1;
    uint32_t value = 0;
    int result = bpf_map_lookup_elem(inner_map_fd, &non_zero_key, &value);
    REQUIRE(result != 0);
    REQUIRE(errno == ENOENT);

    // Lookup in the inner map with a clearly nonexistent key should also fail.
    uint32_t nonexistent_key = 12345;
    result = bpf_map_lookup_elem(inner_map_fd, &nonexistent_key, &value);
    REQUIRE(result != 0);
    REQUIRE(errno == ENOENT);
}

TEST_CASE("hash_of_map", "[libbpf]")
{
#if !defined(CONFIG_BPF_JIT_DISABLED)
    _hash_of_map_initial_value_test(EBPF_EXECUTION_JIT);
#endif
    _hash_of_map_initial_value_test(EBPF_EXECUTION_NATIVE);
}

static void
_utility_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    const char dll_name[] = "utility_um.dll";
    const char obj_name[] = "utility.o";
    test_helper.initialize();
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_BIND) == EBPF_SUCCESS);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? dll_name : obj_name);
    struct bpf_object* process_object = bpf_object__open(file_name);
    REQUIRE(process_object != nullptr);

    // Load the program(s).
    REQUIRE(bpf_object__load(process_object) == 0);

    struct bpf_program* caller = bpf_object__find_program_by_name(process_object, "UtilityTest");
    REQUIRE(caller != nullptr);

    bpf_link_ptr link(bpf_program__attach(caller));
    REQUIRE(link != nullptr);

    // Now run the ebpf program.
    INITIALIZE_BIND_CONTEXT
    ctx->operation = BIND_OPERATION_BIND;

    uint32_t result;
    REQUIRE(hook.fire(ctx, &result) == EBPF_SUCCESS);

    // Verify the result.
    REQUIRE(result == 0);

    result = bpf_link__destroy(link.release());
    REQUIRE(result == 0);

    bpf_object__close(process_object);
}

DECLARE_ALL_TEST_CASES("utility_test", "[libbpf]", _utility_test);

static void
_strings_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    const char dll_name[] = "strings_um.dll";
    const char obj_name[] = "strings.o";
    test_helper.initialize();
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_BIND) == EBPF_SUCCESS);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? dll_name : obj_name);
    struct bpf_object* process_object = bpf_object__open(file_name);
    REQUIRE(process_object != nullptr);

    // Load the program(s).
    REQUIRE(bpf_object__load(process_object) == 0);

    struct bpf_program* string_caller = bpf_object__find_program_by_name(process_object, "StringOpsTest");
    REQUIRE(string_caller != nullptr);

    bpf_link_ptr string_link(bpf_program__attach(string_caller));
    REQUIRE(string_link != nullptr);

    // Now run the ebpf program.
    INITIALIZE_BIND_CONTEXT
    ctx->operation = BIND_OPERATION_BIND;

    uint32_t result{};
    REQUIRE(hook.fire(ctx, &result) == EBPF_SUCCESS);

    REQUIRE(result == 0);

    result = bpf_link__destroy(string_link.release());
    REQUIRE(result == 0);

    bpf_object__close(process_object);
}
DECLARE_ALL_TEST_CASES("strings_test", "[libbpf]", _strings_test);

static void
_program_flags_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    const char dll_name[] = "utility_um.dll";
    const char obj_name[] = "utility.o";
    test_helper.initialize();
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_BIND) == EBPF_SUCCESS);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? dll_name : obj_name);
    struct bpf_object* process_object = bpf_object__open(file_name);
    REQUIRE(process_object != nullptr);

    // Set the flag on each program in the object.
    struct bpf_program* program;
    bpf_object__for_each_program(program, process_object)
    {
        // Set some flags on the program. The test attach provider does not use these flags.
        REQUIRE(bpf_program__set_flags(program, 0xCCCCCCCC) == 0);

        // Get the flags and verify they are correct.
        REQUIRE(bpf_program__flags(program) == 0xCCCCCCCC);
    }

    // Load the program(s).
    REQUIRE(bpf_object__load(process_object) == 0);

    // Verify that setting the flag after load fails.
    bpf_object__for_each_program(program, process_object)
    {
        REQUIRE(bpf_program__set_flags(program, 0xCCCCCCCC) == -EBUSY);
    }

    struct bpf_program* caller = bpf_object__find_program_by_name(process_object, "UtilityTest");
    REQUIRE(caller != nullptr);

    bpf_link_ptr link(bpf_program__attach(caller));
    REQUIRE(link != nullptr);

    auto client_data = hook.get_client_data();

    REQUIRE(client_data != nullptr);
    REQUIRE(client_data->header.version == EBPF_ATTACH_CLIENT_DATA_CURRENT_VERSION);
    REQUIRE(client_data->prog_attach_flags == 0xCCCCCCCC);

    // Now run the ebpf program.
    INITIALIZE_BIND_CONTEXT
    ctx->operation = BIND_OPERATION_BIND;

    uint32_t result;
    REQUIRE(hook.fire(ctx, &result) == EBPF_SUCCESS);

    // Verify the result.
    REQUIRE(result == 0);

    result = bpf_link__destroy(link.release());
    REQUIRE(result == 0);
    bpf_object__close(process_object);
}

DECLARE_ALL_TEST_CASES("program_flag_test", "[libbpf]", _program_flags_test);