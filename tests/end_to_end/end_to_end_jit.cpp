// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "api_common.hpp"
#include "api_internal.h"
#include "api_service.h"
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "bpf2c.h"
#include "capture_helper.hpp"
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "ebpf_core.h"
#include "ebpf_tracelog.h"
#include "end_to_end_jit.h"
#include "helpers.h"
namespace ebpf {
#include "net/if_ether.h"
#include "net/ip.h"
#include "net/udp.h"
}; // namespace ebpf.
#include "platform.h"
#include "program_helper.h"
#include "test_helper.hpp"

#include <thread>

using namespace Platform;

int
ebpf_program_load(
    _In_z_ const char* file_name,
    bpf_prog_type prog_type,
    ebpf_execution_type_t execution_type,
    _Out_ bpf_object_ptr* unique_object,
    _Out_ fd_t* program_fd, // File descriptor of first program in the object.
    _Outptr_opt_result_maybenull_z_ const char** log_buffer)
{
    *program_fd = ebpf_fd_invalid;
    if (log_buffer) {
        *log_buffer = nullptr;
    }

    unique_object->reset(nullptr);

    bpf_object* new_object = bpf_object__open(file_name);
    if (new_object == nullptr) {
        return -errno;
    }
    REQUIRE(ebpf_object_set_execution_type(new_object, execution_type) == EBPF_SUCCESS);
    bpf_program* program = bpf_object__next_program(new_object, nullptr);
    if (prog_type != BPF_PROG_TYPE_UNSPEC) {
        bpf_program__set_type(program, prog_type);
    }
    int error = bpf_object__load(new_object);
    if (error < 0) {
        if (log_buffer) {
            size_t log_buffer_size;
            if (program != nullptr) {
                const char* log_buffer_str = bpf_program__log_buf(program, &log_buffer_size);
                if (log_buffer_str != nullptr) {
                    *log_buffer = cxplat_duplicate_string(log_buffer_str);
                }
            }
        }
        bpf_object__close(new_object);
        // Add delay to permit the native module handle cleanup to complete.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        return error;
    }

    if (program != nullptr) {
        *program_fd = bpf_program__fd(program);
    }
    unique_object->reset(new_object);
    return 0;
}

void
cgroup_load_test(
    _In_z_ const char* file,
    _In_z_ const char* name,
    ebpf_program_type_t& program_type,
    ebpf_attach_type_t& attach_type,
    ebpf_execution_type_t execution_type)
{
    int result;
    const char* error_message = nullptr;
    fd_t program_fd;

    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    single_instance_hook_t hook(program_type, attach_type);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t program_info;
    REQUIRE(program_info.initialize(program_type) == EBPF_SUCCESS);
    bpf_object_ptr unique_object;

    result = ebpf_program_load(file, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }

    REQUIRE(result == 0);

    bpf_program* program = bpf_object__find_program_by_name(unique_object.get(), name);
    REQUIRE(program != nullptr);

    uint32_t compartment_id = 0;
    REQUIRE(hook.attach(program, &compartment_id, sizeof(compartment_id)) == EBPF_SUCCESS);
    REQUIRE(hook.detach(ebpf_fd_invalid, &compartment_id, sizeof(compartment_id)) == EBPF_SUCCESS);

    compartment_id = 1;
    REQUIRE(hook.attach(program, &compartment_id, sizeof(compartment_id)) == EBPF_SUCCESS);
    REQUIRE(hook.detach(program_fd, &compartment_id, sizeof(compartment_id)) == EBPF_SUCCESS);

    bpf_object__close(unique_object.release());
}

void
cgroup_sock_addr_load_test(
    _In_z_ const char* file,
    _In_z_ const char* name,
    ebpf_attach_type_t& attach_type,
    ebpf_execution_type_t execution_type)
{
    cgroup_load_test(file, name, EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR, attach_type, execution_type);
}

static void
ebpf_program_attach_fds_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE) ? SAMPLE_PATH "test_sample_ebpf_um.dll"
                                                                      : SAMPLE_PATH "test_sample_ebpf.o";
    const char* error_message = nullptr;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    bpf_object_ptr unique_object;
    fd_t program_fd;
    int result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    fd_t link_fd;
    REQUIRE(ebpf_program_attach_by_fds(program_fd, &EBPF_ATTACH_TYPE_SAMPLE, nullptr, 0, &link_fd) == EBPF_SUCCESS);
    REQUIRE(link_fd > 0);
    REQUIRE(ebpf_close_fd(link_fd) == EBPF_SUCCESS);

    bpf_object__close(unique_object.release());
}

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("cgroup_sockops_load_test", "[cgroup_sockops]")
{
    cgroup_load_test(
        "sockops.o",
        "connection_monitor",
        EBPF_PROGRAM_TYPE_SOCK_OPS,
        EBPF_ATTACH_TYPE_CGROUP_SOCK_OPS,
        EBPF_EXECUTION_JIT);
}

void
test_enumerate_and_query_programs()
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    uint32_t program_id;
    uint32_t next_program_id;
    const char* error_message = nullptr;
    int result;
    const char* file_name = nullptr;
    const char* section_name = nullptr;
    bpf_object_ptr unique_object[2];
    fd_t program_fds[2] = {0};

    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    result = ebpf_program_load(
        SAMPLE_PATH "test_sample_ebpf.o",
        BPF_PROG_TYPE_UNSPEC,
        EBPF_EXECUTION_JIT,
        &unique_object[0],
        &program_fds[0],
        &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    result = ebpf_program_load(
        SAMPLE_PATH "test_sample_ebpf.o",
        BPF_PROG_TYPE_UNSPEC,
        EBPF_EXECUTION_INTERPRET,
        &unique_object[1],
        &program_fds[1],
        &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    ebpf_execution_type_t type;
    program_id = 0;
    REQUIRE(bpf_prog_get_next_id(program_id, &next_program_id) == 0);
    program_id = next_program_id;
    fd_t program_fd = bpf_prog_get_fd_by_id(program_id);
    REQUIRE(program_fd > 0);
    REQUIRE(ebpf_program_query_info(program_fd, &type, &file_name, &section_name) == EBPF_SUCCESS);
    Platform::_close(program_fd);
    REQUIRE(type == EBPF_EXECUTION_JIT);
    REQUIRE(strcmp(file_name, SAMPLE_PATH "test_sample_ebpf.o") == 0);
    ebpf_free_string(file_name);
    file_name = nullptr;
    REQUIRE(strcmp(section_name, "sample_ext") == 0);
    ebpf_free_string(section_name);
    section_name = nullptr;

    REQUIRE(bpf_prog_get_next_id(program_id, &next_program_id) == 0);
    program_id = next_program_id;
    program_fd = bpf_prog_get_fd_by_id(program_id);
    REQUIRE(program_fd > 0);
    REQUIRE(ebpf_program_query_info(program_fd, &type, &file_name, &section_name) == EBPF_SUCCESS);
    Platform::_close(program_fd);
    REQUIRE(type == EBPF_EXECUTION_INTERPRET);
    REQUIRE(strcmp(file_name, SAMPLE_PATH "test_sample_ebpf.o") == 0);
    REQUIRE(strcmp(section_name, "sample_ext") == 0);
    ebpf_free_string(file_name);
    ebpf_free_string(section_name);
    file_name = nullptr;
    section_name = nullptr;

    REQUIRE(bpf_prog_get_next_id(program_id, &next_program_id) == -ENOENT);

    for (int i = 0; i < _countof(unique_object); i++) {
        bpf_object__close(unique_object[i].release());
    }
}

TEST_CASE("enumerate_and_query_programs", "[end_to_end]") { test_enumerate_and_query_programs(); }

void
test_implicit_detach()
{
    // This test case does the following:
    // 1. Close program handle. An implicit detach should happen and program
    //    object should be deleted.
    // 2. Close link handle. The link object should be deleted.

    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    int result = 0;
    bpf_object_ptr unique_object;
    fd_t program_fd;
    const char* error_message = nullptr;
    bpf_link* link = nullptr;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    result = ebpf_program_load(
        SAMPLE_PATH "test_sample_ebpf.o",
        BPF_PROG_TYPE_UNSPEC,
        EBPF_EXECUTION_JIT,
        &unique_object,
        &program_fd,
        &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    REQUIRE(hook.attach_link(program_fd, nullptr, 0, &link) == EBPF_SUCCESS);

    // Call bpf_object__close() which will close the program fd. That should
    // detach the program from the hook and unload the program.
    bpf_object__close(unique_object.release());

    uint32_t program_id;
    REQUIRE(bpf_prog_get_next_id(0, &program_id) == -ENOENT);

    // Close link handle (without detaching). This should delete the link
    // object. ebpf_object_tracking_terminate() which is called when the test
    // exits checks if all the objects in EC have been deleted.
    hook.close_link(link);
}

// This test uses ebpf_link_close() to test implicit detach.
TEST_CASE("implicit_detach", "[end_to_end]") { test_implicit_detach(); }

void
test_implicit_detach_2()
{
    // This test case does the following:
    // 1. Close program handle. An implicit detach should happen and the program
    //    object should be deleted.
    // 2. Close link handle. The link object should be deleted.

    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    int result = 0;
    bpf_object_ptr unique_object;
    fd_t program_fd;
    const char* error_message = nullptr;
    bpf_link* link = nullptr;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    result = ebpf_program_load(
        SAMPLE_PATH "test_sample_ebpf.o",
        BPF_PROG_TYPE_UNSPEC,
        EBPF_EXECUTION_JIT,
        &unique_object,
        &program_fd,
        &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    REQUIRE(hook.attach_link(program_fd, nullptr, 0, &link) == EBPF_SUCCESS);

    // Call bpf_object__close() which will close the program fd. That should
    // detach the program from the hook and unload the program.
    bpf_object__close(unique_object.release());

    uint32_t program_id;
    REQUIRE(bpf_prog_get_next_id(0, &program_id) == -ENOENT);

    // Close link handle (without detaching). This should delete the link
    // object. ebpf_object_tracking_terminate() which is called when the test
    // exits checks if all the objects in the execution context have been deleted.
    bpf_link__disconnect(link);
    REQUIRE(bpf_link__destroy(link) == 0);
}

// This test uses bpf_link__disconnect() and bpf_link__destroy() to test
// implicit detach.
TEST_CASE("implicit_detach_2", "[end_to_end]") { test_implicit_detach_2(); }

TEST_CASE("ebpf_program_attach_by_fds-jit", "[end_to_end]") { ebpf_program_attach_fds_test(EBPF_EXECUTION_JIT); }
#endif

TEST_CASE("ebpf_program_attach_by_fds-native", "[end_to_end]") { ebpf_program_attach_fds_test(EBPF_EXECUTION_NATIVE); }

#if !defined(CONFIG_BPF_INTERPRETER_DISABLED) || !defined(CONFIG_BPF_JIT_DISABLED)
void
xdp_decapsulate_permit_packet_test(ebpf_execution_type_t execution_type, ADDRESS_FAMILY address_family)
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP_TEST, EBPF_ATTACH_TYPE_XDP_TEST);
    uint32_t ifindex = 0;
    program_load_attach_helper_t program_helper;
    program_helper.initialize(
        SAMPLE_PATH "decap_permit_packet.o",
        BPF_PROG_TYPE_XDP_TEST,
        "decapsulate_permit_packet",
        execution_type,
        &ifindex,
        sizeof(ifindex),
        hook);

    // Dummy IP in IP packet with fake IP and MAC addresses.
    ip_in_ip_packet_t packet(address_family);

    size_t offset = sizeof(ebpf::ETHERNET_HEADER);
    offset += (address_family == AF_INET) ? sizeof(ebpf::IPV4_HEADER) : sizeof(ebpf::IPV6_HEADER);
    uint8_t* inner_ip_header = packet.packet().data() + offset;
    std::vector<uint8_t> inner_ip_datagram(inner_ip_header, packet.packet().data() + packet.packet().size());

    uint32_t hook_result = 0;
    xdp_md_helper_t ctx(packet.packet());
    REQUIRE(hook.fire(ctx.get_ctx(), &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == XDP_PASS);

    ebpf::ETHERNET_HEADER* ethernet_header = reinterpret_cast<ebpf::ETHERNET_HEADER*>(ctx.context.data);

    if (address_family == AF_INET) {
        ebpf::IPV4_HEADER* ipv4_header = reinterpret_cast<ebpf::IPV4_HEADER*>(ethernet_header + 1);
        REQUIRE(memcmp(ipv4_header, inner_ip_datagram.data(), inner_ip_datagram.size()) == 0);
    } else {
        ebpf::IPV6_HEADER* ipv6 = reinterpret_cast<ebpf::IPV6_HEADER*>(ethernet_header + 1);
        REQUIRE(memcmp(ipv6, inner_ip_datagram.data(), inner_ip_datagram.size()) == 0);
    }
}

void
test_ebpf_program_load_bytes_name_gen()
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    // Try with a valid set of instructions.
    prevail::EbpfInst instructions[] = {
        {0xb7, prevail::R0_RETURN_VALUE, 0}, // r0 = 0
        {prevail::INST_OP_EXIT},             // return r0
    };
    uint32_t insn_cnt = _countof(instructions);
    const bpf_prog_type_t prog_type = BPF_PROG_TYPE_SAMPLE;
    const ebpf_program_type_t* program_type = ebpf_get_ebpf_program_type(prog_type);

    REQUIRE(program_type != nullptr);
    REQUIRE(insn_cnt != 0);

    fd_t program_fd;
#pragma warning(suppress : 28193) // result is examined.
    ebpf_result_t result = ebpf_program_load_bytes(
        program_type,
        nullptr,
        EBPF_EXECUTION_ANY,
        reinterpret_cast<const ebpf_inst*>(instructions),
        insn_cnt,
        nullptr,
        0,
        &program_fd,
        nullptr);

    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(program_fd >= 0);

    // Now query the program info and verify it matches what we set.
    bpf_prog_info program_info = {};
    uint32_t program_info_size = sizeof(program_info);
    REQUIRE(bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_size) == 0);
    REQUIRE(program_info_size == sizeof(program_info));
    REQUIRE(program_info.nr_map_ids == 0);
    REQUIRE(program_info.map_ids == 0);
    REQUIRE(program_info.name != NULL);
    // Name should contain SHA256 hash in hex (minus last char to stay under BPF_OBJ_NAME_LEN).
    REQUIRE(strlen(program_info.name) == 63);

    REQUIRE(program_info.type == prog_type);

    Platform::_close(program_fd);
}

TEST_CASE("ebpf_program_load_bytes-name-gen", "[end-to-end]") { test_ebpf_program_load_bytes_name_gen(); }
#endif

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("xdp-decapsulate-permit-v4-jit", "[xdp_tests]")
{
    xdp_decapsulate_permit_packet_test(EBPF_EXECUTION_JIT, AF_INET);
}
TEST_CASE("xdp-decapsulate-permit-v6-jit", "[xdp_tests]")
{
    xdp_decapsulate_permit_packet_test(EBPF_EXECUTION_JIT, AF_INET6);
}

void
test_auto_pinned_maps_custom_path()
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    struct bpf_object_open_opts opts = {0};
    opts.pin_root_path = "/custompath/global";
    bpf_object_ptr object;
    {
        struct bpf_object* local_object = bpf_object__open_file("map_reuse.o", &opts);
        REQUIRE(local_object != nullptr);
        object.reset(local_object);
    }

    // Load the program.
    REQUIRE(bpf_object__load(object.get()) == 0);

    struct bpf_program* program = bpf_object__find_program_by_name(object.get(), "lookup_update");
    REQUIRE(program != nullptr);

    // Attach should now succeed.
    bpf_link_ptr link;
    {
        struct bpf_link* local_link = bpf_program__attach(program);
        REQUIRE(local_link != nullptr);
        link.reset(local_link);
    }

    fd_t outer_map_fd = bpf_obj_get("/custompath/global/outer_map");
    REQUIRE(outer_map_fd > 0);

    int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(inner_map_fd > 0);

    __u32 outer_key = 0;
    int error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error == 0);

    // Add an entry in the inner map.
    __u32 key = 0;
    __u32 value = 200;
    error = bpf_map_update_elem(inner_map_fd, &key, &value, BPF_ANY);
    REQUIRE(error == 0);

    fd_t port_map_fd = bpf_obj_get("/custompath/global/port_map");
    REQUIRE(port_map_fd > 0);

    INITIALIZE_SAMPLE_CONTEXT
    uint32_t hook_result = 0;

    REQUIRE(hook.fire(ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == 200);

    key = 0;
    __u32 port_map_value;
    REQUIRE(bpf_map_lookup_elem(port_map_fd, &key, &port_map_value) == EBPF_SUCCESS);
    REQUIRE(port_map_value == 200);

    REQUIRE(get_total_map_count() == 4);

    Platform::_close(outer_map_fd);
    Platform::_close(inner_map_fd);
    Platform::_close(port_map_fd);

    REQUIRE(ebpf_object_unpin("/custompath/global/outer_map") == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin("/custompath/global/port_map") == EBPF_SUCCESS);
}

TEST_CASE("auto_pinned_maps_custom_path", "[end_to_end]") { test_auto_pinned_maps_custom_path(); }
#endif

// This test validates that a different program type (XDP in this case) cannot call
// a helper function that is not implemented for that program type. Program load should
// fail for such a program.
void
test_invalid_bpf_get_socket_cookie(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    int result;
    const char* error_message = nullptr;
    bpf_object_ptr unique_object;
    fd_t program_fd;

    program_info_provider_t xdp_program_info;
    REQUIRE(xdp_program_info.initialize(EBPF_PROGRAM_TYPE_XDP) == EBPF_SUCCESS);

    const char* file_name =
        (execution_type == EBPF_EXECUTION_NATIVE ? "xdp_invalid_socket_cookie_um.dll" : "xdp_invalid_socket_cookie.o");
    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == -22);
}

TEST_CASE("invalid_bpf_get_socket_cookie", "[end_to_end]")
{
#if !defined(CONFIG_BPF_JIT_DISABLED)
    test_invalid_bpf_get_socket_cookie(EBPF_EXECUTION_JIT);
#endif
#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
    test_invalid_bpf_get_socket_cookie(EBPF_EXECUTION_INTERPRET);
#endif
    test_invalid_bpf_get_socket_cookie(EBPF_EXECUTION_NATIVE);
}