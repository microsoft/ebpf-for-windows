// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include "bpf.h"
#include "catch_wrapper.hpp"
#include "helpers.h"
#pragma warning(push)
#pragma warning(disable : 4200)
#include "libbpf.h"
#pragma warning(pop)
#include "test_helper.hpp"

// libbpf.h uses enum types and generates the
// following warning whenever an enum type is used below:
// "The enum type 'bpf_attach_type' is unscoped.
// Prefer 'enum class' over 'enum'"
#pragma warning(disable : 26812)

TEST_CASE("libbpf program", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    struct bpf_object* object;
    int program_fd;
    int result = bpf_prog_load("droppacket.o", BPF_PROG_TYPE_XDP, &object, &program_fd);
    REQUIRE(result == 0);
    REQUIRE(object != nullptr);
    REQUIRE(program_fd != -1);

    const char* name = bpf_object__name(object);
    REQUIRE(strcmp(name, "droppacket.o") == 0);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "DropPacket");
    REQUIRE(program != nullptr);

    name = bpf_program__section_name(program);
    REQUIRE(strcmp(name, "xdp") == 0);

    name = bpf_program__name(program);
    REQUIRE(strcmp(name, "DropPacket") == 0);

    int fd2 = bpf_program__fd(program);
    REQUIRE(fd2 == program_fd);

    size_t size = bpf_program__size(program);
    REQUIRE(size == 192);

    REQUIRE(bpf_program__next(program, object) == nullptr);
    REQUIRE(bpf_program__prev(program, object) == nullptr);
    REQUIRE(bpf_program__next(nullptr, object) == program);
    REQUIRE(bpf_program__prev(nullptr, object) == program);

    bpf_object__close(object);
}

TEST_CASE("libbpf program pinning", "[libbpf]")
{
    _test_helper_libbpf test_helper;
    const char* pin_path = "\\temp\\test";

    struct bpf_object* object;
    int program_fd;
    int result = bpf_prog_load("droppacket.o", BPF_PROG_TYPE_XDP, &object, &program_fd);
    REQUIRE(result == 0);
    REQUIRE(object != nullptr);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "DropPacket");
    REQUIRE(program != nullptr);

    // Try to pin the program.
    result = bpf_program__pin(program, pin_path);
    REQUIRE(result == 0);

    // Make sure a duplicate pin fails.
    result = bpf_program__pin(program, pin_path);
    REQUIRE(result < 0);
    REQUIRE(errno == -result);

    result = bpf_program__unpin(program, pin_path);
    REQUIRE(result == 0);

    // Make sure a duplicate unpin fails.
    result = bpf_program__unpin(program, pin_path);
    REQUIRE(result < 0);
    REQUIRE(errno == -result);

    // Try to pin all (1) programs in the object.
    result = bpf_object__pin_programs(object, pin_path);
    REQUIRE(result == 0);

    // Make sure a duplicate pin fails.
    result = bpf_object__pin_programs(object, pin_path);
    REQUIRE(result < 0);
    REQUIRE(errno == -result);

    result = bpf_object__unpin_programs(object, pin_path);
    REQUIRE(result == 0);

    // Try to pin all programs and maps in the object.
    result = bpf_object__pin(object, pin_path);
    REQUIRE(result == 0);

    // Make sure a duplicate pin fails.
    result = bpf_object__pin_programs(object, pin_path);
    REQUIRE(result < 0);
    REQUIRE(errno == -result);

    // There is no bpf_object__unpin API, so
    // we have to unpin programs and maps separately.
    result = bpf_object__unpin_programs(object, pin_path);
    REQUIRE(result == 0);

    result = bpf_object__unpin_maps(object, pin_path);
    REQUIRE(result == 0);

    bpf_object__close(object);
}

TEST_CASE("libbpf program attach", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    struct bpf_object* object;
    int program_fd;
    int result = bpf_prog_load("droppacket.o", BPF_PROG_TYPE_XDP, &object, &program_fd);
    REQUIRE(result == 0);
    REQUIRE(object != nullptr);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "DropPacket");
    REQUIRE(program != nullptr);

    // Based on the program type, verify that the
    // default attach type is set correctly.
    // TODO: it is not currently set.  Update this
    // test once it is set correctly.
    enum bpf_attach_type type = bpf_program__get_expected_attach_type(program);
    REQUIRE(type == BPF_ATTACH_TYPE_UNKNOWN);

    bpf_program__set_expected_attach_type(program, BPF_ATTACH_TYPE_XDP);

    type = bpf_program__get_expected_attach_type(program);
    REQUIRE(type == BPF_ATTACH_TYPE_XDP);

    bpf_link* link = bpf_program__attach(program);
    REQUIRE(link != nullptr);

    result = bpf_link__destroy(link);
    REQUIRE(result == 0);

    // Verify that a duplicate link destroy fails.
    result = bpf_link__destroy(link);
    REQUIRE(result < 0);
    REQUIRE(errno == -result);

    bpf_object__close(object);
}

TEST_CASE("libbpf map", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    struct bpf_object* object;
    int program_fd;
    int result = bpf_prog_load("droppacket.o", BPF_PROG_TYPE_XDP, &object, &program_fd);
    REQUIRE(result == 0);
    REQUIRE(object != nullptr);

    // Get the first (and only) map.
    struct bpf_map* map = bpf_map__next(nullptr, object);
    REQUIRE(map != nullptr);

    // Verify that it's the only map.
    REQUIRE(bpf_map__next(map, object) == nullptr);
    REQUIRE(bpf_map__prev(map, object) == nullptr);
    REQUIRE(bpf_map__prev(nullptr, object) == map);

    const char* name = bpf_map__name(map);
    REQUIRE(strcmp(name, "port_map") == 0);
    REQUIRE(bpf_map__type(map) == BPF_MAP_TYPE_ARRAY);
    REQUIRE(bpf_map__key_size(map) == 4);
    REQUIRE(bpf_map__value_size(map) == 8);
    REQUIRE(bpf_map__max_entries(map) == 1);
    REQUIRE(bpf_map__fd(map) > 0);

    bpf_object__close(object);
}

TEST_CASE("libbpf map pinning", "[libbpf]")
{
    _test_helper_libbpf test_helper;
    const char* pin_path = "\\temp\\test";

    struct bpf_object* object;
    int program_fd;
    int result = bpf_prog_load("droppacket.o", BPF_PROG_TYPE_XDP, &object, &program_fd);
    REQUIRE(result == 0);
    REQUIRE(object != nullptr);

    struct bpf_map* map = bpf_map__next(nullptr, object);
    REQUIRE(map != nullptr);

    REQUIRE(bpf_map__is_pinned(map) == false);

    // Try to pin the map.
    result = bpf_map__pin(map, pin_path);
    REQUIRE(result == 0);

    REQUIRE(bpf_map__is_pinned(map) == true);

    // Make sure a duplicate pin fails.
    result = bpf_map__pin(map, pin_path);
    REQUIRE(result < 0);
    REQUIRE(errno == -result);

    result = bpf_map__unpin(map, pin_path);
    REQUIRE(result == 0);

    REQUIRE(bpf_map__is_pinned(map) == false);

    // Make sure a duplicate unpin fails.
    result = bpf_map__unpin(map, pin_path);
    REQUIRE(result < 0);
    REQUIRE(errno == -result);

    // Clear pin path for the map.
    result = bpf_map__set_pin_path(map, nullptr);
    REQUIRE(result == 0);

    // Try to pin all (1) maps in the object.
    result = bpf_object__pin_maps(object, pin_path);
    REQUIRE(result == 0);

    REQUIRE(bpf_map__is_pinned(map) == true);

    // Make sure a duplicate pin fails.
    result = bpf_object__pin_maps(object, pin_path);
    REQUIRE(result < 0);
    REQUIRE(errno == -result);

    result = bpf_object__unpin_maps(object, pin_path);
    REQUIRE(result == 0);

    REQUIRE(bpf_map__is_pinned(map) == false);

    // Try to pin all programs and maps in the object.
    result = bpf_object__pin(object, pin_path);
    REQUIRE(result == 0);

    REQUIRE(bpf_map__is_pinned(map) == true);

    // Make sure a duplicate pin fails.
    result = bpf_object__pin_maps(object, pin_path);
    REQUIRE(result < 0);
    REQUIRE(errno == -result);

    // There is no bpf_object__unpin API, so
    // we have to unpin programs and maps separately.
    result = bpf_object__unpin_programs(object, pin_path);
    REQUIRE(result == 0);

    result = bpf_object__unpin_maps(object, pin_path);
    REQUIRE(result == 0);

    REQUIRE(bpf_map__is_pinned(map) == false);

    bpf_object__close(object);
}

static void
_ebpf_test_tail_call(_In_z_ const char* filename, int expected_result)
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    struct bpf_object* object;
    int program_fd;
    int error = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &object, &program_fd);
    REQUIRE(error == 0);
    REQUIRE(object != nullptr);

    struct bpf_program* caller = bpf_object__find_program_by_name(object, "caller");
    REQUIRE(caller != nullptr);

    struct bpf_program* callee = bpf_object__find_program_by_name(object, "callee");
    REQUIRE(callee != nullptr);

    struct bpf_map* map = bpf_map__next(nullptr, object);
    REQUIRE(map != nullptr);

    int callee_fd = bpf_program__fd(callee);
    REQUIRE(callee_fd >= 0);

    int map_fd = bpf_map__fd(map);
    REQUIRE(map_fd >= 0);

    // First do some negative tests.
    int index = 1;
    error = bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&callee_fd, 0);
    REQUIRE(error < 0);
    REQUIRE(errno == -error);
    index = 0;
    int bad_fd = 0;
    error = bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&bad_fd, 0);
    REQUIRE(error < 0);
    REQUIRE(errno == -error);

    // Finally store the correct program fd.
    error = bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&callee_fd, 0);
    REQUIRE(error == 0);

    bpf_link* link = bpf_program__attach_xdp(caller, 1);
    REQUIRE(link != nullptr);

    auto packet = prepare_udp_packet(0);
    xdp_md_t ctx{packet.data(), packet.data() + packet.size()};
    int result;
    REQUIRE(hook.fire(&ctx, &result) == EBPF_SUCCESS);
    REQUIRE(result == expected_result);

    result = bpf_link__destroy(link);
    REQUIRE(result == 0);
    bpf_object__close(object);
}

TEST_CASE("good tail_call", "[libbpf]")
{
    // Verify that 42 is returned, which is done by the callee.
    // TODO(issue #344): change the 6 below to 42 once tail call is done correctly.
    _ebpf_test_tail_call("tail_call.o", 6);
}

TEST_CASE("bad tail_call", "[libbpf]") { _ebpf_test_tail_call("tail_call_bad.o", -EBPF_INVALID_ARGUMENT); }

TEST_CASE("disallow setting bind fd in xdp prog array", "[libbpf]")
{
    _test_helper_end_to_end test_helper;
    program_info_provider_t bind_program_info(EBPF_PROGRAM_TYPE_BIND);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    struct bpf_object* xdp_object;
    int xdp_object_fd;
    int error = bpf_prog_load("tail_call.o", BPF_PROG_TYPE_XDP, &xdp_object, &xdp_object_fd);
    REQUIRE(error == 0);
    REQUIRE(xdp_object != nullptr);

    struct bpf_map* map = bpf_map__next(nullptr, xdp_object);
    REQUIRE(map != nullptr);

    // Load a program of any other type.
    struct bpf_object* bind_object;
    int bind_object_fd;
    error = bpf_prog_load("bindmonitor.o", BPF_PROG_TYPE_BIND, &bind_object, &bind_object_fd);
    REQUIRE(error == 0);
    REQUIRE(bind_object != nullptr);

    struct bpf_program* callee = bpf_object__find_program_by_name(bind_object, "BindMonitor");
    REQUIRE(callee != nullptr);

    int callee_fd = bpf_program__fd(callee);
    REQUIRE(callee_fd >= 0);

    int map_fd = bpf_map__fd(map);
    REQUIRE(map_fd >= 0);

    // Verify that we cannot add a BIND program fd to a prog_array map already
    // associated with an XDP program.
    int index = 0;
    error = bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&callee_fd, 0);
    REQUIRE(error < 0);
    REQUIRE(errno == -error);

    bpf_object__close(bind_object);
    bpf_object__close(xdp_object);
}

TEST_CASE("disallow prog_array mixed program type values", "[libbpf]")
{
    _test_helper_end_to_end test_helper;
    program_info_provider_t bind_program_info(EBPF_PROGRAM_TYPE_BIND);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    struct bpf_object* xdp_object;
    int xdp_object_fd;
    int error = bpf_prog_load("droppacket.o", BPF_PROG_TYPE_XDP, &xdp_object, &xdp_object_fd);
    REQUIRE(error == 0);
    REQUIRE(xdp_object != nullptr);

    struct bpf_object* bind_object;
    int bind_object_fd;
    error = bpf_prog_load("bindmonitor.o", BPF_PROG_TYPE_BIND, &bind_object, &bind_object_fd);
    REQUIRE(error == 0);
    REQUIRE(bind_object != nullptr);

    // Create a map.
    int map_fd = bpf_create_map(BPF_MAP_TYPE_PROG_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 2, 0);
    REQUIRE(map_fd > 0);

    // Since the map is not yet associated with a program, the first program fd
    // we add will become the PROG_ARRAY's program type.
    int index = 0;
    error = bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&xdp_object_fd, 0);
    REQUIRE(error == 0);

    // Adding an entry with a different program type should fail.
    error = bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&bind_object_fd, 0);
    REQUIRE(error < 0);
    REQUIRE(errno == -error);

    bpf_object__close(bind_object);
    bpf_object__close(xdp_object);
}
