// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include "catch_wrapper.hpp"
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
    REQUIRE(result != 0);

    result = bpf_program__unpin(program, pin_path);
    REQUIRE(result == 0);

    // Make sure a duplicate unpin fails.
    result = bpf_program__unpin(program, pin_path);
    REQUIRE(result != 0);

    // Try to pin all (1) programs in the object.
    result = bpf_object__pin_programs(object, pin_path);
    REQUIRE(result == 0);

    // Make sure a duplicate pin fails.
    result = bpf_object__pin_programs(object, pin_path);
    REQUIRE(result != 0);

    result = bpf_object__unpin_programs(object, pin_path);
    REQUIRE(result == 0);

    // Try to pin all programs and maps in the object.
    result = bpf_object__pin(object, pin_path);
    REQUIRE(result == 0);

    // Make sure a duplicate pin fails.
    result = bpf_object__pin_programs(object, pin_path);
    REQUIRE(result != 0);

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
    REQUIRE(result != 0);

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
    REQUIRE(result != 0);

    result = bpf_map__unpin(map, pin_path);
    REQUIRE(result == 0);

    REQUIRE(bpf_map__is_pinned(map) == false);

    // Make sure a duplicate unpin fails.
    result = bpf_map__unpin(map, pin_path);
    REQUIRE(result != 0);

    // Clear pin path for the map.
    result = bpf_map__set_pin_path(map, nullptr);
    REQUIRE(result == 0);

    // Try to pin all (1) maps in the object.
    result = bpf_object__pin_maps(object, pin_path);
    REQUIRE(result == 0);

    REQUIRE(bpf_map__is_pinned(map) == true);

    // Make sure a duplicate pin fails.
    result = bpf_object__pin_maps(object, pin_path);
    REQUIRE(result != 0);

    result = bpf_object__unpin_maps(object, pin_path);
    REQUIRE(result == 0);

    REQUIRE(bpf_map__is_pinned(map) == false);

    // Try to pin all programs and maps in the object.
    result = bpf_object__pin(object, pin_path);
    REQUIRE(result == 0);

    REQUIRE(bpf_map__is_pinned(map) == true);

    // Make sure a duplicate pin fails.
    result = bpf_object__pin_maps(object, pin_path);
    REQUIRE(result != 0);

    // There is no bpf_object__unpin API, so
    // we have to unpin programs and maps separately.
    result = bpf_object__unpin_programs(object, pin_path);
    REQUIRE(result == 0);

    result = bpf_object__unpin_maps(object, pin_path);
    REQUIRE(result == 0);

    REQUIRE(bpf_map__is_pinned(map) == false);

    bpf_object__close(object);
}
