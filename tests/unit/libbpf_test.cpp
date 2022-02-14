// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <io.h>
#include <WinSock2.h>

#define bpf_insn ebpf_inst
#include "bpf/bpf.h"
#pragma warning(push)
#pragma warning(disable : 4200)
#include "bpf/libbpf.h"
#pragma warning(pop)
#include "catch_wrapper.hpp"
#include "ebpf_vm_isa.hpp"
#include "helpers.h"
#include "platform.h"
#include "program_helper.h"
#include "test_helper.hpp"

// libbpf.h uses enum types and generates the
// following warning whenever an enum type is used below:
// "The enum type 'bpf_attach_type' is unscoped.
// Prefer 'enum class' over 'enum'"
#pragma warning(disable : 26812)

TEST_CASE("empty bpf_load_program", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    // An empty set of instructions is invalid.
    int program_fd = bpf_load_program(BPF_PROG_TYPE_XDP, nullptr, 0, nullptr, 0, nullptr, 0);
    REQUIRE(program_fd < 0);
    REQUIRE(errno == EINVAL);
}

TEST_CASE("invalid bpf_load_program", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    // Try with an invalid set of instructions.
    struct bpf_insn instructions[] = {
        {INST_OP_EXIT}, // return r0
    };

    // Try to load and verify the eBPF program.
    char log_buffer[1024];
    int program_fd = bpf_load_program(
        BPF_PROG_TYPE_XDP, instructions, _countof(instructions), nullptr, 0, log_buffer, sizeof(log_buffer));
    REQUIRE(program_fd < 0);
    REQUIRE(errno == EACCES);
    REQUIRE(strcmp(log_buffer, "\n0: r0.type == number\n\n") == 0);
}

TEST_CASE("valid bpf_load_program", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    // Try with a valid set of instructions.
    struct bpf_insn instructions[] = {
        {0xb7, R0_RETURN_VALUE, 0}, // r0 = 0
        {INST_OP_EXIT},             // return r0
    };

    // Load and verify the eBPF program.
    int program_fd = bpf_load_program(BPF_PROG_TYPE_XDP, instructions, _countof(instructions), nullptr, 0, nullptr, 0);
    REQUIRE(program_fd >= 0);

    // Now query the program info and verify it matches what we set.
    bpf_prog_info program_info;
    uint32_t program_info_size = sizeof(program_info);
    REQUIRE(bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_size) == 0);
    REQUIRE(program_info_size == sizeof(program_info));
    REQUIRE(program_info.nr_map_ids == 0);

    // TODO(issue #223): change below to BPF_PROG_TYPE_XDP.
    REQUIRE(program_info.type == BPF_PROG_TYPE_UNSPEC);

    Platform::_close(program_fd);
}

// Define macros that appear in the Linux man page to values in ebpf_vm_isa.h.
#define BPF_LD_MAP_FD(reg, fd) \
    {INST_OP_LDDW_IMM, (reg), 1, 0, (fd)}, { 0 }
#define BPF_ALU64_IMM(op, reg, imm)                                     \
    {                                                                   \
        INST_CLS_ALU64 | INST_SRC_IMM | ((op) << 4), (reg), 0, 0, (imm) \
    }
#define BPF_MOV64_IMM(reg, imm)                                  \
    {                                                            \
        INST_CLS_ALU64 | INST_SRC_IMM | 0xb0, (reg), 0, 0, (imm) \
    }
#define BPF_MOV64_REG(dst, src)                                  \
    {                                                            \
        INST_CLS_ALU64 | INST_SRC_REG | 0xb0, (dst), (src), 0, 0 \
    }
#define BPF_EXIT_INSN() \
    {                   \
        INST_OP_EXIT    \
    }
#define BPF_CALL_FUNC(imm)           \
    {                                \
        INST_OP_CALL, 0, 0, 0, (imm) \
    }
#define BPF_STX_MEM(sz, dst, src, off)                                \
    {                                                                 \
        INST_CLS_STX | (INST_MEM << 5) | (sz), (dst), (src), (off), 0 \
    }
#define BPF_W INST_SIZE_W
#define BPF_REG_1 R1_ARG
#define BPF_REG_2 R2_ARG
#define BPF_REG_3 R3_ARG
#define BPF_REG_4 R4_ARG
#define BPF_REG_10 R10_STACK_POINTER
#define BPF_ADD 0

TEST_CASE("valid bpf_load_program with map", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    int map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 2, 0);
    REQUIRE(map_fd >= 0);

    // Try with a valid set of instructions.
    struct bpf_insn instructions[] = {
        BPF_MOV64_IMM(BPF_REG_1, 0),                   // r1 = 0
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -4), // *(u32 *)(r10 - 4) = r1
        BPF_MOV64_IMM(BPF_REG_1, 42),                  // r1 = 42
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -8), // *(u32 *)(r10 - 8) = r1
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),          // r2 = r10
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),         // r2 += -4
        BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),          // r3 = r10
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -8),         // r3 += -8
        BPF_LD_MAP_FD(BPF_REG_1, map_fd),              // r1 = map_fd ll
        BPF_MOV64_IMM(BPF_REG_4, 0),                   // r4 = 0
        BPF_CALL_FUNC(BPF_FUNC_map_update_elem),       // call map_lookup_elem
        BPF_EXIT_INSN(),                               // return r0
    };

    // Load and verify the eBPF program.
    int program_fd = bpf_load_program(BPF_PROG_TYPE_XDP, instructions, _countof(instructions), nullptr, 0, nullptr, 0);
    REQUIRE(program_fd >= 0);

    // Now query the program info and verify it matches what we set.
    bpf_prog_info program_info;
    uint32_t program_info_size = sizeof(program_info);
    REQUIRE(bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_size) == 0);
    REQUIRE(program_info_size == sizeof(program_info));
    REQUIRE(program_info.nr_map_ids == 1);

    // TODO(issue #223): change below to BPF_PROG_TYPE_XDP.
    REQUIRE(program_info.type == BPF_PROG_TYPE_UNSPEC);

    Platform::_close(program_fd);
    Platform::_close(map_fd);
}

TEST_CASE("libbpf program", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    struct bpf_object* object;
    int program_fd;
    int result = bpf_prog_load("droppacket.o", BPF_PROG_TYPE_XDP, &object, &program_fd);
    REQUIRE(result == 0);
    REQUIRE(object != nullptr);
    REQUIRE(program_fd != ebpf_fd_invalid);

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
    REQUIRE(size == 376);

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
    REQUIRE(errno == EEXIST);

    result = bpf_program__unpin(program, pin_path);
    REQUIRE(result == 0);

    // Make sure a duplicate unpin fails.
    result = bpf_program__unpin(program, pin_path);
    REQUIRE(result < 0);
    REQUIRE(errno == ENOENT);

    // Try to pin all (1) programs in the object.
    result = bpf_object__pin_programs(object, pin_path);
    REQUIRE(result == 0);

    // Make sure a duplicate pin fails.
    REQUIRE(bpf_object__pin_programs(object, pin_path) < 0);
    REQUIRE(errno == EEXIST);

    result = bpf_object__unpin_programs(object, pin_path);
    REQUIRE(result == 0);

    // Try to pin all programs and maps in the object.
    result = bpf_object__pin(object, pin_path);
    REQUIRE(result == 0);

    // Make sure a duplicate pin fails.
    REQUIRE(bpf_object__pin_programs(object, pin_path) < 0);
    REQUIRE(errno == EEXIST);

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
    REQUIRE(type == BPF_ATTACH_TYPE_UNSPEC);

    bpf_program__set_expected_attach_type(program, BPF_ATTACH_TYPE_XDP);

    type = bpf_program__get_expected_attach_type(program);
    REQUIRE(type == BPF_ATTACH_TYPE_XDP);

    bpf_link* link = bpf_program__attach(program);
    REQUIRE(link != nullptr);

    int link_fd = bpf_link__fd(link);
    REQUIRE(link_fd >= 0);

    result = bpf_link_detach(link_fd);
    REQUIRE(result == 0);

    result = bpf_link__destroy(link);
    REQUIRE(result == 0);

    bpf_object__close(object);
}

void
test_xdp_ifindex(uint32_t ifindex, int program_fd[2], bpf_prog_info program_info[2])
{
    // Verify there's no program attached to the specified ifindex.
    uint32_t program_id;
    REQUIRE(bpf_xdp_query_id(ifindex, 0, &program_id) < 0);
    REQUIRE(errno == ENOENT);

    // Attach the first program to the specified ifindex.
    REQUIRE(bpf_xdp_attach(ifindex, program_fd[0], 0, nullptr) == 0);
    REQUIRE(bpf_xdp_query_id(ifindex, 0, &program_id) == 0);
    REQUIRE(program_id == program_info[0].id);

    // Replace it with the second program.
    REQUIRE(bpf_set_link_xdp_fd(ifindex, program_fd[1], XDP_FLAGS_REPLACE) == 0);
    REQUIRE(bpf_xdp_query_id(ifindex, 0, &program_id) == 0);
    REQUIRE(program_id == program_info[1].id);

    // Detach the second program.
    REQUIRE(bpf_xdp_detach(ifindex, XDP_FLAGS_REPLACE, nullptr) == 0);

    // Verify there's no program attached to this ifindex.
    REQUIRE(bpf_xdp_query_id(ifindex, 0, &program_id) < 0);
    REQUIRE(errno == ENOENT);
}

#define TEST_IFINDEX 17

TEST_CASE("bpf_set_link_xdp_fd", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    struct bpf_object* object[2];
    struct bpf_program* program[2];
    int program_fd[2];
    bpf_prog_info program_info[2];

    for (int i = 0; i < 2; i++) {
        REQUIRE(bpf_prog_load("droppacket.o", BPF_PROG_TYPE_XDP, &object[i], &program_fd[i]) == 0);
        REQUIRE(object[i] != nullptr);

        program[i] = bpf_object__find_program_by_name(object[i], "DropPacket");
        REQUIRE(program[i] != nullptr);

        uint32_t program_info_size = sizeof(program_info[i]);
        REQUIRE(bpf_obj_get_info_by_fd(program_fd[i], &program_info[i], &program_info_size) == 0);
    }

    test_xdp_ifindex(TEST_IFINDEX, program_fd, program_info);
    test_xdp_ifindex(0, program_fd, program_info);

    bpf_object__close(object[0]);
    bpf_object__close(object[1]);
}

TEST_CASE("libbpf map", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    struct bpf_object* object;
    int program_fd;
    int result = bpf_prog_load("droppacket.o", BPF_PROG_TYPE_XDP, &object, &program_fd);
    REQUIRE(result == 0);
    REQUIRE(object != nullptr);

    // Get the first map.
    struct bpf_map* map = bpf_map__next(nullptr, object);
    REQUIRE(map != nullptr);

    // Verify that there are no maps before this.
    REQUIRE(bpf_map__prev(map, object) == nullptr);

    // Get the next map.
    struct bpf_map* map2 = bpf_map__next(map, object);
    REQUIRE(map2 != nullptr);
    REQUIRE(bpf_map__prev(map2, object) == map);

    // Verify that there are no other maps after this.
    REQUIRE(bpf_map__next(map2, object) == nullptr);
    REQUIRE(bpf_map__prev(nullptr, object) == map2);

    const char* name = bpf_map__name(map);
    REQUIRE(strcmp(name, "dropped_packet_map") == 0);
    REQUIRE(bpf_map__type(map) == BPF_MAP_TYPE_ARRAY);
    REQUIRE(bpf_map__key_size(map) == 4);
    REQUIRE(bpf_map__value_size(map) == 8);
    REQUIRE(bpf_map__max_entries(map) == 1);
    int map_fd = bpf_map__fd(map);
    REQUIRE(map_fd > 0);

    uint64_t value;
    uint32_t index = 2; // Past end of array.

    result = bpf_map_lookup_elem(map_fd, NULL, NULL);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    result = bpf_map_lookup_elem(map_fd, &index, &value);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    result = bpf_map_delete_elem(map_fd, NULL);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    result = bpf_map_delete_elem(map_fd, &index);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    result = bpf_map_update_elem(map_fd, NULL, NULL, 0);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    result = bpf_map_update_elem(map_fd, &index, &value, 0);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    index = 0;
    REQUIRE(bpf_map_lookup_elem(map_fd, &index, &value) == 0);
    REQUIRE(value == 0);

    REQUIRE(bpf_map_delete_elem(map_fd, &index) == 0);

    value = 12345;
    REQUIRE(bpf_map_update_elem(map_fd, &index, &value, 0) == 0);

    value = 0;
    REQUIRE(bpf_map_lookup_elem(map_fd, &index, &value) == 0);
    REQUIRE(value == 12345);

    REQUIRE(bpf_map_delete_elem(map_fd, &index) == 0);

    REQUIRE(bpf_map_lookup_elem(map_fd, &index, &value) == 0);
    REQUIRE(value == 0);

    bpf_object__close(object);
}

TEST_CASE("libbpf map binding", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    struct bpf_object* object;
    int program_fd;
    int result = bpf_prog_load("droppacket.o", BPF_PROG_TYPE_XDP, &object, &program_fd);
    REQUIRE(result == 0);
    REQUIRE(object != nullptr);
    struct bpf_program* program = bpf_program__next(nullptr, object);
    REQUIRE(program != nullptr);

    // Create a map.
    int map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 2, 0);
    REQUIRE(map_fd > 0);
    bpf_map_info info;
    uint32_t info_size = sizeof(info);
    REQUIRE(bpf_obj_get_info_by_fd(map_fd, &info, &info_size) == 0);
    ebpf_id_t map_id = info.id;

    // Try some invalid FDs.
    int error = bpf_prog_bind_map(ebpf_fd_invalid, map_fd, nullptr);
    REQUIRE(error < 0);
    REQUIRE(errno == EBADF);

    error = bpf_prog_bind_map(map_fd, map_fd, nullptr);
    REQUIRE(error < 0);
    REQUIRE(errno == EINVAL);

    error = bpf_prog_bind_map(program_fd, ebpf_fd_invalid, nullptr);
    REQUIRE(error < 0);
    REQUIRE(errno == EBADF);

    error = bpf_prog_bind_map(program_fd, program_fd, nullptr);
    REQUIRE(error < 0);
    REQUIRE(errno == EINVAL);

    // Bind it to the program.
    error = bpf_prog_bind_map(program_fd, map_fd, nullptr);
    REQUIRE(error == 0);

    // Release our own reference on the map.
    Platform::_close(map_fd);

    // Verify that the map still exists.
    map_fd = bpf_map_get_fd_by_id(map_id);
    REQUIRE(map_fd > 0);
    Platform::_close(map_fd);

    // Close the object, which should cause the map to be deleted.
    bpf_object__close(object);
    REQUIRE(bpf_map_get_fd_by_id(map_id) < 0);
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
    REQUIRE(errno == EEXIST);

    result = bpf_map__unpin(map, pin_path);
    REQUIRE(result == 0);

    REQUIRE(bpf_map__is_pinned(map) == false);

    // Make sure a duplicate unpin fails.
    result = bpf_map__unpin(map, pin_path);
    REQUIRE(result < 0);
    REQUIRE(errno == ENOENT);

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
    REQUIRE(errno == EEXIST);

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
    REQUIRE(errno == EEXIST);

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
    struct bpf_map* canary_map = bpf_map__next(map, object);
    REQUIRE(canary_map != nullptr);

    int callee_fd = bpf_program__fd(callee);
    REQUIRE(callee_fd >= 0);

    int map_fd = bpf_map__fd(map);
    REQUIRE(map_fd >= 0);

    int canary_map_fd = bpf_map__fd(canary_map);
    REQUIRE(canary_map_fd >= 0);

    // First do some negative tests.
    int index = 10;
    error = bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&callee_fd, 0);
    REQUIRE(error < 0);
    REQUIRE(errno == -error);
    index = 0;
    int bad_fd = 0;
    error = bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&bad_fd, 0);
    REQUIRE(error < 0);
    REQUIRE(errno == -error);

    // Finally store the correct program fd.
    index = 9;
    error = bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&callee_fd, 0);
    REQUIRE(error == 0);

    // Verify that we can read it back.
    ebpf_id_t callee_id;
    REQUIRE(bpf_map_lookup_elem(map_fd, &index, &callee_id) == 0);

    // Verify that we can convert the ID to a new fd, so we know it is actually
    // a valid program ID.
    int callee_fd2 = bpf_prog_get_fd_by_id(callee_id);
    REQUIRE(callee_fd2 > 0);
    Platform::_close(callee_fd2);

    bpf_link* link = bpf_program__attach_xdp(caller, 1);
    REQUIRE(link != nullptr);

    auto packet = prepare_udp_packet(0, ETHERNET_TYPE_IPV4);
    xdp_md_t ctx{packet.data(), packet.data() + packet.size()};
    int result;
    REQUIRE(hook.fire(&ctx, &result) == EBPF_SUCCESS);
    REQUIRE(result == expected_result);

    uint32_t key = 0;
    uint32_t value = 0;
    error = bpf_map_lookup_elem(canary_map_fd, &key, &value);
    REQUIRE(error == 0);

    // Is bpf_tail_call expected to work?
    // Verify stack unwind occured.
    if (expected_result >= 0) {
        REQUIRE(value == 0);
    } else {
        REQUIRE(value != 0);
    }

    result = bpf_link__destroy(link);
    REQUIRE(result == 0);
    bpf_object__close(object);
}

TEST_CASE("good tail_call", "[libbpf]")
{
    // Verify that 42 is returned, which is done by the callee.
    _ebpf_test_tail_call("tail_call.o", 42);
}

TEST_CASE("bad tail_call", "[libbpf]") { _ebpf_test_tail_call("tail_call_bad.o", -EBPF_INVALID_ARGUMENT); }

TEST_CASE("multiple tail calls", "[libbpf]")
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    struct bpf_object* object;
    int program_fd;
    int index;

    int error = bpf_prog_load("tail_call_multiple.o", BPF_PROG_TYPE_XDP, &object, &program_fd);
    REQUIRE(error == 0);
    REQUIRE(object != nullptr);

    struct bpf_program* caller = bpf_object__find_program_by_name(object, "caller");
    REQUIRE(caller != nullptr);

    struct bpf_program* callee0 = bpf_object__find_program_by_name(object, "callee0");
    REQUIRE(callee0 != nullptr);

    struct bpf_program* callee1 = bpf_object__find_program_by_name(object, "callee1");
    REQUIRE(callee1 != nullptr);

    struct bpf_map* map = bpf_map__next(nullptr, object);
    REQUIRE(map != nullptr);

    int callee0_fd = bpf_program__fd(callee0);
    REQUIRE(callee0_fd >= 0);

    int callee1_fd = bpf_program__fd(callee1);
    REQUIRE(callee1_fd >= 0);

    int map_fd = bpf_map__fd(map);
    REQUIRE(map_fd >= 0);

    // Store callee0 at index 0.
    index = 0;
    error = bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&callee0_fd, 0);
    REQUIRE(error == 0);

    // Store callee1 at index 9
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

    bpf_link* link = bpf_program__attach_xdp(caller, 1);
    REQUIRE(link != nullptr);

    auto packet = prepare_udp_packet(0, ETHERNET_TYPE_IPV4);
    xdp_md_t ctx{packet.data(), packet.data() + packet.size()};
    int result;
    REQUIRE(hook.fire(&ctx, &result) == EBPF_SUCCESS);
    REQUIRE(result == 3);

    // Clear the prog array map entries. This is needed to release reference on the
    // programs which are inserted in the prog array.
    index = 0;
    REQUIRE(bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&ebpf_fd_invalid, 0) == 0);
    REQUIRE(error == 0);

    index = 9;
    REQUIRE(bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&ebpf_fd_invalid, 0) == 0);
    REQUIRE(error == 0);

    result = bpf_link__destroy(link);
    REQUIRE(result == 0);
    bpf_object__close(object);
}

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
    REQUIRE(errno == EBADF);

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
    REQUIRE(errno == EBADF);

    Platform::_close(map_fd);
    bpf_object__close(bind_object);
    bpf_object__close(xdp_object);
}

TEST_CASE("enumerate program IDs", "[libbpf]")
{
    _test_helper_end_to_end test_helper;
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    // Verify the enumeration is empty.
    uint32_t id1;
    REQUIRE(bpf_prog_get_next_id(0, &id1) < 0);
    REQUIRE(errno == ENOENT);

    REQUIRE(bpf_prog_get_next_id(EBPF_ID_NONE, &id1) < 0);
    REQUIRE(errno == ENOENT);

    // Load a file with multiple programs.
    struct bpf_object* xdp_object;
    int xdp_object_fd;
    int error = bpf_prog_load("tail_call.o", BPF_PROG_TYPE_XDP, &xdp_object, &xdp_object_fd);
    REQUIRE(error == 0);
    REQUIRE(xdp_object != nullptr);

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

    bpf_object__close(xdp_object);
}

static void
_ebpf_test_map_in_map(ebpf_map_type_t type)
{
    _test_helper_end_to_end test_helper;

    // Create an inner map that we'll use both as a template and as an actual entry.
    int inner_map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32), sizeof(__u32), 1, 0);
    REQUIRE(inner_map_fd > 0);

    // Verify that we cannot simply create an outer map without a template.
    REQUIRE(bpf_create_map(type, sizeof(__u32), sizeof(__u32), 2, 0) < 0);
    REQUIRE(errno == EBADF);

    REQUIRE(bpf_create_map_in_map(type, nullptr, sizeof(__u32), ebpf_fd_invalid, 2, 0) < 0);
    REQUIRE(errno == EBADF);

    // Verify we can create an outer map with a template.
    int outer_map_fd = bpf_create_map_in_map(type, nullptr, sizeof(__u32), inner_map_fd, 2, 0);
    REQUIRE(outer_map_fd > 0);

    // Verify we can insert the inner map into the outer map.
    __u32 outer_key = 0;
    int error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error == 0);

    // Verify that we can read it back.
    ebpf_id_t inner_map_id;
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
        // Try deleting outer key that doesn't exist
        error = bpf_map_delete_elem(outer_map_fd, &outer_key);
        REQUIRE(error < 0);
        REQUIRE(errno == ENOENT);
    }

    // Try deleting outer key that does exist.
    outer_key = 0;
    error = bpf_map_delete_elem(outer_map_fd, &outer_key);
    REQUIRE(error == 0);

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
TEST_CASE("array of maps", "[libbpf]")
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    struct bpf_object* xdp_object;
    int xdp_object_fd;
    int error = bpf_prog_load("map_in_map.o", BPF_PROG_TYPE_XDP, &xdp_object, &xdp_object_fd);
    REQUIRE(error == 0);
    REQUIRE(xdp_object != nullptr);

    struct bpf_program* caller = bpf_object__find_program_by_name(xdp_object, "lookup");
    REQUIRE(caller != nullptr);

    struct bpf_map* outer_map = bpf_object__find_map_by_name(xdp_object, "outer_map");
    REQUIRE(outer_map != nullptr);

    int outer_map_fd = bpf_map__fd(outer_map);
    REQUIRE(outer_map_fd > 0);

    // Create an inner map.
    int inner_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32), sizeof(__u32), 1, 0);
    REQUIRE(inner_map_fd > 0);

    // Add a value to the inner map.
    int inner_value = 42;
    uint32_t inner_key = 0;
    error = bpf_map_update_elem(inner_map_fd, &inner_key, &inner_value, 0);
    REQUIRE(error == 0);

    // Add inner map to outer map.
    __u32 outer_key = 0;
    error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error == 0);

    bpf_link* link = bpf_program__attach_xdp(caller, 1);
    REQUIRE(link != nullptr);

    // Now run the ebpf program.
    auto packet = prepare_udp_packet(0, ETHERNET_TYPE_IPV4);
    xdp_md_t ctx{packet.data(), packet.data() + packet.size()};
    int result;
    REQUIRE(hook.fire(&ctx, &result) == EBPF_SUCCESS);

    // Verify the return value is what we saved in the inner map.
    REQUIRE(result == inner_value);

    Platform::_close(inner_map_fd);
    bpf_object__close(xdp_object);
}

// Create a map-in-map using id and inner_id.
TEST_CASE("array of maps2", "[libbpf]")
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    struct bpf_object* xdp_object;
    int xdp_object_fd;
    int error = bpf_prog_load("map_in_map_v2.o", BPF_PROG_TYPE_XDP, &xdp_object, &xdp_object_fd);
    REQUIRE(error == 0);
    REQUIRE(xdp_object != nullptr);

    struct bpf_program* caller = bpf_object__find_program_by_name(xdp_object, "lookup");
    REQUIRE(caller != nullptr);

    struct bpf_map* outer_map = bpf_object__find_map_by_name(xdp_object, "outer_map");
    REQUIRE(outer_map != nullptr);

    int outer_map_fd = bpf_map__fd(outer_map);
    REQUIRE(outer_map_fd > 0);

    // Create an inner map.
    int inner_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32), sizeof(__u32), 1, 0);
    REQUIRE(inner_map_fd > 0);

    // Add a value to the inner map.
    int inner_value = 42;
    uint32_t inner_key = 0;
    error = bpf_map_update_elem(inner_map_fd, &inner_key, &inner_value, 0);
    REQUIRE(error == 0);

    // Add inner map to outer map.
    __u32 outer_key = 0;
    error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error == 0);

    bpf_link* link = bpf_program__attach_xdp(caller, 1);
    REQUIRE(link != nullptr);

    // Now run the ebpf program.
    auto packet = prepare_udp_packet(0, ETHERNET_TYPE_IPV4);
    xdp_md_t ctx{packet.data(), packet.data() + packet.size()};
    int result;
    REQUIRE(hook.fire(&ctx, &result) == EBPF_SUCCESS);

    // Verify the return value is what we saved in the inner map.
    REQUIRE(result == inner_value);

    Platform::_close(inner_map_fd);
    bpf_object__close(xdp_object);
}

TEST_CASE("disallow wrong inner map types", "[libbpf]")
{
    _test_helper_end_to_end test_helper;
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    struct bpf_object* xdp_object;
    int xdp_object_fd;
    int error = bpf_prog_load("map_in_map.o", BPF_PROG_TYPE_XDP, &xdp_object, &xdp_object_fd);
    REQUIRE(error == 0);
    REQUIRE(xdp_object != nullptr);

    struct bpf_map* outer_map = bpf_object__find_map_by_name(xdp_object, "outer_map");
    REQUIRE(outer_map != nullptr);

    int outer_map_fd = bpf_map__fd(outer_map);
    REQUIRE(outer_map_fd > 0);

    // Create an inner map of the wrong type.
    int inner_map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32), sizeof(__u32), 1, 0);
    REQUIRE(inner_map_fd > 0);

    // Try to add the array map to the outer map.
    __u32 outer_key = 0;
    error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error < 0);
    REQUIRE(errno == EINVAL);

    Platform::_close(inner_map_fd);

    // Try an inner map with wrong key_size.
    inner_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u64), sizeof(__u32), 1, 0);
    REQUIRE(inner_map_fd > 0);
    error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error < 0);
    REQUIRE(errno == EINVAL);
    Platform::_close(inner_map_fd);

    // Try an inner map of the wrong value size.
    inner_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32), sizeof(__u64), 1, 0);
    REQUIRE(inner_map_fd > 0);
    error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error < 0);
    REQUIRE(errno == EINVAL);
    Platform::_close(inner_map_fd);

    // Try an inner map with wrong max_entries.
    inner_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32), sizeof(__u32), 2, 0);
    REQUIRE(inner_map_fd > 0);
    error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error < 0);
    REQUIRE(errno == EINVAL);
    Platform::_close(inner_map_fd);

    bpf_object__close(xdp_object);
}

TEST_CASE("create map with name", "[libbpf]")
{
    _test_helper_end_to_end test_helper;

    // Create a map with a given name.
    PCSTR name = "mymapname";
    bpf_create_map_attr attr = {0};
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = sizeof(__u32);
    attr.value_size = sizeof(__u32);
    attr.max_entries = 1;
    attr.name = name;
    int map_fd = bpf_create_map_xattr(&attr);
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

    // Verify the enumeration is empty.
    uint32_t id1;
    REQUIRE(bpf_map_get_next_id(0, &id1) < 0);
    REQUIRE(errno == ENOENT);

    REQUIRE(bpf_map_get_next_id(EBPF_ID_NONE, &id1) < 0);
    REQUIRE(errno == ENOENT);

    // Create two maps.
    int map1_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32), sizeof(__u32), 1, 0);
    REQUIRE(map1_fd > 0);

    int map2_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32), sizeof(__u32), 1, 0);
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

TEST_CASE("enumerate link IDs", "[libbpf]")
{
    _test_helper_end_to_end test_helper;
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);
    program_info_provider_t bind_program_info(EBPF_PROGRAM_TYPE_BIND);
    single_instance_hook_t xdp_hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    single_instance_hook_t bind_hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);

    // Verify the enumeration is empty.
    uint32_t id1;
    REQUIRE(bpf_link_get_next_id(0, &id1) < 0);
    REQUIRE(errno == ENOENT);

    REQUIRE(bpf_link_get_next_id(EBPF_ID_NONE, &id1) < 0);
    REQUIRE(errno == ENOENT);

    // Load and attach some programs.
    uint32_t ifindex = 0;
    program_load_attach_helper_t xdp_helper(
        "droppacket.o", EBPF_PROGRAM_TYPE_XDP, "DropPacket", EBPF_EXECUTION_JIT, &ifindex, sizeof(ifindex), xdp_hook);
    program_load_attach_helper_t bind_helper(
        "bindmonitor.o", EBPF_PROGRAM_TYPE_BIND, "BindMonitor", EBPF_EXECUTION_JIT, nullptr, 0, bind_hook);

    // Now enumerate the IDs.
    REQUIRE(bpf_link_get_next_id(0, &id1) == 0);
    fd_t fd1 = bpf_link_get_fd_by_id(id1);
    REQUIRE(fd1 >= 0);
    Platform::_close(fd1);

    uint32_t id2;
    REQUIRE(bpf_link_get_next_id(id1, &id2) == 0);
    fd_t fd2 = bpf_link_get_fd_by_id(id2);
    REQUIRE(fd2 >= 0);
    Platform::_close(fd2);

    uint32_t id3;
    REQUIRE(bpf_link_get_next_id(id2, &id3) < 0);
    REQUIRE(errno == ENOENT);
}

TEST_CASE("bpf_obj_get_info_by_fd", "[libbpf]")
{
    _test_helper_end_to_end test_helper;
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);
    single_instance_hook_t xdp_hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    uint32_t ifindex = 0;
    program_load_attach_helper_t xdp_helper(
        "droppacket.o", EBPF_PROGRAM_TYPE_XDP, "DropPacket", EBPF_EXECUTION_JIT, &ifindex, sizeof(ifindex), xdp_hook);

    struct bpf_object* object = xdp_helper.get_object();
    REQUIRE(object != nullptr);

    struct bpf_program* program = bpf_program__next(nullptr, object);
    REQUIRE(program != nullptr);

    const char* program_name = bpf_program__name(program);
    REQUIRE(program_name != nullptr);

    int program_fd = bpf_program__fd(program);
    REQUIRE(program_fd > 0);

    struct bpf_map* map = bpf_map__next(nullptr, object);
    REQUIRE(map != nullptr);

    const char* map_name = bpf_map__name(map);
    REQUIRE(map_name != nullptr);

    int map_fd = bpf_map__fd(map);
    REQUIRE(map_fd > 0);

    // Fetch info about the map and verify it matches what we'd expect.
    bpf_map_info map_info;
    uint32_t map_info_size = sizeof(map_info);
    REQUIRE(bpf_obj_get_info_by_fd(map_fd, &map_info, &map_info_size) == 0);
    REQUIRE(map_info_size == sizeof(map_info));
    REQUIRE(map_info.type == BPF_MAP_TYPE_ARRAY);
    REQUIRE(map_info.key_size == sizeof(uint32_t));
    REQUIRE(map_info.value_size == sizeof(uint64_t));
    REQUIRE(map_info.max_entries == 1);
    REQUIRE(strcmp(map_info.name, map_name) == 0);

    // Fetch info about the program and verify it matches what we'd expect.
    bpf_prog_info program_info;
    uint32_t program_info_size = sizeof(program_info);
    REQUIRE(bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_size) == 0);
    REQUIRE(program_info_size == sizeof(program_info));
    REQUIRE(strcmp(program_info.name, program_name) == 0);
    REQUIRE(program_info.nr_map_ids == 2);

    // Fetch info about the attachment and verify it matches what we'd expect.
    uint32_t link_id;
    REQUIRE(bpf_link_get_next_id(0, &link_id) == 0);
    fd_t link_fd = bpf_link_get_fd_by_id(link_id);
    REQUIRE(link_fd >= 0);

    bpf_link_info link_info;
    uint32_t link_info_size = sizeof(link_info);
    REQUIRE(bpf_obj_get_info_by_fd(link_fd, &link_info, &link_info_size) == 0);
    REQUIRE(link_info_size == sizeof(link_info));

    REQUIRE(link_info.prog_id == program_info.id);

    // Verify we can detach using this link fd.
    // This is the flow used by bpftool to detach a link.
    REQUIRE(bpf_link_detach(link_fd) == 0);

    Platform::_close(link_fd);
}

TEST_CASE("libbpf_prog_type_by_name", "[libbpf]")
{
    bpf_prog_type prog_type;
    bpf_attach_type expected_attach_type;

    // Try a cross-platform type.
    REQUIRE(libbpf_prog_type_by_name("xdp", &prog_type, &expected_attach_type) == 0);
    REQUIRE(prog_type == BPF_PROG_TYPE_XDP);
    REQUIRE(expected_attach_type == BPF_ATTACH_TYPE_XDP);

    // Try a Windows-specific type.
    REQUIRE(libbpf_prog_type_by_name("bind", &prog_type, &expected_attach_type) == 0);
    REQUIRE(prog_type == BPF_PROG_TYPE_BIND);
    REQUIRE(expected_attach_type == BPF_ATTACH_TYPE_UNSPEC);

    // Try something that will fall back to the default.
    REQUIRE(libbpf_prog_type_by_name("default", &prog_type, &expected_attach_type) == 0);
    REQUIRE(prog_type == BPF_PROG_TYPE_XDP);
    REQUIRE(expected_attach_type == BPF_ATTACH_TYPE_XDP);
}

TEST_CASE("libbpf_get_error", "[libbpf]")
{
    errno = 123;
    REQUIRE(libbpf_get_error(nullptr) == -123);
}

TEST_CASE("bpf_object__load", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    const char* my_object_name = "my_object_name";
    struct bpf_object_open_opts opts = {0};
    opts.object_name = my_object_name;
    struct bpf_object* object = bpf_object__open_file("droppacket.o", &opts);
    REQUIRE(object != nullptr);

    REQUIRE(strcmp(bpf_object__name(object), my_object_name) == 0);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "DropPacket");
    REQUIRE(program != nullptr);

    REQUIRE(bpf_program__fd(program) == ebpf_fd_invalid);
    REQUIRE(bpf_program__get_type(program) == BPF_PROG_TYPE_XDP);

    // Make sure we can override the program type if desired.
    bpf_program__set_type(program, BPF_PROG_TYPE_BIND);
    REQUIRE(bpf_program__get_type(program) == BPF_PROG_TYPE_BIND);

    bpf_program__set_type(program, BPF_PROG_TYPE_XDP);

    // Trying to attach the program should fail since it's not loaded yet.
    bpf_link* link = bpf_program__attach(program);
    REQUIRE(link == nullptr);
    REQUIRE(libbpf_get_error(link) == -EINVAL);

    // Load the program.
    REQUIRE(bpf_object__load(object) == 0);

    // Attach should now succeed.
    link = bpf_program__attach(program);
    REQUIRE(link != nullptr);

    REQUIRE(bpf_link__destroy(link) == 0);
    bpf_object__close(object);
}

// Test bpf() with the following command ids:
// BPF_PROG_LOAD, BPF_OBJ_GET_INFO_BY_FD, BPF_PROG_GET_NEXT_ID,
// BPF_MAP_CREATE, BPF_MAP_GET_NEXT_ID, BPF_PROG_BIND_MAP,
// and BPF_MAP_GET_FD_BY_ID.
TEST_CASE("BPF_PROG_BIND_MAP etc.", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    struct bpf_insn instructions[] = {
        {0xb7, R0_RETURN_VALUE, 0}, // r0 = 0
        {INST_OP_EXIT},             // return r0
    };

    // Load and verify the eBPF program.
    union bpf_attr attr = {};
    attr.prog_type = BPF_PROG_TYPE_XDP;
    attr.insns = (uintptr_t)instructions;
    attr.insn_cnt = _countof(instructions);
    int program_fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    REQUIRE(program_fd >= 0);

    // Now query the program info and verify it matches what we set.
    bpf_prog_info program_info;
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = program_fd;
    attr.info.info = (uintptr_t)&program_info;
    attr.info.info_len = sizeof(program_info);
    REQUIRE(bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0);
    REQUIRE(attr.info.info_len == sizeof(program_info));
    REQUIRE(program_info.nr_map_ids == 0);
    REQUIRE(program_info.type == BPF_PROG_TYPE_UNSPEC); // TODO(issue #223): change to BPF_PROG_TYPE_XDP.

    // Verify we can enumerate the program id.
    memset(&attr, 0, sizeof(attr));
    attr.start_id = 0;
    REQUIRE(bpf(BPF_PROG_GET_NEXT_ID, &attr, sizeof(attr)) == 0);
    REQUIRE(attr.next_id == program_info.id);

    // Create a map.
    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = sizeof(uint32_t);
    attr.value_size = sizeof(uint32_t);
    attr.max_entries = 2;
    attr.map_flags = 0;
    int map_fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
    REQUIRE(map_fd > 0);

    // Query the map id.
    bpf_map_info info;
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = map_fd;
    attr.info.info = (uintptr_t)&info;
    attr.info.info_len = sizeof(info);
    REQUIRE(bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0);
    ebpf_id_t map_id = info.id;

    // Verify we can enumerate the map id.
    memset(&attr, 0, sizeof(attr));
    attr.start_id = 0;
    REQUIRE(bpf(BPF_MAP_GET_NEXT_ID, &attr, sizeof(attr)) == 0);
    REQUIRE(attr.next_id == map_id);

    // Bind it to the program.
    memset(&attr, 0, sizeof(attr));
    attr.prog_bind_map.prog_fd = program_fd;
    attr.prog_bind_map.map_fd = map_fd;
    attr.prog_bind_map.flags = 0;
    REQUIRE(bpf(BPF_PROG_BIND_MAP, &attr, sizeof(attr)) == 0);

    // Release our own references on the map and program.
    Platform::_close(map_fd);
    Platform::_close(program_fd);
}

// Test bpf() with the following command ids:
// BPF_MAP_CREATE, BPF_MAP_UPDATE_ELEM, BPF_MAP_LOOKUP_ELEM,
// BPF_MAP_GET_NEXT_KEY, and BPF_MAP_DELETE_ELEM.
TEST_CASE("BPF_MAP_GET_NEXT_KEY etc.", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    // Create a hash map.
    union bpf_attr attr = {};
    attr.map_type = BPF_MAP_TYPE_HASH;
    attr.key_size = sizeof(uint32_t);
    attr.value_size = sizeof(uint32_t);
    attr.max_entries = 2;
    attr.map_flags = 0;
    int map_fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
    REQUIRE(map_fd > 0);

    // Add an entry.
    uint64_t value = 12345;
    uint32_t key = 42;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd;
    attr.key = (uintptr_t)&key;
    attr.value = (uintptr_t)&value;
    attr.flags = 0;
    REQUIRE(bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) == 0);

    // Look up the entry.
    value = 0;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd;
    attr.key = (uintptr_t)&key;
    attr.value = (uintptr_t)&value;
    REQUIRE(bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) == 0);
    REQUIRE(value == 12345);

    // Enumerate the entry.
    uint32_t next_key;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd;
    attr.key = 0;
    attr.next_key = (uintptr_t)&next_key;
    REQUIRE(bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr)) == 0);
    REQUIRE(next_key == key);

    // Verify the entry is the last entry.
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd;
    attr.key = (uintptr_t)&key;
    attr.next_key = (uintptr_t)&next_key;
    REQUIRE(bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr)) < 0);
    REQUIRE(errno == ENOENT);

    // Delete the entry.
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd;
    attr.key = (uintptr_t)&key;
    REQUIRE(bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr)) == 0);

    // Verify that no entries exist.
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd;
    attr.key = 0;
    attr.next_key = (uintptr_t)&next_key;
    REQUIRE(bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr)) < 0);
    REQUIRE(errno == ENOENT);

    Platform::_close(map_fd);
}
