// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

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

#include <chrono>
#include <stop_token>
#include <thread>

// The helper function definitions in bpf_helpers.h conflict with the definitions
// in libbpf.h, but this code needs to use MAX_TAIL_CALL_CNT from bpf_helpers.h.
// Work around this by defining MAX_TAIL_CALL_CNT here.
#if !defined(MAX_TAIL_CALL_CNT)
#define MAX_TAIL_CALL_CNT 32
#endif

std::vector<std::string>
ebpf_platform_printk_output();

// libbpf.h uses enum types and generates the
// following warning whenever an enum type is used below:
// "The enum type 'bpf_attach_type' is unscoped.
// Prefer 'enum class' over 'enum'"
#pragma warning(disable : 26812)

#define CONCAT(s1, s2) s1 s2
#define DECLARE_TEST_CASE(_name, _group, _function, _suffix, _execution_type) \
    TEST_CASE(CONCAT(_name, _suffix), _group) { _function(_execution_type); }
#define DECLARE_NATIVE_TEST(_name, _group, _function) \
    DECLARE_TEST_CASE(_name, _group, _function, "-native", EBPF_EXECUTION_NATIVE)
#if !defined(CONFIG_BPF_JIT_DISABLED)
#define DECLARE_JIT_TEST(_name, _group, _function) \
    DECLARE_TEST_CASE(_name, _group, _function, "-jit", EBPF_EXECUTION_JIT)
#else
#define DECLARE_JIT_TEST(_name, _group, _function)
#endif
#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
#define DECLARE_INTERPRET_TEST(_name, _group, _function) \
    DECLARE_TEST_CASE(_name, _group, _function, "-interpret", EBPF_EXECUTION_INTERPRET)
#else
#define DECLARE_INTERPRET_TEST(_name, _group, _function)
#endif

#define DECLARE_ALL_TEST_CASES(_name, _group, _function) \
    DECLARE_JIT_TEST(_name, _group, _function)           \
    DECLARE_NATIVE_TEST(_name, _group, _function)        \
    DECLARE_INTERPRET_TEST(_name, _group, _function)

#define DECLARE_JIT_TEST_CASES(_name, _group, _function) \
    DECLARE_JIT_TEST(_name, _group, _function)           \
    DECLARE_NATIVE_TEST(_name, _group, _function)

const int nonexistent_fd = 12345678;

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("libbpf load program", "[libbpf][deprecated]")
{
    _test_helper_libbpf test_helper;
    struct bpf_object* object;
    int program_fd;
#pragma warning(suppress : 4996) // deprecated
    int result = bpf_prog_load_deprecated("droppacket.o", BPF_PROG_TYPE_XDP, &object, &program_fd);
    REQUIRE(result == 0);
    REQUIRE(object != nullptr);
    REQUIRE(program_fd != ebpf_fd_invalid);

    bpf_object__close(object);
}
#endif

std::vector<uint8_t>
prepare_udp_packet(uint16_t udp_length, uint16_t ethernet_type);

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("libbpf prog test run", "[libbpf][deprecated]")
{
    _test_helper_libbpf test_helper;
    struct bpf_object* object;
    int program_fd;
#pragma warning(suppress : 4996) // deprecated
    int result = bpf_prog_load_deprecated("droppacket.o", BPF_PROG_TYPE_XDP, &object, &program_fd);
    REQUIRE(result == 0);
    REQUIRE(object != nullptr);
    REQUIRE(program_fd != ebpf_fd_invalid);

    auto packet = prepare_udp_packet(100, ETHERNET_TYPE_IPV4);

    bpf_test_run_opts opts = {};
    opts.repeat = 10;
    opts.data_in = packet.data();
    opts.data_size_in = static_cast<uint32_t>(packet.size());
    opts.data_out = nullptr;
    opts.data_size_out = 0;

    REQUIRE(bpf_prog_test_run_opts(program_fd, &opts) == 0);

    REQUIRE(opts.duration > 0);

    // Negative tests

    // Bad fd
    REQUIRE(bpf_prog_test_run_opts(nonexistent_fd, &opts) == -EINVAL);

    // NULL data
    opts.data_in = nullptr;
    opts.data_size_in = 0;
    REQUIRE(bpf_prog_test_run_opts(program_fd, &opts) == 0);

    // Zero length data
    opts.data_in = packet.data();
    opts.data_size_in = 0;
    REQUIRE(bpf_prog_test_run_opts(program_fd, &opts) == 0);

    // Context out is too small
    std::vector<uint8_t> context(1);
    opts.data_in = packet.data();
    opts.data_size_in = static_cast<uint32_t>(packet.size());
    opts.ctx_in = context.data();
    opts.ctx_size_in = static_cast<uint32_t>(context.size());
    opts.ctx_out = context.data();
    opts.ctx_size_out = static_cast<uint32_t>(context.size());
    REQUIRE(bpf_prog_test_run_opts(program_fd, &opts) == -EINVAL);

    // Data in, null data out
    opts.data_in = packet.data();
    opts.data_size_in = static_cast<uint32_t>(packet.size());
    opts.data_out = nullptr;
    opts.data_size_out = 0;
    opts.ctx_in = nullptr;
    opts.ctx_size_in = 0;
    REQUIRE(bpf_prog_test_run_opts(program_fd, &opts) == 0);

    // No context in, Context out
    std::vector<uint8_t> context_out(1024);
    opts.data_in = packet.data();
    opts.data_size_in = static_cast<uint32_t>(packet.size());
    opts.data_out = nullptr;
    opts.data_size_out = 0;
    opts.ctx_in = nullptr;
    opts.ctx_size_in = 0;
    opts.ctx_out = context_out.data();
    opts.ctx_size_out = static_cast<uint32_t>(context_out.size());
    REQUIRE(bpf_prog_test_run_opts(program_fd, &opts) == 0);
    REQUIRE(opts.ctx_size_out == 0);

    // Data out and context out
    context_out.resize(100);
    xdp_md_t context_in = {};
    opts.ctx_in = &context_in;
    opts.ctx_size_in = sizeof(context_in);
    opts.data_out = packet.data();
    opts.data_size_out = static_cast<uint32_t>(packet.size());
    opts.ctx_out = context_out.data();
    opts.ctx_size_out = static_cast<uint32_t>(context_out.size());
    REQUIRE(bpf_prog_test_run_opts(program_fd, &opts) == 0);
    REQUIRE(opts.ctx_size_out == sizeof(xdp_md_t));

    // With bpf syscall
    bpf_attr attr = {};
    attr.test.prog_fd = program_fd;
    attr.test.repeat = 1000;
    attr.test.data_in = reinterpret_cast<uint64_t>(packet.data());
    attr.test.data_out = reinterpret_cast<uint64_t>(packet.data());
    attr.test.data_size_in = static_cast<uint32_t>(packet.size());
    attr.test.data_size_out = static_cast<uint32_t>(packet.size());
    attr.test.ctx_in = reinterpret_cast<uint64_t>(&context_in);
    attr.test.ctx_out = reinterpret_cast<uint64_t>(context_out.data());
    attr.test.ctx_size_in = sizeof(context_in);
    attr.test.ctx_size_out = static_cast<uint32_t>(context_out.size());
    REQUIRE(bpf(BPF_PROG_TEST_RUN, &attr, sizeof(attr)) == 0);
    REQUIRE(attr.test.ctx_size_out == sizeof(xdp_md_t));
    REQUIRE(attr.test.duration > 0);

    bpf_object__close(object);
}
#endif

TEST_CASE("empty bpf_load_program", "[libbpf][deprecated]")
{
    _test_helper_libbpf test_helper;

    // An empty set of instructions is invalid.
#pragma warning(suppress : 4996) // deprecated
    int program_fd = bpf_load_program(BPF_PROG_TYPE_XDP, nullptr, 0, nullptr, 0, nullptr, 0);
    REQUIRE(program_fd < 0);
    REQUIRE(errno == EINVAL);
}

TEST_CASE("empty bpf_prog_load", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    // An empty set of instructions is invalid.
    int program_fd = bpf_prog_load(BPF_PROG_TYPE_XDP, "name", "license", nullptr, 0, nullptr);
    REQUIRE(program_fd < 0);
    REQUIRE(errno == EINVAL);
}

TEST_CASE("too big bpf_prog_load", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    // An empty set of instructions is invalid.
    int program_fd = bpf_prog_load(BPF_PROG_TYPE_XDP, "name", "license", nullptr, UINT32_MAX, nullptr);
    REQUIRE(program_fd < 0);
    REQUIRE(errno == EINVAL);
}

TEST_CASE("invalid bpf_load_program", "[libbpf][deprecated]")
{
    _test_helper_libbpf test_helper;

    // Try with an invalid set of instructions.
    struct ebpf_inst instructions[] = {
        {INST_OP_EXIT}, // return r0
    };

    // Try to load and verify the eBPF program.
    char log_buffer[1024];
#pragma warning(suppress : 4996) // deprecated
    int program_fd = bpf_load_program(
        BPF_PROG_TYPE_XDP,
        (struct bpf_insn*)instructions,
        _countof(instructions),
        nullptr,
        0,
        log_buffer,
        sizeof(log_buffer));
    REQUIRE(program_fd < 0);
#if !defined(CONFIG_BPF_JIT_DISABLED)
    REQUIRE(errno == EACCES);
    REQUIRE(strcmp(log_buffer, "\n0:  (r0.type == number)\n\n") == 0);
#else
    REQUIRE(errno == ENOTSUP);
#endif
}

TEST_CASE("invalid bpf_prog_load", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    // Try with an invalid set of instructions.
    struct ebpf_inst instructions[] = {
        {INST_OP_EXIT}, // return r0
    };

    // Try to load and verify the eBPF program.
    char log_buffer[1024] = "";
    struct bpf_prog_load_opts opts = {.sz = sizeof(opts), .log_size = sizeof(log_buffer), .log_buf = log_buffer};
    int program_fd = bpf_prog_load(
        BPF_PROG_TYPE_XDP, "name", "license", (struct bpf_insn*)instructions, _countof(instructions), &opts);
    REQUIRE(program_fd < 0);
#if !defined(CONFIG_BPF_JIT_DISABLED)
    REQUIRE(errno == EACCES);
    REQUIRE(strcmp(log_buffer, "\n0:  (r0.type == number)\n\n") == 0);
#else
    REQUIRE(errno == ENOTSUP);
#endif
}

TEST_CASE("invalid bpf_load_program - wrong type", "[libbpf][deprecated]")
{
    _test_helper_libbpf test_helper;

    // Try with a valid set of instructions.
    struct ebpf_inst instructions[] = {
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

    // Try with a valid set of instructions.
    struct ebpf_inst instructions[] = {
        {0xb7, R0_RETURN_VALUE, 0}, // r0 = 0
        {INST_OP_EXIT},             // return r0
    };

    // Load and verify the eBPF program.
    int program_fd = bpf_prog_load(
        (bpf_prog_type)-1, "name", "license", (struct bpf_insn*)instructions, _countof(instructions), nullptr);
    REQUIRE(program_fd < 0);
    REQUIRE(errno == EINVAL);
}

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("valid bpf_load_program", "[libbpf][deprecated]")
{
    _test_helper_libbpf test_helper;

    // Try with a valid set of instructions.
    struct ebpf_inst instructions[] = {
        {0xb7, R0_RETURN_VALUE, 0}, // r0 = 0
        {INST_OP_EXIT},             // return r0
    };

    // Load and verify the eBPF program.
#pragma warning(suppress : 4996) // deprecated
    int program_fd = bpf_load_program(
        BPF_PROG_TYPE_XDP, (struct bpf_insn*)instructions, _countof(instructions), nullptr, 0, nullptr, 0);
    REQUIRE(program_fd >= 0);

    // Now query the program info and verify it matches what we set.
    bpf_prog_info program_info = {};
    uint32_t program_info_size = sizeof(program_info);
    REQUIRE(bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_size) == 0);
    REQUIRE(program_info_size == sizeof(program_info));
    REQUIRE(program_info.nr_map_ids == 0);
    REQUIRE(program_info.map_ids == 0);

    REQUIRE(program_info.type == BPF_PROG_TYPE_XDP);

    Platform::_close(program_fd);
}

TEST_CASE("valid bpf_prog_load", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    // Try with a valid set of instructions.
    struct ebpf_inst instructions[] = {
        {0xb7, R0_RETURN_VALUE, 0}, // r0 = 0
        {INST_OP_EXIT},             // return r0
    };

    // Load and verify the eBPF program.
    int program_fd = bpf_prog_load(
        BPF_PROG_TYPE_XDP, "name", nullptr, (struct bpf_insn*)instructions, _countof(instructions), nullptr);
    REQUIRE(program_fd >= 0);

    // Now query the program info and verify it matches what we set.
    bpf_prog_info program_info = {};
    uint32_t program_info_size = sizeof(program_info);
    REQUIRE(bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_size) == 0);
    REQUIRE(program_info_size == sizeof(program_info));
    REQUIRE(program_info.nr_map_ids == 0);
    REQUIRE(program_info.map_ids == 0);
    REQUIRE(strcmp(program_info.name, "name") == 0);

    REQUIRE(program_info.type == BPF_PROG_TYPE_XDP);

    Platform::_close(program_fd);
}

TEST_CASE("valid bpf_load_program_xattr", "[libbpf][deprecated]")
{
    _test_helper_libbpf test_helper;

    // Try with a valid set of instructions.
    struct ebpf_inst instructions[] = {
        {0xb7, R0_RETURN_VALUE, 0}, // r0 = 0
        {INST_OP_EXIT},             // return r0
    };

    // Load and verify the eBPF program.
    struct bpf_load_program_attr attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
        .name = "name",
        .insns = (struct bpf_insn*)instructions,
        .insns_cnt = _countof(instructions)};
#pragma warning(suppress : 4996) // deprecated
    int program_fd = bpf_load_program_xattr(&attr, nullptr, 0);
    REQUIRE(program_fd >= 0);

    // Now query the program info and verify it matches what we set.
    bpf_prog_info program_info = {};
    uint32_t program_info_size = sizeof(program_info);
    REQUIRE(bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_size) == 0);
    REQUIRE(program_info_size == sizeof(program_info));
    REQUIRE(program_info.nr_map_ids == 0);
    REQUIRE(program_info.map_ids == 0);
    REQUIRE(strcmp(program_info.name, "name") == 0);

    REQUIRE(program_info.type == BPF_PROG_TYPE_XDP);

    Platform::_close(program_fd);
}
#endif

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

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("valid bpf_load_program with map", "[libbpf][deprecated]")
{
    _test_helper_libbpf test_helper;

    int map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(uint32_t), sizeof(uint32_t), 2, nullptr);
    REQUIRE(map_fd >= 0);

    // Try with a valid set of instructions.
    struct ebpf_inst instructions[] = {
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
#pragma warning(suppress : 4996) // deprecated
    int program_fd = bpf_load_program(
        BPF_PROG_TYPE_XDP, (struct bpf_insn*)instructions, _countof(instructions), nullptr, 0, nullptr, 0);
    REQUIRE(program_fd >= 0);

    // Now query the program info and verify it matches what we set.
    bpf_prog_info program_info = {};
    uint32_t program_info_size = sizeof(program_info);
    REQUIRE(bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_size) == 0);
    REQUIRE(program_info_size == sizeof(program_info));
    REQUIRE(program_info.nr_map_ids == 1);
    REQUIRE(program_info.map_ids == 0);

    REQUIRE(program_info.type == BPF_PROG_TYPE_XDP);

    Platform::_close(program_fd);
    Platform::_close(map_fd);
}

TEST_CASE("libbpf program", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    struct bpf_object* object = bpf_object__open("droppacket.o");
    REQUIRE(object != nullptr);
    // Load the program(s).
    REQUIRE(bpf_object__load(object) == 0);

    const char* name = bpf_object__name(object);
    REQUIRE(strcmp(name, "droppacket.o") == 0);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "DropPacket");
    REQUIRE(program != nullptr);

    REQUIRE(bpf_object__find_program_by_name(object, "not_a_valid_name") == NULL);
    REQUIRE(errno == ENOENT);

    name = bpf_program__section_name(program);
    REQUIRE(strcmp(name, "xdp") == 0);

    name = bpf_program__name(program);
    REQUIRE(strcmp(name, "DropPacket") == 0);

    int fd2 = bpf_program__fd(program);
    REQUIRE(fd2 != ebpf_fd_invalid);

    size_t size = bpf_program__insn_cnt(program);
    REQUIRE(size == 47);

#pragma warning(suppress : 4996) // deprecated
    size = bpf_program__size(program);
    REQUIRE(size == 376);

    REQUIRE(bpf_object__next_program(object, program) == nullptr);
    REQUIRE(bpf_object__prev_program(object, program) == nullptr);
    REQUIRE(bpf_object__next_program(object, nullptr) == program);
    REQUIRE(bpf_object__prev_program(object, nullptr) == program);

    bpf_object__close(object);
}

TEST_CASE("libbpf program pinning", "[libbpf]")
{
    _test_helper_libbpf test_helper;
    const char* pin_path = "\\temp\\test";

    struct bpf_object* object = bpf_object__open("droppacket.o");
    REQUIRE(object != nullptr);
    // Load the program(s).
    REQUIRE(bpf_object__load(object) == 0);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "DropPacket");
    REQUIRE(program != nullptr);

    // Try to pin the program.
    int result = bpf_program__pin(program, pin_path);
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

    struct bpf_object* object = bpf_object__open("droppacket.o");
    REQUIRE(object != nullptr);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "DropPacket");
    REQUIRE(program != nullptr);

    // Based on the program type, verify that the/ default attach type is set correctly.
    enum bpf_attach_type type = bpf_program__get_expected_attach_type(program);
    REQUIRE(type == BPF_XDP);

    REQUIRE(bpf_program__set_expected_attach_type(program, BPF_XDP) == 0);

    type = bpf_program__get_expected_attach_type(program);
    REQUIRE(type == BPF_XDP);

    int result = bpf_object__load(object);
    REQUIRE(result == 0);

    bpf_link_ptr link(bpf_program__attach(program));
    REQUIRE(link != nullptr);

    int link_fd = bpf_link__fd(link.get());
    REQUIRE(link_fd >= 0);

    result = bpf_link_detach(link_fd);
    REQUIRE(result == 0);

    // Second detach is idempotent.
    result = bpf_link_detach(link_fd);
    REQUIRE(result == 0);

    result = bpf_link_detach(ebpf_handle_invalid);
    REQUIRE(result < 0);
    REQUIRE(errno == EBADF);

    result = bpf_link__destroy(link.release());
    REQUIRE(result == 0);

    bpf_object__close(object);
}
#endif

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
    REQUIRE(bpf_xdp_attach(ifindex, program_fd[1], XDP_FLAGS_REPLACE, nullptr) == 0);
    REQUIRE(bpf_xdp_query_id(ifindex, 0, &program_id) == 0);
    REQUIRE(program_id == program_info[1].id);

    // Detach the second program.
    REQUIRE(bpf_xdp_detach(ifindex, XDP_FLAGS_REPLACE, nullptr) == 0);

    // Verify there's no program attached to this ifindex.
    REQUIRE(bpf_xdp_query_id(ifindex, 0, &program_id) < 0);
    REQUIRE(errno == ENOENT);
}

#define TEST_IFINDEX 17

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("bpf_set_link_xdp_fd", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    struct bpf_object* object[2];
    struct bpf_program* program[2];
    int program_fd[2];
    bpf_prog_info program_info[2] = {};

    for (int i = 0; i < 2; i++) {
        object[i] = bpf_object__open("droppacket.o");
        REQUIRE(object[i] != nullptr);
        // Load the program(s).
        REQUIRE(bpf_object__load(object[i]) == 0);

        program[i] = bpf_object__find_program_by_name(object[i], "DropPacket");
        REQUIRE(program[i] != nullptr);
        program_fd[i] = bpf_program__fd(const_cast<const bpf_program*>(program[i]));

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
    std::vector<std::string> expected_map_names = {
        "HASH_map",
        "PERCPU_HASH_map",
        "ARRAY_map",
        "PERCPU_ARRAY_map",
        "LRU_HASH_map",
        "LRU_PERCPU_HASH_map",
        "QUEUE_map",
        "STACK_map"};
    std::vector<bpf_map_type> expected_map_types = {
        BPF_MAP_TYPE_HASH,
        BPF_MAP_TYPE_PERCPU_HASH,
        BPF_MAP_TYPE_ARRAY,
        BPF_MAP_TYPE_PERCPU_ARRAY,
        BPF_MAP_TYPE_LRU_HASH,
        BPF_MAP_TYPE_LRU_PERCPU_HASH,
        BPF_MAP_TYPE_QUEUE,
        BPF_MAP_TYPE_STACK};
    std::vector<struct bpf_map*> maps;

    struct bpf_object* object = bpf_object__open("map.o");
    REQUIRE(object != nullptr);

    // Load the program(s).
    REQUIRE(bpf_object__load(object) == 0);

    // Find all maps.
    struct bpf_map* map = nullptr;
    bpf_object__for_each_map(map, object) { maps.push_back(map); };

    REQUIRE(maps.size() == expected_map_names.size());

    // Get the first map.
    map = bpf_object__next_map(object, nullptr);
    REQUIRE(map != nullptr);

    // Verify that there are no maps before this.
    REQUIRE(bpf_object__prev_map(object, map) == nullptr);

    // Get the next map.
    struct bpf_map* map2 = bpf_object__next_map(object, map);
    REQUIRE(map2 != nullptr);
    REQUIRE(bpf_object__prev_map(object, map2) == map);

    // Verify that there are no other maps after the last map.
    REQUIRE(bpf_object__next_map(object, maps.back()) == nullptr);

    // Verify the map names, types, key size, value size, max entries, and flags.
    for (size_t i = 0; i < maps.size(); i++) {
        REQUIRE(bpf_map__name(maps[i]) == expected_map_names[i]);
        REQUIRE(bpf_map__type(maps[i]) == expected_map_types[i]);

        if (expected_map_types[i] == BPF_MAP_TYPE_QUEUE || expected_map_types[i] == BPF_MAP_TYPE_STACK) {
            REQUIRE(bpf_map__key_size(maps[i]) == 0);
        } else {
            REQUIRE(bpf_map__key_size(maps[i]) == 4);
        }

        REQUIRE(bpf_map__value_size(maps[i]) == 4);
        REQUIRE(bpf_map__max_entries(maps[i]) == 10);
    }

    int map_fd = bpf_map__fd(maps[2]);
    REQUIRE(map_fd > 0);

    uint64_t value = 0;
    uint32_t index = bpf_map__max_entries(maps[2]) + 10; // Past end of array.

    int result = bpf_map_lookup_elem(map_fd, &index, &value);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    // Wrong fd type.
    struct bpf_program* program = bpf_object__find_program_by_name(object, "test_maps");
    int program_fd = bpf_program__fd(const_cast<const bpf_program*>(program));
    result = bpf_map_lookup_elem(program_fd, &index, &value);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    // Invalid fd.
    result = bpf_map_lookup_elem(nonexistent_fd, &index, &value);
    REQUIRE(result < 0);
    REQUIRE(errno == EBADF);

    // NULL key.
    result = bpf_map_lookup_elem(map_fd, NULL, &value);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    // Invalid key.
    result = bpf_map_delete_elem(map_fd, &index);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    // Wrong fd type.
    result = bpf_map_delete_elem(program_fd, &index);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    // Invalid fd.
    result = bpf_map_delete_elem(nonexistent_fd, &index);
    REQUIRE(result < 0);
    REQUIRE(errno == EBADF);

    // NULL key.
    result = bpf_map_update_elem(map_fd, NULL, &value, 0);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    // Invalid key.
    result = bpf_map_update_elem(map_fd, &index, &value, 0);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    index = 0;
    // Invalid fd.
    result = bpf_map_update_elem(nonexistent_fd, &index, &value, 0);
    REQUIRE(result < 0);
    REQUIRE(errno == EBADF);

    // Wrong fd type.
    result = bpf_map_update_elem(program_fd, &index, &value, 0);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    REQUIRE(bpf_map_lookup_elem(map_fd, &index, &value) == 0);
    REQUIRE(value == 0);

    REQUIRE(bpf_map_delete_elem(map_fd, &index) == 0);

    value = 12345;
    REQUIRE(bpf_map_update_elem(map_fd, &index, &value, 0) == 0);

    // Wrong flags.
    result = bpf_map_update_elem(map_fd, &index, &value, UINT64_MAX);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    value = 0;
    REQUIRE(bpf_map_lookup_elem(map_fd, &index, &value) == 0);
    REQUIRE(value == 12345);

    REQUIRE(bpf_map_delete_elem(map_fd, &index) == 0);

    REQUIRE(bpf_map_lookup_elem(map_fd, &index, &value) == 0);
    REQUIRE(value == 0);

    // Query value from per-CPUs maps.
    for (size_t i = 0; i < expected_map_names.size(); i++) {
        if (expected_map_names[i].find("PERCPU") == std::string::npos) {
            continue;
        };
        std::vector<uint8_t> per_cpu_value(
            EBPF_PAD_8(bpf_map__value_size(maps[i])) * static_cast<size_t>(libbpf_num_possible_cpus()));
        REQUIRE(bpf_map_update_elem(bpf_map__fd(maps[i]), &index, per_cpu_value.data(), 0) == 0);
        REQUIRE(bpf_map_lookup_elem(bpf_map__fd(maps[i]), &index, per_cpu_value.data()) == 0);
    }

    // Invalid map type.
    result = bpf_map_create(BPF_MAP_TYPE_UNSPEC, "BPF_MAP_TYPE_UNSPEC", 1, 1, 1, NULL);
    REQUIRE(result < 0);
    REQUIRE(errno == ENOTSUP);

    // Invalid key size.
    result = bpf_map_create(BPF_MAP_TYPE_HASH, "no_key", 0, 1, 1, NULL);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    // Invalid value size.
    result = bpf_map_create(BPF_MAP_TYPE_HASH, "no_value", 1, 0, 1, NULL);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    // Invalid entry count.
    result = bpf_map_create(BPF_MAP_TYPE_HASH, "no_entries", 1, 1, 0, NULL);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    // Invalid options - bad inner_map_fd.
    bpf_map_create_opts opts{
        sizeof(opts),         // sz
        0,                    // btf_fd
        0,                    // btf_key_type_id
        0,                    // btf_value_type_id
        0,                    // btf_vmlinux_value_type_id
        (uint32_t)program_fd, // inner_map_fd
        0,                    // map_flags
        0,                    // map_extra
        0,                    // numa_node
        0,                    // map_ifindex
    };
    result = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, "bad_opts", 1, 1, 1, &opts);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    // Invalid options - bad flags.
    opts = {
        sizeof(opts), // sz
        0,            // btf_fd
        0,            // btf_key_type_id
        0,            // btf_value_type_id
        0,            // btf_vmlinux_value_type_id
        0,            // inner_map_fd
        UINT32_MAX,   // map_flags
        0,            // map_extra
        0,            // numa_node
        0,            // map_ifindex
    };
    result = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, "bad_opts", 1, 1, 1, &opts);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    // Invalid fd.
    result = bpf_map_get_next_key(nonexistent_fd, NULL, &value);
    REQUIRE(result < 0);
    REQUIRE(errno == EBADF);

    // FD not a map.
    result = bpf_map_get_next_key(program_fd, NULL, &value);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    bpf_object__close(object);
}
#endif

TEST_CASE("libbpf create queue", "[libbpf]")
{
    _test_helper_libbpf test_helper;

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
    REQUIRE(info.inner_map_id == -1);
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
    REQUIRE(info.inner_map_id == -1);
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

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("libbpf map binding", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    struct bpf_object* object = bpf_object__open("droppacket.o");
    REQUIRE(object != nullptr);

    // Load the program(s).
    REQUIRE(bpf_object__load(object) == 0);

    struct bpf_program* program = bpf_object__next_program(object, nullptr);
    REQUIRE(program != nullptr);
    int program_fd = bpf_program__fd(const_cast<const bpf_program*>(program));

    // Create a map.
    int map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(uint32_t), sizeof(uint32_t), 2, nullptr);
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

    struct bpf_object* object = bpf_object__open("droppacket.o");
    REQUIRE(object != nullptr);

    // Load the program(s).
    REQUIRE(bpf_object__load(object) == 0);

    struct bpf_map* map = bpf_object__next_map(object, nullptr);
    REQUIRE(map != nullptr);

    REQUIRE(bpf_map__is_pinned(map) == false);

    // Try to pin the map.
    int result = bpf_map__pin(map, pin_path);
    REQUIRE(result == 0);

    REQUIRE(bpf_map__is_pinned(map) == true);

    // Make sure a duplicate pin fails.
    result = bpf_map__pin(map, pin_path);
    REQUIRE(result < 0);
    REQUIRE(errno == EEXIST);

    result = bpf_map__unpin(map, pin_path);
    REQUIRE(result == 0);

    REQUIRE(bpf_map__is_pinned(map) == false);

    // Make sure pinning with a different name fails.
    result = bpf_map__pin(map, "second_pin_path");
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    // Make sure an invalid path fails.
    result = bpf_map__unpin(map, NULL);
    REQUIRE(result < 0);
    REQUIRE(errno == ENOENT);

    // Make sure a duplicate unpin fails.
    result = bpf_map__unpin(map, pin_path);
    REQUIRE(result < 0);
    REQUIRE(errno == ENOENT);

    // Clear pin path for the map.
    result = bpf_map__set_pin_path(map, nullptr);
    REQUIRE(result == 0);

    // Set pin path for the map.
    result = bpf_map__set_pin_path(map, pin_path);
    REQUIRE(result == 0);

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

TEST_CASE("libbpf obj pinning", "[libbpf]")
{
    _test_helper_libbpf test_helper;
    const char* pin_path = "\\temp\\test";

    struct bpf_object* object = bpf_object__open("droppacket.o");
    REQUIRE(object != nullptr);

    // Load the program(s).
    REQUIRE(bpf_object__load(object) == 0);

    struct bpf_map* map = bpf_object__next_map(object, nullptr);
    REQUIRE(map != nullptr);

    int map_fd = bpf_map__fd(map);
    REQUIRE(map_fd > 0);

    int result = bpf_obj_pin(map_fd, pin_path);
    REQUIRE(result == 0);

    // Linux lacks a bpf_object_unpin, so call the ebpf_ variety.
    REQUIRE(ebpf_object_unpin(pin_path) == EBPF_SUCCESS);

    result = bpf_obj_pin(-1, "invalid_fd");
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    result = bpf_obj_pin(map_fd, NULL);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    result = bpf_obj_pin(nonexistent_fd, "not_a_real_fd");
    REQUIRE(result < 0);
    REQUIRE(errno == EBADF);

    bpf_object__close(object);
}
#endif

static void
_ebpf_test_tail_call(_In_z_ const char* filename, uint32_t expected_result)
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    struct bpf_object* object = bpf_object__open(filename);
    REQUIRE(object != nullptr);

    // Load the program(s).
    REQUIRE(bpf_object__load(object) == 0);

    struct bpf_program* caller = bpf_object__find_program_by_name(object, "caller");
    REQUIRE(caller != nullptr);

    struct bpf_program* callee = bpf_object__find_program_by_name(object, "callee");
    REQUIRE(callee != nullptr);

    struct bpf_map* map = bpf_object__find_map_by_name(object, "map");
    REQUIRE(map != nullptr);
    struct bpf_map* canary_map = bpf_object__find_map_by_name(object, "canary");
    REQUIRE(canary_map != nullptr);

    int callee_fd = bpf_program__fd(callee);
    REQUIRE(callee_fd >= 0);

    int map_fd = bpf_map__fd(map);
    REQUIRE(map_fd >= 0);

    int canary_map_fd = bpf_map__fd(canary_map);
    REQUIRE(canary_map_fd >= 0);

    // First do some negative tests.
    int index = 10;
    int error = bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&callee_fd, 0);
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

    bpf_link_ptr link(bpf_program__attach_xdp(caller, 1));
    REQUIRE(link != nullptr);

    auto packet = prepare_udp_packet(0, ETHERNET_TYPE_IPV4);
    xdp_md_t ctx{packet.data(), packet.data() + packet.size()};
    uint32_t result;
    REQUIRE(hook.fire(&ctx, &result) == EBPF_SUCCESS);
    REQUIRE(result == expected_result);

    uint32_t key = 0;
    uint32_t value = 0;
    error = bpf_map_lookup_elem(canary_map_fd, &key, &value);
    REQUIRE(error == 0);

    // Is bpf_tail_call expected to work?
    // Verify stack unwind occured.
    if ((int)expected_result >= 0) {
        REQUIRE(value == 0);
    } else {
        REQUIRE(value != 0);
    }

    result = bpf_link__destroy(link.release());
    REQUIRE(result == 0);
    bpf_object__close(object);
}

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("good_tail_call-jit", "[libbpf]")
{
    // Verify that 42 is returned, which is done by the callee.
    _ebpf_test_tail_call("tail_call.o", 42);
}
#endif

TEST_CASE("good_tail_call-native", "[libbpf]")
{
    // Verify that 42 is returned, which is done by the callee.
    _ebpf_test_tail_call("tail_call_um.dll", 42);
}

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("bad_tail_call-jit", "[libbpf]")
{
    _ebpf_test_tail_call("tail_call_bad.o", (uint32_t)(-EBPF_INVALID_ARGUMENT));
}
#endif

TEST_CASE("bad_tail_call-native", "[libbpf]")
{
    _ebpf_test_tail_call("tail_call_bad_um.dll", (uint32_t)(-EBPF_INVALID_ARGUMENT));
}

static void
_multiple_tail_calls_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

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

    bpf_link_ptr link(bpf_program__attach_xdp(caller, 1));
    REQUIRE(link != nullptr);

    auto packet = prepare_udp_packet(0, ETHERNET_TYPE_IPV4);
    xdp_md_t ctx{packet.data(), packet.data() + packet.size()};
    uint32_t result;
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

    result = bpf_link__destroy(link.release());
    REQUIRE(result == 0);
    bpf_object__close(object);
}

DECLARE_JIT_TEST_CASES("multiple tail calls", "[libbpf]", _multiple_tail_calls_test);

static void
_test_bind_fd_to_prog_array(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    program_info_provider_t bind_program_info(EBPF_PROGRAM_TYPE_BIND);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "tail_call_um.dll" : "tail_call.o");
    struct bpf_object* xdp_object = bpf_object__open(file_name);
    REQUIRE(xdp_object != nullptr);

    // Load the program(s).
    REQUIRE(bpf_object__load(xdp_object) == 0);

    struct bpf_map* map = bpf_object__find_map_by_name(xdp_object, "map");
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
    // associated with an XDP program.
    int index = 0;
    int error = bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&callee_fd, 0);
    REQUIRE(error < 0);
    REQUIRE(errno == EBADF);

    bpf_object__close(bind_object);
    bpf_object__close(xdp_object);
}

DECLARE_ALL_TEST_CASES("disallow setting bind fd in xdp prog array", "[libbpf]", _test_bind_fd_to_prog_array);

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("disallow prog_array mixed program type values", "[libbpf]")
{
    _test_helper_end_to_end test_helper;
    program_info_provider_t bind_program_info(EBPF_PROGRAM_TYPE_BIND);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    struct bpf_object* xdp_object = bpf_object__open("droppacket.o");
    REQUIRE(xdp_object != nullptr);
    // Load the program(s).
    REQUIRE(bpf_object__load(xdp_object) == 0);
    struct bpf_program* xdp_program = bpf_object__find_program_by_name(xdp_object, "DropPacket");
    int xdp_program_fd = bpf_program__fd(const_cast<const bpf_program*>(xdp_program));

    struct bpf_object* bind_object = bpf_object__open("bindmonitor.o");
    REQUIRE(bind_object != nullptr);
    // Load the program(s).
    REQUIRE(bpf_object__load(bind_object) == 0);
    struct bpf_program* bind_program = bpf_object__find_program_by_name(bind_object, "BindMonitor");
    int bind_program_fd = bpf_program__fd(const_cast<const bpf_program*>(bind_program));

    // Create a map.
    int map_fd = bpf_map_create(BPF_MAP_TYPE_PROG_ARRAY, nullptr, sizeof(uint32_t), sizeof(uint32_t), 2, nullptr);
    REQUIRE(map_fd > 0);

    // Since the map is not yet associated with a program, the first program fd
    // we add will become the PROG_ARRAY's program type.
    int index = 0;
    int error = bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&xdp_program_fd, 0);
    REQUIRE(error == 0);

    // Adding an entry with a different program type should fail.
    error = bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&bind_program_fd, 0);
    REQUIRE(error < 0);
    REQUIRE(errno == EBADF);

    Platform::_close(map_fd);
    bpf_object__close(bind_object);
    bpf_object__close(xdp_object);
}
#endif

static void
_enumerate_program_ids_test(ebpf_execution_type_t execution_type)
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
    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "tail_call_um.dll" : "tail_call.o");
    struct bpf_object* xdp_object = bpf_object__open(file_name);
    REQUIRE(xdp_object != nullptr);

    // Load the program(s).
    REQUIRE(bpf_object__load(xdp_object) == 0);

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

DECLARE_JIT_TEST_CASES("enumerate program IDs", "[libbpf]", _enumerate_program_ids_test);

static void
_ebpf_test_map_in_map(ebpf_map_type_t type)
{
    _test_helper_end_to_end test_helper;

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
        // Try deleting outer key that doesn't exist.
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
static void
_array_of_maps_test(ebpf_execution_type_t execution_type, _In_ PCSTR dll_name, _In_ PCSTR obj_name)
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? dll_name : obj_name);
    struct bpf_object* xdp_object = bpf_object__open(file_name);
    REQUIRE(xdp_object != nullptr);

    // Load the program(s).
    REQUIRE(bpf_object__load(xdp_object) == 0);

    struct bpf_program* caller = bpf_object__find_program_by_name(xdp_object, "lookup");
    REQUIRE(caller != nullptr);

    struct bpf_map* outer_map = bpf_object__find_map_by_name(xdp_object, "outer_map");
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

    bpf_link_ptr link(bpf_program__attach_xdp(caller, 1));
    REQUIRE(link != nullptr);

    // Now run the ebpf program.
    auto packet = prepare_udp_packet(0, ETHERNET_TYPE_IPV4);
    xdp_md_t ctx{packet.data(), packet.data() + packet.size()};
    uint32_t result;
    REQUIRE(hook.fire(&ctx, &result) == EBPF_SUCCESS);

    // Verify the return value is what we saved in the inner map.
    REQUIRE(result == inner_value);

    Platform::_close(inner_map_fd);
    result = bpf_link__destroy(link.release());
    REQUIRE(result == 0);
    bpf_object__close(xdp_object);
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
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "map_in_map_btf_um.dll" : "map_in_map_btf.o");
    struct bpf_object* xdp_object = bpf_object__open(file_name);
    REQUIRE(xdp_object != nullptr);

    // Load the program(s).
    REQUIRE(bpf_object__load(xdp_object) == 0);

    struct bpf_map* outer_map = bpf_object__find_map_by_name(xdp_object, "outer_map");
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

    bpf_object__close(xdp_object);
}

DECLARE_JIT_TEST_CASES("disallow wrong inner map types", "[libbpf]", _wrong_inner_map_types_test);

TEST_CASE("create map with name", "[libbpf]")
{
    _test_helper_end_to_end test_helper;

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

#if !defined(CONFIG_BPF_JIT_DISABLED)
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
        "droppacket.o", BPF_PROG_TYPE_XDP, "DropPacket", EBPF_EXECUTION_JIT, &ifindex, sizeof(ifindex), xdp_hook);
    program_load_attach_helper_t bind_helper(
        "bindmonitor.o", BPF_PROG_TYPE_BIND, "BindMonitor", EBPF_EXECUTION_JIT, nullptr, 0, bind_hook);

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

TEST_CASE("enumerate link IDs with bpf", "[libbpf]")
{
    _test_helper_end_to_end test_helper;
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);
    program_info_provider_t bind_program_info(EBPF_PROGRAM_TYPE_BIND);
    single_instance_hook_t xdp_hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    single_instance_hook_t bind_hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);

    // Verify the enumeration is empty.
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    REQUIRE(bpf(BPF_LINK_GET_NEXT_ID, &attr, sizeof(attr)) < 0);
    REQUIRE(errno == ENOENT);

    memset(&attr, 0, sizeof(attr));
    attr.link_id = EBPF_ID_NONE;
    REQUIRE(bpf(BPF_LINK_GET_NEXT_ID, &attr, sizeof(attr)) < 0);
    REQUIRE(errno == ENOENT);

    // Load and attach some programs.
    uint32_t ifindex = 1;
    program_load_attach_helper_t xdp_helper(
        "droppacket.o", BPF_PROG_TYPE_XDP, "DropPacket", EBPF_EXECUTION_JIT, &ifindex, sizeof(ifindex), xdp_hook);
    program_load_attach_helper_t bind_helper(
        "bindmonitor.o", BPF_PROG_TYPE_BIND, "BindMonitor", EBPF_EXECUTION_JIT, nullptr, 0, bind_hook);

    // Now enumerate the IDs.
    memset(&attr, 0, sizeof(attr));
    REQUIRE(bpf(BPF_LINK_GET_NEXT_ID, &attr, sizeof(attr)) == 0);
    uint32_t id1 = attr.next_id;

    memset(&attr, 0, sizeof(attr));
    attr.link_id = id1;
    fd_t fd1 = bpf(BPF_LINK_GET_FD_BY_ID, &attr, sizeof(attr));
    REQUIRE(fd1 >= 0);

    REQUIRE(bpf(BPF_LINK_GET_NEXT_ID, &attr, sizeof(attr)) == 0);
    uint32_t id2 = attr.next_id;

    memset(&attr, 0, sizeof(attr));
    attr.link_id = id2;
    fd_t fd2 = bpf(BPF_LINK_GET_FD_BY_ID, &attr, sizeof(attr));
    REQUIRE(fd2 >= 0);

    REQUIRE(bpf(BPF_LINK_GET_NEXT_ID, &attr, sizeof(attr)) < 0);
    REQUIRE(errno == ENOENT);

    // Get info on the first link.
    memset(&attr, 0, sizeof(attr));
    bpf_link_info info;
    attr.info.bpf_fd = fd1;
    attr.info.info = (uintptr_t)&info;
    attr.info.info_len = sizeof(info);
    REQUIRE(bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0);
    REQUIRE(info.attach_type_uuid == EBPF_ATTACH_TYPE_XDP);
    REQUIRE(info.xdp.ifindex == ifindex);

    // Detach the first link.
    memset(&attr, 0, sizeof(attr));
    attr.link_detach.link_fd = fd1;
    REQUIRE(bpf(BPF_LINK_DETACH, &attr, sizeof(attr)) == 0);

    // Get info on the detached link.
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = fd1;
    attr.info.info = (uintptr_t)&info;
    attr.info.info_len = sizeof(info);
    REQUIRE(bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0);
    REQUIRE(info.attach_type_uuid == EBPF_ATTACH_TYPE_XDP);
    REQUIRE(info.xdp.ifindex == 0);

    // Pin the detached link.
    memset(&attr, 0, sizeof(attr));
    attr.bpf_fd = fd1;
    attr.pathname = (uintptr_t) "MyPath";
    REQUIRE(bpf(BPF_OBJ_PIN, &attr, sizeof(attr)) == 0);

    // Verify that bpf_fd must be 0 when calling BPF_OBJ_GET.
    REQUIRE(bpf(BPF_OBJ_GET, &attr, sizeof(attr)) < 0);
    REQUIRE(errno == EINVAL);

    // Retrieve a new fd from the pin path.
    attr.bpf_fd = 0;
    fd_t fd3 = bpf(BPF_OBJ_GET, &attr, sizeof(attr));
    REQUIRE(fd3 > 0);

    // Get info on the new fd.
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = fd3;
    attr.info.info = (uintptr_t)&info;
    attr.info.info_len = sizeof(info);
    REQUIRE(bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0);
    REQUIRE(info.id == id1);
    REQUIRE(info.xdp.ifindex == 0);

    // And for completeness, try an invalid bpf() call.
    REQUIRE(bpf(-1, &attr, sizeof(attr)) < 0);
    REQUIRE(errno == EINVAL);

    // Unpin the link.
    REQUIRE(ebpf_object_unpin("MyPath") == EBPF_SUCCESS);

    Platform::_close(fd1);
    Platform::_close(fd2);
    Platform::_close(fd3);
}

TEST_CASE("bpf_prog_attach", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    struct bpf_object* object = bpf_object__open("cgroup_sock_addr.o");
    REQUIRE(object != nullptr);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "authorize_connect4");
    REQUIRE(program != nullptr);

    REQUIRE(bpf_object__load(object) == 0);

    int program_fd = bpf_program__fd(program);
    REQUIRE(program_fd > 0);

    // Verify we can't attach the program to an attach type that doesn't work with this API.
    REQUIRE(bpf_prog_attach(program_fd, 0, BPF_XDP, 0) == -ENOTSUP);

    // Verify we can't use an illegal program fd.
    REQUIRE(bpf_prog_attach(ebpf_fd_invalid, 0, BPF_CGROUP_INET4_CONNECT, 0) == -EBADF);

    // TODO (issue #1028): Currently one can pass an invalid attachable fd and bpf_prog_attach
    // will succeed because it's temporarily just treated as a compartment id. The following
    // should instead return errors.
    REQUIRE(bpf_prog_attach(program_fd, ebpf_fd_invalid, BPF_CGROUP_INET4_CONNECT, 0) == 0);
    uint32_t link_id;
    REQUIRE(bpf_link_get_next_id(0, &link_id) == 0);
    fd_t link_fd = bpf_link_get_fd_by_id(link_id);
    REQUIRE(link_fd >= 0);
    REQUIRE(bpf_link_detach(link_fd) == 0);
    REQUIRE(bpf_prog_attach(program_fd, program_fd, BPF_CGROUP_INET4_CONNECT, 0) == 0);

    bpf_object__close(object);
}

TEST_CASE("bpf_link__pin", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    struct bpf_object* object = bpf_object__open("droppacket.o");
    REQUIRE(object != nullptr);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "DropPacket");
    REQUIRE(program != nullptr);

    // Load and pin the program.
    REQUIRE(bpf_object__load(object) == 0);
    const char* program_pin_name = "ProgramPinName";
    REQUIRE(bpf_program__pin(program, program_pin_name) == 0);
    int program_fd = bpf_program__fd(program);
    REQUIRE(program_fd > 0);

    // Verify we can't attach the program to a different attach type.
    REQUIRE(bpf_prog_attach(program_fd, 0, BPF_CGROUP_INET4_CONNECT, 0) == -EINVAL);

    // Attach the program so we get a link object.
    bpf_link_ptr link(bpf_program__attach(program));
    REQUIRE(link != nullptr);

    // Verify that unpinning an unpinned link fails.
    REQUIRE(bpf_link__unpin(link.get()) == -ENOENT);

    // Verify that pinning a link to an already-in-use path fails.
    REQUIRE(bpf_link__pin(link.get(), program_pin_name) == -EEXIST);

    // Verify that pinning a link to a new path works.
    REQUIRE(bpf_link__pin(link.get(), "MyPath") == 0);

    // Verify that pinning an already-pinned link fails.
    REQUIRE(bpf_link__pin(link.get(), "MyPath2") == -EBUSY);

    REQUIRE(bpf_link__unpin(link.get()) == 0);

    REQUIRE(bpf_link__destroy(link.release()) == 0);
    REQUIRE(bpf_program__unpin(program, program_pin_name) == 0);

    bpf_program__unload(program);

    bpf_object__close(object);
}

TEST_CASE("bpf_obj_get_info_by_fd", "[libbpf]")
{
    _test_helper_end_to_end test_helper;
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);
    single_instance_hook_t xdp_hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    uint32_t ifindex = 0;
    program_load_attach_helper_t xdp_helper(
        "droppacket.o", BPF_PROG_TYPE_XDP, "DropPacket", EBPF_EXECUTION_JIT, &ifindex, sizeof(ifindex), xdp_hook);

    struct bpf_object* object = xdp_helper.get_object();
    REQUIRE(object != nullptr);

    struct bpf_program* program = bpf_object__next_program(object, nullptr);
    REQUIRE(program != nullptr);

    const char* program_name = bpf_program__name(program);
    REQUIRE(program_name != nullptr);

    int program_fd = bpf_program__fd(program);
    REQUIRE(program_fd > 0);

    struct bpf_map* map = bpf_object__find_map_by_name(object, "dropped_packet_map");
    REQUIRE(map != nullptr);

    const char* map_name = bpf_map__name(map);
    REQUIRE(map_name != nullptr);

    int map_fd = bpf_map__fd(map);
    REQUIRE(map_fd > 0);

    // Fetch info about the maps and verify it matches what we'd expect.
    bpf_map_info map_info[2];
    uint32_t map_info_size = sizeof(map_info[0]);
    REQUIRE(bpf_obj_get_info_by_fd(map_fd, &map_info[0], &map_info_size) == 0);
    REQUIRE(map_info_size == sizeof(map_info[0]));
    REQUIRE(map_info[0].type == BPF_MAP_TYPE_ARRAY);
    REQUIRE(map_info[0].key_size == sizeof(uint32_t));
    REQUIRE(map_info[0].value_size == sizeof(uint64_t));
    REQUIRE(map_info[0].max_entries == 1);
    REQUIRE(strcmp(map_info[0].name, map_name) == 0);

    map = bpf_object__find_map_by_name(object, "interface_index_map");
    REQUIRE(map != nullptr);
    map_fd = bpf_map__fd(map);
    REQUIRE(map_fd > 0);
    map_name = bpf_map__name(map);
    REQUIRE(map_name != nullptr);

    REQUIRE(bpf_obj_get_info_by_fd(map_fd, &map_info[1], &map_info_size) == 0);
    REQUIRE(map_info_size == sizeof(map_info[1]));
    REQUIRE(map_info[1].type == BPF_MAP_TYPE_ARRAY);
    REQUIRE(map_info[1].key_size == sizeof(uint32_t));
    REQUIRE(map_info[1].value_size == sizeof(uint32_t));
    REQUIRE(map_info[1].max_entries == 1);
    REQUIRE(strcmp(map_info[1].name, map_name) == 0);

    // Fetch info about the program and verify it matches what we'd expect.
    bpf_prog_info program_info = {};
    uint32_t program_info_size = sizeof(program_info);
    REQUIRE(bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_size) == 0);
    REQUIRE(program_info_size == sizeof(program_info));
    REQUIRE(strcmp(program_info.name, program_name) == 0);
    REQUIRE(program_info.nr_map_ids == 2);
    REQUIRE(program_info.map_ids == 0);
    REQUIRE(program_info.type == BPF_PROG_TYPE_XDP);

    // Fetch info about the maps and verify it matches what we'd expect.
    ebpf_id_t map_ids[2] = {0};
    program_info.map_ids = (uintptr_t)map_ids;
    REQUIRE(bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_size) == 0);
    REQUIRE(map_ids[0] == map_info[1].id);
    REQUIRE(map_ids[1] == map_info[0].id);

    // Try again with nr_map_ids set to get only partial.
    map_ids[0] = map_ids[1] = 0;
    program_info.nr_map_ids = 1;
    program_info.map_ids = (uintptr_t)map_ids;
    REQUIRE(bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_size) == -EFAULT);
    REQUIRE(map_ids[0] == map_info[1].id);

    // Try again with an invalid pointer.
    program_info.map_ids++;
    REQUIRE(bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_size) == -EFAULT);

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
    REQUIRE(link_info.attach_type == BPF_XDP);

    // Verify we can detach using this link fd.
    // This is the flow used by bpftool to detach a link.
    REQUIRE(bpf_link_detach(link_fd) == 0);

    Platform::_close(link_fd);
}

TEST_CASE("bpf_obj_get_info_by_fd_2", "[libbpf]")
{
    _test_helper_end_to_end test_helper;
    program_info_provider_t sock_addr_program_info(EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR);
    single_instance_hook_t v4_connect_hook(EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR, EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT);

    program_load_attach_helper_t sock_addr_helper(
        "cgroup_sock_addr.o",
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        "authorize_connect4",
        EBPF_EXECUTION_JIT,
        nullptr,
        0,
        v4_connect_hook);

    struct bpf_object* object = sock_addr_helper.get_object();
    REQUIRE(object != nullptr);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "authorize_connect4");
    REQUIRE(program != nullptr);

    int program_fd = bpf_program__fd(program);
    REQUIRE(program_fd > 0);

    // Fetch info about the program and verify it matches what we'd expect.
    bpf_prog_info program_info = {};
    uint32_t program_info_size = sizeof(program_info);
    REQUIRE(bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_size) == 0);
    REQUIRE(program_info_size == sizeof(program_info));
    REQUIRE(strcmp(program_info.name, "authorize_connect4") == 0);
    REQUIRE(program_info.nr_map_ids == 1);
    REQUIRE(program_info.map_ids == 0);
    REQUIRE(program_info.type == BPF_PROG_TYPE_CGROUP_SOCK_ADDR);

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
    REQUIRE(link_info.attach_type == BPF_CGROUP_INET4_CONNECT);

    // Verify we can detach using this link fd.
    // This is the flow used by bpftool to detach a link.
    REQUIRE(bpf_link_detach(link_fd) == 0);

    Platform::_close(link_fd);
}
#endif

TEST_CASE("libbpf_prog_type_by_name_test", "[libbpf]")
{
    _test_helper_end_to_end test_helper;
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

    const char* prog_type_str_xdp = libbpf_bpf_prog_type_str(BPF_PROG_TYPE_XDP);
    REQUIRE(prog_type_str_xdp);
    REQUIRE(strcmp(prog_type_str_xdp, "xdp") == 0);
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

    enum bpf_attach_type attach_type;
    for (int i = 1; i < __MAX_BPF_ATTACH_TYPE; i++) {
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
    REQUIRE(libbpf_bpf_link_type_str((bpf_link_type)123) == nullptr);
}

TEST_CASE("libbpf map type names", "[libbpf]")
{
    REQUIRE(strcmp(libbpf_bpf_map_type_str(BPF_MAP_TYPE_ARRAY), "array") == 0);
    REQUIRE(strcmp(libbpf_bpf_map_type_str(BPF_MAP_TYPE_UNSPEC), "unspec") == 0);
    REQUIRE(libbpf_bpf_map_type_str((bpf_map_type)123) == nullptr);
}

TEST_CASE("bpf_object__open with .dll", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    struct bpf_object* object = bpf_object__open("droppacket_um.dll");
    REQUIRE(object != nullptr);

    struct bpf_program* program = bpf_object__next_program(object, nullptr);
    REQUIRE(program != nullptr);
    REQUIRE(bpf_program__type(program) == BPF_PROG_TYPE_XDP);
    REQUIRE(bpf_program__get_expected_attach_type(program) == BPF_XDP);

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

    const char* my_object_name = "my_object_name";
    struct bpf_object_open_opts opts = {0};
    opts.object_name = my_object_name;
    struct bpf_object* object = bpf_object__open_file("droppacket_um.dll", &opts);
    REQUIRE(object != nullptr);

    REQUIRE(strcmp(bpf_object__name(object), my_object_name) == 0);

    struct bpf_program* program = bpf_object__next_program(object, nullptr);
    REQUIRE(program != nullptr);
    REQUIRE(bpf_program__type(program) == BPF_PROG_TYPE_XDP);
    REQUIRE(bpf_program__get_expected_attach_type(program) == BPF_XDP);

    REQUIRE(bpf_object__next_program(object, program) == nullptr);

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

    // Attach should now succeed.
    link.reset(bpf_program__attach(program));
    REQUIRE(link != nullptr);

    REQUIRE(bpf_link__destroy(link.release()) == 0);

    bpf_object__close(object);
}

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("bpf_object__load with .o", "[libbpf]")
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
    REQUIRE(bpf_program__type(program) == BPF_PROG_TYPE_XDP);

    // Make sure we can override the program type if desired.
    REQUIRE(bpf_program__set_type(program, BPF_PROG_TYPE_BIND) == 0);
    REQUIRE(bpf_program__type(program) == BPF_PROG_TYPE_BIND);

    REQUIRE(bpf_program__set_type(program, BPF_PROG_TYPE_XDP) == 0);

    struct bpf_map* map = bpf_object__next_map(object, nullptr);
    REQUIRE(map != nullptr);
    REQUIRE(strcmp(bpf_map__name(map), "dropped_packet_map") == 0);
    REQUIRE(bpf_map__fd(map) == ebpf_fd_invalid);
    map = bpf_object__next_map(object, map);
    REQUIRE(strcmp(bpf_map__name(map), "interface_index_map") == 0);
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
    REQUIRE(strcmp(bpf_map__name(map), "dropped_packet_map") == 0);
    REQUIRE(bpf_map__fd(map) != ebpf_fd_invalid);
    map = bpf_object__next_map(object, map);
    REQUIRE(strcmp(bpf_map__name(map), "interface_index_map") == 0);
    REQUIRE(bpf_map__fd(map) != ebpf_fd_invalid);
    map = bpf_object__next_map(object, map);
    REQUIRE(map == nullptr);

    REQUIRE(bpf_link__destroy(link.release()) == 0);
    bpf_object__close(object);
}

// Test bpf() with the following command ids:
// BPF_PROG_LOAD, BPF_OBJ_GET_INFO_BY_FD, BPF_PROG_GET_NEXT_ID,
// BPF_MAP_CREATE, BPF_MAP_GET_NEXT_ID, BPF_PROG_BIND_MAP,
// BPF_PROG_GET_FD_BY_ID, BPF_MAP_GET_FD_BY_ID, and BPF_MAP_GET_FD_BY_ID.
TEST_CASE("BPF_PROG_BIND_MAP etc.", "[libbpf]")
{
    _test_helper_libbpf test_helper;

    struct ebpf_inst instructions[] = {
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
    REQUIRE(program_info.type == BPF_PROG_TYPE_XDP);

    // Verify we can enumerate the program id.
    memset(&attr, 0, sizeof(attr));
    attr.start_id = 0;
    REQUIRE(bpf(BPF_PROG_GET_NEXT_ID, &attr, sizeof(attr)) == 0);
    REQUIRE(attr.next_id == program_info.id);

    // Verify we can convert the program id to an fd.
    memset(&attr, 0, sizeof(attr));
    attr.prog_id = program_info.id;
    int prog_fd2 = bpf(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
    REQUIRE(prog_fd2 > 0);
    Platform::_close(prog_fd2);

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

    // Verify we can convert the map id to an fd.
    memset(&attr, 0, sizeof(attr));
    attr.map_id = map_id;
    int map_fd2 = bpf(BPF_MAP_GET_FD_BY_ID, &attr, sizeof(attr));
    REQUIRE(map_fd2 > 0);
    Platform::_close(map_fd2);

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
//  BPF_PROG_ATTACH, BPF_PROG_DETACH
TEST_CASE("BPF_PROG_ATTACH", "[libbpf]")
{
    _test_helper_libbpf test_helper;
    // Load and verify the eBPF program.
    union bpf_attr attr = {};

    struct bpf_object* object = bpf_object__open("cgroup_sock_addr.o");
    REQUIRE(object != nullptr);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "authorize_connect4");
    REQUIRE(program != nullptr);

    REQUIRE(bpf_object__load(object) == 0);

    int program_fd = bpf_program__fd(program);
    REQUIRE(program_fd > 0);

    // Verify we can't attach the program using an attach type that doesn't work with this API.
    memset(&attr, 0, sizeof(attr));
    attr.attach_bpf_fd = program_fd;
    attr.target_fd = program_fd;
    attr.attach_flags = 0;
    attr.attach_type = BPF_XDP;
    REQUIRE(bpf(BPF_PROG_ATTACH, &attr, sizeof(attr)) == -ENOTSUP);

    // Verify we can attach the program.
    memset(&attr, 0, sizeof(attr));
    attr.attach_bpf_fd = program_fd;
    // TODO (issue #1028): Currently the target_fd is treated as a compartment id.
    attr.target_fd = program_fd;
    attr.attach_flags = 0;
    attr.attach_type = BPF_CGROUP_INET4_CONNECT;
    REQUIRE(bpf(BPF_PROG_ATTACH, &attr, sizeof(attr)) == 0);

    // Verify we can detach the program.
    memset(&attr, 0, sizeof(attr));
    attr.target_fd = program_fd;
    attr.attach_type = BPF_CGROUP_INET4_CONNECT;
    REQUIRE(bpf(BPF_PROG_DETACH, &attr, sizeof(attr)) == 0);

    // Verify we can't detach the program using a type that doesn't work with this API.
    memset(&attr, 0, sizeof(attr));
    attr.target_fd = program_fd;
    attr.attach_type = BPF_XDP;
    REQUIRE(bpf(BPF_PROG_DETACH, &attr, sizeof(attr)) == -ENOTSUP);
}
#endif

// Test bpf() with the following command ids:
// BPF_MAP_CREATE, BPF_MAP_UPDATE_ELEM, BPF_MAP_LOOKUP_ELEM,
// BPF_MAP_GET_NEXT_KEY, BPF_MAP_LOOKUP_AND_DELETE_ELEM, and BPF_MAP_DELETE_ELEM.
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

    // Look up and delete the entry.
    memset(&attr, 0, sizeof(attr));
    value = 0;
    key = 42;
    attr.map_fd = map_fd;
    attr.key = (uintptr_t)&key;
    attr.value = (uintptr_t)&value;

    // Add the element back to the entry after the previous test entry deletion.
    bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
    REQUIRE(bpf(BPF_MAP_LOOKUP_AND_DELETE_ELEM, &attr, sizeof(attr)) == 0);

    // Test the API again and verify looking up and deleting fails.
    REQUIRE(bpf(BPF_MAP_LOOKUP_AND_DELETE_ELEM, &attr, sizeof(attr)) < 0);
    REQUIRE(errno == ENOENT);

    // Verify that no entries exist.
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd;
    attr.key = 0;
    attr.next_key = (uintptr_t)&next_key;
    REQUIRE(bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr)) < 0);
    REQUIRE(errno == ENOENT);

    Platform::_close(map_fd);
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

    std::vector<std::jthread> threads;
    // Schedule 4 threads per CPU to force contention.
    for (size_t i = 0; i < static_cast<size_t>(ebpf_get_cpu_count()) * 4; i++) {
        // Initialize thread object with lambda plus stop token
        threads.emplace_back([i](std::stop_token stop_token) {
            while (!stop_token.stop_requested()) {
                struct bpf_object* object = bpf_object__open("droppacket_um.dll");
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
    REQUIRE(bpf_map_update_elem(map_fd, &key, &program_fd, 0) == 0);

    uint32_t value = 0;
    REQUIRE(bpf_map_update_elem(canary_map_fd, &key, &value, 0) == 0);

    bpf_test_run_opts opts = {};
    opts.repeat = 1;

    // Clear previous printk output.
    auto unused_output = ebpf_platform_printk_output();

    // Run the program.
    REQUIRE(bpf_prog_test_run_opts(program_fd, &opts) == 0);

    // Capture printk output from the program.
    auto output = ebpf_platform_printk_output();

    // Verify that the printk output is correct.
    REQUIRE(output.size() == MAX_TAIL_CALL_CNT);
    for (size_t i = 0; i < MAX_TAIL_CALL_CNT; i++) {
        REQUIRE(output[i] == std::format("recurse: *value={}", i));
    }

    // The program should have returned -EBPF_NO_MORE_TAIL_CALLS.
    REQUIRE(opts.retval == -EBPF_NO_MORE_TAIL_CALLS);

    // Read the map to determine how many times the program was called.
    REQUIRE(bpf_map_lookup_elem(canary_map_fd, &key, &value) == 0);

    // The program should have been called MAX_TAIL_CALL_CNT times.
    REQUIRE(value == MAX_TAIL_CALL_CNT);

    // Close the map and programs.
    bpf_object__close(object);
}

TEST_CASE("sequential_tail_call", "[libbpf]")
{
    _test_helper_libbpf test_helper;
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

    fd_t first_program_fd = ebpf_fd_invalid;

    // Add each program to the map.
    for (uint32_t i = 0; i < MAX_TAIL_CALL_CNT + 1; i++) {
        std::string program_name = "sequential";
        program_name += std::to_string(i);
        struct bpf_program* program = bpf_object__find_program_by_name(object, program_name.c_str());
        REQUIRE(program != nullptr);

        // Get the fd for the program.
        fd_t program_fd = bpf_program__fd(program);
        REQUIRE(program_fd > 0);

        if (i == 0) {
            first_program_fd = program_fd;
        }

        uint32_t key = i;
        REQUIRE(bpf_map_update_elem(map_fd, &key, &program_fd, 0) == 0);
    }

    // Invoke the first program in the chain.
    bpf_test_run_opts opts = {};
    opts.repeat = 1;

    // Clear previous printk output.
    auto unused_output = ebpf_platform_printk_output();

    // Run the program.
    REQUIRE(bpf_prog_test_run_opts(first_program_fd, &opts) == 0);

    // Capture printk output from the program.
    auto output = ebpf_platform_printk_output();

    // Verify that the printk output is correct.
    REQUIRE(output.size() == MAX_TAIL_CALL_CNT);
    for (size_t i = 0; i < MAX_TAIL_CALL_CNT; i++) {
        REQUIRE(output[i] == std::format("sequential{}: *value={}", i, i));
    }

    // Read the map to determine how many times the program was called.
    uint32_t key = 0;
    uint32_t value = 0;
    REQUIRE(bpf_map_lookup_elem(canary_map_fd, &key, &value) == 0);

    // The program should have been called MAX_TAIL_CALL_CNT times.
    REQUIRE(value == MAX_TAIL_CALL_CNT);

    // The last program should have returned -EBPF_NO_MORE_TAIL_CALLS.
    REQUIRE(opts.retval == -EBPF_NO_MORE_TAIL_CALLS);
}
