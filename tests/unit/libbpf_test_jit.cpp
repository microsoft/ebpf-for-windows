// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#pragma warning(push)
#pragma warning(disable : 4200)
#include "bpf/libbpf.h"
#pragma warning(pop)
#include "capture_helper.hpp"
#include "catch_wrapper.hpp"
#include "ebpf_execution_type.h"
#include "ebpf_platform.h"
#include "ebpf_vm_isa.hpp"
#include "helpers.h"
#include "libbpf_test_jit.h"
#include "platform.h"
#include "program_helper.h"
#include "test_helper.hpp"

#include <fstream>

// Pulling in the prevail namespace to get the definitions in ebpf_vm_isa.h.
// See: https://github.com/vbpf/prevail/issues/876
using namespace prevail;

// libbpf.h uses enum types and generates the
// following warning whenever an enum type is used below:
// "The enum type 'bpf_attach_type' is unscoped.
// Prefer 'enum class' over 'enum'"
#pragma warning(disable : 26812)

void
ebpf_test_tail_call(_In_z_ const char* filename, uint32_t expected_result)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

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

    bpf_link_ptr link(bpf_program__attach(caller));
    REQUIRE(link != nullptr);

    INITIALIZE_SAMPLE_CONTEXT
    uint32_t result;
    REQUIRE(hook.fire(ctx, &result) == EBPF_SUCCESS);
    REQUIRE(result == expected_result);

    uint32_t key = 0;
    uint32_t value = 0;
    error = bpf_map_lookup_elem(canary_map_fd, &key, &value);
    REQUIRE(error == 0);

    // Is bpf_tail_call expected to work?
    // Verify stack unwind occurred.
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
    ebpf_test_tail_call("tail_call.o", 42);
}

TEST_CASE("bad_tail_call-jit", "[libbpf]")
{
    ebpf_test_tail_call("tail_call_bad.o", (uint32_t)(-EBPF_INVALID_ARGUMENT));
}
#endif

#if !defined(CONFIG_BPF_JIT_DISABLED)
void
test_invalid_bpf_action(char log_buffer[])
{
    REQUIRE(errno == EACCES);
    REQUIRE(strcmp(log_buffer, "0: Invalid type (r0.type == number)\n\n") == 0);
}
#else
void
test_invalid_bpf_action(char log_buffer[])
{
    UNREFERENCED_PARAMETER(log_buffer);
    REQUIRE(errno == ENOTSUP);
}
#endif

#if !defined(CONFIG_BPF_JIT_DISABLED)
static void
test_libbpf_load_program()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();
    struct bpf_object* object;
    int program_fd;
#pragma warning(suppress : 4996) // deprecated
    int result = bpf_prog_load_deprecated("test_sample_ebpf.o", BPF_PROG_TYPE_SAMPLE, &object, &program_fd);
    REQUIRE(result == 0);
    REQUIRE(object != nullptr);
    REQUIRE(program_fd != ebpf_fd_invalid);

    bpf_object__close(object);
}

TEST_CASE("libbpf load program-jit", "[libbpf][deprecated]") { test_libbpf_load_program(); }

static void
test_libbpf_prog_test_run()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();
    struct bpf_object* object;
    int program_fd;
#pragma warning(suppress : 4996) // deprecated
    int result = bpf_prog_load_deprecated("test_sample_ebpf.o", BPF_PROG_TYPE_SAMPLE, &object, &program_fd);
    REQUIRE(result == 0);
    REQUIRE(object != nullptr);
    REQUIRE(program_fd != ebpf_fd_invalid);

    bpf_test_run_opts opts = {};
    sample_program_context_t in_ctx{0};
    sample_program_context_t out_ctx{0};
    opts.repeat = 10;
    opts.ctx_in = reinterpret_cast<uint8_t*>(&in_ctx);
    opts.ctx_size_in = sizeof(in_ctx);
    opts.ctx_out = reinterpret_cast<uint8_t*>(&out_ctx);
    opts.ctx_size_out = sizeof(out_ctx);

    REQUIRE(bpf_prog_test_run_opts(program_fd, &opts) == 0);

    REQUIRE(opts.duration > 0);

    // Negative tests.

    // Bad fd.
    REQUIRE(bpf_prog_test_run_opts(nonexistent_fd, &opts) == -EINVAL);

    // NULL context.
    opts.ctx_in = nullptr;
    opts.ctx_size_in = 0;
    REQUIRE(bpf_prog_test_run_opts(program_fd, &opts) == -EINVAL);

    // Zero length context.
    opts.ctx_in = reinterpret_cast<uint8_t*>(&in_ctx);
    opts.ctx_size_in = 0;
    REQUIRE(bpf_prog_test_run_opts(program_fd, &opts) == -EINVAL);

    // Context out is too small.
    std::vector<uint8_t> small_context(1);
    opts.ctx_in = reinterpret_cast<uint8_t*>(&in_ctx);
    opts.ctx_size_in = sizeof(in_ctx);
    opts.ctx_out = small_context.data();
    opts.ctx_size_out = static_cast<uint32_t>(small_context.size());
    REQUIRE(bpf_prog_test_run_opts(program_fd, &opts) == -EOTHER);

    // Context in, null context out.
    opts.ctx_in = reinterpret_cast<uint8_t*>(&in_ctx);
    opts.ctx_size_in = sizeof(in_ctx);
    opts.ctx_out = nullptr;
    opts.ctx_size_out = 0;
    REQUIRE(bpf_prog_test_run_opts(program_fd, &opts) == -EOTHER);

    // No context in, Context out.
    std::vector<uint8_t> context_out(1024);
    opts.ctx_in = nullptr;
    opts.ctx_size_in = 0;
    opts.ctx_out = reinterpret_cast<uint8_t*>(&out_ctx);
    opts.ctx_size_out = sizeof(out_ctx);
    REQUIRE(bpf_prog_test_run_opts(program_fd, &opts) == -EINVAL);
    REQUIRE(opts.ctx_size_out == sizeof(sample_program_context_t));

    // With bpf syscall.
    bpf_attr attr = {};
    attr.test.prog_fd = program_fd;
    attr.test.repeat = 1000;
    attr.test.data_in = reinterpret_cast<uint64_t>(nullptr);
    attr.test.data_out = reinterpret_cast<uint64_t>(nullptr);
    attr.test.data_size_in = 0;
    attr.test.data_size_out = 0;
    attr.test.ctx_in = reinterpret_cast<uint64_t>(&in_ctx);
    attr.test.ctx_size_in = sizeof(in_ctx);
    attr.test.ctx_out = reinterpret_cast<uint64_t>(&out_ctx);
    attr.test.ctx_size_out = sizeof(out_ctx);
    REQUIRE(bpf(BPF_PROG_TEST_RUN, &attr, sizeof(attr)) == 0);
    REQUIRE(attr.test.ctx_size_out == sizeof(sample_program_context_t));
    REQUIRE(attr.test.duration > 0);

    bpf_object__close(object);
}

TEST_CASE("libbpf prog test run-jit", "[libbpf][deprecated]") { test_libbpf_prog_test_run(); }

static void
_test_valid_bpf_load_program()
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
        BPF_PROG_TYPE_SAMPLE, (struct bpf_insn*)instructions, _countof(instructions), nullptr, 0, nullptr, 0);
    REQUIRE(program_fd >= 0);

    // Now query the program info and verify it matches what we set.
    bpf_prog_info program_info = {};
    uint32_t program_info_size = sizeof(program_info);
    REQUIRE(bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_size) == 0);
    REQUIRE(program_info_size == sizeof(program_info));
    REQUIRE(program_info.nr_map_ids == 0);
    REQUIRE(program_info.map_ids == 0);

    REQUIRE(program_info.type == BPF_PROG_TYPE_SAMPLE);

    Platform::_close(program_fd);
}

TEST_CASE("valid bpf_load_program-jit", "[libbpf][deprecated]") { _test_valid_bpf_load_program(); }

static void
_test_valid_bpf_prog_load()
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
        BPF_PROG_TYPE_SAMPLE, "name", nullptr, (struct bpf_insn*)instructions, _countof(instructions), nullptr);
    REQUIRE(program_fd >= 0);

    // Now query the program info and verify it matches what we set.
    bpf_prog_info program_info = {};
    uint32_t program_info_size = sizeof(program_info);
    REQUIRE(bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_size) == 0);
    REQUIRE(program_info_size == sizeof(program_info));
    REQUIRE(program_info.nr_map_ids == 0);
    REQUIRE(program_info.map_ids == 0);
    REQUIRE(strcmp(program_info.name, "name") == 0);

    REQUIRE(program_info.type == BPF_PROG_TYPE_SAMPLE);

    Platform::_close(program_fd);
}

TEST_CASE("valid bpf_prog_load-jit", "[libbpf]") { _test_valid_bpf_prog_load(); }

static void
_test_valid_bpf_load_program_xattr()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    // Try with a valid set of instructions.
    prevail::EbpfInst instructions[] = {
        {0xb7, R0_RETURN_VALUE, 0}, // r0 = 0
        {INST_OP_EXIT},             // return r0
    };

    // Load and verify the eBPF program.
    struct bpf_load_program_attr attr = {
        .prog_type = BPF_PROG_TYPE_SAMPLE,
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

    REQUIRE(program_info.type == BPF_PROG_TYPE_SAMPLE);

    Platform::_close(program_fd);
}

TEST_CASE("valid bpf_load_program_xattr-jit", "[libbpf][deprecated]") { _test_valid_bpf_load_program_xattr(); }
#endif

// Define macros that appear in the Linux man page to values in ebpf_vm_isa.h.
#define BPF_LD_MAP_FD(reg, fd) {INST_OP_LDDW_IMM, (reg), 1, 0, (fd)}, {0}
#define BPF_ALU64_IMM(op, reg, imm) {INST_CLS_ALU64 | INST_SRC_IMM | ((op) << 4), (reg), 0, 0, (imm)}
#define BPF_MOV64_IMM(reg, imm) {INST_CLS_ALU64 | INST_SRC_IMM | 0xb0, (reg), 0, 0, (imm)}
#define BPF_MOV64_REG(dst, src) {INST_CLS_ALU64 | INST_SRC_REG | 0xb0, (dst), (src), 0, 0}
#define BPF_EXIT_INSN() {INST_OP_EXIT}
#define BPF_CALL_FUNC(imm) {INST_OP_CALL, 0, 0, 0, (imm)}
#define BPF_STX_MEM(sz, dst, src, off) {INST_CLS_STX | INST_MODE_MEM | (sz), (dst), (src), (off), 0}
#define BPF_W INST_SIZE_W
#define BPF_REG_1 R1_ARG
#define BPF_REG_2 R2_ARG
#define BPF_REG_3 R3_ARG
#define BPF_REG_4 R4_ARG
#define BPF_REG_10 R10_STACK_POINTER
#define BPF_ADD 0

#if !defined(CONFIG_BPF_JIT_DISABLED)
static void
test_valid_bpf_load_program_with_map()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    int map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(uint32_t), sizeof(uint32_t), 2, nullptr);
    REQUIRE(map_fd >= 0);

    // Try with a valid set of instructions.
    prevail::EbpfInst instructions[] = {
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
        BPF_PROG_TYPE_SAMPLE, (struct bpf_insn*)instructions, _countof(instructions), nullptr, 0, nullptr, 0);
    REQUIRE(program_fd >= 0);

    // Now query the program info and verify it matches what we set.
    bpf_prog_info program_info = {};
    uint32_t program_info_size = sizeof(program_info);
    REQUIRE(bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_size) == 0);
    REQUIRE(program_info_size == sizeof(program_info));
    REQUIRE(program_info.nr_map_ids == 1);
    REQUIRE(program_info.map_ids == 0);

    REQUIRE(program_info.type == BPF_PROG_TYPE_SAMPLE);

    Platform::_close(program_fd);
    Platform::_close(map_fd);
}

TEST_CASE("valid bpf_load_program with map-jit", "[libbpf][deprecated]") { test_valid_bpf_load_program_with_map(); }
#endif

#if !defined(CONFIG_BPF_JIT_DISABLED)
static void
_test_bpf_object_load_with_o()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    const char* my_object_name = "my_object_name";
    struct bpf_object_open_opts opts = {0};
    opts.object_name = my_object_name;
    struct bpf_object* object = bpf_object__open_file("cgroup_sock_addr.o", &opts);
    REQUIRE(object != nullptr);

    REQUIRE(strcmp(bpf_object__name(object), my_object_name) == 0);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "authorize_connect4");
    REQUIRE(program != nullptr);

    REQUIRE(bpf_program__fd(program) == ebpf_fd_invalid);
    REQUIRE(bpf_program__type(program) == BPF_PROG_TYPE_CGROUP_SOCK_ADDR);

    // Make sure we can override the program type if desired.
    REQUIRE(bpf_program__set_type(program, BPF_PROG_TYPE_BIND) == 0);
    REQUIRE(bpf_program__type(program) == BPF_PROG_TYPE_BIND);

    REQUIRE(bpf_program__set_type(program, BPF_PROG_TYPE_CGROUP_SOCK_ADDR) == 0);

    struct bpf_map* map = bpf_object__next_map(object, nullptr);
    REQUIRE(map != nullptr);
    REQUIRE(strcmp(bpf_map__name(map), "socket_cookie_map") == 0);
    REQUIRE(bpf_map__fd(map) == ebpf_fd_invalid);
    map = bpf_object__next_map(object, map);
    REQUIRE(strcmp(bpf_map__name(map), "egress_connection_policy_map") == 0);
    REQUIRE(bpf_map__fd(map) == ebpf_fd_invalid);
    map = bpf_object__next_map(object, map);
    REQUIRE(strcmp(bpf_map__name(map), "ingress_connection_policy_map") == 0);
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
    REQUIRE(strcmp(bpf_map__name(map), "socket_cookie_map") == 0);
    REQUIRE(bpf_map__fd(map) != ebpf_fd_invalid);
    map = bpf_object__next_map(object, map);
    REQUIRE(strcmp(bpf_map__name(map), "egress_connection_policy_map") == 0);
    REQUIRE(bpf_map__fd(map) != ebpf_fd_invalid);
    map = bpf_object__next_map(object, map);
    REQUIRE(strcmp(bpf_map__name(map), "ingress_connection_policy_map") == 0);
    REQUIRE(bpf_map__fd(map) != ebpf_fd_invalid);
    map = bpf_object__next_map(object, map);
    REQUIRE(map == nullptr);

    REQUIRE(bpf_link__destroy(link.release()) == 0);
    bpf_object__close(object);
}

TEST_CASE("bpf_object__load with .o-jit", "[libbpf]") { _test_bpf_object_load_with_o(); }

static void
_test_bpf_object_load_with_o_from_memory()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    const char* my_object_name = "my_object_name";
    struct bpf_object_open_opts opts = {0};
    opts.object_name = my_object_name;

    // Read droppacket.o into a std::vector.
    std::vector<uint8_t> object_data;
    std::fstream file("cgroup_sock_addr.o", std::ios::in | std::ios::binary);
    REQUIRE(file.is_open());
    file.seekg(0, std::ios::end);
    object_data.resize(file.tellg());
    file.seekg(0, std::ios::beg);
    file.read((char*)object_data.data(), object_data.size());
    file.close();

    struct bpf_object* object = bpf_object__open_mem(object_data.data(), object_data.size(), &opts);
    REQUIRE(object != nullptr);

    REQUIRE(strcmp(bpf_object__name(object), my_object_name) == 0);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "authorize_connect4");
    REQUIRE(program != nullptr);

    REQUIRE(bpf_program__fd(program) == ebpf_fd_invalid);
    REQUIRE(bpf_program__type(program) == BPF_PROG_TYPE_CGROUP_SOCK_ADDR);

    // Make sure we can override the program type if desired.
    REQUIRE(bpf_program__set_type(program, BPF_PROG_TYPE_BIND) == 0);
    REQUIRE(bpf_program__type(program) == BPF_PROG_TYPE_BIND);

    REQUIRE(bpf_program__set_type(program, BPF_PROG_TYPE_CGROUP_SOCK_ADDR) == 0);

      struct bpf_map* map = bpf_object__next_map(object, nullptr);
    REQUIRE(map != nullptr);
    REQUIRE(strcmp(bpf_map__name(map), "socket_cookie_map") == 0);
    REQUIRE(bpf_map__fd(map) == ebpf_fd_invalid);
    map = bpf_object__next_map(object, map);
    REQUIRE(strcmp(bpf_map__name(map), "egress_connection_policy_map") == 0);
    REQUIRE(bpf_map__fd(map) == ebpf_fd_invalid);
    map = bpf_object__next_map(object, map);
    REQUIRE(strcmp(bpf_map__name(map), "ingress_connection_policy_map") == 0);
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
    REQUIRE(strcmp(bpf_map__name(map), "socket_cookie_map") == 0);
    REQUIRE(bpf_map__fd(map) != ebpf_fd_invalid);
    map = bpf_object__next_map(object, map);
    REQUIRE(strcmp(bpf_map__name(map), "egress_connection_policy_map") == 0);
    REQUIRE(bpf_map__fd(map) != ebpf_fd_invalid);
    map = bpf_object__next_map(object, map);
    REQUIRE(strcmp(bpf_map__name(map), "ingress_connection_policy_map") == 0);
    REQUIRE(bpf_map__fd(map) != ebpf_fd_invalid);
    map = bpf_object__next_map(object, map);
    REQUIRE(map == nullptr);

    REQUIRE(bpf_link__destroy(link.release()) == 0);
    bpf_object__close(object);
}

TEST_CASE("bpf_object__load with .o from memory-jit", "[libbpf]") { _test_bpf_object_load_with_o_from_memory(); }

static void
_test_bpf_backwards_compatibility()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    struct
    {
        union bpf_attr attr;
        char pad[3];
    } tmp = {};
    union bpf_attr* attr = &tmp.attr;

    attr->map_create.map_type = BPF_MAP_TYPE_ARRAY;
    attr->map_create.key_size = sizeof(uint32_t);
    attr->map_create.value_size = sizeof(uint32_t);
    attr->map_create.max_entries = 2;
    attr->map_create.map_flags = 0;

    // Truncate bpf_attr before map_flags.
    int map_fd = bpf(BPF_MAP_CREATE, attr, offsetof(union bpf_attr, map_create.map_flags));
    REQUIRE(map_fd > 0);
    Platform::_close(map_fd);

    // Pass extra trailing bytes.
    map_fd = bpf(BPF_MAP_CREATE, attr, sizeof(tmp));
    REQUIRE(map_fd > 0);
    Platform::_close(map_fd);

    // Ensure that non-zero trailing bytes are rejected.
    tmp.pad[0] = 1;
    map_fd = bpf(BPF_MAP_CREATE, attr, sizeof(tmp));
    REQUIRE(map_fd == -EINVAL);
}

// Test that bpf() accepts a smaller and a larger bpf_attr.
TEST_CASE("bpf() backwards compatibility-jit", "[libbpf][bpf]") { _test_bpf_backwards_compatibility(); }

static void
_test_bpf_prog_bind_map_etc()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    prevail::EbpfInst instructions[] = {
        {0xb7, R0_RETURN_VALUE, 0}, // r0 = 0
        {INST_OP_EXIT},             // return r0
    };

    // Load and verify the eBPF program.
    union bpf_attr attr = {};
    attr.prog_load.prog_type = BPF_PROG_TYPE_SAMPLE;
    attr.prog_load.insns = (uintptr_t)instructions;
    attr.prog_load.insn_cnt = _countof(instructions);
    int program_fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    REQUIRE(program_fd >= 0);

    // Now query the program info and verify it matches what we set.
    sys_bpf_prog_info_t program_info = {};
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = program_fd;
    attr.info.info = (uintptr_t)&program_info;
    attr.info.info_len = sizeof(program_info);
    REQUIRE(bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0);
    REQUIRE(attr.info.info_len == sizeof(program_info));
    REQUIRE(program_info.nr_map_ids == 0);
    REQUIRE(program_info.type == BPF_PROG_TYPE_SAMPLE);
    REQUIRE(strnlen(program_info.name, sizeof(program_info.name)) == 0);

    // Verify we can enumerate the program id.
    memset(&attr, 0, sizeof(attr));
    attr.prog_get_next_id.start_id = 0;
    REQUIRE(bpf(BPF_PROG_GET_NEXT_ID, &attr, sizeof(attr)) == 0);
    REQUIRE(attr.prog_get_next_id.next_id == program_info.id);

    // Verify we can convert the program id to an fd.
    memset(&attr, 0, sizeof(attr));
    attr.prog_id = program_info.id;
    int prog_fd2 = bpf(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
    REQUIRE(prog_fd2 > 0);
    Platform::_close(prog_fd2);

    // Create a map.
    memset(&attr, 0, sizeof(attr));
    attr.map_create.map_type = BPF_MAP_TYPE_ARRAY;
    attr.map_create.key_size = sizeof(uint32_t);
    attr.map_create.value_size = sizeof(uint32_t);
    attr.map_create.max_entries = 2;
    attr.map_create.map_flags = 0;
    int map_fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
    REQUIRE(map_fd > 0);

    // Query the map id.
    sys_bpf_map_info_t map_info = {};
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = map_fd;
    attr.info.info = (uintptr_t)&map_info;
    attr.info.info_len = sizeof(map_info);
    REQUIRE(bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0);
    ebpf_id_t map_id = map_info.id;

    // Verify we can enumerate the map id.
    memset(&attr, 0, sizeof(attr));
    attr.map_get_next_id.start_id = 0;
    REQUIRE(bpf(BPF_MAP_GET_NEXT_ID, &attr, sizeof(attr)) == 0);
    REQUIRE(attr.map_get_next_id.next_id == map_id);

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

    // Verify we can create a nested array map.
    uint32_t key = 0;
    fd_t value = map_fd;
    attr.map_create = {};
    attr.map_create.map_type = BPF_MAP_TYPE_ARRAY_OF_MAPS;
    attr.map_create.key_size = sizeof(key);
    attr.map_create.value_size = sizeof(value);
    attr.map_create.max_entries = 1;
    attr.map_create.inner_map_fd = map_fd;
    int nested_map_fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr.map_create));
    REQUIRE(nested_map_fd >= 0);

    // Ensure we can insert map_fd into the outer map.
    attr.map_update = {};
    attr.map_update.map_fd = nested_map_fd;
    attr.map_update.key = (uintptr_t)&key;
    attr.map_update.value = (uintptr_t)&value;
    REQUIRE(bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr.map_update)) == 0);

    // Ensure that looking up the same key gives the ID of the inner map.
    ebpf_id_t value_id = 0;
    attr.map_lookup = {};
    attr.map_lookup.map_fd = nested_map_fd;
    attr.map_lookup.key = (uintptr_t)&key;
    attr.map_lookup.value = (uintptr_t)&value_id;
    REQUIRE(bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr.map_lookup)) == 0);
    REQUIRE(value_id == map_id);

    Platform::_close(nested_map_fd);

    // Verify we can create a nested hash map.
    attr.map_create = {};
    attr.map_create.map_type = BPF_MAP_TYPE_HASH_OF_MAPS;
    attr.map_create.key_size = sizeof(key);
    attr.map_create.value_size = sizeof(value);
    attr.map_create.max_entries = 1;
    attr.map_create.inner_map_fd = map_fd;
    nested_map_fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr.map_create));
    REQUIRE(nested_map_fd >= 0);

    // Ensure we can insert map_fd into the outer map.
    attr.map_update = {};
    attr.map_update.map_fd = nested_map_fd;
    attr.map_update.key = (uintptr_t)&key;
    attr.map_update.value = (uintptr_t)&value;
    REQUIRE(bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr.map_update)) == 0);

    // Ensure that looking up the same key gives the ID of the inner map.
    value_id = 0;
    attr.map_lookup = {};
    attr.map_lookup.map_fd = nested_map_fd;
    attr.map_lookup.key = (uintptr_t)&key;
    attr.map_lookup.value = (uintptr_t)&value_id;
    REQUIRE(bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr.map_lookup)) == 0);
    REQUIRE(value_id == map_id);

    Platform::_close(nested_map_fd);

    // Release our own references on the map and program.
    Platform::_close(map_fd);
    Platform::_close(program_fd);
}

// Test bpf() with the following command ids:
// BPF_PROG_LOAD, BPF_OBJ_GET_INFO_BY_FD, BPF_PROG_GET_NEXT_ID,
// BPF_MAP_CREATE, BPF_MAP_GET_NEXT_ID, BPF_PROG_BIND_MAP,
// BPF_PROG_GET_FD_BY_ID, BPF_MAP_GET_FD_BY_ID, and BPF_MAP_GET_FD_BY_ID.
TEST_CASE("BPF_PROG_BIND_MAP etc.-jit", "[libbpf][bpf]") { _test_bpf_prog_bind_map_etc(); }

void
test_bpf_prog_attach_macro()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();
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
    attr.prog_attach.attach_bpf_fd = program_fd;
    attr.prog_attach.target_fd = program_fd;
    attr.prog_attach.attach_flags = 0;
    attr.prog_attach.attach_type = BPF_ATTACH_TYPE_SAMPLE;
    REQUIRE(bpf(BPF_PROG_ATTACH, &attr, sizeof(attr)) == -ENOTSUP);

    // Verify we can attach the program.
    memset(&attr, 0, sizeof(attr));
    attr.prog_attach.attach_bpf_fd = program_fd;
    // TODO (issue #1028): Currently the target_fd is treated as a compartment id.
    attr.prog_attach.target_fd = program_fd;
    attr.prog_attach.attach_flags = 0;
    attr.prog_attach.attach_type = BPF_CGROUP_INET4_CONNECT;
    REQUIRE(bpf(BPF_PROG_ATTACH, &attr, sizeof(attr)) == 0);

    // Verify we can detach the program.
    memset(&attr, 0, sizeof(attr));
    attr.prog_detach.target_fd = program_fd;
    attr.prog_detach.attach_type = BPF_CGROUP_INET4_CONNECT;
    REQUIRE(bpf(BPF_PROG_DETACH, &attr, sizeof(attr)) == 0);

    // Verify we can't detach the program using a type that doesn't work with this API.
    memset(&attr, 0, sizeof(attr));
    attr.prog_detach.target_fd = program_fd;
    attr.prog_detach.attach_type = BPF_ATTACH_TYPE_SAMPLE;
    REQUIRE(bpf(BPF_PROG_DETACH, &attr, sizeof(attr)) == -ENOTSUP);
}

// Test bpf() with the following command ids:
//  BPF_PROG_ATTACH, BPF_PROG_DETACH
TEST_CASE("BPF_PROG_ATTACH-jit", "[libbpf][bpf]") { test_bpf_prog_attach_macro(); }
#endif

TEST_CASE("BPF_PROG_LOAD logging-jit", "[libbpf][bpf]")
{
#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    prevail::EbpfInst program[] = {
        {INST_OP_EXIT, 0, 0, 0} // Bare return instruction.
    };
    const size_t program_size = sizeof(program);
    char log_buf[256] = {};

    // log_true_size must reflect the minimum size of the log buffer.
    sys_bpf_prog_load_attr_t attr = {};
    attr.prog_type = BPF_PROG_TYPE_SAMPLE;
    attr.insns = reinterpret_cast<uint64_t>(program);
    attr.insn_cnt = program_size / sizeof(prevail::EbpfInst);
    attr.log_buf = reinterpret_cast<uint64_t>(log_buf);
    attr.log_size = sizeof(log_buf);
    attr.log_level = 1;

    int fd = bpf(BPF_PROG_LOAD, (union bpf_attr*)&attr, sizeof(attr));
    REQUIRE(fd < 0);
    REQUIRE(strlen(log_buf) + 1 == attr.log_true_size);

    // a smaller log buffer should fail with ENOSPC.
    attr.log_size = 1;
    fd = bpf(BPF_PROG_LOAD, (union bpf_attr*)&attr, sizeof(attr));
    REQUIRE(fd == -ENOSPC);
#else
    // If JIT or interpreter is disabled, ensure the error is ERROR_NOT_SUPPORTED.
    union bpf_attr attr = {};
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    REQUIRE(fd < 0);
    REQUIRE(GetLastError() == ERROR_NOT_SUPPORTED);
#endif
}