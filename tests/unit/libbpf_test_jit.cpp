// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#pragma warning(push)
#pragma warning(disable : 4200)
#include "bpf/libbpf.h"
#pragma warning(pop)
#include "capture_helper.hpp"
#include "catch_wrapper.hpp"
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
void test_libbpf_load_program()
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

// Only run the test if JIT is enabled.
TEST_CASE("libbpf load program", "[libbpf][deprecated]")
{
    test_libbpf_load_program();
}

void
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

TEST_CASE("libbpf prog test run", "[libbpf][deprecated]")
{
    test_libbpf_prog_test_run();   
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
void
test_valid_bpf_load_program()
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

void
test_valid_bpf_prog_load() 
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

void
test_valid_bpf_load_program_xattr()
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

TEST_CASE("valid bpf_load_program", "[libbpf][deprecated]")
{
    test_valid_bpf_load_program();
}

TEST_CASE("valid bpf_prog_load", "[libbpf]")
{
    test_valid_bpf_load_program();
}

TEST_CASE("valid bpf_load_program_xattr", "[libbpf][deprecated]")
{
    test_valid_bpf_load_program_xattr();
}
#endif

// Define macros that appear in the Linux man page to values in ebpf_vm_isa.h.
#define BPF_LD_MAP_FD(reg, fd) \
    {INST_OP_LDDW_IMM, (reg), 1, 0, (fd)}, { 0 }
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
void
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

TEST_CASE("valid bpf_load_program with map", "[libbpf][deprecated]")
{
    test_valid_bpf_load_program_with_map();
}

void
test_libbpf_program()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    struct bpf_object* object = bpf_object__open("test_sample_ebpf.o");
    REQUIRE(object != nullptr);
    // Load the program(s).
    REQUIRE(bpf_object__load(object) == 0);

    const char* name = bpf_object__name(object);
    REQUIRE(strcmp(name, "test_sample_ebpf.o") == 0);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "test_program_entry");
    REQUIRE(program != nullptr);

    errno = 0;
    REQUIRE(bpf_object__find_program_by_name(object, "not_a_valid_name") == NULL);
    REQUIRE(errno == ENOENT);

    // Testing invalid map name.
    errno = 0;
    REQUIRE(bpf_object__find_map_by_name(object, "not_a_valid_map") == NULL);
    REQUIRE(errno == ENOENT);

    name = bpf_program__section_name(program);
    REQUIRE(strcmp(name, "sample_ext") == 0);

    name = bpf_program__name(program);
    REQUIRE(strcmp(name, "test_program_entry") == 0);

    int fd2 = bpf_program__fd(program);
    REQUIRE(fd2 != ebpf_fd_invalid);

    size_t size = bpf_program__insn_cnt(program);
    REQUIRE(size == 40);

#pragma warning(suppress : 4996) // deprecated
    size = bpf_program__size(program);
    REQUIRE(size == 320);

    REQUIRE(bpf_object__next_program(object, program) == nullptr);
    REQUIRE(bpf_object__prev_program(object, program) == nullptr);
    REQUIRE(bpf_object__next_program(object, nullptr) == program);
    REQUIRE(bpf_object__prev_program(object, nullptr) == program);

    bpf_object__close(object);
}

TEST_CASE("libbpf program", "[libbpf]")
{
    test_libbpf_program();
}

void
test_libbpf_subprogram()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    struct bpf_object* object = bpf_object__open("bindmonitor_bpf2bpf.o");
    REQUIRE(object != nullptr);

    // Test bpf_object__find_program_by_name().
    struct bpf_program* program = bpf_object__find_program_by_name(object, "BindMonitor_Callee");
    REQUIRE(program == nullptr);
    program = bpf_object__find_program_by_name(object, "BindMonitor_Caller");
    REQUIRE(program != nullptr);

    // Test bpf_object__next_program().
    REQUIRE(bpf_object__next_program(object, program) == nullptr);
    REQUIRE(bpf_object__next_program(object, nullptr) == program);

    // Test bpf_object__next_program().
    REQUIRE(bpf_object__prev_program(object, program) == nullptr);
    REQUIRE(bpf_object__prev_program(object, nullptr) == program);

    // Load the program.
    REQUIRE(bpf_object__load(object) == 0);

    bpf_object__close(object);
}

TEST_CASE("libbpf subprogram", "[libbpf]")
{
    test_libbpf_subprogram();
}

static void
_test_program_autoload(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    const char* file_name =
        (execution_type == EBPF_EXECUTION_NATIVE ? "tail_call_same_section_um.dll" : "tail_call_same_section.o");
    struct bpf_object* object = bpf_object__open(file_name);
    REQUIRE(object != nullptr);
    struct bpf_program* caller = bpf_object__find_program_by_name(object, "caller");
    REQUIRE(caller != nullptr);
    int caller_fd = bpf_program__fd(const_cast<const bpf_program*>(caller));
    REQUIRE(caller_fd == ebpf_fd_invalid);
    struct bpf_program* callee = bpf_object__find_program_by_name(object, "callee");
    REQUIRE(callee != nullptr);
    int callee_fd = bpf_program__fd(const_cast<const bpf_program*>(callee));
    REQUIRE(callee_fd == ebpf_fd_invalid);

    // Check initial autoload values.
    REQUIRE(bpf_program__autoload(caller) == true);
    REQUIRE(bpf_program__autoload(callee) == true);

    // Update an autoload value.
    REQUIRE(bpf_program__set_autoload(caller, false) == 0);
    REQUIRE(bpf_program__autoload(caller) == false);
    REQUIRE(bpf_program__autoload(callee) == true);

    // Load the program(s).
    REQUIRE(bpf_object__load(object) == 0);

    // Verify what programs were loaded.
    caller_fd = bpf_program__fd(const_cast<const bpf_program*>(caller));
    REQUIRE(caller_fd == ebpf_fd_invalid);
    callee_fd = bpf_program__fd(const_cast<const bpf_program*>(callee));
    REQUIRE(callee_fd > 0);

    // Verify we cannot change autoload values after loading.
    int error = bpf_program__set_autoload(caller, false);
    REQUIRE(error < 0);
    REQUIRE(errno == EINVAL);
    error = bpf_program__set_autoload(caller, true);
    REQUIRE(error < 0);
    REQUIRE(errno == EINVAL);
    error = bpf_program__set_autoload(callee, false);
    REQUIRE(error < 0);
    REQUIRE(errno == EINVAL);
    error = bpf_program__set_autoload(callee, true);
    REQUIRE(error < 0);
    REQUIRE(errno == EINVAL);

    bpf_object__close(object);
}

DECLARE_ALL_TEST_CASES("libbpf program autoload", "[libbpf]", _test_program_autoload);

void
test_libbpf_program_pinning()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();
    const char* pin_path = "\\temp\\test";
    const char* bad_pin_path = "\\bad\\path";

    struct bpf_object* object = bpf_object__open("test_sample_ebpf.o");
    REQUIRE(object != nullptr);
    // Load the program(s).
    REQUIRE(bpf_object__load(object) == 0);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "test_program_entry");
    REQUIRE(program != nullptr);

    // Try to pin the program.
    int result = bpf_program__pin(program, pin_path);
    REQUIRE(result == 0);

    // Make sure a duplicate pin fails.
    result = bpf_program__pin(program, pin_path);
    REQUIRE(result < 0);
    REQUIRE(errno == EEXIST);

    // Test bpf_obj_get() to return the fd and correctly set 'errno'.
    fd_t obj_fd = bpf_obj_get(pin_path);
    REQUIRE(obj_fd != ebpf_fd_invalid);
    REQUIRE(errno == EEXIST);
    obj_fd = bpf_obj_get(bad_pin_path);
    REQUIRE(obj_fd == -ENOENT);
    REQUIRE(errno == ENOENT);

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

TEST_CASE("libbpf program pinning", "[libbpf]")
{
    test_libbpf_program_pinning();
}

void
test_libbpf_program_attach()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    struct bpf_object* object = bpf_object__open("test_sample_ebpf.o");
    REQUIRE(object != nullptr);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "test_program_entry");
    REQUIRE(program != nullptr);

    // Based on the program type, verify that the/ default attach type is set correctly.
    enum bpf_attach_type type = bpf_program__get_expected_attach_type(program);
    REQUIRE(type == BPF_ATTACH_TYPE_SAMPLE);

    REQUIRE(bpf_program__set_expected_attach_type(program, BPF_ATTACH_TYPE_SAMPLE) == 0);

    type = bpf_program__get_expected_attach_type(program);
    REQUIRE(type == BPF_ATTACH_TYPE_SAMPLE);

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

TEST_CASE("libbpf program attach", "[libbpf]")
{
    test_libbpf_program_attach();
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

#if !defined(CONFIG_BPF_JIT_DISABLED)
void
test_bpf_set_link_xdp_fd()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

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

TEST_CASE("bpf_set_link_xdp_fd", "[libbpf]")
{
   test_bpf_set_link_xdp_fd();
}

void
test_libbpf_map()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();
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

    struct bpf_program* program = bpf_object__find_program_by_name(object, "test_maps");
    REQUIRE(program != nullptr);

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
    REQUIRE(errno == ENOENT);

    // Wrong fd type.
    int program_fd = bpf_program__fd(const_cast<const bpf_program*>(program));
    result = bpf_map_lookup_elem(program_fd, &index, &value);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    // Invalid fd.
    result = bpf_map_lookup_elem(nonexistent_fd, &index, &value);
    REQUIRE(result < 0);
    REQUIRE(errno == EBADF);

    result = bpf_map_lookup_elem(-1, &index, &value);
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

    result = bpf_map_update_elem(-1, &index, &value, 0);
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

    // next_key is NULL.
    result = bpf_map_get_next_key(map_fd, NULL, NULL);
    REQUIRE(result < 0);
    REQUIRE(errno == EINVAL);

    bpf_object__close(object);
}

TEST_CASE("libbpf map", "[libbpf]")
{
    test_libbpf_map();
}

void
test_libbpf_map_binding()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    struct bpf_object* object = bpf_object__open("test_sample_ebpf.o");
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

TEST_CASE("libbpf map binding", "[libbpf]")
{
    test_libbpf_map_binding();
}

void
test_libbpf_map_pinning()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();
    const char* pin_path = "\\temp\\test";

    struct bpf_object* object = bpf_object__open("test_sample_ebpf.o");
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

TEST_CASE("libbpf map pinning", "[libbpf]")
{
    test_libbpf_map_pinning();
}

void
test_libbpf_obj_pinning()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();
    const char* pin_path = "\\temp\\test";

    struct bpf_object* object = bpf_object__open("test_sample_ebpf.o");
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

TEST_CASE("libbpf obj pinning", "[libbpf]")
{
   test_libbpf_obj_pinning();
}

TEST_CASE("good_tail_call-jit", "[libbpf]")
{
    // Verify that 42 is returned, which is done by the callee.
    ebpf_test_tail_call("tail_call.o", 42);
}

TEST_CASE("bad_tail_call-jit", "[libbpf]")
{
    ebpf_test_tail_call("tail_call_bad.o", (uint32_t)(-EBPF_INVALID_ARGUMENT));
}

void
test_disallow_prog_array_mixed_program_type_values()
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    program_info_provider_t bind_program_info;
    REQUIRE(bind_program_info.initialize(EBPF_PROGRAM_TYPE_BIND) == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    struct bpf_object* sample_object = bpf_object__open("test_sample_ebpf.o");
    REQUIRE(sample_object != nullptr);
    // Load the program(s).
    REQUIRE(bpf_object__load(sample_object) == 0);
    struct bpf_program* sample_program = bpf_object__find_program_by_name(sample_object, "test_program_entry");
    int sample_program_fd = bpf_program__fd(const_cast<const bpf_program*>(sample_program));

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
    int error = bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&sample_program_fd, 0);
    REQUIRE(error == 0);

    // Adding an entry with a different program type should fail.
    error = bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&bind_program_fd, 0);
    REQUIRE(error < 0);
    REQUIRE(errno == EBADF);

    Platform::_close(map_fd);
    bpf_object__close(bind_object);
    bpf_object__close(sample_object);
}

TEST_CASE("disallow prog_array mixed program type values", "[libbpf]")
{
    test_disallow_prog_array_mixed_program_type_values();
}

void
test_enumerate_link_IDs()
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);
    program_info_provider_t bind_program_info;
    REQUIRE(bind_program_info.initialize(EBPF_PROGRAM_TYPE_BIND) == EBPF_SUCCESS);
    single_instance_hook_t sample_hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(sample_hook.initialize() == EBPF_SUCCESS);
    single_instance_hook_t bind_hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);
    REQUIRE(bind_hook.initialize() == EBPF_SUCCESS);

    // Verify the enumeration is empty.
    uint32_t id1;
    REQUIRE(bpf_link_get_next_id(0, &id1) < 0);
    REQUIRE(errno == ENOENT);

    REQUIRE(bpf_link_get_next_id(EBPF_ID_NONE, &id1) < 0);
    REQUIRE(errno == ENOENT);

    // Load and attach some programs.
    program_load_attach_helper_t sample_helper;
    sample_helper.initialize(
        "test_sample_ebpf.o", BPF_PROG_TYPE_SAMPLE, "test_program_entry", EBPF_EXECUTION_JIT, nullptr, 0, sample_hook);
    program_load_attach_helper_t bind_helper;
    bind_helper.initialize(
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

TEST_CASE("enumerate link IDs", "[libbpf]")
{
    test_enumerate_link_IDs();
}

void
test_enumerate_link_IDs_with_bpf()
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);
    program_info_provider_t bind_program_info;
    REQUIRE(bind_program_info.initialize(EBPF_PROGRAM_TYPE_BIND) == EBPF_SUCCESS);
    single_instance_hook_t sample_hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE, BPF_LINK_TYPE_UNSPEC);
    REQUIRE(sample_hook.initialize() == EBPF_SUCCESS);
    single_instance_hook_t bind_hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND, BPF_LINK_TYPE_PLAIN);
    REQUIRE(bind_hook.initialize() == EBPF_SUCCESS);

    // Verify the enumeration is empty.
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    REQUIRE(bpf(BPF_LINK_GET_NEXT_ID, &attr, sizeof(attr)) == -ENOENT);

    memset(&attr, 0, sizeof(attr));
    attr.link_id = EBPF_ID_NONE;
    REQUIRE(bpf(BPF_LINK_GET_NEXT_ID, &attr, sizeof(attr)) == -ENOENT);

    // Load and attach some programs.
    program_load_attach_helper_t sample_helper;
    sample_helper.initialize(
        "test_sample_ebpf.o", BPF_PROG_TYPE_SAMPLE, "test_program_entry", EBPF_EXECUTION_JIT, nullptr, 0, sample_hook);
    program_load_attach_helper_t bind_helper;
    bind_helper.initialize(
        "bindmonitor.o", BPF_PROG_TYPE_BIND, "BindMonitor", EBPF_EXECUTION_JIT, nullptr, 0, bind_hook);

    // Now enumerate the IDs.
    memset(&attr, 0, sizeof(attr));
    REQUIRE(bpf(BPF_LINK_GET_NEXT_ID, &attr, sizeof(attr)) == 0);
    uint32_t id1 = attr.link_get_next_id.next_id;

    memset(&attr, 0, sizeof(attr));
    attr.link_id = id1;
    fd_t fd1 = bpf(BPF_LINK_GET_FD_BY_ID, &attr, sizeof(attr));
    REQUIRE(fd1 >= 0);

    REQUIRE(bpf(BPF_LINK_GET_NEXT_ID, &attr, sizeof(attr)) == 0);
    uint32_t id2 = attr.link_get_next_id.next_id;

    memset(&attr, 0, sizeof(attr));
    attr.link_id = id2;
    fd_t fd2 = bpf(BPF_LINK_GET_FD_BY_ID, &attr, sizeof(attr));
    REQUIRE(fd2 >= 0);

    REQUIRE(bpf(BPF_LINK_GET_NEXT_ID, &attr, sizeof(attr)) == -ENOENT);

    // Get info on the first link.
    memset(&attr, 0, sizeof(attr));
    sys_bpf_link_info_t info = {};
    attr.info.bpf_fd = fd1;
    attr.info.info = (uintptr_t)&info;
    attr.info.info_len = sizeof(info);
    REQUIRE(bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0);
    REQUIRE(info.type == BPF_LINK_TYPE_UNSPEC);
    REQUIRE(info.id == id1);
    REQUIRE(info.prog_id != 0);

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
    REQUIRE(info.type == BPF_LINK_TYPE_UNSPEC);
    REQUIRE(info.id == id1);
    REQUIRE(info.prog_id == 0);

    // Pin the detached link.
    memset(&attr, 0, sizeof(attr));
    attr.obj_pin.bpf_fd = fd1;
    attr.obj_pin.pathname = (uintptr_t) "MyPath";
    REQUIRE(bpf(BPF_OBJ_PIN, &attr, sizeof(attr)) == 0);

    // Verify that bpf_fd must be 0 when calling BPF_OBJ_GET.
    REQUIRE(bpf(BPF_OBJ_GET, &attr, sizeof(attr)) == -EINVAL);

    // Retrieve a new fd from the pin path.
    attr.obj_pin.bpf_fd = 0;
    fd_t fd3 = bpf(BPF_OBJ_GET, &attr, sizeof(attr));
    REQUIRE(fd3 > 0);

    // Get info on the new fd.
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = fd3;
    attr.info.info = (uintptr_t)&info;
    attr.info.info_len = sizeof(info);
    REQUIRE(bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0);
    REQUIRE(info.id == id1);

    // Get info on the second link.
    memset(&attr, 0, sizeof(attr));
    info = {};
    attr.info.bpf_fd = fd2;
    attr.info.info = (uintptr_t)&info;
    attr.info.info_len = sizeof(info);
    REQUIRE(bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0);
    REQUIRE(info.type == BPF_LINK_TYPE_PLAIN);
    REQUIRE(info.id == id2);
    REQUIRE(info.prog_id != 0);

    // And for completeness, try an invalid bpf() call.
    REQUIRE(bpf(-1, &attr, sizeof(attr)) == -EINVAL);

    // Unpin the link.
    REQUIRE(ebpf_object_unpin("MyPath") == EBPF_SUCCESS);

    Platform::_close(fd1);
    Platform::_close(fd2);
    Platform::_close(fd3);
}

TEST_CASE("enumerate link IDs with bpf", "[libbpf][bpf]")
{
    test_enumerate_link_IDs_with_bpf();   
}

void
test_bpf_prog_attach()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    struct bpf_object* object = bpf_object__open("cgroup_sock_addr.o");
    REQUIRE(object != nullptr);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "authorize_connect4");
    REQUIRE(program != nullptr);

    REQUIRE(bpf_object__load(object) == 0);

    int program_fd = bpf_program__fd(program);
    REQUIRE(program_fd > 0);

    // Verify we can't attach the program to an attach type that doesn't work with this API.
    REQUIRE(bpf_prog_attach(program_fd, 0, BPF_ATTACH_TYPE_SAMPLE, 0) == -ENOTSUP);

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

TEST_CASE("bpf_prog_attach", "[libbpf]")
{
   test_bpf_prog_attach();
}

void
test_bpf_link_pin()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    struct bpf_object* object = bpf_object__open("test_sample_ebpf.o");
    REQUIRE(object != nullptr);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "test_program_entry");
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

TEST_CASE("bpf_link__pin", "[libbpf]")
{
    test_bpf_link_pin();
}

void
test_bpf_obj_get_info_by_fd()
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);
    single_instance_hook_t sample_hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(sample_hook.initialize() == EBPF_SUCCESS);
    program_load_attach_helper_t sample_helper;
    sample_helper.initialize(
        "map_reuse.o", BPF_PROG_TYPE_SAMPLE, "lookup_update", EBPF_EXECUTION_JIT, nullptr, 0, sample_hook);

    struct bpf_object* object = sample_helper.get_object();
    REQUIRE(object != nullptr);

    struct bpf_program* program = bpf_object__next_program(object, nullptr);
    REQUIRE(program != nullptr);

    const char* program_name = bpf_program__name(program);
    REQUIRE(program_name != nullptr);

    int program_fd = bpf_program__fd(program);
    REQUIRE(program_fd > 0);

    // Fetch info about the maps and verify it matches what we'd expect.
    bpf_map_info map_info[3];
    uint32_t map_info_size = sizeof(bpf_map_info);

    // Find the inner map.
    struct bpf_map* map = bpf_object__find_map_by_name(object, "inner_map");
    REQUIRE(map != nullptr);

    int map_fd = bpf_map__fd(map);
    REQUIRE(map_fd > 0);

    bpf_map_info inner_map_info;
    REQUIRE(bpf_obj_get_info_by_fd(map_fd, &inner_map_info, &map_info_size) == 0);

    // Find the outer map.
    map = bpf_object__find_map_by_name(object, "outer_map");
    REQUIRE(map != nullptr);

    map_fd = bpf_map__fd(map);
    REQUIRE(map_fd > 0);

    const char* map_name = bpf_map__name(map);
    REQUIRE(map_name != nullptr);

    REQUIRE(bpf_obj_get_info_by_fd(map_fd, &map_info[0], &map_info_size) == 0);

    bpf_map_info expected_map_info = {
        .type = BPF_MAP_TYPE_HASH_OF_MAPS,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(uint32_t),
        .max_entries = 1,
        .name = {0},
        .pinned_path_count = 1};
    expected_map_info.id = map_info[0].id;
    expected_map_info.inner_map_id = inner_map_info.id;
    strcpy_s(expected_map_info.name, sizeof(expected_map_info.name), map_name);
    if (strlen(map_name) < sizeof(expected_map_info.name)) {
        memset(expected_map_info.name + strlen(map_name), 0, sizeof(expected_map_info.name) - strlen(map_name));
    }

    // Verify the map info matches what we expect.
    REQUIRE(memcmp(&map_info[0], &expected_map_info, sizeof(expected_map_info)) == 0);

    // Find the second map.
    map = bpf_object__find_map_by_name(object, "port_map");
    REQUIRE(map != nullptr);

    map_fd = bpf_map__fd(map);
    REQUIRE(map_fd > 0);

    map_name = bpf_map__name(map);
    REQUIRE(map_name != nullptr);

    REQUIRE(bpf_obj_get_info_by_fd(map_fd, &map_info[1], &map_info_size) == 0);

    expected_map_info.type = BPF_MAP_TYPE_ARRAY;
    expected_map_info.id = map_info[1].id;
    expected_map_info.inner_map_id = 0;
    strcpy_s(expected_map_info.name, sizeof(expected_map_info.name), map_name);
    if (strlen(map_name) < sizeof(expected_map_info.name)) {
        memset(expected_map_info.name + strlen(map_name), 0, sizeof(expected_map_info.name) - strlen(map_name));
    }

    // Verify the map info matches what we expect.
    REQUIRE(memcmp(&map_info[1], &expected_map_info, sizeof(expected_map_info)) == 0);

    // Get info but pass in a buffer that is too small.
    uint32_t reduced_map_info_size = sizeof(bpf_map_info) / 2;
    memset(&map_info[2], 0xa, sizeof(map_info[2]));
    REQUIRE(bpf_obj_get_info_by_fd(map_fd, &map_info[2], &reduced_map_info_size) == 0);
    // Verify the map info matches what we expect.
    REQUIRE(memcmp(&map_info[2], &expected_map_info, reduced_map_info_size) == 0);
    const std::vector<std::byte> buf(sizeof(bpf_map_info) - reduced_map_info_size, std::byte{0xa});
    REQUIRE(
        memcmp(
            reinterpret_cast<std::byte*>(&map_info[2]) + reduced_map_info_size,
            buf.data(),
            sizeof(bpf_map_info) - reduced_map_info_size) == 0);

    // Fetch info about the program and verify it matches what we'd expect.
    bpf_prog_info program_info = {};
    uint32_t program_info_size = sizeof(program_info);
    REQUIRE(bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_size) == 0);
    REQUIRE(program_info_size == sizeof(program_info));
    REQUIRE(strcmp(program_info.name, program_name) == 0);
    REQUIRE(program_info.nr_map_ids == 2);
    REQUIRE(program_info.map_ids == 0);
    REQUIRE(program_info.type == BPF_PROG_TYPE_SAMPLE);

    // Get info but pass in a buffer that smaller than the minimum required input size.
    bpf_prog_info reduced_program_info = {};
    uint32_t reduced_prog_info_size = EBPF_OFFSET_OF(bpf_prog_info, name) - 1;
    REQUIRE(bpf_obj_get_info_by_fd(program_fd, &reduced_program_info, &reduced_prog_info_size) == -EINVAL);

    // Get info but pass in a output buffer that is smaller than the full size of bpf_prog_info.
    reduced_prog_info_size = sizeof(bpf_prog_info) / 2;
    memset(&reduced_program_info, 0xa, sizeof(reduced_program_info));
    reduced_program_info.nr_map_ids = 0;
    reduced_program_info.map_ids = 0;
    REQUIRE(bpf_obj_get_info_by_fd(program_fd, &reduced_program_info, &reduced_prog_info_size) == 0);
    // Verify the program info matches what we expect.
    REQUIRE(memcmp(&reduced_program_info, &program_info, reduced_prog_info_size) == 0);
    const std::vector<std::byte> buf2(sizeof(bpf_prog_info) - reduced_prog_info_size, std::byte{0xa});
    REQUIRE(
        memcmp(
            reinterpret_cast<std::byte*>(&reduced_program_info) + reduced_prog_info_size,
            buf2.data(),
            sizeof(bpf_prog_info) - reduced_prog_info_size) == 0);

    // Fetch info about the maps and verify it matches what we'd expect.
    ebpf_id_t map_ids[2] = {0};
    program_info.map_ids = (uintptr_t)map_ids;
    REQUIRE(bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_size) == 0);
    REQUIRE(map_ids[0] == map_info[0].id);
    REQUIRE(map_ids[1] == map_info[1].id);

    // Try again with nr_map_ids set to get only partial.
    map_ids[0] = map_ids[1] = 0;
    program_info.nr_map_ids = 1;
    program_info.map_ids = (uintptr_t)map_ids;
    REQUIRE(bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_size) == -EFAULT);
    REQUIRE(map_ids[0] == map_info[0].id);

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
    REQUIRE(link_info.attach_type == BPF_ATTACH_TYPE_SAMPLE);

    // Get info but pass in a buffer that is too small.
    bpf_link_info reduced_link_info = {};
    uint32_t reduced_link_info_size = sizeof(bpf_link_info) / 2;
    memset(&reduced_link_info, 0xa, sizeof(reduced_link_info));
    REQUIRE(bpf_obj_get_info_by_fd(link_fd, &reduced_link_info, &reduced_link_info_size) == 0);
    // Verify the link info matches what we expect.
    REQUIRE(memcmp(&reduced_link_info, &link_info, reduced_link_info_size) == 0);
    const std::vector<std::byte> buf3(sizeof(bpf_link_info) - reduced_link_info_size, std::byte{0xa});
    REQUIRE(
        memcmp(
            reinterpret_cast<std::byte*>(&reduced_link_info) + reduced_link_info_size,
            buf3.data(),
            sizeof(bpf_link_info) - reduced_link_info_size) == 0);

    // Verify we can detach using this link fd.
    // This is the flow used by bpftool to detach a link.
    REQUIRE(bpf_link_detach(link_fd) == 0);

    Platform::_close(link_fd);
}

TEST_CASE("bpf_obj_get_info_by_fd", "[libbpf]")
{
    test_bpf_obj_get_info_by_fd();
}

void
test_bpf_obj_get_info_by_fd_2()
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    program_info_provider_t sock_addr_program_info;
    REQUIRE(sock_addr_program_info.initialize(EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR) == EBPF_SUCCESS);
    single_instance_hook_t v4_connect_hook(EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR, EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT);
    REQUIRE(v4_connect_hook.initialize() == EBPF_SUCCESS);

    program_load_attach_helper_t sock_addr_helper;
    sock_addr_helper.initialize(
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
    REQUIRE(program_info.nr_map_ids == 2);
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

TEST_CASE("bpf_obj_get_info_by_fd_2", "[libbpf]")
{
    test_bpf_obj_get_info_by_fd_2();
}

void
test_bpf_object_load_with_o()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

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

TEST_CASE("bpf_object__load with .o", "[libbpf]")
{
    test_bpf_object_load_with_o();
}

void 
test_bpf_object_load_with_o_from_memory()
{
    _test_helper_libbpf test_helper;
    test_helper.initialize();

    const char* my_object_name = "my_object_name";
    struct bpf_object_open_opts opts = {0};
    opts.object_name = my_object_name;

    // Read droppacket.o into a std::vector.
    std::vector<uint8_t> object_data;
    std::fstream file("droppacket.o", std::ios::in | std::ios::binary);
    REQUIRE(file.is_open());
    file.seekg(0, std::ios::end);
    object_data.resize(file.tellg());
    file.seekg(0, std::ios::beg);
    file.read((char*)object_data.data(), object_data.size());
    file.close();

    struct bpf_object* object = bpf_object__open_mem(object_data.data(), object_data.size(), &opts);
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

TEST_CASE("bpf_object__load with .o from memory", "[libbpf]")
{
    test_bpf_object_load_with_o_from_memory();
}

void
test_bpf_backwards_compatibility()
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
TEST_CASE("bpf() backwards compatibility", "[libbpf][bpf]")
{
    test_bpf_backwards_compatibility();
}

void
test_bpf_prog_bind_map_etc()
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
TEST_CASE("BPF_PROG_BIND_MAP etc.", "[libbpf][bpf]")
{
    test_bpf_prog_bind_map_etc();
}

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
TEST_CASE("BPF_PROG_ATTACH", "[libbpf][bpf]")
{
    test_bpf_prog_attach_macro();
}
#endif

TEST_CASE("BPF_PROG_LOAD logging", "[libbpf][bpf]")
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
