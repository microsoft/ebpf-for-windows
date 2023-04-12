// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include "bpf_assembler.h"
#include "bpf_code_generator.h"
#include "catch_wrapper.hpp"
#include "test_helpers.h"
#include "watchdog.h"

extern "C"
{
#include "ubpf.h"
}

#define SEPARATOR "\\"

#define UBPF_CODE_SIZE 8192

CATCH_REGISTER_LISTENER(_watchdog)

std::string
env_or_default(const char* environment_variable, const char* default_value)
{
    std::string return_value = default_value;
    char* buffer = nullptr;
    size_t buffer_size = 0;
    if (_dupenv_s(&buffer, &buffer_size, environment_variable) == 0) {
        if (buffer != nullptr) {
            return_value = buffer;
        }
        free(buffer);
    }

    return return_value;
}

std::tuple<std::string, std::string, std::string, std::vector<ebpf_inst>>
parse_test_file(const std::string& data_file)
{
    enum class _state
    {
        state_ignore,
        state_assembly,
        state_raw,
        state_result,
        state_memory,
    } state = _state::state_ignore;
    std::string prefix = data_file.substr(data_file.find_last_of(SEPARATOR) + 1);

    std::stringstream data_out;
    std::ifstream data_in(data_file);

    std::string result;
    std::string mem;
    std::string line;
    while (std::getline(data_in, line)) {
        if (line.find("--") != std::string::npos) {
            if (line.find("asm") != std::string::npos) {
                state = _state::state_assembly;
                continue;
            } else if (line.find("result") != std::string::npos) {
                state = _state::state_result;
                continue;
            } else if (line.find("mem") != std::string::npos) {
                state = _state::state_memory;
                continue;
            } else if (line.find("raw") != std::string::npos) {
                state = _state::state_ignore;
                continue;
            } else if (line.find("result") != std::string::npos) {
                state = _state::state_result;
                continue;
            } else if (line.find("no register offset") != std::string::npos) {
                state = _state::state_ignore;
                continue;
            } else if (line.find(" c") != std::string::npos) {
                state = _state::state_ignore;
                continue;
            } else {
                std::cout << "Unknown directive " << line << std::endl;
                state = _state::state_ignore;
                continue;
            }
        }
        if (line.empty()) {
            continue;
        }

        switch (state) {
        case _state::state_assembly:
            if (line.find("#") != std::string::npos) {
                line = line.substr(0, line.find("#"));
            }
            data_out << line << std::endl;
            break;
        case _state::state_result:
            result = line;
            break;
        case _state::state_memory:
            mem += std::string(" ") + line;
            break;
        default:
            continue;
        }
    }

    if (result.find("0x") != std::string::npos) {
        result = result.substr(result.find("0x") + 2);
    }
    data_out.seekg(0);
    auto instructions = bpf_assembler(data_out);
    return {prefix, mem, result, instructions};
}

ubpf_vm*
prepare_ubpf_vm(const std::vector<ebpf_inst> instructions)
{
    auto vm = ubpf_create();
    char* error = nullptr;
    REQUIRE(vm != nullptr);
    for (auto& [key, value] : helper_functions) {
        REQUIRE(ubpf_register(vm, key, "unnamed", value) == 0);
    }
    REQUIRE(ubpf_set_unwind_function_index(vm, 5) == 0);

    REQUIRE(
        ubpf_load(vm, instructions.data(), static_cast<uint32_t>(instructions.size() * sizeof(ebpf_inst)), &error) ==
        0);
    return vm;
}

void
run_ubpf_jit_test(const std::string& data_file)
{
    auto [prefix, mem, result, instructions] = parse_test_file(data_file);
    char* error = nullptr;
    ubpf_vm* vm = prepare_ubpf_vm(instructions);
    size_t code_size = UBPF_CODE_SIZE;
    uint8_t* code = reinterpret_cast<uint8_t*>(VirtualAlloc2(
        GetCurrentProcess(), nullptr, code_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, nullptr, 0));
    REQUIRE(code != nullptr);

    REQUIRE(ubpf_translate(vm, code, &code_size, &error) == 0);

    ubpf_jit_fn jit = reinterpret_cast<ubpf_jit_fn>(code);

    std::vector<uint8_t> input_buffer;

    if (!mem.empty()) {
        std::stringstream ss(mem);
        uint32_t value;
        while (ss >> std::hex >> value) {
            input_buffer.push_back(static_cast<uint8_t>(value));
        }
    }

    uint64_t expected_result = std::stoull(result, nullptr, 16);

    uint64_t actual_result = jit(input_buffer.data(), input_buffer.size());

    REQUIRE(actual_result == expected_result);

    ubpf_destroy(vm);
    VirtualFree(jit, 0, MEM_RELEASE);
}

void
run_ubpf_interpret_test(const std::string& data_file)
{
    auto [prefix, mem, result, instructions] = parse_test_file(data_file);
    ubpf_vm* vm = prepare_ubpf_vm(instructions);

    std::vector<uint8_t> input_buffer;

    if (!mem.empty()) {
        std::stringstream ss(mem);
        uint32_t value;
        while (ss >> std::hex >> value) {
            input_buffer.push_back(static_cast<uint8_t>(value));
        }
    }

    uint64_t expected_result = std::stoull(result, nullptr, 16);

    uint64_t actual_result;
    REQUIRE(ubpf_exec(vm, input_buffer.data(), input_buffer.size(), &actual_result) == 0);

    REQUIRE(actual_result == expected_result);

    ubpf_destroy(vm);
}

void
run_bpf_code_generator_test(const std::string& data_file)
{
    std::string cc = env_or_default("CC", "cl.exe");
    std::string cxxflags = env_or_default("CXXFLAGS", "/EHsc /nologo");

    auto [prefix, mem, result, instructions] = parse_test_file(data_file);

    std::ofstream c_file(std::string(prefix) + std::string(".c"));
    try {

        bpf_code_generator code("test", instructions);
        code.generate("test");
        code.emit_c_code(c_file);
    } catch (std::runtime_error& err) {
        REQUIRE(err.what() == NULL);
    }
    c_file.flush();
    c_file.close();

    std::string compile_command = cc + std::string(" ") + cxxflags +
                                  std::string(" -I.." SEPARATOR ".." SEPARATOR "include ") + std::string(prefix) +
                                  std::string(".c ") + std::string(" bpf_test.cpp >") + std::string(prefix) +
                                  std::string(".log 2>&1");
    REQUIRE(system(compile_command.c_str()) == 0);
    std::string test_command = std::string("." SEPARATOR) + std::string(prefix) + std::string(" ") +
                               std::string(result) + std::string(" \"") + std::string(mem) + std::string("\"");
    REQUIRE(system(test_command.c_str()) == 0);
}

#define DECLARE_TEST(FILE)                                                                                            \
    TEST_CASE(FILE "_native", "[bpf_code_generator]")                                                                 \
    {                                                                                                                 \
        run_bpf_code_generator_test(".." SEPARATOR ".." SEPARATOR "external" SEPARATOR "ubpf" SEPARATOR               \
                                    "tests" SEPARATOR "" FILE ".data");                                               \
    }                                                                                                                 \
    TEST_CASE(FILE "_jit", "[ubpf_jit]")                                                                              \
    {                                                                                                                 \
        run_ubpf_jit_test(".." SEPARATOR ".." SEPARATOR "external" SEPARATOR "ubpf" SEPARATOR "tests" SEPARATOR       \
                          "" FILE ".data");                                                                           \
    }                                                                                                                 \
    TEST_CASE(FILE "_interpret", "[ubpf_interpret]")                                                                  \
    {                                                                                                                 \
        run_ubpf_interpret_test(".." SEPARATOR ".." SEPARATOR "external" SEPARATOR "ubpf" SEPARATOR "tests" SEPARATOR \
                                "" FILE ".data");                                                                     \
    }

// Tests are dependent on the collateral from the https://github.com/iovisor/ubpf project.
// Most uBPF tests are declared as a block of assembly, an expected result and a block of memory
// to be passed to the test, but some of the uBPF tests are not currently usable due to the
// following reasons:
// 1) They do not declare an expected result block.
// 2) They assume certain validations on malformed code are performed by bpf2c.
// 3) They assume non-standard eBPF ISA behavior (r2 == length of memory as an example).
// 4) They use directives that don't make sense in this context.
// These tests are included for completeness, but commented out as they are not supported.
// Note on 2:
// The intended flow has bpf2c execute after the BPF byte code has been verified by PREVAIL.
// As such, these would be redundant. In addition, the tests look for specific text error messages
// from the uBPF JIT compiler which would not match.
DECLARE_TEST("add")
DECLARE_TEST("alu-arith")
DECLARE_TEST("alu-bit")
// Test doesn't declare expected result.
// DECLARE_TEST("alu")
DECLARE_TEST("alu64-arith")
DECLARE_TEST("alu64-bit")
// Test doesn't declare expected result.
// DECLARE_TEST("alu64")
DECLARE_TEST("arsh-reg")
DECLARE_TEST("arsh")
DECLARE_TEST("arsh32-high-shift")
DECLARE_TEST("arsh64")
DECLARE_TEST("be16-high")
DECLARE_TEST("be16")
DECLARE_TEST("be32-high")
DECLARE_TEST("be32")
DECLARE_TEST("be64")
DECLARE_TEST("call-memfrob")
DECLARE_TEST("call-save")
DECLARE_TEST("call")
DECLARE_TEST("call_unwind")
DECLARE_TEST("call_unwind_fail")
DECLARE_TEST("div32-high-divisor")
DECLARE_TEST("div32-imm")
DECLARE_TEST("div32-reg")
DECLARE_TEST("div64-imm")
DECLARE_TEST("div64-reg")
DECLARE_TEST("div-by-zero-imm")
DECLARE_TEST("div-by-zero-reg")
DECLARE_TEST("div64-by-zero-reg")
DECLARE_TEST("div64-by-zero-imm")
DECLARE_TEST("early-exit")
// Malformed byte code tests - Verifier rejects prior to bpf2c.
// DECLARE_TEST("err-call-bad-imm")
// DECLARE_TEST("err-call-unreg")
// DECLARE_TEST("err-endian-size")
// DECLARE_TEST("err-incomplete-lddw")
// DECLARE_TEST("err-incomplete-lddw2")
// DECLARE_TEST("err-infinite-loop")
// DECLARE_TEST("err-invalid-reg-dst")
// DECLARE_TEST("err-invalid-reg-src")
// DECLARE_TEST("err-jmp-lddw")
// DECLARE_TEST("err-jmp-out")
// DECLARE_TEST("err-stack-oob")
// DECLARE_TEST("err-too-many-instructions")
// DECLARE_TEST("err-unknown-opcode")
DECLARE_TEST("exit-not-last")
DECLARE_TEST("exit")
DECLARE_TEST("ja")
DECLARE_TEST("jeq-imm")
DECLARE_TEST("jeq-reg")
DECLARE_TEST("jge-imm")
DECLARE_TEST("jgt-imm")
DECLARE_TEST("jgt-reg")
DECLARE_TEST("jit-bounce")
DECLARE_TEST("jle-imm")
DECLARE_TEST("jle-reg")
DECLARE_TEST("jlt-imm")
DECLARE_TEST("jlt-reg")
// Test doesn't declare expected result.
// DECLARE_TEST("jmp")
DECLARE_TEST("jne-reg")
DECLARE_TEST("jset-imm")
DECLARE_TEST("jset-reg")
DECLARE_TEST("jsge-imm")
DECLARE_TEST("jsge-reg")
DECLARE_TEST("jsgt-imm")
DECLARE_TEST("jsgt-reg")
DECLARE_TEST("jsle-imm")
DECLARE_TEST("jsle-reg")
DECLARE_TEST("jslt-imm")
DECLARE_TEST("jslt-reg")
DECLARE_TEST("lddw")
DECLARE_TEST("lddw2")
// Test doesn't declare expected result.
// DECLARE_TEST("ldx")
DECLARE_TEST("ldxb-all")
DECLARE_TEST("ldxb")
DECLARE_TEST("ldxdw")
DECLARE_TEST("ldxh-all")
DECLARE_TEST("ldxh-all2")
DECLARE_TEST("ldxh-same-reg")
DECLARE_TEST("ldxh")
DECLARE_TEST("ldxw-all")
DECLARE_TEST("ldxw")
DECLARE_TEST("le16")
DECLARE_TEST("le32")
DECLARE_TEST("le64")
DECLARE_TEST("lsh-reg")
// bpf2c generated code doesn't pass length as r2.
// DECLARE_TEST("mem-len")
DECLARE_TEST("mod")
DECLARE_TEST("mod32")
DECLARE_TEST("mod64")
DECLARE_TEST("mod-by-zero-imm")
DECLARE_TEST("mod-by-zero-reg")
DECLARE_TEST("mod64-by-zero-imm")
DECLARE_TEST("mod64-by-zero-reg")
DECLARE_TEST("mov")
DECLARE_TEST("mul-loop")
DECLARE_TEST("mul32-imm")
DECLARE_TEST("mul32-reg-overflow")
DECLARE_TEST("mul32-reg")
DECLARE_TEST("mul64-imm")
DECLARE_TEST("mul64-reg")
DECLARE_TEST("neg")
DECLARE_TEST("neg64")
DECLARE_TEST("prime")
// Test doesn't support reload directive.
// DECLARE_TEST("reload")
DECLARE_TEST("rsh-reg")
DECLARE_TEST("rsh32")
// Test doesn't declare expected result.
// DECLARE_TEST("st")
DECLARE_TEST("stack")
DECLARE_TEST("stack2")
DECLARE_TEST("stb")
DECLARE_TEST("stdw")
DECLARE_TEST("sth")
DECLARE_TEST("string-stack")
DECLARE_TEST("stw")
// Test doesn't declare expected result.
// DECLARE_TEST("stx")
DECLARE_TEST("stxb-all")
DECLARE_TEST("stxb-all2")
DECLARE_TEST("stxb-chain")
DECLARE_TEST("stxb")
DECLARE_TEST("stxdw")
DECLARE_TEST("stxh")
DECLARE_TEST("stxw")
DECLARE_TEST("subnet")
// Test doesn't support unload directive.
// DECLARE_TEST("unload_reload")

void
verify_invalid_opcode_sequence(const std::vector<ebpf_inst>& instructions, const std::string& error)
{
    bpf_code_generator code("test", instructions);
    try {
        code.generate("test");
        FAIL("bpf_code_generator permitted invalid sequence");
    } catch (const std::runtime_error& ex) {
        REQUIRE(ex.what() == error);
    }
}

TEST_CASE("BE/LE", "[raw_bpf_code_gen][negative]")
{
    // EBPF_OP_LE/EBPF_OP_BE only supports imm == {16,32,64}
    verify_invalid_opcode_sequence({{EBPF_OP_LE, 0, 0, 0, 15}}, "invalid operand at offset 0");
    verify_invalid_opcode_sequence({{EBPF_OP_BE, 0, 0, 0, 15}}, "invalid operand at offset 0");
}

TEST_CASE("unknown EBPF_CLS_ALU operation", "[raw_bpf_code_gen][negative]")
{
    // EBPF_CLS_ALU + operations 0xe0 doesn't exist
    verify_invalid_opcode_sequence({{(EBPF_CLS_ALU | EBPF_SRC_IMM | 0xe0), 0, 0, 0, 0}}, "invalid operand at offset 0");
}

TEST_CASE("unknown EBPF_CLS_ALU64 operation", "[raw_bpf_code_gen][negative]")
{
    // EBPF_CLS_ALU64 + operations 0xe0 doesn't exist
    verify_invalid_opcode_sequence(
        {{(EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0xe0), 0, 0, 0, 0}}, "invalid operand at offset 0");
}

TEST_CASE("unknown EBPF_CLS_LD operation", "[raw_bpf_code_gen][negative]")
{
    // EBPF_CLS_LD is only valid with immediate and size _DW
    verify_invalid_opcode_sequence(
        {{(EBPF_CLS_LD | EBPF_MODE_MEM | EBPF_SIZE_DW), 0, 0, 0, 0}}, "invalid operand at offset 0");
    verify_invalid_opcode_sequence(
        {{(EBPF_CLS_LD | EBPF_MODE_IMM | EBPF_SIZE_W), 0, 0, 0, 0}}, "invalid operand at offset 0");
}

TEST_CASE("malformed EBPF_CLS_LD operation", "[raw_bpf_code_gen][negative]")
{
    // EBPF_CLS_LD is always 2 instructions wide
    verify_invalid_opcode_sequence(
        {{(EBPF_CLS_LD | EBPF_MODE_IMM | EBPF_SIZE_DW), 0, 0, 0, 0}}, "invalid operand at offset 0");
}

TEST_CASE("EBPF_CLS_JMP invalid target", "[raw_bpf_code_gen][negative]")
{
    // Offset > end of program
    verify_invalid_opcode_sequence({{EBPF_OP_JA, 0, 0, 1, 0}}, "invalid jump target at offset 0");
}

TEST_CASE("EBPF_CLS_JMP invalid operation", "[raw_bpf_code_gen][negative]")
{
    // 0xf0 is an invalid jump operation
    verify_invalid_opcode_sequence(
        {{(EBPF_CLS_JMP | 0xf0), 0, 0, 0, 0}, {EBPF_OP_EXIT, 0, 0, 0, 0}}, "invalid operand at offset 0");
}

TEST_CASE("invalid register", "[raw_bpf_code_gen][negative]")
{
    // 14 and 15 aren't valid registers.
    verify_invalid_opcode_sequence({{EBPF_OP_DIV_REG, 15, 14, 0, 0}}, "invalid register id");
}

TEST_CASE("invalid ELF stream", "[raw_bpf_code_gen][negative]")
{
    // An empty stream is not valid
    std::string str;
    std::stringstream stream(str);
    try {
        bpf_code_generator code(stream, "test");
        FAIL("bpf_code_generator failed to detect error");
    } catch (const std::runtime_error& ex) {
        REQUIRE(ex.what() == std::string("can't process ELF file test"));
    }
}
