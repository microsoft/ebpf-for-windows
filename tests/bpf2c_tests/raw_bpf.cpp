// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include "bpf_code_generator.h"
#include "catch_wrapper.hpp"

#define SEPERATOR "/"
#define CC "g++"
#define CXXFLAG "-g -O2"
#define EXT ".out"
#define PYTHON "python3"

void
run_test(const std::string& data_file)
{
    enum class _state
    {
        state_ignore,
        state_assembly,
        state_raw,
        state_result,
        state_memory,
    } state = _state::state_ignore;
    std::string prefix = data_file.substr(data_file.find_last_of(SEPERATOR) + 1);

    std::string temp_asm_name = std::string(prefix) + ".asm";

    std::ofstream data_out(temp_asm_name);
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
    data_out.flush();
    data_out.close();

    if (result.find("0x") != std::string::npos) {
        result = result.substr(result.find("0x") + 2);
    }

    std::string assembler_command = std::string(PYTHON " .." SEPERATOR ".." SEPERATOR "external" SEPERATOR
                                                       "ubpf" SEPERATOR "bin" SEPERATOR "ubpf-assembler <") +
                                    std::string(temp_asm_name) + std::string(" >") + std::string(prefix) +
                                    std::string(".bc");
    REQUIRE(system(assembler_command.c_str()) == 0);

    std::ifstream bytcode_in(std::string(prefix) + std::string(".bc"), std::ios_base::in | std::ios_base::binary);
    std::vector<ebpf_inst> program;
    ebpf_inst instruction;
    while (bytcode_in.read(reinterpret_cast<char*>(&instruction), sizeof(instruction))) {
        program.push_back(instruction);
    }
    bytcode_in.close();

    std::ofstream c_file(std::string(prefix) + std::string(".c"));
    try {

        bpf_code_generator code("test", program);
        code.generate();
        code.emit_c_code(c_file);
    } catch (std::runtime_error& err) {
        REQUIRE(err.what() == NULL);
    }
    c_file.flush();
    c_file.close();

    std::string compile_command = std::string(CC " " CXXFLAG " -I.." SEPERATOR ".." SEPERATOR "include ") +
                                  std::string(prefix) + std::string(".c ") + std::string(" bpf_test.cpp >") +
                                  std::string(prefix) + std::string(".log -o ") + std::string(prefix) +
                                  std::string(EXT);
    REQUIRE(system(compile_command.c_str()) == 0);
    std::string test_command = std::string("." SEPERATOR) + std::string(prefix) + std::string(EXT) + std::string(" ") +
                               std::string(result) + std::string(" \"") + std::string(mem) + std::string("\"");
    REQUIRE(system(test_command.c_str()) == 0);
}

#define DECLARE_TEST(FILE)                                                                                     \
    TEST_CASE(FILE, "[raw_bpf_code_gen]")                                                                      \
    {                                                                                                          \
        run_test(".." SEPERATOR ".." SEPERATOR "external" SEPERATOR "ubpf" SEPERATOR "tests" SEPERATOR "" FILE \
                 ".data");                                                                                     \
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
DECLARE_TEST("early-exit")
// Malformed byte code tests - Verifier rejects prior to bpf2c.
// DECLARE_TEST("err-call-bad-imm")
// DECLARE_TEST("err-call-unreg")
// DECLARE_TEST("err-div-by-zero-imm")
// DECLARE_TEST("err-div-by-zero-reg")
// DECLARE_TEST("err-div64-by-zero-reg")
// DECLARE_TEST("err-endian-size")
// DECLARE_TEST("err-incomplete-lddw")
// DECLARE_TEST("err-incomplete-lddw2")
// DECLARE_TEST("err-infinite-loop")
// DECLARE_TEST("err-invalid-reg-dst")
// DECLARE_TEST("err-invalid-reg-src")
// DECLARE_TEST("err-jmp-lddw")
// DECLARE_TEST("err-jmp-out")
// DECLARE_TEST("err-mod-by-zero-reg")
// DECLARE_TEST("err-mod64-by-zero-reg")
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
