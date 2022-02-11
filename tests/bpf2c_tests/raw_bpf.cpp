// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include "bpf_code_generator.h"
#include "catch_wrapper.hpp"

void
run_test(const std::string& data_file)
{
    enum
    {
        state_begin,
        state_assembly,
        state_raw,
        state_result,
        state_memory,
        state_done,
    } state = state_begin;
    std::string prefix = data_file.substr(data_file.find_last_of("\\") + 1);

    std::string temp_asm_name = std::string(prefix) + ".asm";

    std::ofstream data_out(temp_asm_name);
    std::ifstream data_in(data_file);

    std::string result;
    std::string mem;
    std::string line;
    while (std::getline(data_in, line)) {
        switch (state) {
        case state_begin:
            if (line == "-- asm")
                state = state_assembly;
            break;
        case state_assembly:
            if (line == "-- result") {
                state = state_result;
                continue;
            }
            if (line == "-- mem") {
                state = state_memory;
                continue;
            }
            if (line == "-- raw") {
                state = state_memory;
                continue;
            }
            if (line.find("#") != std::string::npos) {
                continue;
            }
            data_out << line << std::endl;
            break;
        case state_raw:
            if (line == "-- result") {
                state = state_result;
                continue;
            }
            break;
        case state_result:
            if (line == "-- mem") {
                state = state_memory;
                continue;
            }
            if (line.empty()) {
                continue;
            }
            result = line;
            break;
        case state_memory:
            mem = line;
            state = state_done;
            break;
        }
    }
    data_out.flush();
    data_out.close();

    if (result.find("0x") != std::string::npos) {
        result = result.substr(result.find("0x") + 2);
    }

    std::string assembler_command = std::string("python ..\\..\\external\\ubpf\\bin\\ubpf-assembler <") +
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

        bpf_code_generator code(program, "test");
        code.generate(c_file);
    } catch (std::runtime_error err) {
        REQUIRE(err.what() == NULL);
    }
    c_file.flush();
    c_file.close();

    std::string compile_command = std::string("cl /EHsc /nologo -I../../include  ") + std::string(prefix) +
                                  std::string(".c ") + std::string(" bpf_test.cpp >") + std::string(prefix) +
                                  std::string(".log");

    REQUIRE(system(compile_command.c_str()) == 0);
    std::string test_command =
        std::string(prefix) + std::string(".exe ") + std::string(result) + std::string(" ") + std::string(mem);

    REQUIRE(system(test_command.c_str()) == 0);
}

#define DECLARE_TEST(FILE) \
    TEST_CASE(FILE, "[raw_bpf_code_gen]") { run_test("..\\..\\external\\ubpf\\tests\\" FILE); }

DECLARE_TEST("add.data")
DECLARE_TEST("alu-arith.data")
DECLARE_TEST("alu-bit.data")
DECLARE_TEST("alu64-arith.data")
DECLARE_TEST("alu64-bit.data")
DECLARE_TEST("arsh-reg.data")
DECLARE_TEST("arsh.data")
DECLARE_TEST("arsh32-high-shift.data")
DECLARE_TEST("arsh64.data")
DECLARE_TEST("be16-high.data")
DECLARE_TEST("be16.data")
DECLARE_TEST("be32-high.data")
DECLARE_TEST("be32.data")
DECLARE_TEST("be64.data")
// FUTURE - register helper functions
// DECLARE_TEST("call-memfrob.data")
// DECLARE_TEST("call-save.data")
// DECLARE_TEST("call.data")
// DECLARE_TEST("call_unwind.data")
// DECLARE_TEST("call_unwind_fail.data")
DECLARE_TEST("div32-high-divisor.data")
DECLARE_TEST("div32-imm.data")
DECLARE_TEST("div32-reg.data")
DECLARE_TEST("div64-imm.data")
DECLARE_TEST("div64-reg.data")
DECLARE_TEST("early-exit.data")
DECLARE_TEST("exit-not-last.data")
DECLARE_TEST("exit.data")
DECLARE_TEST("ja.data")
DECLARE_TEST("jeq-imm.data")
DECLARE_TEST("jeq-reg.data")
DECLARE_TEST("jge-imm.data")
DECLARE_TEST("jgt-imm.data")
DECLARE_TEST("jgt-reg.data")
DECLARE_TEST("jit-bounce.data")
DECLARE_TEST("jle-imm.data")
DECLARE_TEST("jle-reg.data")
DECLARE_TEST("jlt-imm.data")
DECLARE_TEST("jlt-reg.data")
DECLARE_TEST("jne-reg.data")
DECLARE_TEST("jset-imm.data")
DECLARE_TEST("jset-reg.data")
DECLARE_TEST("jsge-imm.data")
DECLARE_TEST("jsge-reg.data")
DECLARE_TEST("jsgt-imm.data")
DECLARE_TEST("jsgt-reg.data")
DECLARE_TEST("jsle-imm.data")
DECLARE_TEST("jsle-reg.data")
DECLARE_TEST("jslt-imm.data")
DECLARE_TEST("jslt-reg.data")
DECLARE_TEST("lddw.data")
DECLARE_TEST("lddw2.data")
DECLARE_TEST("ldxb-all.data")
DECLARE_TEST("ldxb.data")
DECLARE_TEST("ldxdw.data")
DECLARE_TEST("ldxh-all.data")
DECLARE_TEST("ldxh-all2.data")
DECLARE_TEST("ldxh-same-reg.data")
DECLARE_TEST("ldxh.data")
DECLARE_TEST("ldxw-all.data")
DECLARE_TEST("ldxw.data")
DECLARE_TEST("le16.data")
DECLARE_TEST("le32.data")
DECLARE_TEST("le64.data")
DECLARE_TEST("lsh-reg.data")
DECLARE_TEST("mem-len.data")
DECLARE_TEST("mod.data")
DECLARE_TEST("mod32.data")
DECLARE_TEST("mod64.data")
DECLARE_TEST("mov.data")
DECLARE_TEST("mul-loop.data")
DECLARE_TEST("mul32-imm.data")
DECLARE_TEST("mul32-reg-overflow.data")
DECLARE_TEST("mul32-reg.data")
DECLARE_TEST("mul64-imm.data")
DECLARE_TEST("mul64-reg.data")
DECLARE_TEST("neg.data")
DECLARE_TEST("neg64.data")
DECLARE_TEST("prime.data")
DECLARE_TEST("reload.data")
DECLARE_TEST("rsh-reg.data")
DECLARE_TEST("rsh32.data")
DECLARE_TEST("stack.data")
DECLARE_TEST("stack2.data")
DECLARE_TEST("stb.data")
DECLARE_TEST("stdw.data")
DECLARE_TEST("sth.datav")
DECLARE_TEST("string-stack.data")
DECLARE_TEST("stw.data")
DECLARE_TEST("stxb-all.data")
DECLARE_TEST("stxb-all2.data")
DECLARE_TEST("stxb-chain.data")
DECLARE_TEST("stxb.data")
DECLARE_TEST("stxdw.data")
DECLARE_TEST("stxh.data")
DECLARE_TEST("stxw.data")
DECLARE_TEST("subnet.data")
