// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <set>
#include "elfio/elfio.hpp"
#include "ebpf.h"

struct output_instruction
{
    ebpf_inst instruction;
    bool jump_target;
    std::string label;
    std::string line;
    std::string relocation;
};

std::string reg[11] = {
    "r0",
    "r1",
    "r2",
    "r3",
    "r4",
    "r5",
    "r6",
    "r7",
    "r8",
    "r9",
    "r10",
};

std::string
immediate(uint32_t imm)
{
    return std::string("IMMEDIATE(") + std::to_string(imm) + std::string(")");
}

#define ALU_ADD 0x00
#define ALU_SUB 0x10
#define ALU_MUL 0x20
#define ALU_DIV 0x30
#define ALU_OR 0x40
#define ALU_AND 0x50
#define ALU_LSH 0x60
#define ALU_RSH 0x70
#define ALU_NEG 0x80
#define ALU_MOD 0x90
#define ALU_XOR 0xa0
#define ALU_MOV 0xb0
#define ALU_ARSH 0xc0
#define ALU_LE 0xd0
#define ALU_BE 0xd0

std::tuple<std::string, size_t> alu_format_string[] = {
    {"%s += %s;", 2},
    {"%s -= %s;", 2},
    {"%s *= %s;", 2},
    {"%s /= %s;", 2},
    {"%s |= %s;", 2},
    {"%s &= %s;", 2},
    {"%s <<= %s;", 2},
    {"%s <<= %s;", 2},
    {"%s = u32(%s) >> %s;", 3},
    {"%s = -(int64_t)%s;", 2},
    {"%s ^= %s;", 2},
    {"%s = %s;", 2},
    {"%s = (int32_t)%s >> %s;", 3},
    {"%s = swap(%s, %s);", 3},
};

std::string predicate_string[] = {
    "",                                 // JA
    "%s == %s",                         // JEQ
    "%s > %s",                          // JGT
    "%s >= %s",                         // JGE
    "%s & %s",                          // JSET
    "%s != %s",                         // JNE
    "(int64_t)%s > (int64_t)inst.imm",  // JSGT
    "(int64_t)%s >= (int64_t)inst.imm", // JSGE
    "",                                 // CALL
    "",                                 // exit
    "%s < %s",                          // JLT
    "%s <= %s",                         // JTE
    "(int64_t)%s > (int64_t)inst.imm",  // JSLT
    "(int64_t)%s >= (int64_t)inst.imm", // JSLE

};

std::string
format_string(
    const std::string& format,
    const std::string insert_1,
    const std::string insert_2 = "",
    const std::string insert_3 = "",
    const std::string insert_4 = "'")
{
    std::string output(120, '\0');
    if (insert_2.empty()) {
        auto count = snprintf(output.data(), output.size(), format.c_str(), insert_1.c_str());
    } else if (insert_3.empty()) {
        auto count = snprintf(output.data(), output.size(), format.c_str(), insert_1.c_str(), insert_2.c_str());
    }
    if (insert_4.empty()) {
        auto count = snprintf(
            output.data(), output.size(), format.c_str(), insert_1.c_str(), insert_2.c_str(), insert_3.c_str());
    } else {
        auto count = snprintf(
            output.data(),
            output.size(),
            format.c_str(),
            insert_1.c_str(),
            insert_2.c_str(),
            insert_3.c_str(),
            insert_4.c_str());
    }
    output.resize(strlen(output.c_str()));
    return output;
}

int
main(int argc, char** argv)
{
    ELFIO::elfio reader;
    const std::string path = argv[1];
    const std::string desired_section = argv[2];
    std::set<std::string> function_names;
    std::set<std::string> map_names;
    if (!reader.load(path)) {
        throw std::runtime_error(std::string("Can't process ELF file ") + path);
    }

    auto program_section = reader.sections[desired_section];
    std::vector<ebpf_inst> program{
        reinterpret_cast<const ebpf_inst*>(program_section->get_data()),
        reinterpret_cast<const ebpf_inst*>(program_section->get_data() + program_section->get_size())};

    std::vector<output_instruction> program_output;
    for (const auto& instruction : program) {
        program_output.push_back({instruction});
    }

    auto map_section = reader.sections["maps"];
    ELFIO::const_symbol_section_accessor symbols{reader, reader.sections[".symtab"]};

    auto relocations = reader.sections[std::string(".rel") + desired_section];
    if (!relocations)
        relocations = reader.sections[std::string(".rela") + desired_section];

    if (relocations) {
        ELFIO::const_relocation_section_accessor relocation_reader{reader, relocations};
        ELFIO::Elf_Xword relocation_count = relocation_reader.get_entries_num();
        for (ELFIO::Elf_Xword index = 0; index < relocation_count; index++) {
            ELFIO::Elf64_Addr offset{};
            ELFIO::Elf_Word symbol{};
            ELFIO::Elf_Word type{};
            ELFIO::Elf_Sxword addend{};
            relocation_reader.get_entry(index, offset, symbol, type, addend);
            {
                std::string name{};
                ELFIO::Elf64_Addr value{};
                ELFIO::Elf_Xword size{};
                unsigned char bind{};
                unsigned char type{};
                ELFIO::Elf_Half section_index{};
                unsigned char other{};
                if (!symbols.get_symbol(symbol, name, value, size, bind, type, section_index, other)) {
                    throw std::runtime_error(
                        std::string("Can't perform relocation at offset ") + std::to_string(offset));
                }
                program_output[offset / sizeof(ebpf_inst)].relocation = name;
                if (section_index == map_section->get_index()) {
                    map_names.insert(name);
                } else {
                    function_names.insert(name);
                }
            }
        }
    }

    // Tag jump targets
    for (size_t i = 0; i < program_output.size(); i++) {
        auto& output = program_output[i];
        if ((output.instruction.opcode & EBPF_CLS_MASK) != EBPF_CLS_JMP) {
            continue;
        }
        if (output.instruction.opcode == EBPF_OP_CALL) {
            continue;
        }
        if (output.instruction.opcode == EBPF_OP_EXIT) {
            continue;
        }
        program_output[i + output.instruction.offset + 1].jump_target = true;
    }
    // Add labels to instructions that are targets of jumps
    size_t label_index = 1;
    for (auto& output : program_output) {
        if (!output.jump_target) {
            continue;
        }
        output.label = std::string("label_") + std::to_string(label_index++);
    }

    // Encode instructions
    for (size_t i = 0; i < program_output.size(); i++) {
        auto& output = program_output[i];
        auto& inst = output.instruction;
        switch (inst.opcode & EBPF_CLS_MASK) {
        case EBPF_CLS_ALU:
        case EBPF_CLS_ALU64: {
            std::string destination = reg[inst.dst];
            // Special case for EBPF_OP_BE/EBPF_OP_LE
            if (inst.opcode == EBPF_OP_BE) {
                std::string swap_function;
                switch (inst.imm) {
                case 16:
                    swap_function = "htobe16";
                    break;
                case 32:
                    swap_function = "htobe32";
                    break;
                case 64:
                    swap_function = "htobe64";
                    break;
                }
                output.line = format_string("%s = %s(%s);", destination, swap_function, destination);
                continue;
            }

            std::string source;
            if (inst.opcode & EBPF_SRC_REG) {
                source = reg[inst.src];
            } else {
                source = std::string("IMMEDIATE(") + std::to_string(inst.imm) + std::string(")");
            }
            auto& [format, count] = alu_format_string[inst.opcode >> 4];
            if (count == 2)
                output.line = format_string(format, destination, source);
            else if (count == 3)
                output.line = format_string(format, destination, destination, source);
            if ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU)
                output.line += std::string("\n") + destination + std::string(" &= UINT32_MAX;\n");
        } break;
        case EBPF_CLS_LD: {
            i++;
            if (inst.opcode != EBPF_OP_LDDW) {
                throw std::runtime_error("invalid operand");
            }
            std::string destination = reg[inst.dst];
            if (output.relocation.empty()) {
                uint64_t imm = (uint64_t)inst.imm | (uint64_t)(program_output[i].instruction.imm) << 32;
                std::string source;
                source = std::string("IMMEDIATE(") + std::to_string(imm) + std::string(")");
                output.line = format_string("%s = %s;", destination, source);
            } else {
                output.line = format_string("%s = POINTER(%s);", destination, output.relocation);
            }
        } break;
        case EBPF_CLS_LDX: {
            std::string size_type;
            std::string destination = reg[inst.dst];
            std::string source = reg[inst.src];
            std::string offset = std::string("OFFSET(") + std::to_string(inst.offset) + ")";
            switch (inst.opcode & EBPF_SIZE_DW) {
            case EBPF_SIZE_B:
                size_type = std::string("uint8_t");
                break;
            case EBPF_SIZE_H:
                size_type = std::string("uint16_t");
                break;
            case EBPF_SIZE_W:
                size_type = std::string("uint32_t");
                break;
            case EBPF_SIZE_DW:
                size_type = std::string("uint64_t");
                break;
            }
            output.line = format_string("%s = *(%s *)(uintptr_t)(%s + %s);", destination, size_type, source, offset);
        } break;
        case EBPF_CLS_ST:
        case EBPF_CLS_STX: {
            std::string size_type;
            std::string destination = reg[inst.dst];
            std::string source;
            if ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ST) {
                source = std::string("IMMEDIATE(") + std::to_string(inst.imm) + std::string(")");
            } else {
                source = reg[inst.src];
            }
            std::string offset = std::string("OFFSET(") + std::to_string(inst.offset) + ")";
            switch (inst.opcode & EBPF_SIZE_DW) {
            case EBPF_SIZE_B:
                size_type = std::string("uint8_t");
                break;
            case EBPF_SIZE_H:
                size_type = std::string("uint16_t");
                break;
            case EBPF_SIZE_W:
                size_type = std::string("uint32_t");
                break;
            case EBPF_SIZE_DW:
                size_type = std::string("uint64_t");
                break;
            }
            output.line = format_string("*(%s *)(uintptr_t)(%s + %s) = %s;", size_type, destination, offset, source);
        } break;
        case EBPF_CLS_JMP: {
            std::string destination = reg[inst.dst];
            std::string source;
            if (inst.opcode & EBPF_SRC_REG) {
                source = reg[inst.src];
            } else {
                source = std::string("IMMEDIATE(") + std::to_string(inst.imm) + std::string(")");
            }
            auto& format = predicate_string[inst.opcode >> 4];
            if (inst.opcode == EBPF_OP_JA) {
                std::string target = program_output[i + inst.offset + 1].label;
                output.line = std::string("goto ") + target + std::string(";");
            } else if (inst.opcode == EBPF_OP_CALL) {
                output.line = reg[0] + std::string(" = ") + output.relocation;
                output.line += std::string("(") + reg[1] + std::string(", ");
                output.line += reg[2] + std::string(", ");
                output.line += reg[3] + std::string(", ");
                output.line += reg[4] + std::string(", ") + reg[5] + std::string(");");
            } else if (inst.opcode == EBPF_OP_EXIT) {
                output.line += std::string("return ") + reg[0] + std::string(";");
            } else {
                std::string target = program_output[i + inst.offset + 1].label;
                if (target.empty()) {
                    throw std::runtime_error("invalid jump target");
                }
                std::string predicate = format_string(format, destination, source);
                output.line = format_string("if (%s) goto %s;", predicate, target);
            }
        } break;
        }
    }
    std::cout << "// Do not alter this generated file." << std::endl;
    std::cout << "// This file was generated from " << path.c_str() << std::endl << std::endl;
    std::cout << "#include \"bpf2c.h\"" << std::endl << std::endl;
    std::cout << "// Relocations" << std::endl;
    for (const auto& name : map_names) {
        std::cout << "extern struct ebpf_map_t " << name.c_str() << ";" << std::endl;
    }
    for (const auto& name : function_names) {
        std::cout << "extern uint64_t " << name.c_str()
                  << "(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);" << std::endl;
    }
    std::cout << std::endl;
    std::cout << "uint64_t " << desired_section.c_str() << "(void* context)" << std::endl;
    std::cout << "{" << std::endl;
    std::cout << "\t//Prolog" << std::endl;
    std::cout << "\tuint64_t stack[(UBPF_STACK_SIZE + 7) / 8];" << std::endl;
    for (const auto& r : reg) {
        std::cout << "\tregister uint64_t " << r.c_str() << ";" << std::endl;
    }
    std::cout << std::endl;
    std::cout << "\t" << reg[1] << " = (uintptr_t)context;" << std::endl;
    std::cout << "\t" << reg[10] << " = (uintptr_t)((uint8_t*)stack + sizeof(stack));" << std::endl;
    std::cout << std::endl;
    // Emit final C code
    for (const auto& output : program_output) {
        if (output.line.empty()) {
            continue;
        }
        if (!output.label.empty())
            std::cout << output.label << ":" << std::endl;
        std::cout << "\t" << output.line << std::endl;
    }

    std::cout << "}" << std::endl;
}
