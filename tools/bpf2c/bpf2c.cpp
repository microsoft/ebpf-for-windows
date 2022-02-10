// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <set>
#include "elfio/elfio.hpp"
#include "ebpf.h"
#include "ebpf_structs.h"

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

typedef struct _helper_function
{
    int32_t id;
    size_t index;
} helper_function_t;

typedef struct _map_entry
{
    const ebpf_map_definition_in_file_t* definition;
    size_t index;
} map_entry_t;

int
main(int argc, char** argv)
{
    try {

        ELFIO::elfio reader;
        if (argc != 3) {
            std::cerr << "Usage: " << argv[0] << " ELF section" << std::endl;
            return 1;
        }
        const std::string path = argv[1];
        const std::string desired_section = argv[2];
        std::map<std::string, helper_function_t> functions;
        std::map<std::string, map_entry_t> map_definitions;

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
                    if (map_section && section_index == map_section->get_index()) {
                        if (size != sizeof(ebpf_map_definition_in_file_t)) {
                            throw std::runtime_error("invalid map size");
                        }
                        map_definitions[name].definition =
                            reinterpret_cast<const ebpf_map_definition_in_file_t*>(map_section->get_data() + value);
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

        // Assign index to each map
        size_t map_index = 0;
        for (auto& map : map_definitions) {
            map.second.index = map_index++;
        }

        // Gather functions
        size_t index = 0;
        for (auto& output : program_output) {
            if (output.instruction.opcode != EBPF_OP_CALL) {
                continue;
            }
            std::string name;
            if (!output.relocation.empty()) {
                name = output.relocation;
            } else {
                name = "helper_id_";
                name += std::to_string(output.instruction.imm);
            }

            if (functions.find(name) == functions.end()) {
                functions[name] = {output.instruction.imm, index++};
            }
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
                    std::string source;
                    source = format_string(
                        "%s_maps[%s].address",
                        desired_section,
                        std::to_string(map_definitions[output.relocation].index));
                    output.line = format_string("%s = POINTER(%s);", destination, source);
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
                output.line =
                    format_string("%s = *(%s *)(uintptr_t)(%s + %s);", destination, size_type, source, offset);
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
                output.line =
                    format_string("*(%s *)(uintptr_t)(%s + %s) = %s;", size_type, destination, offset, source);
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
                    std::string function_name;
                    if (output.relocation.empty()) {
                        function_name = format_string(
                            "%s_helpers[%s]",
                            desired_section,
                            std::to_string(
                                functions[std::string("helper_id_") + std::to_string(output.instruction.imm)].index));
                    } else {
                        function_name = format_string(
                            "%s_helpers[%s]", desired_section, std::to_string(functions[output.relocation].index));
                    }
                    output.line = reg[0] + std::string(" = ") + function_name + std::string(".address");
                    output.line += std::string("(") + reg[1] + std::string(", ");
                    output.line += reg[2] + std::string(", ");
                    output.line += reg[3] + std::string(", ");
                    output.line += reg[4] + std::string(", ") + reg[5] + std::string(");\n");
                    output.line += format_string("\tif ((%s.tail_call) && (%s == 0)) return;", function_name, reg[0]);
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

        // Emit C file
        std::cout << "// Do not alter this generated file." << std::endl;
        std::cout << "// This file was generated from " << path.c_str() << std::endl << std::endl;
        std::cout << "#include \"bpf2c.h\"" << std::endl << std::endl;

        // Emit import tables
        std::cout << "static map_entry_t " << desired_section.c_str() << "_maps[] = {" << std::endl;
        for (const auto& map : map_definitions) {
            std::cout << "{ NULL, { ";
            std::cout << map.second.definition->size << ", ";
            std::cout << map.second.definition->type << ", ";
            std::cout << map.second.definition->key_size << ", ";
            std::cout << map.second.definition->value_size << ", ";
            std::cout << map.second.definition->max_entries << ", ";
            std::cout << " }, \"" << map.first.c_str() << "\" }," << std::endl;
        }
        std::cout << "};" << std::endl;
        std::cout << std::endl;
        std::cout << "static helper_function_entry_t " << desired_section.c_str() << "_helpers[] = {" << std::endl;
        for (const auto& function : functions) {
            std::cout << "{ NULL, " << function.second.id << ", \"" << function.first << "\"}," << std::endl;
        }
        std::cout << "};" << std::endl;
        std::cout << std::endl;

        // Emit import table accessor functions
        std::cout << "void get_" << desired_section.c_str() << "_maps(map_entry_t** maps, size_t* count)" << std::endl;
        std::cout << "{" << std::endl;
        std::cout << "\t*maps = " << desired_section.c_str() << "_maps;" << std::endl;
        std::cout << "\t*count = " << std::to_string(map_definitions.size()) << ";" << std::endl;
        std::cout << "}" << std::endl;
        std::cout << std::endl;
        std::cout << "void get_" << desired_section.c_str()
                  << "_helpers(helper_function_entry_t** helpers, size_t* count)" << std::endl;
        std::cout << "{" << std::endl;
        std::cout << "\t*helpers = " << desired_section.c_str() << "_helpers;" << std::endl;
        std::cout << "\t*count = " << std::to_string(functions.size()) << ";" << std::endl;
        std::cout << "}" << std::endl;
        std::cout << std::endl;

        // Emit entry point
        std::cout << "uint64_t " << desired_section.c_str() << "(void* context)" << std::endl;
        std::cout << "{" << std::endl;

        // Emit prolog
        std::cout << "\t//Prolog" << std::endl;
        std::cout << "\tuint64_t stack[(UBPF_STACK_SIZE + 7) / 8];" << std::endl;
        for (const auto& r : reg) {
            std::cout << "\tregister uint64_t " << r.c_str() << ";" << std::endl;
        }
        std::cout << std::endl;
        std::cout << "\t" << reg[1] << " = (uintptr_t)context;" << std::endl;
        std::cout << "\t" << reg[10] << " = (uintptr_t)((uint8_t*)stack + sizeof(stack));" << std::endl;
        std::cout << std::endl;

        // Emit encode intructions
        for (const auto& output : program_output) {
            if (output.line.empty()) {
                continue;
            }
            if (!output.label.empty())
                std::cout << output.label << ":" << std::endl;
            std::cout << "\t" << output.line << std::endl;
        }

        // Emit epilog
        std::cout << "}" << std::endl;
    } catch (std::runtime_error err) {
        std::cerr << err.what() << std::endl;
        return 1;
    }
    return 0;
}
