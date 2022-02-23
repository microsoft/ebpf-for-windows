// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <iostream>
#include <vector>

#include "bpf_code_generator.h"

#if !defined(_countof)
#define _countof(array) (sizeof(array) / sizeof(array[0]))
#endif

static const std::string _register_names[11] = {
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

enum class AluOperations
{
    Add,
    Sub,
    Mul,
    Div,
    Or,
    And,
    Lsh,
    Rsh,
    Neg,
    Mod,
    Xor,
    Mov,
    Ashr,
    ByteOrder,
};

static const std::string _predicate_format_string[] = {
    "",                           // JA
    "%s == %s",                   // JEQ
    "%s > %s",                    // JGT
    "%s >= %s",                   // JGE
    "%s & %s",                    // JSET
    "%s != %s",                   // JNE
    "(int64_t)%s > (int64_t)%s",  // JSGT
    "(int64_t)%s >= (int64_t)%s", // JSGE
    "",                           // CALL
    "",                           // EXIT
    "%s < %s",                    // JLT
    "%s <= %s",                   // JLE
    "(int64_t)%s < (int64_t)%s",  // JSLT
    "(int64_t)%s <= (int64_t)%s", // JSLE
};

#define ADD_OPCODE(X)                            \
    {                                            \
        static_cast<uint8_t>(X), std::string(#X) \
    }
static std::map<uint8_t, std::string> _opcode_name_strings = {
    ADD_OPCODE(EBPF_OP_ADD_IMM),    ADD_OPCODE(EBPF_OP_ADD_REG),   ADD_OPCODE(EBPF_OP_SUB_IMM),
    ADD_OPCODE(EBPF_OP_SUB_REG),    ADD_OPCODE(EBPF_OP_MUL_IMM),   ADD_OPCODE(EBPF_OP_MUL_REG),
    ADD_OPCODE(EBPF_OP_DIV_IMM),    ADD_OPCODE(EBPF_OP_DIV_REG),   ADD_OPCODE(EBPF_OP_OR_IMM),
    ADD_OPCODE(EBPF_OP_OR_REG),     ADD_OPCODE(EBPF_OP_AND_IMM),   ADD_OPCODE(EBPF_OP_AND_REG),
    ADD_OPCODE(EBPF_OP_LSH_IMM),    ADD_OPCODE(EBPF_OP_LSH_REG),   ADD_OPCODE(EBPF_OP_RSH_IMM),
    ADD_OPCODE(EBPF_OP_RSH_REG),    ADD_OPCODE(EBPF_OP_NEG),       ADD_OPCODE(EBPF_OP_MOD_IMM),
    ADD_OPCODE(EBPF_OP_MOD_REG),    ADD_OPCODE(EBPF_OP_XOR_IMM),   ADD_OPCODE(EBPF_OP_XOR_REG),
    ADD_OPCODE(EBPF_OP_MOV_IMM),    ADD_OPCODE(EBPF_OP_MOV_REG),   ADD_OPCODE(EBPF_OP_ARSH_IMM),
    ADD_OPCODE(EBPF_OP_ARSH_REG),   ADD_OPCODE(EBPF_OP_LE),        ADD_OPCODE(EBPF_OP_BE),
    ADD_OPCODE(EBPF_OP_ADD64_IMM),  ADD_OPCODE(EBPF_OP_ADD64_REG), ADD_OPCODE(EBPF_OP_SUB64_IMM),
    ADD_OPCODE(EBPF_OP_SUB64_REG),  ADD_OPCODE(EBPF_OP_MUL64_IMM), ADD_OPCODE(EBPF_OP_MUL64_REG),
    ADD_OPCODE(EBPF_OP_DIV64_IMM),  ADD_OPCODE(EBPF_OP_DIV64_REG), ADD_OPCODE(EBPF_OP_OR64_IMM),
    ADD_OPCODE(EBPF_OP_OR64_REG),   ADD_OPCODE(EBPF_OP_AND64_IMM), ADD_OPCODE(EBPF_OP_AND64_REG),
    ADD_OPCODE(EBPF_OP_LSH64_IMM),  ADD_OPCODE(EBPF_OP_LSH64_REG), ADD_OPCODE(EBPF_OP_RSH64_IMM),
    ADD_OPCODE(EBPF_OP_RSH64_REG),  ADD_OPCODE(EBPF_OP_NEG64),     ADD_OPCODE(EBPF_OP_MOD64_IMM),
    ADD_OPCODE(EBPF_OP_MOD64_REG),  ADD_OPCODE(EBPF_OP_XOR64_IMM), ADD_OPCODE(EBPF_OP_XOR64_REG),
    ADD_OPCODE(EBPF_OP_MOV64_IMM),  ADD_OPCODE(EBPF_OP_MOV64_REG), ADD_OPCODE(EBPF_OP_ARSH64_IMM),
    ADD_OPCODE(EBPF_OP_ARSH64_REG), ADD_OPCODE(EBPF_OP_LDXW),      ADD_OPCODE(EBPF_OP_LDXH),
    ADD_OPCODE(EBPF_OP_LDXB),       ADD_OPCODE(EBPF_OP_LDXDW),     ADD_OPCODE(EBPF_OP_STW),
    ADD_OPCODE(EBPF_OP_STH),        ADD_OPCODE(EBPF_OP_STB),       ADD_OPCODE(EBPF_OP_STDW),
    ADD_OPCODE(EBPF_OP_STXW),       ADD_OPCODE(EBPF_OP_STXH),      ADD_OPCODE(EBPF_OP_STXB),
    ADD_OPCODE(EBPF_OP_STXDW),      ADD_OPCODE(EBPF_OP_LDDW),      ADD_OPCODE(EBPF_OP_JA),
    ADD_OPCODE(EBPF_OP_JEQ_IMM),    ADD_OPCODE(EBPF_OP_JEQ_REG),   ADD_OPCODE(EBPF_OP_JGT_IMM),
    ADD_OPCODE(EBPF_OP_JGT_REG),    ADD_OPCODE(EBPF_OP_JGE_IMM),   ADD_OPCODE(EBPF_OP_JGE_REG),
    ADD_OPCODE(EBPF_OP_JSET_REG),   ADD_OPCODE(EBPF_OP_JSET_IMM),  ADD_OPCODE(EBPF_OP_JNE_IMM),
    ADD_OPCODE(EBPF_OP_JNE_REG),    ADD_OPCODE(EBPF_OP_JSGT_IMM),  ADD_OPCODE(EBPF_OP_JSGT_REG),
    ADD_OPCODE(EBPF_OP_JSGE_IMM),   ADD_OPCODE(EBPF_OP_JSGE_REG),  ADD_OPCODE(EBPF_OP_CALL),
    ADD_OPCODE(EBPF_OP_EXIT),       ADD_OPCODE(EBPF_OP_JLT_IMM),   ADD_OPCODE(EBPF_OP_JLT_REG),
    ADD_OPCODE(EBPF_OP_JLE_IMM),    ADD_OPCODE(EBPF_OP_JLE_REG),   ADD_OPCODE(EBPF_OP_JSLT_IMM),
    ADD_OPCODE(EBPF_OP_JSLT_REG),   ADD_OPCODE(EBPF_OP_JSLE_IMM),  ADD_OPCODE(EBPF_OP_JSLE_REG),
};

std::string
bpf_code_generator::get_register_name(uint8_t id)
{
    if (id >= _countof(_register_names)) {
        throw std::runtime_error("Invalid register id");
    } else {
        current_section->referenced_registers.insert(_register_names[id]);
        return _register_names[id];
    }
}

bpf_code_generator::bpf_code_generator(const std::string& path, const std::string& c_name)
    : current_section(nullptr), c_name(c_name), path(path)
{
    if (!reader.load(path)) {
        throw std::runtime_error(std::string("Can't process ELF file ") + path);
    }

    extract_btf_information();
}

bpf_code_generator::bpf_code_generator(const std::string& c_name, const std::vector<ebpf_inst>& instructions)
    : c_name(c_name)
{
    current_section = &sections[c_name];
    get_register_name(0);
    get_register_name(1);
    get_register_name(10);
    uint32_t offset = 0;
    for (const auto& instruction : instructions) {
        current_section->output.push_back({instruction, offset++});
    }
}

std::vector<std::string>
bpf_code_generator::program_sections()
{
    std::vector<std::string> section_names;
    for (const auto& section : reader.sections) {
        std::string name = section->get_name();
        if (name.empty() || name[0] == '.')
            continue;
        if ((section->get_type() == 1) && (section->get_flags() == 6)) {
            section_names.push_back(section->get_name());
        }
    }
    return section_names;
}

void
bpf_code_generator::parse(const std::string& section_name)
{
    current_section = &sections[section_name];
    get_register_name(0);
    get_register_name(1);
    get_register_name(10);

    extract_program(section_name);
    extract_relocations_and_maps(section_name);
}

void
bpf_code_generator::generate()
{
    generate_labels();
    build_function_table();
    encode_instructions();
}

void
bpf_code_generator::extract_program(const std::string& section_name)
{
    auto program_section = reader.sections[section_name];
    std::vector<ebpf_inst> program{
        reinterpret_cast<const ebpf_inst*>(program_section->get_data()),
        reinterpret_cast<const ebpf_inst*>(program_section->get_data() + program_section->get_size())};

    ELFIO::const_symbol_section_accessor symbols{reader, reader.sections[".symtab"]};
    for (ELFIO::Elf_Xword index = 0; index < symbols.get_symbols_num(); index++) {
        std::string name{};
        ELFIO::Elf64_Addr value{};
        ELFIO::Elf_Xword size{};
        unsigned char bind{};
        unsigned char symbol_type{};
        ELFIO::Elf_Half section_index{};
        unsigned char other{};
        symbols.get_symbol(index, name, value, size, bind, symbol_type, section_index, other);
        if (name.empty()) {
            continue;
        }
        if (section_index == program_section->get_index() && value == 0) {
            current_section->function_name = name;
            break;
        }
    }

    uint32_t offset = 0;
    for (const auto& instruction : program) {
        current_section->output.push_back({instruction, offset++});
    }
}

void
bpf_code_generator::extract_relocations_and_maps(const std::string& section_name)
{
    auto map_section = reader.sections["maps"];
    ELFIO::const_symbol_section_accessor symbols{reader, reader.sections[".symtab"]};

    auto relocations = reader.sections[std::string(".rel") + section_name];
    if (!relocations)
        relocations = reader.sections[std::string(".rela") + section_name];

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
                unsigned char symbol_type{};
                ELFIO::Elf_Half section_index{};
                unsigned char other{};
                if (!symbols.get_symbol(symbol, name, value, size, bind, symbol_type, section_index, other)) {
                    throw std::runtime_error(
                        std::string("Can't perform relocation at offset ") + std::to_string(offset));
                }
                current_section->output[offset / sizeof(ebpf_inst)].relocation = name;
                if (map_section && section_index == map_section->get_index()) {
                    if (size != sizeof(ebpf_map_definition_in_file_t)) {
                        throw std::runtime_error("invalid map size");
                    }
                    map_definitions[name].definition =
                        *reinterpret_cast<const ebpf_map_definition_in_file_t*>(map_section->get_data() + value);
                }
            }
        }
    }

    // Assign index to each map
    size_t map_index = 0;
    for (auto& map : map_definitions) {
        map.second.index = map_index++;
    }
}

void
bpf_code_generator::extract_btf_information()
{
    auto btf = reader.sections[".BTF"];
    auto btf_ext = reader.sections[".BTF.ext"];

    if (btf == nullptr) {
        return;
    }

    if (btf_ext == nullptr) {
        return;
    }
    std::vector<uint8_t> btf_data(
        reinterpret_cast<const uint8_t*>(btf->get_data()),
        reinterpret_cast<const uint8_t*>(btf->get_data()) + btf->get_size());
    std::vector<uint8_t> btf_ext_data(
        reinterpret_cast<const uint8_t*>(btf_ext->get_data()),
        reinterpret_cast<const uint8_t*>(btf_ext->get_data()) + btf_ext->get_size());
    section_line_info = btf_parse_line_information(btf_data, btf_ext_data);
}

void
bpf_code_generator::generate_labels()
{
    std::vector<output_instruction_t>& program_output = current_section->output;

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
}

void
bpf_code_generator::build_function_table()
{
    std::vector<output_instruction_t>& program_output = current_section->output;

    // Gather helper_functions
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

        if (helper_functions.find(name) == helper_functions.end()) {
            helper_functions[name] = {output.instruction.imm, index++};
        }
    }
}

void
bpf_code_generator::encode_instructions()
{
    std::vector<output_instruction_t>& program_output = current_section->output;

    // Encode instructions
    for (size_t i = 0; i < program_output.size(); i++) {
        auto& output = program_output[i];
        auto& inst = output.instruction;

        switch (inst.opcode & EBPF_CLS_MASK) {
        case EBPF_CLS_ALU:
        case EBPF_CLS_ALU64: {
            std::string destination = get_register_name(inst.dst);
            std::string source;
            if (inst.opcode & EBPF_SRC_REG)
                source = get_register_name(inst.src);
            else
                source = std::string("IMMEDIATE(") + std::to_string(inst.imm) + std::string(")");
            bool is64bit = (inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU64;
            AluOperations operation = static_cast<AluOperations>(inst.opcode >> 4);
            std::string check_div_by_zero =
                format_string("if (%s == 0) { division_by_zero(%s); return 0; }", source, std::to_string(i));
            std::string swap_function;
            switch (operation) {
            case AluOperations::Add:
                output.lines.push_back(format_string("%s += %s;", destination, source));
                break;
            case AluOperations::Sub:
                output.lines.push_back(format_string("%s -= %s;", destination, source));
                break;
            case AluOperations::Mul:
                output.lines.push_back(format_string("%s *= %s;", destination, source));
                break;
            case AluOperations::Div:
                output.lines.push_back(check_div_by_zero);
                if (is64bit)
                    output.lines.push_back(format_string("%s /= %s;", destination, source));
                else
                    output.lines.push_back(
                        format_string("%s = (uint32_t)%s / (uint32_t)%s;", destination, destination, source));
                break;
            case AluOperations::Or:
                output.lines.push_back(format_string("%s |= %s;", destination, source));
                break;
            case AluOperations::And:
                output.lines.push_back(format_string("%s &= %s;", destination, source));
                break;
            case AluOperations::Lsh:
                output.lines.push_back(format_string("%s <<= %s;", destination, source));
                break;
            case AluOperations::Rsh:
                if (is64bit)
                    output.lines.push_back(format_string("%s >>= %s;", destination, source));
                else
                    output.lines.push_back(format_string("%s = (uint32_t)%s >> %s;", destination, destination, source));
                break;
            case AluOperations::Neg:
                if (is64bit)
                    output.lines.push_back(format_string("%s = -%s;", destination, destination));
                else
                    output.lines.push_back(format_string("%s = -(int64_t)%s;", destination, destination));
                break;
            case AluOperations::Mod:
                output.lines.push_back(check_div_by_zero);
                if (is64bit)
                    output.lines.push_back(format_string("%s %%= %s;", destination, source));
                else
                    output.lines.push_back(
                        format_string("%s = (uint32_t)%s %% (uint32_t)%s;", destination, destination, source));
                break;
            case AluOperations::Xor:
                output.lines.push_back(format_string("%s ^= %s;", destination, source));
                break;
            case AluOperations::Mov:
                output.lines.push_back(format_string("%s = %s;", destination, source));
                break;
            case AluOperations::Ashr:
                if (is64bit)
                    output.lines.push_back(
                        format_string("%s = (int64_t)%s >> (uint32_t)%s;", destination, destination, source));
                else
                    output.lines.push_back(format_string("%s = (int32_t)%s >> %s;", destination, destination, source));
                break;
            case AluOperations::ByteOrder: {
                std::string size_type = "";
                if (output.instruction.opcode & EBPF_SRC_REG) {
                    switch (inst.imm) {
                    case 16:
                        swap_function = "htobe16";
                        size_type = "uint16_t";
                        break;
                    case 32:
                        swap_function = "htobe32";
                        size_type = "uint32_t";
                        break;
                    case 64:
                        is64bit = true;
                        size_type = "uint64_t";
                        swap_function = "htobe64";
                        break;
                    default:
                        throw std::runtime_error("invalid operand");
                    }
                } else {
                    switch (inst.imm) {
                    case 16:
                        swap_function = "htole16";
                        size_type = "uint16_t";
                        break;
                    case 32:
                        swap_function = "htole32";
                        size_type = "uint32_t";
                        break;
                    case 64:
                        is64bit = true;
                        swap_function = "htole64";
                        size_type = "uint64_t";
                        break;
                    default:
                        throw std::runtime_error("invalid operand");
                    }
                }
                output.lines.push_back(
                    format_string("%s = %s((%s)%s);", destination, swap_function, size_type, destination));
            } break;
            default:
                throw std::runtime_error("invalid operand");
            }
            if (!is64bit)
                output.lines.push_back(format_string("%s &= UINT32_MAX;", destination));

        } break;
        case EBPF_CLS_LD: {
            i++;
            if (inst.opcode != EBPF_OP_LDDW) {
                throw std::runtime_error("invalid operand");
            }
            std::string destination = get_register_name(inst.dst);
            if (output.relocation.empty()) {
                uint64_t imm = static_cast<uint32_t>(program_output[i].instruction.imm);
                imm <<= 32;
                imm |= static_cast<uint32_t>(output.instruction.imm);
                std::string source;
                source = std::string("(uint64_t)") + std::to_string(imm);
                output.lines.push_back(format_string("%s = %s;", destination, source));
            } else {
                std::string source;
                source = format_string("_maps[%s].address", std::to_string(map_definitions[output.relocation].index));
                output.lines.push_back(format_string("%s = POINTER(%s);", destination, source));
            }
        } break;
        case EBPF_CLS_LDX: {
            std::string size_type;
            std::string destination = get_register_name(inst.dst);
            std::string source = get_register_name(inst.src);
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
            output.lines.push_back(
                format_string("%s = *(%s *)(uintptr_t)(%s + %s);", destination, size_type, source, offset));
        } break;
        case EBPF_CLS_ST:
        case EBPF_CLS_STX: {
            std::string size_type;
            std::string destination = get_register_name(inst.dst);
            std::string source;
            if ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ST) {
                source = std::string("IMMEDIATE(") + std::to_string(inst.imm) + std::string(")");
            } else {
                source = get_register_name(inst.src);
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
            source = std::string("(") + size_type + std::string(")") + source;
            output.lines.push_back(
                format_string("*(%s *)(uintptr_t)(%s + %s) = %s;", size_type, destination, offset, source));
        } break;
        case EBPF_CLS_JMP: {
            std::string destination = get_register_name(inst.dst);
            std::string source;
            if (inst.opcode & EBPF_SRC_REG) {
                source = get_register_name(inst.src);
            } else {
                source = std::string("IMMEDIATE(") + std::to_string(inst.imm) + std::string(")");
            }
            auto& format = _predicate_format_string[inst.opcode >> 4];
            if (inst.opcode == EBPF_OP_JA) {
                std::string target = program_output[i + inst.offset + 1].label;
                output.lines.push_back(std::string("goto ") + target + std::string(";"));
            } else if (inst.opcode == EBPF_OP_CALL) {
                std::string function_name;
                if (output.relocation.empty()) {
                    function_name = format_string(
                        "_helpers[%s]",
                        std::to_string(
                            helper_functions[std::string("helper_id_") + std::to_string(output.instruction.imm)]
                                .index));
                } else {
                    function_name =
                        format_string("_helpers[%s]", std::to_string(helper_functions[output.relocation].index));
                }
                output.lines.push_back(
                    get_register_name(0) + std::string(" = ") + function_name + std::string(".address"));
                output.lines.push_back(
                    std::string("(") + get_register_name(1) + std::string(", ") + get_register_name(2) +
                    std::string(", ") + get_register_name(3) + std::string(", ") + get_register_name(4) +
                    std::string(", ") + get_register_name(5) + std::string(");"));
                output.lines.push_back(
                    format_string("if ((%s.tail_call) && (%s == 0)) return 0;", function_name, get_register_name(0)));
            } else if (inst.opcode == EBPF_OP_EXIT) {
                output.lines.push_back(std::string("return ") + get_register_name(0) + std::string(";"));
            } else {
                std::string target = program_output[i + inst.offset + 1].label;
                if (target.empty()) {
                    throw std::runtime_error("invalid jump target");
                }
                std::string predicate = format_string(format, destination, source);
                output.lines.push_back(format_string("if (%s) goto %s;", predicate, target));
            }
        } break;
        default:
            throw std::runtime_error("invalid operand");
        }
    }
}

void
bpf_code_generator::emit_c_code(std::ostream& output_stream)
{
    // Emit C file
    output_stream << "// Do not alter this generated file." << std::endl;
    output_stream << "// This file was generated from " << path.c_str() << std::endl << std::endl;
    output_stream << "#include \"bpf2c.h\"" << std::endl << std::endl;

    // Emit import tables
    if (map_definitions.size() > 0) {
        output_stream << "static map_entry_t _maps[] = {" << std::endl;
        for (const auto& map : map_definitions) {
            output_stream << "{ NULL, { ";
            output_stream << map.second.definition.size << ", ";
            output_stream << map.second.definition.type << ", ";
            output_stream << map.second.definition.key_size << ", ";
            output_stream << map.second.definition.value_size << ", ";
            output_stream << map.second.definition.max_entries << ", ";
            output_stream << " }, \"" << map.first.c_str() << "\" }," << std::endl;
        }
        output_stream << "};" << std::endl;
        output_stream << std::endl;
        output_stream << "static void _get_maps(map_entry_t** maps, size_t* count)" << std::endl;
        output_stream << "{" << std::endl;
        output_stream << "\t*maps = _maps;" << std::endl;
        output_stream << "\t*count = " << std::to_string(map_definitions.size()) << ";" << std::endl;
        output_stream << "}" << std::endl;
        output_stream << std::endl;
    } else {
        output_stream << "static void _get_maps(map_entry_t** maps, size_t* count)" << std::endl;
        output_stream << "{" << std::endl;
        output_stream << "\t*maps = NULL;" << std::endl;
        output_stream << "\t*count = 0;" << std::endl;
        output_stream << "}" << std::endl;
        output_stream << std::endl;
    }

    if (helper_functions.size() > 0) {
        output_stream << "static helper_function_entry_t _helpers[] = {" << std::endl;

        // Functions are emitted in the order in which they occur in the byte code.
        std::vector<std::tuple<std::string, uint32_t>> index_ordered_helpers;
        index_ordered_helpers.resize(helper_functions.size());
        for (const auto& function : helper_functions) {
            index_ordered_helpers[function.second.index] = std::make_tuple(function.first, function.second.id);
        }

        for (const auto& [name, id] : index_ordered_helpers) {
            output_stream << "{ NULL, " << id << ", \"" << name.c_str() << "\"}," << std::endl;
        }

        output_stream << "};" << std::endl;
        output_stream << std::endl;
        output_stream << "static void _get_helpers(helper_function_entry_t** helpers, size_t* count)" << std::endl;
        output_stream << "{" << std::endl;
        output_stream << "\t*helpers = _helpers;" << std::endl;
        output_stream << "\t*count = " << std::to_string(helper_functions.size()) << ";" << std::endl;
        output_stream << "}" << std::endl;
        output_stream << std::endl;
    } else {
        output_stream << "static void _get_helpers(helper_function_entry_t** helpers, size_t* count)" << std::endl;
        output_stream << "{" << std::endl;
        output_stream << "\t*helpers = NULL;" << std::endl;
        output_stream << "\t*count = 0;" << std::endl;
        output_stream << "}" << std::endl;
        output_stream << std::endl;
    }

    for (auto& [name, section] : sections) {
        auto function_name = !section.function_name.empty() ? section.function_name : name;
        // Emit entry point
        output_stream << format_string("static uint64_t %s(void* context)", sanitize_name(function_name)) << std::endl;
        output_stream << "{" << std::endl;

        // Emit prologue
        output_stream << "\t// Prologue" << std::endl;
        output_stream << "\tuint64_t stack[(UBPF_STACK_SIZE + 7) / 8];" << std::endl;
        for (const auto& r : _register_names) {
            // Skip unused registers
            if (section.referenced_registers.find(r) == section.referenced_registers.end()) {
                continue;
            }
            output_stream << "\tregister uint64_t " << r.c_str() << " = 0;" << std::endl;
        }
        output_stream << std::endl;
        output_stream << "\t" << get_register_name(1) << " = (uintptr_t)context;" << std::endl;
        output_stream << "\t" << get_register_name(10) << " = (uintptr_t)((uint8_t*)stack + sizeof(stack));"
                      << std::endl;
        output_stream << std::endl;

        std::string source_file = "";
        uint32_t source_line = 0;
        // Emit encode intructions
        for (const auto& output : section.output) {
            auto& line_info = section_line_info[name];
            if (output.lines.empty()) {
                continue;
            }
            if (!output.label.empty())
                output_stream << output.label << ":" << std::endl;
            auto current_line = line_info.find(output.instruction_offset);
            if (current_line != line_info.end()) {
                source_line = current_line->second.line_number;
                source_file = current_line->second.file_name;
            }
#if defined(_DEBUG)
            output_stream << "\t// " << _opcode_name_strings[output.instruction.opcode]
                          << " pc=" << output.instruction_offset << " dst=" << get_register_name(output.instruction.dst)
                          << " src=" << get_register_name(output.instruction.src)
                          << " offset=" << std::to_string(output.instruction.offset)
                          << " imm=" << std::to_string(output.instruction.imm) << std::endl;
#endif
            for (const auto& line : output.lines) {
                if (!source_file.empty()) {
                    output_stream << "#line " << source_line << " \"" << escape_string(source_file.c_str()) << "\""
                                  << std::endl;
                }
                output_stream << "\t" << line << std::endl;
            }
        }
        output_stream << "#line __LINE__ __FILE__" << std::endl;
        // Emit epilogue
        output_stream << "}" << std::endl << std::endl;
    }

    output_stream << "static program_entry_t _programs[] = {" << std::endl;
    for (auto& [name, program] : sections) {
        auto function_name = !program.function_name.empty() ? program.function_name : name;
        output_stream << "\t{ " << sanitize_name(function_name) << ", "
                      << "\"" << name.c_str() << "\", "
                      << "\"" << program.function_name.c_str() << "\", " << program.output.size() << "}," << std::endl;
    }
    output_stream << "};" << std::endl;
    output_stream << std::endl;
    output_stream << "static void _get_programs(program_entry_t** programs, size_t* count)" << std::endl;
    output_stream << "{" << std::endl;
    output_stream << "\t*programs = _programs;" << std::endl;
    output_stream << "\t*count = " << std::to_string(sections.size()) << ";" << std::endl;
    output_stream << "}" << std::endl;
    output_stream << std::endl;

    output_stream << std::endl;
    output_stream << format_string(
        "metadata_table_t %s = { _get_programs, _get_maps, _get_helpers };\n",
        c_name.c_str() + std::string("_metadata_table"));
}

std::string
bpf_code_generator::format_string(
    const std::string& format,
    const std::string insert_1,
    const std::string insert_2,
    const std::string insert_3,
    const std::string insert_4)
{
    std::string output(120, '\0');
    if (insert_2.empty()) {
        auto count = snprintf(output.data(), output.size(), format.c_str(), insert_1.c_str());
        if (count < 0)
            throw std::runtime_error("Error formatting string");
    } else if (insert_3.empty()) {
        auto count = snprintf(output.data(), output.size(), format.c_str(), insert_1.c_str(), insert_2.c_str());
        if (count < 0)
            throw std::runtime_error("Error formatting string");
    }
    if (insert_4.empty()) {
        auto count = snprintf(
            output.data(), output.size(), format.c_str(), insert_1.c_str(), insert_2.c_str(), insert_3.c_str());
        if (count < 0)
            throw std::runtime_error("Error formatting string");
    } else {
        auto count = snprintf(
            output.data(),
            output.size(),
            format.c_str(),
            insert_1.c_str(),
            insert_2.c_str(),
            insert_3.c_str(),
            insert_4.c_str());
        if (count < 0)
            throw std::runtime_error("Error formatting string");
    }
    output.resize(strlen(output.c_str()));
    return output;
}

std::string
bpf_code_generator::sanitize_name(const std::string& name)
{
    std::string safe_name = name;
    for (auto& c : safe_name) {
        if (!isalnum(c)) {
            c = '_';
        }
    }
    return safe_name;
}

std::string
bpf_code_generator::escape_string(const std::string& input)
{
    std::string output;
    for (const auto& c : input) {
        if (c != '\\') {
            output += c;
        } else {
            output += "\\\\";
        }
    }
    return output;
}
