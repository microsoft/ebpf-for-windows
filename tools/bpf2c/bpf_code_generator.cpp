// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Whenever bpf code generate output changes, bpf2c_tests will fail unless the
// expected files in tests\bpf2c_tests\expected are updated. The following
// script can be used to regenerate the expected files:
//     generate_expected_bpf2c_output.ps1
//
// Usage:
// .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>
// Example:
// .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\

#include "bpf_code_generator.h"
#include "btf_parser.h"
#include "ebpf_version.h"

#include <windows.h>
#include <cassert>
#include <format>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>
#undef max

#if !defined(_countof)
#define _countof(array) (sizeof(array) / sizeof(array[0]))
#endif

#define INDENT "    "
#define LINE_BREAK_WIDTH 120

#define EBPF_MODE_MASK 0xe0
#define EBPF_MODE_ATOMIC 0xc0
#define EBPF_MODE_MEM 0x60

#define EBPF_ATOMIC_FETCH 0x01
#define EBPF_ATOMIC_ADD 0x00
#define EBPF_ATOMIC_ADD_FETCH (0x00 | EBPF_ATOMIC_FETCH)
#define EBPF_ATOMIC_OR 0x40
#define EBPF_ATOMIC_OR_FETCH (0x40 | EBPF_ATOMIC_FETCH)
#define EBPF_ATOMIC_AND 0x50
#define EBPF_ATOMIC_AND_FETCH (0x50 | EBPF_ATOMIC_FETCH)
#define EBPF_ATOMIC_XOR 0xa0
#define EBPF_ATOMIC_XOR_FETCH (0xa0 | EBPF_ATOMIC_FETCH)
#define EBPF_ATOMIC_XCHG (0xe0 | EBPF_ATOMIC_FETCH)
#define EBPF_ATOMIC_CMPXCHG (0xf0 | EBPF_ATOMIC_FETCH)

#define EBPF_OP_ATOMIC64 (EBPF_CLS_STX | EBPF_MODE_ATOMIC | EBPF_SIZE_DW)
#define EBPF_OP_ATOMIC (EBPF_CLS_STX | EBPF_MODE_ATOMIC | EBPF_SIZE_W)
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
    "",             // JA
    "{}{} == {}{}", // JEQ
    "{}{} > {}{}",  // JGT
    "{}{} >= {}{}", // JGE
    "{}{} & {}{}",  // JSET
    "{}{} != {}{}", // JNE
    "{}{} > {}{}",  // JSGT
    "{}{} >= {}{}", // JSGE
    "",             // CALL
    "",             // EXIT
    "{}{} < {}{}",  // JLT
    "{}{} <= {}{}", // JLE
    "{}{} < {}{}",  // JSLT
    "{}{} <= {}{}", // JSLE
};

#define ADD_OPCODE(X)                            \
    {                                            \
        static_cast<uint8_t>(X), std::string(#X) \
    }

// remove EBPF_ATOMIC_ prefix
#define ADD_ATOMIC_OPCODE(X)                                \
    {                                                       \
        static_cast<int32_t>(X), std::string(#X).substr(12) \
    }

static std::map<int32_t, std::string> _atomic_opcode_name_strings = {
    ADD_ATOMIC_OPCODE(EBPF_ATOMIC_ADD),
    ADD_ATOMIC_OPCODE(EBPF_ATOMIC_ADD_FETCH),
    ADD_ATOMIC_OPCODE(EBPF_ATOMIC_OR),
    ADD_ATOMIC_OPCODE(EBPF_ATOMIC_OR_FETCH),
    ADD_ATOMIC_OPCODE(EBPF_ATOMIC_AND),
    ADD_ATOMIC_OPCODE(EBPF_ATOMIC_AND_FETCH),
    ADD_ATOMIC_OPCODE(EBPF_ATOMIC_XOR),
    ADD_ATOMIC_OPCODE(EBPF_ATOMIC_XOR_FETCH),
    ADD_ATOMIC_OPCODE(EBPF_ATOMIC_XCHG),
    ADD_ATOMIC_OPCODE(EBPF_ATOMIC_CMPXCHG)};

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
    ADD_OPCODE(EBPF_OP_ATOMIC64),   ADD_OPCODE(EBPF_OP_ATOMIC)};

#define IS_ATOMIC_OPCODE(_opcode) \
    (((_opcode)&EBPF_CLS_MASK) == EBPF_CLS_STX && ((_opcode)&EBPF_MODE_MASK) == EBPF_MODE_ATOMIC)

#define IS_JMP_CLASS_OPCODE(_opcode) \
    (((_opcode)&EBPF_CLS_MASK) == EBPF_CLS_JMP || ((_opcode)&EBPF_CLS_MASK) == EBPF_CLS_JMP32)

#define IS_JMP32_CLASS_OPCODE(_opcode) (((_opcode)&EBPF_CLS_MASK) == EBPF_CLS_JMP32)

#define IS_SIGNED_CMP_OPCODE(_opcode)                                                          \
    (((_opcode) >> 4) == (EBPF_MODE_JSGT >> 4) || ((_opcode) >> 4) == (EBPF_MODE_JSGE >> 4) || \
     ((_opcode) >> 4) == (EBPF_MODE_JSLT >> 4) || ((_opcode) >> 4) == (EBPF_MODE_JSLE >> 4))

/**
 * @brief Global operator to permit concatenating a safe and unsafe string.
 *
 * @param[in] lhs Safe string.
 * @param[in] rhs Unsafe string.
 * @return Unsafe string containing safe string + unsafe string.
 */
bpf_code_generator::unsafe_string
operator+(const std::string& lhs, const bpf_code_generator::unsafe_string& rhs)
{
    return bpf_code_generator::unsafe_string(lhs) + rhs;
}

std::string
bpf_code_generator::get_register_name(uint8_t id)
{
    if (id >= _countof(_register_names)) {
        throw bpf_code_generator_exception("invalid register id");
    } else {
        current_section->referenced_registers.insert(_register_names[id]);
        return _register_names[id];
    }
}

ELFIO::section*
bpf_code_generator::get_required_section(const bpf_code_generator::unsafe_string& name)
{
    auto section = get_optional_section(name);
    if (!section) {
        throw bpf_code_generator_exception("ELF file has missing or invalid section " + name);
    }
    return section;
}

ELFIO::section*
bpf_code_generator::get_optional_section(const bpf_code_generator::unsafe_string& name)
{
    auto section = reader.sections[name.raw()];
    if (!is_section_valid(section)) {
        return nullptr;
    }
    return section;
}

bool
bpf_code_generator::is_section_valid(const ELFIO::section* section)
{
    if (!section) {
        return false;
    }
    if (section->get_data() == nullptr) {
        return false;
    }
    if (section->get_size() == 0) {
        return false;
    }
    return true;
}

bpf_code_generator::bpf_code_generator(
    std::istream& stream,
    const bpf_code_generator::unsafe_string& c_name,
    const std::optional<std::vector<uint8_t>>& elf_file_hash)
    : current_section(nullptr), c_name(c_name), path(path), elf_file_hash(elf_file_hash)
{
    if (!reader.load(stream)) {
        throw bpf_code_generator_exception("can't process ELF file " + c_name);
    }

    extract_btf_information();
}

bpf_code_generator::bpf_code_generator(
    const bpf_code_generator::unsafe_string& c_name, const std::vector<ebpf_inst>& instructions)
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

std::vector<bpf_code_generator::unsafe_string>
bpf_code_generator::program_sections()
{
    std::vector<bpf_code_generator::unsafe_string> section_names;
    for (const auto& section : reader.sections) {
        if (!is_section_valid(section.get())) {
            continue;
        }
        bpf_code_generator::unsafe_string name = section->get_name();
        if (name.empty() || (section->get_size() == 0) || name == ".text") {
            continue;
        }
        if ((section->get_type() == 1) && (section->get_flags() == 6)) {
            section_names.push_back(section->get_name());
        }
    }
    if (section_names.empty()) {
        auto text_section = get_optional_section(".text");
        if (text_section) {
            section_names.push_back(".text");
        }
    }
    return section_names;
}

void
bpf_code_generator::parse(
    const bpf_code_generator::unsafe_string& section_name,
    const GUID& program_type,
    const GUID& attach_type,
    const std::optional<std::vector<uint8_t>>& program_info_hash)
{
    current_section = &sections[section_name];
    get_register_name(0);
    get_register_name(1);
    get_register_name(10);

    set_pe_section_name(section_name);
    set_program_and_attach_type_and_hash(program_type, attach_type, program_info_hash);
    extract_program(section_name);
    extract_relocations_and_maps(section_name);
}

void
bpf_code_generator::set_program_and_attach_type_and_hash(
    const GUID& program_type, const GUID& attach_type, const std::optional<std::vector<uint8_t>>& program_info_hash)
{
    memcpy(&current_section->program_type, &program_type, sizeof(GUID));
    memcpy(&current_section->expected_attach_type, &attach_type, sizeof(GUID));
    current_section->program_info_hash = program_info_hash;
}

void
bpf_code_generator::generate(const bpf_code_generator::unsafe_string& section_name)
{
    current_section = &sections[section_name];

    generate_labels();
    build_function_table();
    encode_instructions(section_name);
}

void
bpf_code_generator::extract_program(const bpf_code_generator::unsafe_string& section_name)
{
    auto program_section = get_required_section(section_name);
    std::vector<ebpf_inst> program{
        reinterpret_cast<const ebpf_inst*>(program_section->get_data()),
        reinterpret_cast<const ebpf_inst*>(program_section->get_data() + program_section->get_size())};

    auto symtab = get_required_section(".symtab");
    ELFIO::const_symbol_section_accessor symbols{reader, symtab};
    for (ELFIO::Elf_Xword index = 0; index < symbols.get_symbols_num(); index++) {
        std::string unsafe_name{};
        ELFIO::Elf64_Addr value{};
        ELFIO::Elf_Xword size{};
        unsigned char bind{};
        unsigned char symbol_type{};
        ELFIO::Elf_Half section_index{};
        unsigned char other{};
        symbols.get_symbol(index, unsafe_name, value, size, bind, symbol_type, section_index, other);
        if (unsafe_name.empty()) {
            continue;
        }
        unsafe_string name(unsafe_name);
        if (section_index == program_section->get_index() && value == 0) {
            current_section->program_name = name;
            break;
        }
    }

    uint32_t offset = 0;
    for (const auto& instruction : program) {
        current_section->output.push_back({instruction, offset++});
    }
}

void
bpf_code_generator::parse()
{
    auto map_section = get_optional_section("maps");
    if (map_section) {
        ELFIO::const_symbol_section_accessor symbols{reader, get_required_section(".symtab")};
        size_t data_size = map_section->get_size();
        size_t map_count = data_size / sizeof(ebpf_map_definition_in_file_t);

        if (data_size % sizeof(ebpf_map_definition_in_file_t) != 0) {
            throw bpf_code_generator_exception(
                "bad maps section size, must be a multiple of " +
                std::to_string(sizeof(ebpf_map_definition_in_file_t)));
        }

        for (ELFIO::Elf_Xword i = 0; i < symbols.get_symbols_num(); i++) {
            std::string unsafe_symbol_name;
            ELFIO::Elf64_Addr symbol_value{};
            unsigned char symbol_bind{};
            unsigned char symbol_type{};
            ELFIO::Elf_Half symbol_section_index{};
            unsigned char symbol_other{};
            ELFIO::Elf_Xword symbol_size{};

            symbols.get_symbol(
                i,
                unsafe_symbol_name,
                symbol_value,
                symbol_size,
                symbol_bind,
                symbol_type,
                symbol_section_index,
                symbol_other);

            if (symbol_section_index == map_section->get_index()) {
                if (symbol_size != sizeof(ebpf_map_definition_in_file_t)) {
                    throw bpf_code_generator_exception("invalid map size");
                }
                if (symbol_value > map_section->get_size()) {
                    throw bpf_code_generator_exception("invalid symbol value");
                }
                if ((symbol_value + symbol_size) > map_section->get_size()) {
                    throw bpf_code_generator_exception("invalid symbol value");
                }

                map_definitions[unsafe_symbol_name].definition =
                    *reinterpret_cast<const ebpf_map_definition_in_file_t*>(map_section->get_data() + symbol_value);

                map_definitions[unsafe_symbol_name].index = symbol_value / sizeof(ebpf_map_definition_in_file_t);
            }
        }

        if (map_definitions.size() != map_count) {
            throw bpf_code_generator_exception("bad maps section, map must have associated symbol");
        }
    }
}

void
bpf_code_generator::extract_relocations_and_maps(const bpf_code_generator::unsafe_string& section_name)
{
    auto map_section = get_optional_section("maps");
    ELFIO::const_symbol_section_accessor symbols{reader, get_required_section(".symtab")};

    auto relocations = get_optional_section(".rel" + section_name);
    if (!relocations) {
        relocations = get_optional_section(".rela" + section_name);
    }

    if (relocations) {
        ELFIO::const_relocation_section_accessor relocation_reader{reader, relocations};
        ELFIO::Elf_Xword relocation_count = relocation_reader.get_entries_num();
        for (ELFIO::Elf_Xword index = 0; index < relocation_count; index++) {
            ELFIO::Elf64_Addr offset{};
            ELFIO::Elf_Word symbol{};
            unsigned int type{};
            ELFIO::Elf_Sxword addend{};
            relocation_reader.get_entry(index, offset, symbol, type, addend);
            {
                std::string unsafe_name{};
                ELFIO::Elf64_Addr value{};
                ELFIO::Elf_Xword size{};
                unsigned char bind{};
                unsigned char symbol_type{};
                ELFIO::Elf_Half section_index{};
                unsigned char other{};
                if (!symbols.get_symbol(symbol, unsafe_name, value, size, bind, symbol_type, section_index, other)) {
                    throw bpf_code_generator_exception("Can't perform relocation at offset ", offset);
                }
                current_section->output[offset / sizeof(ebpf_inst)].relocation = unsafe_name;
                if (map_section && section_index == map_section->get_index()) {
                    // Check that the map exists in the list of map definitions.
                    if (map_definitions.find(unsafe_name) == map_definitions.end()) {
                        throw bpf_code_generator_exception("map not found in map definitions: " + unsafe_name);
                    }
                }
            }
        }
    }
}

void
bpf_code_generator::extract_btf_information()
{
    auto btf = get_optional_section(".BTF");
    auto btf_ext = get_optional_section(".BTF.ext");

    if (!btf || !btf_ext) {
        return;
    }

    std::vector<uint8_t> btf_data(
        reinterpret_cast<const uint8_t*>(btf->get_data()),
        reinterpret_cast<const uint8_t*>(btf->get_data()) + btf->get_size());
    std::vector<uint8_t> btf_ext_data(
        reinterpret_cast<const uint8_t*>(btf_ext->get_data()),
        reinterpret_cast<const uint8_t*>(btf_ext->get_data()) + btf_ext->get_size());

    btf_parse_line_information(
        btf_data,
        btf_ext_data,
        [&section_line_info = this->section_line_info](
            const std::string& section,
            uint32_t instruction_offset,
            const std::string& file_name,
            const std::string& source,
            uint32_t line_number,
            uint32_t column_number) {
            line_info_t info{file_name, source, line_number, column_number};
            section_line_info[section].emplace(instruction_offset / sizeof(ebpf_inst), info);
        });
}

void
bpf_code_generator::generate_labels()
{
    std::vector<output_instruction_t>& program_output = current_section->output;

    // Tag jump targets
    for (size_t i = 0; i < program_output.size(); i++) {
        auto& output = program_output[i];
        if (!IS_JMP_CLASS_OPCODE(output.instruction.opcode)) {
            continue;
        }
        if (output.instruction.opcode == EBPF_OP_CALL) {
            continue;
        }
        if (output.instruction.opcode == EBPF_OP_EXIT) {
            continue;
        }
        if ((i + output.instruction.offset + 1) >= program_output.size()) {
            throw bpf_code_generator_exception("invalid jump target", i);
        }
        program_output[i + output.instruction.offset + 1].jump_target = true;
    }

    // Add labels to instructions that are targets of jumps
    size_t label_index = 1;
    for (auto& output : program_output) {
        if (!output.jump_target) {
            continue;
        }
        output.label = "label_" + std::to_string(label_index++);
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
        bpf_code_generator::unsafe_string name;
        if (!output.relocation.empty()) {
            name = output.relocation;
        } else {
            name = "helper_id_";
            name += std::to_string(output.instruction.imm);
        }

        if (current_section->helper_functions.find(name) == current_section->helper_functions.end()) {
            current_section->helper_functions[name] = {output.instruction.imm, index++};
        }
    }
}

void
bpf_code_generator::encode_instructions(const bpf_code_generator::unsafe_string& section_name)
{
    std::vector<output_instruction_t>& program_output = current_section->output;
    auto program_name = !current_section->program_name.empty() ? current_section->program_name : section_name;
    auto helper_array_prefix = program_name.c_identifier() + "_helpers[{}]";

    // Encode instructions
    for (size_t i = 0; i < program_output.size(); i++) {
        auto& output = program_output[i];
        auto& inst = output.instruction;

        switch (inst.opcode & EBPF_CLS_MASK) {
        case EBPF_CLS_ALU:
        case EBPF_CLS_ALU64: {
            std::string destination = get_register_name(inst.dst);
            std::string source;
            if (inst.opcode & EBPF_SRC_REG) {
                source = get_register_name(inst.src);
            } else {
                source = "IMMEDIATE(" + std::to_string(inst.imm) + ")";
            }
            bool is64bit = (inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU64;
            AluOperations operation = static_cast<AluOperations>(inst.opcode >> 4);
            std::string swap_function;
            switch (operation) {
            case AluOperations::Add:
                output.lines.push_back(std::format("{} += {};", destination, source));
                break;
            case AluOperations::Sub:
                output.lines.push_back(std::format("{} -= {};", destination, source));
                break;
            case AluOperations::Mul:
                output.lines.push_back(std::format("{} *= {};", destination, source));
                break;
            case AluOperations::Div:
                if (is64bit) {
                    output.lines.push_back(
                        std::format("{} = {} ? ({} / {}) : 0;", destination, source, destination, source));
                } else {
                    output.lines.push_back(std::format(
                        "{} = (uint32_t){} ? (uint32_t){} / (uint32_t){} : 0;",
                        destination,
                        source,
                        destination,
                        source));
                }
                break;
            case AluOperations::Or:
                output.lines.push_back(std::format("{} |= {};", destination, source));
                break;
            case AluOperations::And:
                output.lines.push_back(std::format("{} &= {};", destination, source));
                break;
            case AluOperations::Lsh:
                output.lines.push_back(std::format("{} <<= {};", destination, source));
                break;
            case AluOperations::Rsh:
                if (is64bit) {
                    output.lines.push_back(std::format("{} >>= {};", destination, source));
                } else {
                    output.lines.push_back(std::format("{} = (uint32_t){} >> {};", destination, destination, source));
                }
                break;
            case AluOperations::Neg:
                output.lines.push_back(std::format("{} = -(int64_t){};", destination, destination));
                break;
            case AluOperations::Mod:
                if (is64bit) {
                    output.lines.push_back(std::format(
                        "{} = {} ? ({} % {}): {} ;", destination, source, destination, source, destination));
                } else {
                    output.lines.push_back(std::format(
                        "{} = (uint32_t){} ? ((uint32_t){} % (uint32_t){}) : (uint32_t){};",
                        destination,
                        source,
                        destination,
                        source,
                        destination));
                }
                break;
            case AluOperations::Xor:
                output.lines.push_back(std::format("{} ^= {};", destination, source));
                break;
            case AluOperations::Mov:
                output.lines.push_back(std::format("{} = {};", destination, source));
                break;
            case AluOperations::Ashr:
                if (is64bit) {
                    output.lines.push_back(
                        std::format("{} = (int64_t){} >> (uint32_t){};", destination, destination, source));
                } else {
                    output.lines.push_back(std::format("{} = (int32_t){} >> {};", destination, destination, source));
                }
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
                        throw bpf_code_generator_exception("invalid operand", output.instruction_offset);
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
                        throw bpf_code_generator_exception("invalid operand", output.instruction_offset);
                    }
                }
                output.lines.push_back(
                    std::format("{} = {}(({}){});", destination, swap_function, size_type, destination));
            } break;
            default:
                throw bpf_code_generator_exception("invalid operand", output.instruction_offset);
            }
            if (!is64bit) {
                output.lines.push_back(std::format("{} &= UINT32_MAX;", destination));
            }

        } break;
        case EBPF_CLS_LD: {
            i++;
            if (inst.opcode != EBPF_OP_LDDW) {
                throw bpf_code_generator_exception("invalid operand", output.instruction_offset);
            }
            if (i >= program_output.size()) {
                throw bpf_code_generator_exception("invalid operand", output.instruction_offset);
            }
            std::string destination = get_register_name(inst.dst);
            if (output.relocation.empty()) {
                uint64_t imm = static_cast<uint32_t>(program_output[i].instruction.imm);
                imm <<= 32;
                imm |= static_cast<uint32_t>(output.instruction.imm);
                std::string source;
                source = "(uint64_t)" + std::to_string(imm);
                output.lines.push_back(std::format("{} = {};", destination, source));
            } else {
                std::string source;
                auto map_definition = map_definitions.find(output.relocation);
                if (map_definition == map_definitions.end()) {
                    throw bpf_code_generator_exception(
                        "Map " + output.relocation + " doesn't exist", output.instruction_offset);
                }
                source = std::format("_maps[{}].address", std::to_string(map_definition->second.index));
                output.lines.push_back(std::format("{} = POINTER({});", destination, source));
                current_section->referenced_map_indices.insert(map_definitions[output.relocation].index);
            }
        } break;
        case EBPF_CLS_LDX: {
            std::string size_type;
            std::string destination = get_register_name(inst.dst);
            std::string source = get_register_name(inst.src);
            std::string offset = "OFFSET(" + std::to_string(inst.offset) + ")";
            switch (inst.opcode & EBPF_SIZE_DW) {
            case EBPF_SIZE_B:
                size_type = "uint8_t";
                break;
            case EBPF_SIZE_H:
                size_type = "uint16_t";
                break;
            case EBPF_SIZE_W:
                size_type = "uint32_t";
                break;
            case EBPF_SIZE_DW:
                size_type = "uint64_t";
                break;
            }
            output.lines.push_back(
                std::format("{} = *({}*)(uintptr_t)({} + {});", destination, size_type, source, offset));
        } break;
        case EBPF_CLS_ST:
        case EBPF_CLS_STX: {
            std::string size_type;
            std::string lock_type;
            std::string size_num;
            std::string destination = get_register_name(inst.dst);
            std::string source;
            std::string raw_source;
            bool is_complex = false;
            if ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ST) {
                source = "IMMEDIATE(" + std::to_string(inst.imm) + ")";
            } else {
                source = get_register_name(inst.src);
            }
            std::string offset = "OFFSET(" + std::to_string(inst.offset) + ")";
            switch (inst.opcode & EBPF_SIZE_DW) {
            case EBPF_SIZE_B:
                size_type = "uint8_t";
                break;
            case EBPF_SIZE_H:
                size_type = "uint16_t";
                break;
            case EBPF_SIZE_W:
                size_type = "uint32_t";
                lock_type = "volatile long";
                break;
            case EBPF_SIZE_DW:
                size_num = "64";
                size_type = "uint64_t";
                lock_type = "volatile int64_t";
                break;
            }
            raw_source = source;
            source = "(" + size_type + ")" + source;
            if ((inst.opcode & EBPF_MODE_MASK) == EBPF_MODE_ATOMIC) { // MODE_ATOMIC
                auto line = std::string("");
                switch (inst.imm) {
                case EBPF_ATOMIC_ADD:
                case EBPF_ATOMIC_ADD_FETCH:
                    line = std::format(
                        "_InterlockedExchangeAdd{}(({}*)(uintptr_t)({} + {}), {});",
                        size_num,
                        lock_type,
                        destination,
                        offset,
                        source);
                    break;
                case EBPF_ATOMIC_OR:
                case EBPF_ATOMIC_OR_FETCH:
                    line = std::format(
                        "_InterlockedOr{}(({}*)(uintptr_t)({} + {}), {});",
                        size_num,
                        lock_type,
                        destination,
                        offset,
                        source);
                    break;
                case EBPF_ATOMIC_AND:
                case EBPF_ATOMIC_AND_FETCH:
                    line = std::format(
                        "_InterlockedAnd{}(({}*)(uintptr_t)({} + {}), {});",
                        size_num,
                        lock_type,
                        destination,
                        offset,
                        source);
                    break;
                case EBPF_ATOMIC_XOR:
                case EBPF_ATOMIC_XOR_FETCH:
                    line = std::format(
                        "_InterlockedXor{}(({}*)(uintptr_t)({} + {}), {});",
                        size_num,
                        lock_type,
                        destination,
                        offset,
                        source);
                    break;
                case EBPF_ATOMIC_XCHG:
                    is_complex = true;
                    line = std::format(
                        "_InterlockedExchange{}(({}*)(uintptr_t)({} + {}), {});",
                        size_num,
                        lock_type,
                        destination,
                        offset,
                        source);
                    break;
                case EBPF_ATOMIC_CMPXCHG:
                    is_complex = true;
                    line = std::format(
                        "r0 = ({})_InterlockedCompareExchange{}(({}*)(uintptr_t)({} + {}), {}, r0);",
                        size_type,
                        size_num,
                        lock_type,
                        destination,
                        offset,
                        source);
                    break;
                default:
                    throw bpf_code_generator_exception("invalid atomic operation", inst.imm);
                }
                if ((inst.imm & EBPF_ATOMIC_FETCH) && (!is_complex)) {
                    output.lines.push_back(std::format("{} = ({}){}", raw_source, size_type, line));
                } else {
                    output.lines.push_back(line);
                }
            } else if ((inst.opcode & EBPF_MODE_MASK) == EBPF_MODE_MEM) {
                output.lines.push_back(
                    std::format("*({}*)(uintptr_t)({} + {}) = {};", size_type, destination, offset, source));
            } else {
                throw bpf_code_generator_exception("invalid atomic mode", inst.opcode & EBPF_MODE_MASK);
            }
        } break;
        case EBPF_CLS_JMP:
        case EBPF_CLS_JMP32: {
            std::string destination = get_register_name(inst.dst);
            std::string destination_cast;
            if (IS_JMP32_CLASS_OPCODE(inst.opcode)) {
                destination_cast = IS_SIGNED_CMP_OPCODE(inst.opcode) ? "(int32_t)" : "(uint32_t)";
            } else {
                destination_cast = IS_SIGNED_CMP_OPCODE(inst.opcode) ? "(int64_t)" : "";
            }

            std::string source;
            std::string source_cast;
            if (inst.opcode & EBPF_SRC_REG) {
                source = get_register_name(inst.src);
                if (IS_JMP32_CLASS_OPCODE(inst.opcode)) {
                    source_cast = IS_SIGNED_CMP_OPCODE(inst.opcode) ? "(int32_t)" : "(uint32_t)";
                } else {
                    source_cast = IS_SIGNED_CMP_OPCODE(inst.opcode) ? "(int64_t)" : "";
                }
            } else {
                source = "IMMEDIATE(" + std::to_string(inst.imm) + ")";
            }
            if ((inst.opcode >> 4) >= _countof(_predicate_format_string)) {
                throw bpf_code_generator_exception("invalid operand", output.instruction_offset);
            }

            auto& format = _predicate_format_string[inst.opcode >> 4];
            if (inst.opcode == EBPF_OP_JA) {
                std::string target = program_output[i + inst.offset + 1].label;
                output.lines.push_back("goto " + target + ";");
            } else if (inst.opcode == EBPF_OP_CALL) {
                std::string function_name;
                if (output.relocation.empty()) {
                    function_name = std::vformat(
                        helper_array_prefix,
                        make_format_args(std::to_string(
                            current_section->helper_functions["helper_id_" + std::to_string(output.instruction.imm)]
                                .index)));
                } else {
                    auto helper_function = current_section->helper_functions.find(output.relocation);
                    assert(helper_function != current_section->helper_functions.end());
                    function_name = std::vformat(
                        helper_array_prefix,
                        make_format_args(std::to_string(current_section->helper_functions[output.relocation].index)));
                }
                output.lines.push_back(get_register_name(0) + " = " + function_name + ".address");
                output.lines.push_back(
                    INDENT " (" + get_register_name(1) + ", " + get_register_name(2) + ", " + get_register_name(3) +
                    ", " + get_register_name(4) + ", " + get_register_name(5) + ");");
                output.lines.push_back(
                    std::format("if (({}.tail_call) && ({} == 0))", function_name, get_register_name(0)));
                output.lines.push_back(INDENT "return 0;");
            } else if (inst.opcode == EBPF_OP_EXIT) {
                output.lines.push_back("return " + get_register_name(0) + ";");
            } else {
                std::string target = program_output[i + inst.offset + 1].label;
                if (target.empty()) {
                    throw bpf_code_generator_exception("invalid jump target", output.instruction_offset);
                }

                std::string predicate =
                    vformat(format, make_format_args(destination_cast, destination, source_cast, source));
                output.lines.push_back(vformat("if ({})", make_format_args(predicate)));
                output.lines.push_back(vformat(INDENT "goto {};", make_format_args(target)));
            }
        } break;

        default:
            throw bpf_code_generator_exception("invalid operand", output.instruction_offset);
        }
    }
}

void
bpf_code_generator::emit_c_code(std::ostream& output_stream)
{
    // Emit C file
    output_stream << "#include \"bpf2c.h\"" << std::endl << std::endl;

    output_stream << "static void" << std::endl
                  << "_get_hash(_Outptr_result_buffer_maybenull_(*size) const uint8_t** hash, _Out_ size_t* size)"
                  << std::endl;
    output_stream << "{" << std::endl;
    if (elf_file_hash.has_value()) {
        output_stream << INDENT "const uint8_t hash_buffer[] = {" << std::endl;
        for (size_t i = 0; i < elf_file_hash.value().size(); i++) {
            if (i % 16 == 0) {
                output_stream << INDENT "";
            }
            output_stream << std::to_string(elf_file_hash.value().at(i)) << ", ";
            if (i % 16 == 15) {
                output_stream << std::endl;
            }
        }
        output_stream << INDENT "};" << std::endl;
        output_stream << INDENT "*hash = hash_buffer;" << std::endl;
        output_stream << INDENT "*size = sizeof(hash_buffer);" << std::endl;
    } else {
        output_stream << INDENT "*hash = NULL;" << std::endl;
        output_stream << INDENT "*size = 0;" << std::endl;
    }
    output_stream << "}" << std::endl;

    // Emit import tables
    if (map_definitions.size() > 0) {
        output_stream << "#pragma data_seg(push, \"maps\")" << std::endl;
        output_stream << "static map_entry_t _maps[] = {" << std::endl;
        size_t map_size = map_definitions.size();
        // Sort maps by index.
        std::vector<std::tuple<bpf_code_generator::unsafe_string, map_entry_t>> maps_by_index(map_size);
        for (const auto& pair : map_definitions) {
            if (pair.second.index >= maps_by_index.size()) {
                throw bpf_code_generator_exception("Invalid map section");
            }
            maps_by_index[pair.second.index] = pair;
        }
        // Emit maps by index.
        for (const auto& [name, entry] : maps_by_index) {
            std::string map_type;
            std::string map_pinning;
            if (entry.definition.type < _countof(_ebpf_map_type_names)) {
                map_type = _ebpf_map_type_names[entry.definition.type];
            } else {
                map_type = std::to_string(entry.definition.type);
            }
            if (entry.definition.pinning < _countof(_ebpf_pin_type_names)) {
                map_pinning = _ebpf_pin_type_names[entry.definition.pinning];
            } else {
                map_pinning = std::to_string(entry.definition.pinning);
            }
            double width = 0;
            width = std::max(width, (double)map_type.size() - 1);
            width = std::max(width, std::log10((size_t)entry.definition.key_size));
            width = std::max(width, std::log10((size_t)entry.definition.value_size));
            width = std::max(width, std::log10((size_t)entry.definition.max_entries));
            width = std::max(width, std::log10((size_t)entry.definition.inner_map_idx));
            width = std::max(width, (double)map_pinning.size() - 1);
            width = std::max(width, std::log10((size_t)entry.definition.id));

            width = std::max(width, std::log10((size_t)entry.definition.inner_id));
            auto stream_width = static_cast<std::streamsize>(std::floor(width) + 1);
            stream_width += 2; // Add space for the trailing ", "

            output_stream << INDENT "{NULL," << std::endl;
            output_stream << INDENT " {" << std::endl;
            output_stream << INDENT INDENT " " << std::left << std::setw(stream_width) << map_type + ","
                          << "// Type of map." << std::endl;
            output_stream << INDENT INDENT " " << std::left << std::setw(stream_width)
                          << std::to_string(entry.definition.key_size) + ","
                          << "// Size in bytes of a map key." << std::endl;
            output_stream << INDENT INDENT " " << std::left << std::setw(stream_width)
                          << std::to_string(entry.definition.value_size) + ","
                          << "// Size in bytes of a map value." << std::endl;
            output_stream << INDENT INDENT " " << std::left << std::setw(stream_width)
                          << std::to_string(entry.definition.max_entries) + ","
                          << "// Maximum number of entries allowed in the map." << std::endl;
            output_stream << INDENT INDENT " " << std::left << std::setw(stream_width)
                          << std::to_string(entry.definition.inner_map_idx) + ","
                          << "// Inner map index." << std::endl;
            output_stream << INDENT INDENT " " << std::left << std::setw(stream_width) << map_pinning + ","
                          << "// Pinning type for the map." << std::endl;
            output_stream << INDENT INDENT " " << std::left << std::setw(stream_width)
                          << std::to_string(entry.definition.id) + ","
                          << "// Identifier for a map template." << std::endl;
            output_stream << INDENT INDENT " " << std::left << std::setw(stream_width)
                          << std::to_string(entry.definition.inner_id) + ","
                          << "// The id of the inner map template." << std::endl;
            output_stream << INDENT " }," << std::endl;
            output_stream << INDENT " " << name.quoted() << "}," << std::endl;
        }
        output_stream << "};" << std::endl;
        output_stream << "#pragma data_seg(pop)" << std::endl;
        output_stream << std::endl;
        output_stream << "static void" << std::endl
                      << "_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)"
                      << std::endl;
        output_stream << "{" << std::endl;
        output_stream << INDENT "*maps = _maps;" << std::endl;
        output_stream << INDENT "*count = " << std::to_string(map_definitions.size()) << ";" << std::endl;
        output_stream << "}" << std::endl;
        output_stream << std::endl;
    } else {
        output_stream << "static void" << std::endl
                      << "_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)"
                      << std::endl;
        output_stream << "{" << std::endl;
        output_stream << INDENT "*maps = NULL;" << std::endl;
        output_stream << INDENT "*count = 0;" << std::endl;
        output_stream << "}" << std::endl;
        output_stream << std::endl;
    }

    for (auto& [name, section] : sections) {
        auto program_name = !section.program_name.empty() ? section.program_name : name;

        if (section.output.size() == 0) {
            continue;
        }

        // Emit section specific helper function array.
        if (section.helper_functions.size() > 0) {
            std::string helper_array_name = program_name.c_identifier() + "_helpers";
            output_stream << "static helper_function_entry_t " << helper_array_name << "[] = {" << std::endl;

            // Functions are emitted in the order in which they occur in the byte code.
            std::vector<std::tuple<bpf_code_generator::unsafe_string, uint32_t>> index_ordered_helpers;
            index_ordered_helpers.resize(section.helper_functions.size());
            for (const auto& function : section.helper_functions) {
                index_ordered_helpers[function.second.index] = std::make_tuple(function.first, function.second.id);
            }

            for (const auto& [helper_name, id] : index_ordered_helpers) {
                output_stream << INDENT "{NULL, " << id << ", " << helper_name.quoted() << "}," << std::endl;
            }

            output_stream << "};" << std::endl;
            output_stream << std::endl;
        }

        // Emit the program and attach type GUID.
        std::string program_type_name = program_name.c_identifier() + "_program_type_guid";
        std::string attach_type_name = program_name.c_identifier() + "_attach_type_guid";
        std::string program_info_hash_name = program_name.c_identifier() + "_program_info_hash";

        auto guid_declaration =
            std::format("static GUID {} = {};", program_type_name, format_guid(&section.program_type, false));

        if (guid_declaration.length() <= LINE_BREAK_WIDTH) {
            output_stream << guid_declaration << std::endl;
        } else {
            output_stream << format("static GUID {} = {};", program_type_name, format_guid(&section.program_type, true))
                          << std::endl;
        }
        guid_declaration =
            std::format("static GUID {} = {};", attach_type_name, format_guid(&section.expected_attach_type, false));
        if (guid_declaration.length() <= LINE_BREAK_WIDTH) {
            output_stream << guid_declaration << std::endl;
        } else {
            output_stream << std::format(
                                 "static GUID {} = {};",
                                 attach_type_name,
                                 format_guid(&section.expected_attach_type, true))
                          << std::endl;
        }

        if (section.program_info_hash.has_value()) {
            output_stream << "static const uint8_t " << program_info_hash_name << "[] = {" << std::endl;
            for (size_t i = 0; i < section.program_info_hash.value().size(); i++) {
                if (i % 16 == 0) {
                    output_stream << INDENT "";
                }
                output_stream << std::to_string(section.program_info_hash.value().at(i)) << ", ";
                if (i % 16 == 15) {
                    output_stream << std::endl;
                }
            }
            output_stream << INDENT "};" << std::endl;
        }

        if (section.referenced_map_indices.size() > 0) {
            // Emit the array for the maps used.
            std::string map_array_name = program_name.c_identifier() + "_maps";
            output_stream << std::format("static uint16_t {}[] = {{\n", map_array_name);
            for (const auto& map_index : section.referenced_map_indices) {
                output_stream << INDENT << std::to_string(map_index) << "," << std::endl;
            }
            output_stream << "};" << std::endl;
            output_stream << std::endl;
        }

        auto& line_info = section_line_info[name];
        auto first_line_info = line_info.find(section.output.front().instruction_offset);
        std::string prolog_line_info;
        if (first_line_info != line_info.end() && !first_line_info->second.file_name.empty()) {
            prolog_line_info = std::format(
                "#line {} {}\n",
                std::to_string(first_line_info->second.line_number),
                first_line_info->second.file_name.quoted_filename());
        }

        // Emit entry point
        output_stream << "#pragma code_seg(push, " << section.pe_section_name.quoted() << ")" << std::endl;
        output_stream << std::format("static uint64_t\n{}(void* context)", program_name.c_identifier()) << std::endl;
        output_stream << prolog_line_info << "{" << std::endl;

        // Emit prologue
        output_stream << prolog_line_info << INDENT "// Prologue" << std::endl;
        output_stream << prolog_line_info << INDENT "uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];" << std::endl;
        for (const auto& r : _register_names) {
            // Skip unused registers
            if (section.referenced_registers.find(r) == section.referenced_registers.end()) {
                continue;
            }
            output_stream << prolog_line_info << INDENT "register uint64_t " << r.c_str() << " = 0;" << std::endl;
        }
        output_stream << std::endl;
        output_stream << prolog_line_info << INDENT "" << get_register_name(1) << " = (uintptr_t)context;" << std::endl;
        output_stream << prolog_line_info << INDENT "" << get_register_name(10)
                      << " = (uintptr_t)((uint8_t*)stack + sizeof(stack));" << std::endl;
        output_stream << std::endl;

        // Emit encoded instructions.
        for (const auto& output : section.output) {
            if (output.lines.empty()) {
                continue;
            }
            if (!output.label.empty()) {
                output_stream << output.label << ":" << std::endl;
            }
            auto current_line = line_info.find(output.instruction_offset);
            if (current_line != line_info.end() && !current_line->second.file_name.empty() &&
                current_line->second.line_number != 0) {
                prolog_line_info = std::format(
                    "#line {} {}\n",
                    std::to_string(current_line->second.line_number),
                    current_line->second.file_name.quoted_filename());
            }
#if defined(_DEBUG) || defined(BPF2C_VERBOSE)
            output_stream << INDENT "// " << _opcode_name_strings[output.instruction.opcode];
            if (IS_ATOMIC_OPCODE(output.instruction.opcode)) {
                output_stream << "_" << _atomic_opcode_name_strings[output.instruction.imm];
            }
            output_stream << " pc=" << output.instruction_offset << " dst=r" << std::to_string(output.instruction.dst)
                          << " src=r" << std::to_string(output.instruction.src)
                          << " offset=" << std::to_string(output.instruction.offset)
                          << " imm=" << std::to_string(output.instruction.imm) << std::endl;

#endif
            for (const auto& line : output.lines) {
                output_stream << prolog_line_info << INDENT "" << line << std::endl;
            }
        }
        // Emit epilogue
        output_stream << prolog_line_info << "}" << std::endl;
        output_stream << "#pragma code_seg(pop)" << std::endl;
        output_stream << "#line __LINE__ __FILE__" << std::endl << std::endl;
    }

    if (sections.size() != 0) {

        output_stream << "#pragma data_seg(push, \"programs\")" << std::endl;
        output_stream << "static program_entry_t _programs[] = {" << std::endl;
        for (auto& [name, program] : sections) {
            auto program_name = !program.program_name.empty() ? program.program_name : name;
            size_t map_count = program.referenced_map_indices.size();
            size_t helper_count = program.helper_functions.size();
            auto map_array_name = map_count ? (program_name.c_identifier() + "_maps") : "NULL";
            auto helper_array_name = helper_count ? (program_name.c_identifier() + "_helpers") : "NULL";
            auto program_type_guid_name = program_name.c_identifier() + "_program_type_guid";
            auto attach_type_guid_name = program_name.c_identifier() + "_attach_type_guid";
            auto program_info_hash_name = program_name.c_identifier() + "_program_info_hash";
            output_stream << INDENT "{" << std::endl;
            output_stream << INDENT INDENT << "0," << std::endl;
            output_stream << INDENT INDENT << program_name.c_identifier() << "," << std::endl;
            output_stream << INDENT INDENT << program.pe_section_name.quoted() << "," << std::endl;
            output_stream << INDENT INDENT << name.quoted() << "," << std::endl;
            output_stream << INDENT INDENT << program.program_name.quoted() << "," << std::endl;
            output_stream << INDENT INDENT << map_array_name << "," << std::endl;
            output_stream << INDENT INDENT << program.referenced_map_indices.size() << "," << std::endl;
            output_stream << INDENT INDENT << helper_array_name.c_str() << "," << std::endl;
            output_stream << INDENT INDENT << program.helper_functions.size() << "," << std::endl;
            output_stream << INDENT INDENT << program.output.size() << "," << std::endl;
            output_stream << INDENT INDENT "&" << program_type_guid_name << "," << std::endl;
            output_stream << INDENT INDENT "&" << attach_type_guid_name << "," << std::endl;
            if (program.program_info_hash.has_value()) {
                output_stream << INDENT INDENT << program_info_hash_name << "," << std::endl;
                output_stream << INDENT INDENT << program.program_info_hash.value().size() << "," << std::endl;
            }
            output_stream << INDENT "}," << std::endl;
        }
        output_stream << "};" << std::endl;
        output_stream << "#pragma data_seg(pop)" << std::endl;
        output_stream << std::endl;
    }
    output_stream << "static void" << std::endl
                  << "_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)"
                  << std::endl;
    output_stream << "{" << std::endl;
    if (sections.size() != 0) {
        output_stream << INDENT "*programs = _programs;" << std::endl;
    } else {
        output_stream << INDENT "*programs = NULL;" << std::endl;
    }
    output_stream << INDENT "*count = " << std::to_string(sections.size()) << ";" << std::endl;
    output_stream << "}" << std::endl;
    output_stream << std::endl;

    std::istringstream version_stream(EBPF_VERSION);
    std::string version_major;
    std::string version_minor;
    std::string version_revision;
    std::getline(version_stream, version_major, '.');
    std::getline(version_stream, version_minor, '.');
    std::getline(version_stream, version_revision, '.');

    output_stream << "static void" << std::endl
                  << "_get_version(_Out_ bpf2c_version_t* version)" << std::endl
                  << "{" << std::endl
                  << INDENT "version->major = " << version_major << ";" << std::endl
                  << INDENT "version->minor = " << version_minor << ";" << std::endl
                  << INDENT "version->revision = " << version_revision << ";" << std::endl
                  << "}" << std::endl
                  << std::endl;

    std::string meta_data_table = "metadata_table_t " + c_name.c_identifier() + "_metadata_table = {";
    meta_data_table += "sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};\n";

    if ((meta_data_table.size() - 1) > LINE_BREAK_WIDTH) {
        meta_data_table.insert(meta_data_table.find_first_of("{") + 1, "\n" INDENT);
    }

    output_stream << meta_data_table;
}

std::string
bpf_code_generator::format_guid(const GUID* guid, bool split)
{
    std::string output(120, '\0');
    std::string format_string;
    if (split) {
        format_string =
            "{\n" INDENT "0x%08x, 0x%04x, 0x%04x, {0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x}}";
    } else {
        format_string = "{0x%08x, 0x%04x, 0x%04x, {0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x}}";
    }
    auto count = snprintf(
        output.data(),
        output.size(),
        format_string.c_str(),
        guid->Data1,
        guid->Data2,
        guid->Data3,
        guid->Data4[0],
        guid->Data4[1],
        guid->Data4[2],
        guid->Data4[3],
        guid->Data4[4],
        guid->Data4[5],
        guid->Data4[6],
        guid->Data4[7]);
    if (count < 0) {
        throw bpf_code_generator_exception("Error formatting GUID");
    }

    output.resize(strlen(output.c_str()));
    return output;
}

void
bpf_code_generator::set_pe_section_name(const bpf_code_generator::unsafe_string& elf_section_name)
{
    if (elf_section_name.length() <= 8) {
        current_section->pe_section_name = elf_section_name;
        return;
    }

    // Name is too long for PE, so generate a short name.
    // Subtract 3 so there is space for the tilde, the last counter digit,
    // and a null terminator.
    pe_section_name_counter++;
    char shortname[9];
    int prefix_length = sizeof(shortname) - 3 - (int)(log10(pe_section_name_counter));
    strncpy_s(shortname, sizeof(shortname), elf_section_name.raw().c_str(), prefix_length);
    sprintf_s(shortname + prefix_length, sizeof(shortname) - prefix_length, "~%d", pe_section_name_counter);
    current_section->pe_section_name = shortname;
}
