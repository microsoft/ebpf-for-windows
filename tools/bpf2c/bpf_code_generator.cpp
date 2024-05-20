// Copyright (c) eBPF for Windows contributors
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
#include "ebpf_version.h"
#define ebpf_inst ebpf_inst_btf
#include "libbtf/btf_map.h"
#include "libbtf/btf_parse.h"
#include "libbtf/btf_type_data.h"
#include "spec_type_descriptors.hpp"
#undef ebpf_inst

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

#define EBPF_MODE_ATOMIC 0xc0

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

#define EBPF_OP_ATOMIC64 (INST_CLS_STX | EBPF_MODE_ATOMIC | INST_SIZE_DW)
#define EBPF_OP_ATOMIC (INST_CLS_STX | EBPF_MODE_ATOMIC | INST_SIZE_W)
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
    Arsh,
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
    (((_opcode)&INST_CLS_MASK) == INST_CLS_STX && ((_opcode)&INST_MODE_MASK) == EBPF_MODE_ATOMIC)

#define IS_JMP_CLASS_OPCODE(_opcode) \
    (((_opcode)&INST_CLS_MASK) == INST_CLS_JMP || ((_opcode)&INST_CLS_MASK) == INST_CLS_JMP32)

#define IS_JMP32_CLASS_OPCODE(_opcode) (((_opcode)&INST_CLS_MASK) == INST_CLS_JMP32)

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
    const std::string& program_info_hash_type)
{
    current_section = &sections[section_name];
    get_register_name(0);
    get_register_name(1);
    get_register_name(10);

    set_pe_section_name(section_name);
    set_program_and_attach_type_and_hash_type(program_type, attach_type, program_info_hash_type);
    extract_program(section_name);
    extract_relocations_and_maps(section_name);
}

void
bpf_code_generator::set_program_and_attach_type_and_hash_type(
    const GUID& program_type, const GUID& attach_type, const std::string& program_info_hash_type)
{
    memcpy(&current_section->program_type, &program_type, sizeof(GUID));
    memcpy(&current_section->expected_attach_type, &attach_type, sizeof(GUID));
    current_section->program_info_hash_type = program_info_hash_type;
}

void
bpf_code_generator::set_program_hash_info(const std::optional<std::vector<uint8_t>>& program_info_hash)
{
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

std::vector<int32_t>
bpf_code_generator::get_helper_ids()
{
    std::vector<int32_t> helper_ids;
    for (const auto& [name, helper] : current_section->helper_functions) {
        helper_ids.push_back(helper.id);
    }

    return helper_ids;
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

// BTF maps sections are identified as any section called ".maps".
// PREVAIL does not support multiple BTF map sections.
static bool
_is_btf_map_section(const std::string& name)
{
    return name == ".maps";
}

// Legacy (non-BTF) maps sections are identified as any section called "maps", or matching "maps/<map-name>".
static bool
_is_legacy_map_section(const std::string& name)
{
    std::string maps_prefix = "maps/";
    return name == "maps" || (name.length() > 5 && name.compare(0, maps_prefix.length(), maps_prefix) == 0);
}

void
bpf_code_generator::visit_symbols(symbol_visitor_t visitor, const unsafe_string& section_name)
{
    ELFIO::const_symbol_section_accessor symbols{reader, get_required_section(".symtab")};
    auto target_section = get_required_section(section_name);

    for (ELFIO::Elf_Xword index = 0; index < symbols.get_symbols_num(); index++) {
        std::string unsafe_name{};
        ELFIO::Elf64_Addr value{};
        ELFIO::Elf_Xword size{};
        unsigned char bind{};
        unsigned char symbol_type{};
        ELFIO::Elf_Half section_index{};
        unsigned char other{};
        symbols.get_symbol(index, unsafe_name, value, size, bind, symbol_type, section_index, other);
        if (section_index != target_section->get_index()) {
            continue;
        }
        if (unsafe_name.empty()) {
            continue;
        }
        unsafe_string name(unsafe_name);
        if (value > target_section->get_size()) {
            throw bpf_code_generator_exception("invalid symbol value");
        }

        // Check for overflow of value + size
        if ((value + size) < value) {
            throw bpf_code_generator_exception("invalid symbol value");
        }

        if ((value + size) > target_section->get_size()) {
            throw bpf_code_generator_exception("invalid symbol value");
        }

        if (section_index == target_section->get_index()) {
            visitor(name, value, bind, symbol_type, size);
        }
    }
}

template <typename T>
static std::vector<T>
vector_of(const ELFIO::section& sec)
{
    auto data = sec.get_data();
    auto size = sec.get_size();
    if ((size % sizeof(T) != 0) || size > UINT32_MAX || !data) {
        throw std::runtime_error("Invalid argument to vector_of");
    }
    return {(T*)data, (T*)(data + size)};
}

// Parse a BTF maps section.
void
bpf_code_generator::parse_btf_maps_section(const unsafe_string& name)
{
    auto map_section = get_optional_section(name);
    if (map_section) {
        auto btf_section = get_required_section(".BTF");
        std::optional<libbtf::btf_type_data> btf_data = vector_of<std::byte>(*btf_section);
        std::vector<EbpfMapDescriptor> map_descriptors;

        auto map_data = libbtf::parse_btf_map_section(btf_data.value());
        std::map<std::string, size_t> map_offsets;
        size_t anonymous_map_count = 0;
        for (auto& map : map_data) {
            if (map.name.empty()) {
                map.name = "__anonymous_" + std::to_string(++anonymous_map_count);
            }
            map_offsets.insert({map.name, map_descriptors.size()});
            map_descriptors.push_back({
                .original_fd = static_cast<int>(map.type_id),
                .type = map.map_type,
                .key_size = map.key_size,
                .value_size = map.value_size,
                .max_entries = map.max_entries,
                .inner_map_fd = map.inner_map_type_id != 0 ? map.inner_map_type_id : -1,
            });
        }
        auto map_name_to_index = map_offsets;
        size_t index = 0;

        std::map<std::pair<size_t, size_t>, unsafe_string> map_names_by_offset;
        std::map<unsafe_string, size_t> map_names_to_values_offset;

        // Emit map definitions in the same order as the maps in the .maps section.
        visit_symbols(
            [&](const unsafe_string& unsafe_symbol_name,
                uint64_t symbol_value,
                unsigned char bind,
                unsigned char symbol_type,
                uint64_t symbol_size) {
                UNREFERENCED_PARAMETER(bind);
                UNREFERENCED_PARAMETER(symbol_type);
                UNREFERENCED_PARAMETER(symbol_size);
                auto range = std::make_pair(symbol_value, symbol_value + symbol_size);
                if (map_names_by_offset.find(range) == map_names_by_offset.end()) {
                    map_names_by_offset[range] = unsafe_symbol_name;
                }
            },
            name);

        // Add anonymous maps to the end of the map list.
        size_t last_map_offset = map_names_by_offset.size() != 0 ? map_names_by_offset.rbegin()->first.second : 1;
        for (auto& map : map_data) {
            if (!map.name.starts_with("__anonymous")) {
                continue;
            }
            map_names_by_offset[std::make_pair(last_map_offset, last_map_offset)] = map.name;
            last_map_offset++;
        }

        for (const auto& [range, unsafe_symbol_name] : map_names_by_offset) {
            if (map_name_to_index.find(unsafe_symbol_name.raw()) == map_name_to_index.end()) {
                throw bpf_code_generator_exception("map symbol not found in map section");
            }
            ebpf_map_definition_in_file_t map_definition{};
            EbpfMapDescriptor map_descriptor = map_descriptors[map_name_to_index[unsafe_symbol_name.raw()]];

            map_definition.type = static_cast<ebpf_map_type_t>(map_descriptor.type);
            map_definition.key_size = map_descriptor.key_size;
            map_definition.value_size = map_descriptor.value_size;
            map_definition.max_entries = map_descriptor.max_entries;
            map_definition.id = map_descriptor.original_fd;
            map_definition.inner_id = map_descriptor.inner_map_fd != -1 ? map_descriptor.inner_map_fd : 0;

            // Get pinning data from the BTF data.
            auto map_struct = btf_data->get_kind_type<libbtf::btf_kind_struct>(map_descriptor.original_fd);
            for (const auto& member : map_struct.members) {
                if (member.name == "pinning") {
                    // This should use value_from_BTF__uint from btf_parser.cpp, but it's static.
                    auto pinning_type_id = member.type;
                    // Dereference the pointer type.
                    pinning_type_id = btf_data->dereference_pointer(pinning_type_id);
                    // Get the array type.
                    auto pinning_type = btf_data->get_kind_type<libbtf::btf_kind_array>(pinning_type_id);
                    // Value is encoded as the number of elements in the array.
                    map_definition.pinning = static_cast<ebpf_pin_type_t>(pinning_type.count_of_elements);
                }
                // "values" is a variable length array of pointers to values.
                // Compute the offset of the values array and resize the vector
                // to hold the initial values.
                if (member.name == "values") {
                    map_names_to_values_offset[unsafe_symbol_name] = member.offset_from_start_in_bits / 8;
                    if (map_names_to_values_offset[unsafe_symbol_name] > (range.second - range.first)) {
                        throw bpf_code_generator_exception("map values offset is outside of map range");
                    }

                    // Compute the number of initial values and resize the vector.
                    // Size is the number of bytes in the range minus the offset of the values array divided by the
                    // size of a pointer.
                    size_t value_count =
                        ((range.second - range.first) - map_names_to_values_offset[unsafe_symbol_name]) /
                        sizeof(uintptr_t);
                    if (value_count > 0) {
                        // If the map is statically initialized, then the keys must be uint32_t.
                        if (map_definition.key_size != sizeof(uint32_t)) {
                            throw bpf_code_generator_exception("map keys must be uint32_t for static initialization");
                        }
                        map_initial_values[unsafe_symbol_name].resize(value_count);
                    }
                }
            }
            map_definitions[unsafe_symbol_name] = {map_definition, index++};
        }

        // Extract any initial values for maps.
        // Maps are stored in the .maps section. The symbols for the .maps section gives the starting and ending offset
        // of each map. The relocations for the .maps section give the offset of the initial values for each map.
        // Each relocation record is a pair of (offset, symbol) where the symbol is the map value to insert.
        // To convert offset to index in the "values" field, the first step is to determine which map the offset is
        // for. This is done by finding the map whose range contains the offset. Then the offset is converted to an
        // index by subtracting the offset of the values array and dividing by the size of a pointer.
        // Finally the value is inserted into the map's initial values vector at the computed index.
        auto map_relocation_section = get_optional_section(".rel.maps");
        if (map_relocation_section) {
            ELFIO::const_symbol_section_accessor symbols{reader, get_required_section(".symtab")};
            ELFIO::const_relocation_section_accessor relocation_reader{reader, map_relocation_section};
            ELFIO::Elf_Xword relocation_count = relocation_reader.get_entries_num();
            for (ELFIO::Elf_Xword relocation_index = 0; relocation_index < relocation_count; relocation_index++) {
                ELFIO::Elf64_Addr offset{};
                ELFIO::Elf_Word symbol{};
                unsigned int type{};
                ELFIO::Elf_Sxword addend{};
                relocation_reader.get_entry(relocation_index, offset, symbol, type, addend);
                {
                    std::string unsafe_name{};
                    ELFIO::Elf64_Addr value{};
                    ELFIO::Elf_Xword size{};
                    unsigned char bind{};
                    unsigned char symbol_type{};
                    ELFIO::Elf_Half section_index{};
                    unsigned char other{};
                    if (!symbols.get_symbol(
                            symbol, unsafe_name, value, size, bind, symbol_type, section_index, other)) {
                        throw bpf_code_generator_exception("Can't perform relocation at offset ", offset);
                    }

                    // Determine which map this offset is in.
                    // The map_names_by_offset map is sorted by start and end offset of the map.
                    // The lower_bound function returns the first entry where the (start, end) offset is >=
                    // (offset, 0). Because this range has an invalid end offset, it will never be an exact match
                    // and will always return the first map that starts after the offset.
                    auto iter = map_names_by_offset.lower_bound(std::make_pair(offset, 0));

                    // Boundary conditions are:
                    // 1. The offset is before the first map -> iter == map_names_by_offset.begin()
                    // 2. The offset is after the last map -> iter == map_names_by_offset.end()

                    // map_names_by_offset cannot be empty because there is at least one map.

                    // Select the previous map if it exists.
                    if (iter != map_names_by_offset.begin()) {
                        iter--;
                    } else {
                        // If there is no previous map, then the offset is before the first map.
                        throw bpf_code_generator_exception("Can't perform relocation at offset ", offset);
                    }

                    // Sanity check that the offset is within the map range.
                    if (offset < iter->first.first || offset > iter->first.second) {
                        throw bpf_code_generator_exception("Can't perform relocation at offset ", offset);
                    }

                    auto map_name = iter->second;
                    // Convert the relocation offset into an index in the initial value array.
                    // iter->first.first is the start of map data in the .maps section.
                    // map_names_to_values_offset[map_name] is the offset of the values array in the map data.
                    // offset is from the start of the .maps section where the relocation is performed.
                    // The index is the offset from the start of the values array divided by the size of a pointer.
                    size_t value_array_start = iter->first.first + map_names_to_values_offset[map_name];
                    size_t value_array_index = (offset - value_array_start) / sizeof(uintptr_t);
                    if (value_array_index >= map_initial_values[map_name].size()) {
                        throw bpf_code_generator_exception("Can't perform relocation at offset ", offset);
                    }
                    map_initial_values[map_name][value_array_index] = unsafe_name;
                }
            }
        }
    }
}

// Parse global data (currently map information) in the eBPF file.
void
bpf_code_generator::parse()
{
    for (auto& section : reader.sections) {
        std::string name = section->get_name();
        if (_is_btf_map_section(name)) {
            parse_btf_maps_section(name);
        } else if (_is_legacy_map_section(name)) {
            parse_legacy_maps_section(name);
        }
    }
}

static std::tuple<std::string, ELFIO::Elf_Half>
_get_symbol_name_and_section_index(ELFIO::const_symbol_section_accessor& symbols, ELFIO::Elf_Xword index)
{
    std::string symbol_name;
    ELFIO::Elf64_Addr value{};
    ELFIO::Elf_Xword size{};
    unsigned char bind{};
    unsigned char type{};
    ELFIO::Elf_Half section_index{};
    unsigned char other{};
    symbols.get_symbol(index, symbol_name, value, size, bind, type, section_index, other);
    return {symbol_name, section_index};
}

// We should consider refactoring the code that parses ELF files into a form that can be used by both ebpf-verifier and
// bpf2c.
void
bpf_code_generator::parse_legacy_maps_section(const unsafe_string& name)
{
    auto map_section = get_optional_section(name);
    if (!map_section) {
        return;
    }

    // Count the number of symbols that point into this maps section.
    ELFIO::const_symbol_section_accessor symbols{reader, get_required_section(".symtab")};
    int map_count = 0;
    for (ELFIO::Elf_Xword index = 0; index < symbols.get_symbols_num(); index++) {
        auto [symbol_name, section_index] = _get_symbol_name_and_section_index(symbols, index);
        if ((section_index == map_section->get_index()) && !symbol_name.empty()) {
            map_count++;
        }
    }
    if (map_count == 0) {
        return;
    }

    size_t data_size = map_section->get_size();
    size_t map_record_size = data_size / map_count;
    if (map_record_size == 0) {
        return;
    }

    if (data_size % map_record_size != 0) {
        throw bpf_code_generator_exception(
            "bad maps section size, must be a multiple of " + std::to_string(map_record_size));
    }

    size_t old_map_count = map_definitions.size();
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
            if (symbol_size != map_record_size) {
                throw bpf_code_generator_exception("invalid map size");
            }
            if (symbol_value > map_section->get_size()) {
                throw bpf_code_generator_exception("invalid symbol value");
            }
            if ((symbol_value + symbol_size) > map_section->get_size()) {
                throw bpf_code_generator_exception("invalid symbol value");
            }

            // Copy the data from the record into an ebpf_map_definition_in_file_t structure,
            // zero-padding any extra, and being careful not to overflow the buffer.
            map_definitions[unsafe_symbol_name].definition = {};
            memcpy(
                &map_definitions[unsafe_symbol_name].definition,
                map_section->get_data() + symbol_value,
                min(sizeof(map_definitions[unsafe_symbol_name].definition), map_record_size));

            map_definitions[unsafe_symbol_name].index = old_map_count + (symbol_value / map_record_size);
        }
    }

    if (map_definitions.size() != old_map_count + map_count) {
        throw bpf_code_generator_exception("bad maps section, map must have associated symbol");
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

    std::vector<std::byte> btf_data(
        reinterpret_cast<const std::byte*>(btf->get_data()),
        reinterpret_cast<const std::byte*>(btf->get_data()) + btf->get_size());
    std::vector<std::byte> btf_ext_data(
        reinterpret_cast<const std::byte*>(btf_ext->get_data()),
        reinterpret_cast<const std::byte*>(btf_ext->get_data()) + btf_ext->get_size());

    libbtf::btf_parse_line_information(
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
        if (output.instruction.opcode == INST_OP_CALL) {
            continue;
        }
        if (output.instruction.opcode == INST_OP_EXIT) {
            continue;
        }
        int32_t offset =
            ((output.instruction.opcode == INST_OP_JA32) ? output.instruction.imm : output.instruction.offset);
        if ((i + offset + 1) >= program_output.size()) {
            throw bpf_code_generator_exception("invalid jump target", i);
        }
        program_output[i + offset + 1].jump_target = true;
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
        if (output.instruction.opcode != INST_OP_CALL) {
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
    // auto helper_array_prefix = program_name.c_identifier() + "_helpers[{}]";
    auto helper_array_prefix = "runtime_context->helper_data[{}]";

    // Encode instructions
    for (size_t i = 0; i < program_output.size(); i++) {
        auto& output = program_output[i];
        auto& inst = output.instruction;

        switch (inst.opcode & INST_CLS_MASK) {
        case INST_CLS_ALU:
        case INST_CLS_ALU64: {
            std::string destination = get_register_name(inst.dst);
            std::string source;
            if (inst.opcode & INST_SRC_REG) {
                source = get_register_name(inst.src);
            } else {
                source = "IMMEDIATE(" + std::to_string(inst.imm) + ")";
            }
            bool is64bit = (inst.opcode & INST_CLS_MASK) == INST_CLS_ALU64;
            AluOperations operation = static_cast<AluOperations>(inst.opcode >> 4);
            std::string swap_function;
            std::string type;
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
                    type = (inst.offset == 1) ? "(int64_t)" : "";
                    output.lines.push_back(std::format(
                        "{} = {} ? ({}{} / {}{}) : 0;", destination, source, type, destination, type, source));
                } else {
                    type = (inst.offset == 1) ? "(int32_t)" : "(uint32_t)";
                    output.lines.push_back(std::format(
                        "{} = (uint32_t){} ? {}{} / {}{} : 0;", destination, source, type, destination, type, source));
                }
                break;
            case AluOperations::Or:
                output.lines.push_back(std::format("{} |= {};", destination, source));
                break;
            case AluOperations::And:
                output.lines.push_back(std::format("{} &= {};", destination, source));
                break;
            case AluOperations::Lsh:
                if (is64bit) {

                    // Shifts of >= 64 bits on 64-bit values result in undefined behavior so mask off the msb of the
                    // shift size, i.e., the 'source' in this case.
                    // Note: The 'duplication' of the following two lines for the 32-bit variant is deliberate as this
                    // allows the use of the (applicable) native size for the shift_mask variable, thus doing away with
                    // 'casting' that would otherwise be required. This also makes the code more readable.
                    uint64_t shift_mask = 0x3F;
                    output.lines.push_back(std::format("{} <<= ({} & {});", destination, source, shift_mask));
                } else {

                    // Shifts of >= 32 bits on 32-bit values result in undefined behavior so mask off the msb of the
                    // shift size, i.e., the 'source' in this case.
                    uint32_t shift_mask = 0x1F;
                    output.lines.push_back(std::format("{} <<= ({} & {});", destination, source, shift_mask));
                }
                break;
            case AluOperations::Rsh:
                if (is64bit) {

                    // Shifts of >= 64 bits on 64-bit values result in undefined behavior so mask off the msb of the
                    // shift size, i.e., the 'source' in this case.
                    // Note: The 'duplication' of the following two lines for the 32-bit variant is deliberate as this
                    // allows the use of the (applicable) native size for the shift_mask variable, thus doing away with
                    // 'casting' that would otherwise be required. This also makes the code more readable.
                    uint64_t shift_mask = 0x3F;
                    output.lines.push_back(std::format("{} >>= ({} & {});", destination, source, shift_mask));
                } else {

                    // Shifts of >= 32 bits on 32-bit values result in undefined behavior so mask off the msb of the
                    // shift size, i.e., the 'source' in this case.
                    // The one 'uint32_t' cast here is required to truncate the destination register's initial value to
                    // 32 bits prior to using it, given that this is a 32-bit rsh operation.
                    uint32_t shift_mask = 0x1F;
                    output.lines.push_back(std::format("{} = (uint32_t){};", destination, destination));
                    output.lines.push_back(std::format("{} >>= ({} & {});", destination, source, shift_mask));
                }
                break;
            case AluOperations::Neg:
                output.lines.push_back(std::format("{} = -(int64_t){};", destination, destination));
                break;
            case AluOperations::Mod:
                if (is64bit) {
                    type = (inst.offset == 1) ? "(int64_t)" : "";
                    output.lines.push_back(std::format(
                        "{} = {} ? ({}{} % {}{}) : {}{};",
                        destination,
                        source,
                        type,
                        destination,
                        type,
                        source,
                        type,
                        destination));
                } else {
                    type = (inst.offset == 1) ? "(int32_t)" : "(uint32_t)";
                    output.lines.push_back(std::format(
                        "{} = (uint32_t){} ? ({}{} % {}{}) : {}{};",
                        destination,
                        source,
                        type,
                        destination,
                        type,
                        source,
                        type,
                        destination));
                }
                break;
            case AluOperations::Xor:
                output.lines.push_back(std::format("{} ^= {};", destination, source));
                break;
            case AluOperations::Mov:
                type = (is64bit) ? "(uint64_t)(int64_t)" : "(uint32_t)(int32_t)";
                switch (inst.offset) {
                case 0:
                    output.lines.push_back(std::format("{} = {};", destination, source));
                    break;
                case 8:
                    output.lines.push_back(std::format("{} = {}(int8_t){};", destination, type, source));
                    break;
                case 16:
                    output.lines.push_back(std::format("{} = {}(int16_t){};", destination, type, source));
                    break;
                case 32:
                    output.lines.push_back(std::format("{} = {}(int32_t){};", destination, type, source));
                    break;
                default:
                    throw bpf_code_generator_exception("invalid operand", output.instruction_offset);
                }
                break;
            case AluOperations::Arsh:
                if (is64bit) {
                    uint64_t shift_mask = 0x3F;
                    output.lines.push_back(std::format(
                        "{} = (int64_t){} >> (uint32_t)({} & {});", destination, destination, source, shift_mask));
                } else {
                    uint32_t shift_mask = 0x1F;
                    output.lines.push_back(std::format("{} = (int32_t){};", destination, destination));
                    output.lines.push_back(std::format(
                        "{} = (int32_t){} >> (uint32_t)({} & {});", destination, destination, source, shift_mask));
                }
                break;
            case AluOperations::ByteOrder: {
                std::string size_type = "";
                if ((inst.opcode & INST_CLS_MASK) == INST_CLS_ALU64) {
                    if (output.instruction.opcode & INST_END_BE) {
                        throw bpf_code_generator_exception("invalid operand", output.instruction_offset);
                    } else {
                        switch (inst.imm) {
                        case 16:
                            swap_function = "swap16";
                            size_type = "uint16_t";
                            break;
                        case 32:
                            swap_function = "swap32";
                            size_type = "uint32_t";
                            break;
                        case 64:
                            is64bit = true;
                            swap_function = "swap64";
                            size_type = "uint64_t";
                            break;
                        default:
                            throw bpf_code_generator_exception("invalid operand", output.instruction_offset);
                        }
                    }
                } else if (output.instruction.opcode & INST_END_BE) {
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
                        swap_function = "htobe64";
                        size_type = "uint64_t";
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
        case INST_CLS_LD: {
            i++;
            if (inst.opcode != INST_OP_LDDW_IMM) {
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
                source =
                    std::format("runtime_context->map_data[{}].address", std::to_string(map_definition->second.index));
                output.lines.push_back(std::format("{} = POINTER({});", destination, source));
                current_section->referenced_map_indices.insert(map_definitions[output.relocation].index);
            }
        } break;
        case INST_CLS_LDX: {
            std::string size_type;
            std::string destination = get_register_name(inst.dst);
            std::string source = get_register_name(inst.src);
            std::string offset = "OFFSET(" + std::to_string(inst.offset) + ")";
            switch (inst.opcode & INST_SIZE_DW) {
            case INST_SIZE_B:
                size_type = "uint8_t";
                break;
            case INST_SIZE_H:
                size_type = "uint16_t";
                break;
            case INST_SIZE_W:
                size_type = "uint32_t";
                break;
            case INST_SIZE_DW:
                size_type = "uint64_t";
                break;
            default:
                throw bpf_code_generator_exception("invalid operand", output.instruction_offset);
            }
            output.lines.push_back(
                std::format("{} = *({}*)(uintptr_t)({} + {});", destination, size_type, source, offset));
        } break;
        case INST_CLS_ST:
        case INST_CLS_STX: {
            std::string size_type;
            std::string lock_type;
            std::string size_num;
            std::string destination = get_register_name(inst.dst);
            std::string source;
            std::string raw_source;
            bool is_complex = false;
            if ((inst.opcode & INST_CLS_MASK) == INST_CLS_ST) {
                source = "IMMEDIATE(" + std::to_string(inst.imm) + ")";
            } else {
                source = get_register_name(inst.src);
            }
            std::string offset = "OFFSET(" + std::to_string(inst.offset) + ")";
            switch (inst.opcode & INST_SIZE_DW) {
            case INST_SIZE_B:
                size_type = "uint8_t";
                break;
            case INST_SIZE_H:
                size_type = "uint16_t";
                break;
            case INST_SIZE_W:
                size_type = "uint32_t";
                lock_type = "volatile long";
                break;
            case INST_SIZE_DW:
                size_num = "64";
                size_type = "uint64_t";
                lock_type = "volatile int64_t";
                break;
            default:
                throw bpf_code_generator_exception("invalid operand", output.instruction_offset);
            }
            raw_source = source;
            source = "(" + size_type + ")" + source;
            if ((inst.opcode & INST_MODE_MASK) == EBPF_MODE_ATOMIC) {
                auto line = std::string("");
                switch (inst.imm) {
                case EBPF_ATOMIC_ADD:
                case EBPF_ATOMIC_ADD_FETCH:
                    line = std::format(
                        "InterlockedExchangeAdd{}(({}*)(uintptr_t)({} + {}), {});",
                        size_num,
                        lock_type,
                        destination,
                        offset,
                        source);
                    break;
                case EBPF_ATOMIC_OR:
                case EBPF_ATOMIC_OR_FETCH:
                    line = std::format(
                        "InterlockedOr{}(({}*)(uintptr_t)({} + {}), {});",
                        size_num,
                        lock_type,
                        destination,
                        offset,
                        source);
                    break;
                case EBPF_ATOMIC_AND:
                case EBPF_ATOMIC_AND_FETCH:
                    line = std::format(
                        "InterlockedAnd{}(({}*)(uintptr_t)({} + {}), {});",
                        size_num,
                        lock_type,
                        destination,
                        offset,
                        source);
                    break;
                case EBPF_ATOMIC_XOR:
                case EBPF_ATOMIC_XOR_FETCH:
                    line = std::format(
                        "InterlockedXor{}(({}*)(uintptr_t)({} + {}), {});",
                        size_num,
                        lock_type,
                        destination,
                        offset,
                        source);
                    break;
                case EBPF_ATOMIC_XCHG:
                    is_complex = true;
                    line = std::format(
                        "InterlockedExchange{}(({}*)(uintptr_t)({} + {}), {});",
                        size_num,
                        lock_type,
                        destination,
                        offset,
                        source);
                    break;
                case EBPF_ATOMIC_CMPXCHG:
                    is_complex = true;
                    line = std::format(
                        "r0 = ({})InterlockedCompareExchange{}(({}*)(uintptr_t)({} + {}), {}, r0);",
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
            } else if ((inst.opcode & INST_MODE_MASK) == EBPF_MODE_MEM) {
                output.lines.push_back(
                    std::format("*({}*)(uintptr_t)({} + {}) = {};", size_type, destination, offset, source));
            } else {
                throw bpf_code_generator_exception("invalid atomic mode", inst.opcode & INST_MODE_MASK);
            }
        } break;
        case INST_CLS_JMP:
        case INST_CLS_JMP32: {
            std::string destination = get_register_name(inst.dst);
            std::string destination_cast;
            if (IS_JMP32_CLASS_OPCODE(inst.opcode)) {
                destination_cast = IS_SIGNED_CMP_OPCODE(inst.opcode) ? "(int32_t)" : "(uint32_t)";
            } else {
                destination_cast = IS_SIGNED_CMP_OPCODE(inst.opcode) ? "(int64_t)" : "";
            }

            std::string source;
            std::string source_cast;
            if (inst.opcode & INST_SRC_REG) {
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
            if (inst.opcode == INST_OP_JA16) {
                std::string target = program_output[i + inst.offset + 1].label;
                output.lines.push_back("goto " + target + ";");
            } else if (inst.opcode == INST_OP_JA32) {
                std::string target = program_output[i + inst.imm + 1].label;
                output.lines.push_back("goto " + target + ";");
            } else if (inst.opcode == INST_OP_CALL) {
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
                output.lines.push_back(
                    get_register_name(0) + " = " + function_name + ".address(" + get_register_name(1) + ", " +
                    get_register_name(2) + ", " + get_register_name(3) + ", " + get_register_name(4) + ", " +
                    get_register_name(5) + ");");
                output.lines.push_back(
                    std::format("if (({}.tail_call) && ({} == 0)) {{", function_name, get_register_name(0)));
                output.lines.push_back(INDENT "return 0;");
                output.lines.push_back("}");
            } else if (inst.opcode == INST_OP_EXIT) {
                output.lines.push_back("return " + get_register_name(0) + ";");
            } else {
                std::string target = program_output[i + inst.offset + 1].label;
                if (target.empty()) {
                    throw bpf_code_generator_exception("invalid jump target", output.instruction_offset);
                }

                std::string predicate =
                    vformat(format, make_format_args(destination_cast, destination, source_cast, source));
                output.lines.push_back(vformat("if ({}) {{", make_format_args(predicate)));
                output.lines.push_back(vformat(INDENT "goto {};", make_format_args(target)));
                output.lines.push_back("}");
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

            output_stream << INDENT "{0," << std::endl;
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
                output_stream << INDENT "{" << id << ", " << helper_name.quoted() << "}," << std::endl;
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

        auto result = std::find_if(line_info.begin(), line_info.end(), [&prolog_line_info](const auto& pair) {
            if (pair.second.file_name.empty() || pair.second.line_number == 0) {
                return false;
            }
            prolog_line_info = std::format(
                "#line {} {}\n", std::to_string(pair.second.line_number), pair.second.file_name.quoted_filename());
            return true;
        });

        // Emit entry point
        output_stream << "#pragma code_seg(push, " << section.pe_section_name.quoted() << ")" << std::endl;
        output_stream << std::format(
                             "static uint64_t\n{}(void* context, const program_runtime_context_t* runtime_context)",
                             program_name.c_identifier())
                      << std::endl;
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
        if (section.referenced_map_indices.size() == 0 && section.helper_functions.size() == 0) {
            output_stream << prolog_line_info << INDENT "UNREFERENCED_PARAMETER(runtime_context);" << std::endl;
        }
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
                // Append the hash type
                std::string hash_string = program.program_info_hash_type;
                if (hash_string.empty()) {
                    // If the hash type is not known, use the default hash type.
                    hash_string = EBPF_HASH_ALGORITHM;
                    program.program_info_hash_type = hash_string;
                }
                output_stream << INDENT INDENT << "\"" << hash_string << "\""
                              << "," << std::endl;
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

    std::string version_major = std::to_string(EBPF_VERSION_MAJOR);
    std::string version_minor = std::to_string(EBPF_VERSION_MINOR);
    std::string version_revision = std::to_string(EBPF_VERSION_REVISION);

    output_stream << "static void" << std::endl
                  << "_get_version(_Out_ bpf2c_version_t* version)" << std::endl
                  << "{" << std::endl
                  << INDENT "version->major = " << version_major << ";" << std::endl
                  << INDENT "version->minor = " << version_minor << ";" << std::endl
                  << INDENT "version->revision = " << version_revision << ";" << std::endl
                  << "}" << std::endl
                  << std::endl;

    if (!map_initial_values.empty()) {
        output_stream << "#pragma data_seg(push, \"map_initial_values\")" << std::endl;
        for (const auto& [name, map_values] : map_initial_values) {
            std::string map_name = name.c_identifier();
            std::string map_initial_values_name = "_" + map_name + "_initial_string_table[]";
            output_stream << "// clang-format off" << std::endl;
            output_stream << "static const char* " << map_initial_values_name << " = {" << std::endl;
            for (const auto& value : map_values) {
                if (value.empty()) {
                    output_stream << INDENT << "NULL," << std::endl;
                } else {
                    output_stream << INDENT << value.quoted() << "," << std::endl;
                }
            }
            output_stream << "};" << std::endl;
            output_stream << "// clang-format on" << std::endl;
            output_stream << std::endl;
        }

        // Emit a static array of map_initial_values_t for each map.
        output_stream << "static map_initial_values_t _map_initial_values_array[] = {" << std::endl;
        for (const auto& [name, values] : map_initial_values) {
            output_stream << INDENT "{" << std::endl;
            output_stream << INDENT INDENT << ".name = " << name.quoted() << "," << std::endl;
            output_stream << INDENT INDENT << ".count = " << values.size() << "," << std::endl;
            output_stream << INDENT INDENT << ".values = "
                          << "_" << name.c_identifier() << "_initial_string_table"
                          << "," << std::endl;
            output_stream << INDENT "}," << std::endl;
        }
        output_stream << "};" << std::endl;
        output_stream << "#pragma data_seg(pop)" << std::endl;
        output_stream << std::endl;
    }

    // Emit _get_map_initial_values function.
    output_stream << "static void" << std::endl
                  << "_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** "
                     "map_initial_values, _Out_ size_t* count)"
                  << std::endl;
    output_stream << "{" << std::endl;
    if (map_initial_values.size() != 0) {
        output_stream << INDENT "*map_initial_values = _map_initial_values_array;" << std::endl;
    } else {
        output_stream << INDENT "*map_initial_values = NULL;" << std::endl;
    }
    output_stream << INDENT "*count = " << std::to_string(map_initial_values.size()) << ";" << std::endl;
    output_stream << "}" << std::endl;
    output_stream << std::endl;

    std::string meta_data_table = "metadata_table_t " + c_name.c_identifier() + "_metadata_table = {";
    meta_data_table +=
        "sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};\n";

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
