// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include <map>
#include <set>
#include <string>
#include <vector>

#include "btf_parser.h"
#include "ebpf.h"
#include "ebpf_structs.h"
#pragma warning(push)
#pragma warning(disable : 4458) /* declaration of 'name' hides class member */
#include "elfio/elfio.hpp"
#pragma warning(pop)

class bpf_code_generator
{
  public:
    /**
     * @brief Construct a new bpf code generator object.
     *
     * @param[in] path Path to the eBPF file to parse.
     * @param[in] c_name C compatible name to export this as.
     */
    bpf_code_generator(const std::string& path, const std::string& c_name);

    /**
     * @brief Construct a new bpf code generator object from raw eBPF byte code.
     *
     * @param[in] c_name C compatible name to export this as.
     * @param[in] instructions Set of eBPF instructions to use.
     */
    bpf_code_generator(const std::string& c_name, const std::vector<ebpf_inst>& instructions);

    /**
     * @brief Retrieve a vector of section names.
     *
     * @return Vector of section names.
     */
    std::vector<std::string>
    program_sections();

    /**
     * @brief Parse the eBPF file.
     *
     * @param[in] section_name Section in the ELF file to parse.
     */
    void
    parse(const std::string& section_name);

    /**
     * @brief Generate C code from the parsed eBPF file.
     *
     */
    void
    generate();

    /**
     * @brief Emit the C code to a given output stream.
     *
     * @param[in] output Output stream to write code to.
     */
    void
    emit_c_code(std::ostream& output);

  private:
    typedef struct _helper_function
    {
        int32_t id;
        size_t index;
    } helper_function_t;

    typedef struct _map_entry
    {
        ebpf_map_definition_in_file_t definition;
        size_t index;
    } map_entry_t;

    typedef struct _output_instruction
    {
        ebpf_inst instruction = {};
        uint32_t instruction_offset;
        bool jump_target = false;
        std::string label;
        std::vector<std::string> lines;
        std::string relocation;
    } output_instruction_t;

    typedef struct _section
    {
        std::vector<output_instruction_t> output;
        std::set<std::string> referenced_registers;
        std::string function_name;
    } section_t;

    /**
     * @brief Extract the eBPF byte code from the eBPF file.
     *
     */
    void
    extract_program(const std::string& section_name);

    /**
     * @brief Extract the helper function and map relocation data from the eBPF file.
     *
     */
    void
    extract_relocations_and_maps(const std::string& section_name);

    /**
     * @brief Extract the mapping from instruction offset to line number.
     *
     */
    void
    extract_btf_information();

    /**
     * @brief Assign a label to each jump target.
     *
     */
    void
    generate_labels();

    /**
     * @brief Extract list of helper functions called by this program.
     *
     */
    void
    build_function_table();

    /**
     * @brief Generate the C code for each eBPF instruction.
     *
     */
    void
    encode_instructions();

    /**
     * @brief Format a string and insert up to 4 strings in it.
     *
     * @param[in] format Format string.
     * @param[in] insert_1 First string to insert.
     * @param[in] insert_2 Second string to insert or empty.
     * @param[in] insert_3 Third string to insert or empty.
     * @param[in] insert_4 Fourth string to insert or empty.
     * @return The formatted string.
     */
    std::string
    format_string(
        const std::string& format,
        const std::string insert_1,
        const std::string insert_2 = "",
        const std::string insert_3 = "",
        const std::string insert_4 = "");

    /**
     * @brief Convert a name to a valid C identifier.
     *
     * @param[in] name Name to convert to C identifier.
     * @return A valid C identifier
     */
    std::string
    sanitize_name(const std::string& name);

    /**
     * @brief Replace all "\"" with "\\" in a string.
     *
     * @param[in] input String to escape.
     * @return Escaped string.
     */
    std::string
    escape_string(const std::string& input);

    /**
     * @brief Get the name of a register from its index.
     *
     * @param[in] id Register index.
     * @return Register name
     */
    std::string
    get_register_name(uint8_t id);

    std::map<std::string, section_t> sections;
    section_t* current_section;
    ELFIO::elfio reader;
    std::map<std::string, helper_function_t> helper_functions;
    std::map<std::string, map_entry_t> map_definitions;
    std::string c_name;
    std::string path;
    btf_section_to_instruction_to_line_info_t section_line_info;
};
