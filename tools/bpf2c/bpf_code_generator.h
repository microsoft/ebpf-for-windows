// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include <map>
#include <string>
#include <vector>
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
    typedef struct _output_instruction
    {
        ebpf_inst instruction = {};
        bool jump_target = false;
        std::string label;
        std::vector<std::string> lines;
        std::string relocation;
    } output_instruction_t;

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

    /**
     * @brief Extract the eBPF byte code from the eBPF file.
     *
     */
    void
    extract_program();

    /**
     * @brief Extract the helper function and map relocation data from the eBPF file.
     *
     */
    void
    extract_relocations_and_maps();

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

    std::string
    sanitize_name(const std::string& name);

    std::vector<output_instruction_t> program_output;
    std::map<std::string, std::vector<output_instruction_t>> programs;
    ELFIO::elfio reader;
    std::map<std::string, helper_function_t> functions;
    std::map<std::string, map_entry_t> map_definitions;
    std::string c_name;
    std::string path;
    std::string section_name;
};
