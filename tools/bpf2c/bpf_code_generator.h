// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "ebpf.h"
#include "ebpf_structs.h"
#include "elfio_wrapper.hpp"

class bpf_code_generator
{
  public:
    /**
     * @brief Class to encapsulate a string read from an ELF file that may be
     * malicious.
     */
    class unsafe_string
    {
      public:
        unsafe_string() = default;
        unsafe_string(const std::string& safe) : unsafe(safe) {}
        unsafe_string(const char* safe) : unsafe(safe) {}

        /**
         * @brief Convert ELF supplied string to a C style identifier.
         *
         * @return A C style identifier.
         */
        std::string
        c_identifier() const
        {
            std::string safe = unsafe;
            for (auto& c : safe) {
                // Replace all extended ascii characters and all non-alphanumeric characters with _.
                if (c < 0 || !isalnum(c)) {
                    c = '_';
                }
            }
            return safe;
        }

        /**
         * @brief Return the unmodified string. Use with caution.
         *
         * @return The unmodified string. Potentially malicious.
         */
        std::string
        raw() const
        {
            return unsafe;
        }

        /**
         * @brief Return the string as a quoted C string.
         *
         * @return A version of the string with inner quotes escaped and
         * enclosed in quotes.
         */
        std::string
        quoted() const
        {
            return std::string("\"") + replace_char([](char c) -> std::string {
                       if (c == '"') {
                           return "\"";
                       } else {
                           return std::string(1, c);
                       }
                   }) +
                   std::string("\"");
        }

        /**
         * @brief Return the string as a quoted file name.
         *
         * @return A version of the string with inner quotes escaped and
         * enclosed in quotes.
         */
        std::string
        quoted_filename() const
        {
            return std::string("\"") + replace_char([](char c) -> std::string {
                       if (c == '\\') {
                           return "\\\\";
                       } else if (c == '"') {
                           return "\"";
                       } else {
                           return std::string(1, c);
                       }
                   }) +
                   std::string("\"");
        }

        unsafe_string
        operator+(const unsafe_string& other)
        {
            return unsafe + other.unsafe;
        }

        unsafe_string
        operator+=(const unsafe_string& other)
        {
            unsafe += other.unsafe;
            return unsafe;
        }

        bool
        operator==(const unsafe_string& other) const
        {
            return other.unsafe == unsafe;
        }

        bool
        operator!=(const unsafe_string& other) const
        {
            return other.unsafe != unsafe;
        }

        bool
        operator<(const unsafe_string& other) const
        {
            return unsafe < other.unsafe;
        }

        bool
        empty() const
        {
            return unsafe.empty();
        }

        size_t
        length() const
        {
            return unsafe.length();
        }

      private:
        std::string unsafe;

        /**
         * @brief Apply the supplied function to each character in the string.
         *
         * @param[in] replace Function to be applied
         * @return Transformed string.
         */
        std::string
        replace_char(std::function<std::string(char c)> replace) const
        {
            std::string replaced;
            for (const auto& c : unsafe) {
                replaced += replace(c);
            }
            return replaced;
        }
    };

    /**
     * @brief Wrapper around std::runtime_error to permit interop with unsafe_string.
     *
     */
    class bpf_code_generator_exception : public std::runtime_error
    {
      public:
        /**
         * @brief Construct a new instance using unsafe string as message.
         *
         * @param[in] what Message describing the error.
         */
        bpf_code_generator_exception(const unsafe_string& what) : std::runtime_error(what.raw()) {}

        /**
         * @brief Construct a new instance using unsafe string as message with an offset.
         *
         * @param[in] what Message describing the error.
         * @param[in] offset Where the error occurred. Meaning is dependent on the context.
         */
        bpf_code_generator_exception(const unsafe_string& what, size_t offset)
            : std::runtime_error(what.raw() + " at offset " + std::to_string(offset))
        {}
    };

    /**
     * @brief Construct a new bpf code generator object.
     *
     * @param[in] stream Input stream containing the eBPF file to parse.
     * @param[in] c_name C compatible name to export this as.
     * @param[in] elf_file_hash Optional bytes containing hash of the ELF file.
     */
    bpf_code_generator(
        std::istream& stream,
        const unsafe_string& c_name,
        const std::optional<std::vector<uint8_t>>& elf_file_hash = {});

    /**
     * @brief Construct a new bpf code generator object from raw eBPF byte code.
     *
     * @param[in] c_name C compatible name to export this as.
     * @param[in] instructions Set of eBPF instructions to use.
     */
    bpf_code_generator(const unsafe_string& c_name, const std::vector<ebpf_inst>& instructions);

    /**
     * @brief Retrieve a vector of section names.
     *
     * @return Vector of section names.
     */
    std::vector<unsafe_string>
    program_sections();

    /**
     * @brief Parse the eBPF file.
     *
     * @param[in] section_name Section in the ELF file to parse.
     * @param[in] program_type Program type GUID for the section.
     * @param[in] attach_type Expected attach type GUID for the section.
     * @param[in] program_info_hash Optional bytes containing hash of the program info.
     */
    void
    parse(
        const unsafe_string& section_name,
        const GUID& program_type,
        const GUID& attach_type,
        const std::optional<std::vector<uint8_t>>& program_info_hash);

    /**
     * @brief Parse global data (currently map information) in the eBPF file.
     *
     */
    void
    parse();

    /**
     * @brief Generate C code from the parsed eBPF file.
     *
     * @param[in] section_name Section in the ELF file to generate C code for.
     */
    void
    generate(const unsafe_string& section_name);

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
        unsafe_string relocation;
    } output_instruction_t;

    typedef struct _section
    {
        std::vector<output_instruction_t> output;
        std::set<std::string> referenced_registers;
        unsafe_string pe_section_name;
        unsafe_string program_name;
        GUID program_type = {0};
        GUID expected_attach_type = {0};
        std::optional<std::vector<uint8_t>> program_info_hash;
        // Indices of the maps used in this section.
        std::set<size_t> referenced_map_indices;
        std::map<unsafe_string, helper_function_t> helper_functions;
    } section_t;

    typedef struct _line_info
    {
        unsafe_string file_name;
        unsafe_string source_line;
        uint32_t line_number = {};
        uint32_t column_number = {};
    } line_info_t;

    typedef std::map<unsafe_string, std::map<size_t, line_info_t>> btf_section_to_instruction_to_line_info_t;
    /**
     * @brief Extract the eBPF byte code from the eBPF file.
     *
     */
    void
    extract_program(const unsafe_string& section_name);

    /**
     * @brief Set the program and attach type for the current section.
     *
     * @param[in] program_type Program type GUID.
     * @param[in] attach_type Attach type GUID.
     * @param[in] program_info_hash Hash of the program information used to verify this program.
     */
    void
    set_program_and_attach_type_and_hash(
        const GUID& program_type,
        const GUID& attach_type,
        const std::optional<std::vector<uint8_t>>& program_info_hash);

    /**
     * @brief Extract the helper function and map relocation data from the eBPF file.
     *
     */
    void
    extract_relocations_and_maps(const unsafe_string& section_name);

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
    encode_instructions(const unsafe_string& section_name);

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

#if defined(_MSC_VER)
    /**
     * @brief Format a GUID as a string.
     *
     * @param[in] guid Pointer to the GUID to be formatted.
     * @param[in] split Split the string at the open {.
     * @return The formatted string.
     */
    std::string
    format_guid(const GUID* guid, bool split);
#endif

    /**
     * @brief Convert an ELF section name to a valid PE section name.
     *
     * @param[in] name Name to convert to PE section name.
     */
    void
    set_pe_section_name(const unsafe_string& elf_section_name);

    /**
     * @brief Get the name of a register from its index.
     *
     * @param[in] id Register index.
     * @return Register name
     */
    std::string
    get_register_name(uint8_t id);

    ELFIO::section*
    get_required_section(const unsafe_string& name);

    ELFIO::section*
    get_optional_section(const unsafe_string& name);

    bool
    is_section_valid(const ELFIO::section* section);

    int pe_section_name_counter;
    std::map<unsafe_string, section_t> sections;
    section_t* current_section;
    ELFIO::elfio reader;
    std::map<unsafe_string, map_entry_t> map_definitions;
    unsafe_string c_name;
    unsafe_string path;
    btf_section_to_instruction_to_line_info_t section_line_info;
    std::optional<std::vector<uint8_t>> elf_file_hash;
};
