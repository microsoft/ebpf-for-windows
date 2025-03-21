// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf.h"
#include "ebpf_program_types.h"
#include "ebpf_structs.h"
#include "elfio_wrapper.hpp"

#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

// The CNG algorithm name to use must be listed in
// https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers
#define EBPF_HASH_ALGORITHM "SHA256"

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
        {
        }
    };

    /**
     * @brief Construct a new bpf code generator object from an ELF file.
     *
     * @param[in] stream Input stream containing the eBPF file to parse.
     * @param[in] file_name C compatible name to export this as.
     * @param[in] elf_file_hash Optional bytes containing hash of the ELF file.
     */
    bpf_code_generator(
        std::istream& stream,
        const unsafe_string& file_name,
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
    program_sections() const;

    /**
     * @brief Parse the eBPF file.
     *
     * @param[in] program Program to parse.
     * @param[in] program_info Program information object.
     * @param[in] program_type Program type GUID for the program.
     * @param[in] attach_type Expected attach type GUID for the program.
     * @param[in] program_info_hash_type Optional bytes containing hash type of the program info.
     * @param[in] infos Program infos for the rest of the file.
     */
    void
    parse(
        _In_ const struct _ebpf_api_program_info* program,
        _In_ const ebpf_program_info_t* program_info,
        const GUID& program_type,
        const GUID& attach_type,
        const std::string& program_info_hash_type,
        _In_ const struct _ebpf_api_program_info* infos);

    /**
     * @brief Parse global data (currently map information) in the eBPF file.
     *
     */
    void
    parse_global_data();

    /**
     * @brief Parse BTF map information in the eBPF file.
     *
     * @param[in] section_name Section in the ELF file to parse maps in.
     */
    void
    parse_btf_maps_section(const unsafe_string& name);

    /**
     * @brief Parse BTF map information in the eBPF file.
     *
     * @param[in] section_name Section in the ELF file to parse maps in.
     */
    void
    parse_btf_global_variable_section(const unsafe_string& name);

    /**
     * @brief Parse legacy map information in the eBPF file.
     *
     * @param[in] section_name Section in the ELF file to parse maps in.
     */
    void
    parse_legacy_maps_section(const unsafe_string& name);

    /**
     * @brief Emit the C code to a given output stream.
     *
     * @param[in] output Output stream to write code to.
     */
    void
    emit_c_code(std::ostream& output);

    /**
     * @brief Get the helper function ids used by the current program.
     *
     * @param[in] program_name Name of program to get helper ids for.
     * @return Vector of helper ids.
     */
    std::vector<int32_t>
    get_helper_ids(const unsafe_string& program_name);

    /**
     * @brief Set the program hash info object
     *
     * @param program_name Name of program to set info on.
     * @param program_info_hash Optional bytes containing hash of the program info.
     */
    void
    set_program_hash_info(
        const unsafe_string& program_name, const std::optional<std::vector<uint8_t>>& program_info_hash);

  private:
    typedef struct _helper_function
    {
        int32_t id;
        size_t index;
    } helper_function_t;

    typedef struct _map_info
    {
        ebpf_map_definition_in_file_t definition;
        size_t index;
    } map_info_t;

    typedef struct _output_instruction
    {
        ebpf_inst instruction = {};
        uint32_t instruction_offset;
        bool jump_target = false;
        std::string label;
        std::vector<std::string> lines;
        unsafe_string relocation;
    } output_instruction_t;

    typedef struct _line_info
    {
        unsafe_string file_name;
        unsafe_string source_line;
        uint32_t line_number = {};
        uint32_t column_number = {};
    } line_info_t;

    typedef std::map<unsafe_string, std::map<size_t, line_info_t>> btf_section_to_instruction_to_line_info_t;
    typedef std::function<void(
        const unsafe_string& name,
        ELFIO::Elf64_Addr value,
        unsigned char binding,
        unsigned char type,
        ELFIO::Elf_Xword size)>
        symbol_visitor_t;

    typedef struct _global_variable_section
    {
        size_t index;
        std::vector<uint8_t> initial_data;
    } global_variable_section_t;

    class bpf_code_generator_program
    {
      public:
        std::vector<output_instruction_t> output_instructions;
        std::set<std::string> referenced_registers;
        struct _ebpf_api_program_info* api_program_info{};
        unsafe_string elf_section_name;
        unsafe_string pe_section_name;
        size_t offset_in_section; // Byte offset of program in section.
        unsafe_string program_name;
        GUID program_type = {0};
        GUID expected_attach_type = {0};
        std::optional<std::vector<uint8_t>> program_info_hash;
        // Indices of the maps used in this program.
        std::set<size_t> referenced_map_indices;
        std::map<unsafe_string, helper_function_t> helper_functions;
        std::string program_info_hash_type{};
        const ebpf_program_info_t* program_info = nullptr;

        /**
         * @brief Assign a label to each jump target.
         */
        void
        generate_labels();

        /**
         * @brief Extract list of helper functions called by this program.
         */
        void
        build_function_table();

        /**
         * @brief Generate the C code for each eBPF instruction.
         *
         * @param[in] map_definitions Map definitions.
         */
        void
        encode_instructions(
            std::map<unsafe_string, map_info_t>& map_definitions,
            std::map<unsafe_string, global_variable_section_t>& global_variable_sections);

        /**
         * @brief Get the name of a register from its index.
         *
         * @param[in] id Register index.
         * @return Register name.
         */
        std::string
        get_register_name(uint8_t id);

        /**
         * @brief Set the program and attach type for the current program.
         *
         * @param[in] program_type Program type GUID.
         * @param[in] attach_type Attach type GUID.
         * @param[in] program_info_hash_type Hash algorithm used for program info hash.
         */
        void
        set_program_and_attach_type_and_hash_type(
            const GUID& program_type, const GUID& attach_type, const std::string& program_info_hash_type);

        /**
         * @brief Emit encoded instructions.
         *
         * @param[in] output Output stream to write code to.
         * @param[in] line_info Line info.
         */
        void
        emit_instructions(std::ostream& output_stream, std::map<size_t, line_info_t>& line_info) const;
    };

    /**
     * @brief Add a program to the current section.
     *
     * @param[in] program_name Program name.
     * @param[in] elf_section_name ELF section name.
     * @param[in] offset_in_section Offset in bytes into the ELF section where the program bytecode begins.
     */
    bpf_code_generator_program*
    add_program(const unsafe_string& program_name, const unsafe_string& elf_section_name, size_t offset_in_section);

    /**
     * @brief Generate C code from the parsed eBPF file.
     *
     * @param[in] program_name Program in the ELF file to generate C code for.
     */
    void
    generate(const bpf_code_generator::unsafe_string& program_name);

    /**
     * @brief Check whether a progam is just a subprogram.
     *
     * @param[in] program Program to check.
     */
    bool
    is_subprogram(const bpf_code_generator_program& program) const;

    /**
     * @brief Extract the eBPF byte code from the eBPF program.
     *
     * @param[in] program Program to extract.
     * @param[in] infos Other programs in the file, including any subprograms.
     */
    void
    extract_program(const struct _ebpf_api_program_info* program, _In_ const struct _ebpf_api_program_info* infos);

    /**
     * @brief Extract the helper function and map relocation data from the eBPF file.
     *
     * @param program Program to extract relocations and map data for.
     */
    void
    extract_relocations_and_maps(_In_ const struct _ebpf_api_program_info* program);

    /**
     * @brief Extract the mapping from instruction offset to line number.
     *
     */
    void
    extract_btf_information();

    /**
     * @brief Emit the C code for a subprogram.
     *
     * @param[in] output Output stream to write code to.
     * @param[in] subprogram Subprogram to emit code for.
     */
    void
    emit_subprogram(std::ostream& output, const bpf_code_generator_program& subprogram);

#if defined(_MSC_VER)
    /**
     * @brief Format a GUID as a string.
     *
     * @param[in] guid Pointer to the GUID to be formatted.
     * @param[in] split Split the string at the open {.
     * @return The formatted string.
     */
    std::string
    format_guid(const GUID* guid, bool split) const;
#endif

    /**
     * @brief Convert an ELF section name to a valid PE section name.
     *
     * @param[in] program Program.
     * @param[in] name Name to convert to PE section name.
     */
    void
    set_pe_section_name(_Inout_ bpf_code_generator_program& program, const unsafe_string& elf_section_name);

    ELFIO::section*
    get_required_section(const unsafe_string& name) const;

    ELFIO::section*
    get_optional_section(const unsafe_string& name) const;

    bool
    is_section_valid(const ELFIO::section* section) const;

    unsafe_string
    get_section_name_by_index(ELFIO::Elf_Half index) const;

    /**
     * @brief Invoke the visitor for each symbol in the ELF file section.
     *
     * @param[in] visitor Visitor to invoke.
     */
    void
    visit_symbols(symbol_visitor_t visitor, const unsafe_string& section_name);

    int pe_section_name_counter{};
    std::map<unsafe_string, bpf_code_generator_program> programs;
    ELFIO::elfio reader;
    std::map<unsafe_string, map_info_t> map_definitions;
    unsafe_string c_name;
    unsafe_string path;
    btf_section_to_instruction_to_line_info_t section_line_info;
    std::optional<std::vector<uint8_t>> elf_file_hash;
    std::map<unsafe_string, std::vector<unsafe_string>> map_initial_values;
    std::map<unsafe_string, global_variable_section_t> global_variable_sections;
};
