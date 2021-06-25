// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <filesystem>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include <vector>
#include "api_common.hpp"
#include "api_internal.h"
#include "ebpf_api.h"
#include "ebpf_bind_program_data.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#pragma warning(push)
#pragma warning(disable : 4100) // 'identifier' : unreferenced formal parameter
#pragma warning(disable : 4244) // 'conversion' conversion from 'type1' to
                                // 'type2', possible loss of data
#include "ebpf_verifier.hpp"
#pragma warning(pop)
#include "ebpf_xdp_program_data.h"
#pragma warning(push)
#pragma warning(disable : 6011) // 'Dereferencing NULL pointer - https://github.com/vbpf/ebpf-verifier/issues/239
#include "elfio/elfio.hpp"
#pragma warning(pop)
#include "platform.hpp"
#include "tlv.h"
#include "windows_platform.hpp"
#include "windows_platform_common.hpp"
#include "Verifier.h"

using namespace std;

typedef struct _section_program_map
{
    string section_name;
    string program_name;
} section_program_map_t;

static void
_get_section_and_program_name(string& path, vector<section_program_map_t>& map) noexcept(false)
{
    ELFIO::elfio reader;
    size_t symbols_count = 0;

    if (!reader.load(path)) {
        throw std::runtime_error(string("Can't process ELF file ") + path);
    }

    ELFIO::const_symbol_section_accessor symbols{reader, reader.sections[".symtab"]};
    for (const auto section : reader.sections) {
        const string name = section->get_name();
        bool found = false;
        int index;
        for (index = 0; index < map.size(); index++) {
            if (map[index].section_name == name) {
                found = true;
                break;
            } else {
                continue;
            }
        }

        if (!found) {
            continue;
        }

        auto section_index = section->get_index();
        bool symbol_found = false;

        for (int i = 0; i < symbols.get_symbols_num(); i++) {
            string symbol_name;
            ELFIO::Elf64_Addr symbol_value{};
            unsigned char symbol_bind{};
            unsigned char symbol_type{};
            ELFIO::Elf_Half symbol_section_index{};
            unsigned char symbol_other{};
            ELFIO::Elf_Xword symbol_size{};

            symbols.get_symbol(
                i,
                symbol_name,
                symbol_value,
                symbol_size,
                symbol_bind,
                symbol_type,
                symbol_section_index,
                symbol_other);

            if (!symbol_name.empty() && symbol_section_index == section_index && symbol_value == 0) {
                symbol_found = true;
                map[index].program_name = symbol_name;
                symbols_count++;
                break;
            }
        }

        if (!symbol_found) {
            throw std::runtime_error(string("Program name not found for section ") + name);
        }
    }

    if (symbols_count != map.size()) {
        throw std::runtime_error(string("Program name not found for some sections."));
    }
}

ebpf_result_t
load_byte_code(
    _In_z_ const char* filename,
    _In_opt_z_ const char* sectionname,
    _In_ ebpf_verifier_options_t* verifier_options,
    _Out_ std::vector<ebpf_program_t*>& programs,
    _Outptr_result_maybenull_z_ const char** error_message) noexcept
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_program_t* program = nullptr;
    vector<section_program_map_t> section_to_program_map;
    try {
        const ebpf_platform_t* platform = &g_ebpf_platform_windows;
        std::string file_name(filename);
        std::string section_name;
        if (sectionname != nullptr) {
            section_name = std::string(sectionname);
        }

        auto raw_progams = read_elf(file_name, section_name, verifier_options, platform);
        if (raw_progams.size() == 0) {
            result = EBPF_ELF_PARSING_FAILED;
            goto Exit;
        }

        // read_elf() also returns a section with name ".text".
        // Remove that section from the list of programs returned.
        for (int i = 0; i < raw_progams.size(); i++) {
            if (raw_progams[i].section == ".text") {
                raw_progams.erase(raw_progams.begin() + i);
                break;
            }
        }

        // For each program/section parsed, program type should be same.
        if (get_global_program_type() == nullptr) {
            ebpf_program_type_t program_type = *(const GUID*)raw_progams[0].info.type.platform_specific_data;
            for (auto& raw_program : raw_progams) {
                if (raw_program.info.type.platform_specific_data == 0) {
                    result = EBPF_ELF_PARSING_FAILED;
                    goto Exit;
                }

                ebpf_program_type_t type = *(const GUID*)raw_program.info.type.platform_specific_data;
                if (!IsEqualGUID(program_type, type)) {
                    result = EBPF_ELF_PARSING_FAILED;
                    goto Exit;
                }
            }
        }

        for (auto& raw_program : raw_progams) {
            program = (ebpf_program_t*)calloc(1, sizeof(ebpf_program_t));
            if (program == nullptr) {
                result = EBPF_NO_MEMORY;
                goto Exit;
            }

            program->handle = ebpf_handle_invalid;
            program->program_type = *(const GUID*)raw_program.info.type.platform_specific_data;
            program->section_name = _strdup(raw_program.section.c_str());
            if (program->section_name == nullptr) {
                result = EBPF_NO_MEMORY;
                goto Exit;
            }
            size_t ebpf_bytes = raw_program.prog.size() * sizeof(ebpf_inst);
            program->byte_code = (uint8_t*)calloc(1, ebpf_bytes);
            if (program->byte_code == nullptr) {
                result = EBPF_NO_MEMORY;
                goto Exit;
            }

            // Update attach type for the program.
            if (get_global_program_type() != nullptr) {
                const ebpf_attach_type_t* attach_type = get_global_attach_type();
                if (attach_type != nullptr) {
                    program->attach_type = *attach_type;
                }
            } else {
                program->attach_type = *(get_attach_type_windows(std::string(program->section_name)));
            }

            int i = 0;
            for (ebpf_inst instruction : raw_program.prog) {
                char* buffer = (char*)&instruction;
                for (int j = 0; j < sizeof(ebpf_inst) && i < ebpf_bytes; i++, j++) {
                    program->byte_code[i] = buffer[j];
                }
            }
            program->byte_code_size = static_cast<uint32_t>(ebpf_bytes);
            programs.emplace_back(program);
            program = nullptr;
        }

        // Get program names for each section.
        for (auto& iterator : programs) {
            section_to_program_map.emplace_back(iterator->section_name, std::string());
        }

        _get_section_and_program_name(file_name, section_to_program_map);
        int index = 0;
        for (auto& iterator : programs) {
            iterator->program_name = _strdup(section_to_program_map[index].program_name.c_str());
            if (iterator->program_name == nullptr) {
                result = EBPF_NO_MEMORY;
                goto Exit;
            }
            index++;
        }
    } catch (std::runtime_error& err) {
        auto message = err.what();
        auto message_length = strlen(message) + 1;
        char* error = reinterpret_cast<char*>(calloc(message_length + 1, sizeof(char)));
        if (error) {
            strcpy_s(error, message_length, message);
        }
        *error_message = error;
        result = EBPF_INVALID_ARGUMENT;
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
    } catch (...) {
        result = EBPF_FAILED;
    }

Exit:
    if (result != EBPF_SUCCESS) {
        if (program != nullptr) {
            clean_up_ebpf_program(program);
            free(program);
            program = nullptr;
        }

        clean_up_ebpf_programs(programs);
    }

    return result;
}

uint32_t
ebpf_api_elf_enumerate_sections(
    const char* file,
    const char* section,
    bool verbose,
    const struct _tlv_type_length_value** data,
    const char** error_message)
{
    ebpf_verifier_options_t verifier_options{false, false, false, false, true};
    const ebpf_platform_t* platform = &g_ebpf_platform_windows;
    std::ostringstream str;
    try {
        auto raw_programs = read_elf(file, section ? std::string(section) : std::string(), &verifier_options, platform);
        tlv_sequence sequence;
        for (const auto& raw_program : raw_programs) {
            tlv_sequence stats_sequence;
            if (verbose) {
                std::variant<InstructionSeq, std::string> programOrError = unmarshal(raw_program);
                if (std::holds_alternative<std::string>(programOrError)) {
                    std::cout << "parse failure: " << std::get<std::string>(programOrError) << "\n";
                    return 1;
                }
                auto& program = std::get<InstructionSeq>(programOrError);
                cfg_t controlFlowGraph = prepare_cfg(program, raw_program.info, true);
                std::map<std::string, int> stats = collect_stats(controlFlowGraph);
                for (const auto& [key, value] : stats) {
                    stats_sequence.emplace_back(tlv_pack<tlv_sequence>({tlv_pack(key.c_str()), tlv_pack(value)}));
                }
            }

            sequence.emplace_back(tlv_pack<tlv_sequence>({tlv_pack(raw_program.section.c_str()),
                                                          tlv_pack(raw_program.info.type.name.c_str()),
                                                          tlv_pack(raw_program.info.map_descriptors.size()),
                                                          tlv_pack(convert_ebpf_program_to_bytes(raw_program.prog)),
                                                          tlv_pack(stats_sequence)}));
        }

        auto retval = tlv_pack(sequence);
        auto local_data = reinterpret_cast<tlv_type_length_value_t*>(malloc(retval.size()));
        if (!local_data)
            throw std::runtime_error("Out of memory");

        memcpy(local_data, retval.data(), retval.size());
        *data = local_data;
    } catch (std::runtime_error e) {
        str << "error: " << e.what();
        *error_message = allocate_string(str.str());
        return 1;
    }

    return 0;
}

uint32_t
ebpf_api_elf_disassemble_section(
    const char* file, const char* section, const char** disassembly, const char** error_message)
{
    ebpf_verifier_options_t verifier_options = ebpf_verifier_default_options;
    const ebpf_platform_t* platform = &g_ebpf_platform_windows;
    std::ostringstream error;
    std::ostringstream output;
    try {
        auto raw_programs = read_elf(file, section, &verifier_options, platform);
        raw_program raw_program = raw_programs.back();
        std::variant<InstructionSeq, std::string> programOrError = unmarshal(raw_program);
        if (std::holds_alternative<std::string>(programOrError)) {
            error << "parse failure: " << std::get<std::string>(programOrError);
            *error_message = allocate_string(error.str());
            return 1;
        }
        auto& program = std::get<InstructionSeq>(programOrError);
        print(program, output, {});
        *disassembly = allocate_string(output.str());
    } catch (std::runtime_error e) {
        error << "error: " << e.what();
        *error_message = allocate_string(error.str());
        return 1;
    } catch (std::exception ex) {
        error << "Failed to load eBPF program from " << file;
        *error_message = allocate_string(error.str());
        return 1;
    }
    return 0;
}

uint32_t
ebpf_api_elf_verify_section(
    const char* file,
    const char* section,
    bool verbose,
    const char** report,
    const char** error_message,
    ebpf_api_verifier_stats_t* stats)
{
    std::ostringstream error;

    std::ostringstream output;

    *report = nullptr;
    *error_message = nullptr;

    try {
        const ebpf_platform_t* platform = &g_ebpf_platform_windows;
        ebpf_verifier_options_t verifier_options = ebpf_verifier_default_options;
        verifier_options.check_termination = true;
        verifier_options.print_invariants = verbose;
        verifier_options.print_failures = true;
        verifier_options.mock_map_fds = true;

        auto raw_programs = read_elf(file, section, &verifier_options, platform);
        raw_program raw_program = raw_programs.back();
        std::variant<InstructionSeq, std::string> programOrError = unmarshal(raw_program);
        if (std::holds_alternative<std::string>(programOrError)) {
            error << "parse failure: " << std::get<std::string>(programOrError);
            *error_message = allocate_string(error.str());
            return 1;
        }
        auto& program = std::get<InstructionSeq>(programOrError);

        verifier_options.no_simplify = true;
        bool res =
            ebpf_verify_program(output, program, raw_program.info, &verifier_options, (ebpf_verifier_stats_t*)stats);
        if (!res) {
            error << "Verification failed";
            *error_message = allocate_string(error.str());
            *report = allocate_string(output.str());
            return 1;
        }

        output << "Verification succeeded";
        *report = allocate_string(output.str());
        return 0;
    } catch (std::runtime_error e) {
        error << "error: " << e.what();
        *error_message = allocate_string(error.str());
        return 1;
    } catch (std::exception ex) {
        error << "Failed to load eBPF program from " << file;
        *error_message = allocate_string(error.str());
        return 1;
    }

    return 0;
}

void
ebpf_api_elf_free(const tlv_type_length_value_t* data)
{
    free(const_cast<tlv_type_length_value_t*>(data));
}
