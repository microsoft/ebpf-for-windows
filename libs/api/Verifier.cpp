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
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_verifier_wrapper.hpp"
#include "elfio_wrapper.hpp"
#include "ElfWrapper.h"
#include "platform.hpp"
#include "windows_platform.hpp"
#include "windows_platform_common.hpp"
#include "Verifier.h"

#define elf_everparse_error ElfEverParseError
#define elf_everparse_verify ElfCheckElf

thread_local static std::string _elf_everparse_error;

extern "C" void
elf_everparse_error(_In_ const char* struct_name, _In_ const char* field_name, _In_ const char* reason);

void
elf_everparse_error(_In_ const char* struct_name, _In_ const char* field_name, _In_ const char* reason)
{
    _elf_everparse_error =
        std::string() + "Failed parsing in struct " + struct_name + " field " + field_name + " reason " + reason;
}

using namespace std;

typedef struct _section_program_map
{
    string section_name;
    string program_name;
} section_program_map_t;

typedef struct _section_offset_to_map
{
    size_t section_offset;
    string map_name;
} section_offset_to_map_t;

struct _thread_local_storage_cache
{
    ~_thread_local_storage_cache() { ebpf_clear_thread_local_storage(); }
};

static void
_get_program_and_map_names(
    _In_ string& path,
    _Inout_ vector<section_program_map_t>& section_to_program_map,
    _Inout_ vector<section_offset_to_map_t>& map_names,
    uint32_t expected_map_count) noexcept(false)
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
        for (index = 0; index < section_to_program_map.size(); index++) {
            if (section_to_program_map[index].section_name == name) {
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
                section_to_program_map[index].program_name = symbol_name;
                symbols_count++;
                break;
            }
        }

        if (!symbol_found) {
            throw std::runtime_error(string("Program name not found for section ") + name);
        }
    }

    ELFIO::section* maps_section = reader.sections["maps"];
    if (maps_section) {
        ELFIO::Elf_Half map_section_index = maps_section->get_index();

        for (ELFIO::Elf_Xword i = 0; i < symbols.get_symbols_num(); i++) {
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

            if (symbol_section_index == map_section_index) {
                map_names.emplace_back(symbol_value, symbol_name);
            }
        }
    }

    if (expected_map_count != map_names.size()) {
        throw std::runtime_error(string("Map name not found for some maps."));
    }

    if (symbols_count != section_to_program_map.size()) {
        throw std::runtime_error(string("Program name not found for some sections."));
    }
}

ebpf_result_t
load_byte_code(
    _In_z_ const char* filename,
    _In_opt_z_ const char* sectionname,
    _In_ ebpf_verifier_options_t* verifier_options,
    _In_z_ const char* pin_root_path,
    _Inout_ std::vector<ebpf_program_t*>& programs,
    _Inout_ std::vector<ebpf_map_t*>& maps,
    _Outptr_result_maybenull_z_ const char** error_message) noexcept
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_program_t* program = nullptr;
    ebpf_map_t* map = nullptr;
    vector<section_program_map_t> section_to_program_map;
    vector<section_offset_to_map_t> map_names;
    *error_message = nullptr;

    try {
        const ebpf_platform_t* platform = &g_ebpf_platform_windows;
        std::string file_name(filename);
        std::string section_name;
        if (sectionname != nullptr) {
            section_name = std::string(sectionname);
        }

        auto raw_programs = read_elf(file_name, section_name, verifier_options, platform);
        if (raw_programs.size() == 0) {
            result = EBPF_ELF_PARSING_FAILED;
            goto Exit;
        }

        // read_elf() also returns a section with name ".text".
        // Remove that section from the list of programs returned unless it's the only one.
        for (int i = 0; i < raw_programs.size(); i++) {
            if (raw_programs[i].section == ".text" && raw_programs.size() > 1) {
                raw_programs.erase(raw_programs.begin() + i);
                break;
            }
        }

        // For each program/section parsed, program type should be same.
        if (get_global_program_type() == nullptr) {
            ebpf_program_type_t program_type = *(const GUID*)raw_programs[0].info.type.platform_specific_data;
            for (auto& raw_program : raw_programs) {
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

        for (auto& raw_program : raw_programs) {
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
            size_t instruction_count = raw_program.prog.size();
            if (instruction_count > UINT32_MAX) {
                result = EBPF_NO_MEMORY;
                goto Exit;
            }
            size_t ebpf_bytes = instruction_count * sizeof(ebpf_inst);
            program->instructions = (ebpf_inst*)calloc(1, ebpf_bytes);
            if (program->instructions == nullptr) {
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
                program->instructions[i++] = instruction;
            }
            program->instruction_count = (uint32_t)instruction_count;
            programs.emplace_back(program);
            program = nullptr;
        }

        // Get program names for each section.
        for (auto& iterator : programs) {
            section_to_program_map.emplace_back(iterator->section_name, std::string());
        }

        _get_program_and_map_names(file_name, section_to_program_map, map_names, (uint32_t)get_map_descriptor_size());

        auto map_descriptors = get_all_map_descriptors();
        for (const auto& descriptor : map_descriptors) {
            bool found = false;
            int index;
            for (index = 0; index < map_names.size(); index++) {
                if (descriptor.section_offset == map_names[index].section_offset) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                result = EBPF_ELF_PARSING_FAILED;
                goto Exit;
            }

            // Currently only PIN_NONE and PIN_GLOBAL_NS pinning options are supported.
            if (descriptor.pinning != PIN_NONE && descriptor.pinning != PIN_GLOBAL_NS) {
                result = EBPF_INVALID_ARGUMENT;
                goto Exit;
            }

            map = (ebpf_map_t*)calloc(1, sizeof(ebpf_map_t));
            if (map == nullptr) {
                result = EBPF_NO_MEMORY;
                goto Exit;
            }
            initialize_map(map, descriptor);
            map->name = _strdup(map_names[index].map_name.c_str());
            if (map->name == nullptr) {
                result = EBPF_NO_MEMORY;
                goto Exit;
            }
            if (descriptor.pinning == PIN_GLOBAL_NS) {
                char buffer[EBPF_MAX_PIN_PATH_LENGTH];
                int len = snprintf(buffer, EBPF_MAX_PIN_PATH_LENGTH, "%s/%s", pin_root_path, map->name);
                if (len < 0 || len >= EBPF_MAX_PIN_PATH_LENGTH) {
                    result = EBPF_INVALID_ARGUMENT;
                    goto Exit;
                }
                map->pin_path = _strdup(buffer);
                if (map->pin_path == nullptr) {
                    result = EBPF_NO_MEMORY;
                    goto Exit;
                }
            }
            maps.emplace_back(map);
            map = nullptr;
        }

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
            program = nullptr;
        }
        if (map != nullptr) {
            clean_up_ebpf_map(map);
            map = nullptr;
        }

        clean_up_ebpf_programs(programs);
        clean_up_ebpf_maps(maps);
    }

    return result;
}

static void
_ebpf_add_stat(_Inout_ ebpf_section_info_t* info, std::string key, int value) noexcept(false)
{
    ebpf_stat_t* stat = (ebpf_stat_t*)malloc(sizeof(*stat));
    if (stat == nullptr) {
        throw std::runtime_error("Out of memory");
    }
    stat->key = _strdup(key.c_str());
    if (stat->key == nullptr) {
        free(stat);
        throw std::runtime_error("Out of memory");
    }
    stat->value = value;
    stat->next = info->stats;
    info->stats = stat;
}

uint32_t
ebpf_api_elf_enumerate_sections(
    _In_z_ const char* file,
    _In_opt_z_ const char* section,
    bool verbose,
    _Outptr_result_maybenull_ ebpf_section_info_t** infos,
    _Outptr_result_maybenull_z_ const char** error_message) noexcept
{
    ebpf_verifier_options_t verifier_options{false, false, false, false, true};
    const ebpf_platform_t* platform = &g_ebpf_platform_windows;
    std::ostringstream str;
    struct _thread_local_storage_cache tls_cache;

    *infos = nullptr;
    *error_message = nullptr;

    try {
        auto raw_programs = read_elf(file, section ? std::string(section) : std::string(), &verifier_options, platform);
        for (const auto& raw_program : raw_programs) {
            ebpf_section_info_t* info = (ebpf_section_info_t*)malloc(sizeof(*info));
            if (info == nullptr) {
                throw std::runtime_error("Out of memory");
            }
            memset(info, 0, sizeof(*info));

            if (verbose) {
                std::variant<InstructionSeq, std::string> programOrError = unmarshal(raw_program);
                if (std::holds_alternative<std::string>(programOrError)) {
                    std::cout << "parse failure: " << std::get<std::string>(programOrError) << "\n";
                    free(info);
                    return 1;
                }
                auto& program = std::get<InstructionSeq>(programOrError);
                cfg_t controlFlowGraph = prepare_cfg(program, raw_program.info, true);
                std::map<std::string, int> stats = collect_stats(controlFlowGraph);
                for (auto it = stats.rbegin(); it != stats.rend(); ++it) {
                    _ebpf_add_stat(info, it->first, it->second);
                }
                _ebpf_add_stat(info, "Instructions", (int)raw_program.prog.size());
            }

            info->section_name = _strdup(raw_program.section.c_str());
            info->program_type_name = _strdup(raw_program.info.type.name.c_str());

            std::vector<uint8_t> raw_data = convert_ebpf_program_to_bytes(raw_program.prog);
            info->raw_data_size = raw_data.size();
            info->raw_data = (char*)malloc(info->raw_data_size);
            if (info->raw_data == nullptr || info->section_name == nullptr || info->program_type_name == nullptr) {
                free((void*)info->section_name);
                free((void*)info->program_type_name);
                free((void*)info->raw_data);
                free(info);
                throw std::runtime_error("Out of memory");
            }
            memcpy(info->raw_data, raw_data.data(), info->raw_data_size);

            info->next = *infos;
            *infos = info;
        }
    } catch (std::runtime_error e) {
        str << "error: " << e.what();
        *error_message = allocate_string(str.str());
        return 1;
    }

    return 0;
}

uint32_t
ebpf_api_elf_disassemble_section(
    _In_z_ const char* file,
    _In_z_ const char* section,
    _Outptr_result_maybenull_z_ const char** disassembly,
    _Outptr_result_maybenull_z_ const char** error_message)
{
    ebpf_verifier_options_t verifier_options = ebpf_verifier_default_options;
    const ebpf_platform_t* platform = &g_ebpf_platform_windows;
    std::ostringstream error;
    std::ostringstream output;
    struct _thread_local_storage_cache tls_cache;

    *disassembly = nullptr;
    *error_message = nullptr;

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
        print(program, output, {}, true);
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

static uint32_t
_ebpf_api_elf_verify_section_from_stream(
    std::istream& stream,
    const char* stream_name,
    const char* section,
    bool verbose,
    const char** report,
    const char** error_message,
    ebpf_api_verifier_stats_t* stats) noexcept
{
    std::ostringstream error;
    std::ostringstream output;
    struct _thread_local_storage_cache tls_cache;
    *report = nullptr;
    *error_message = nullptr;

    try {
        const ebpf_platform_t* platform = &g_ebpf_platform_windows;
        ebpf_verifier_options_t verifier_options = ebpf_verifier_default_options;
        verifier_options.check_termination = true;
        verifier_options.print_invariants = verbose;
        verifier_options.print_failures = true;
        verifier_options.mock_map_fds = true;
        verifier_options.print_line_info = true;
        if (!stream) {
            throw std::runtime_error(std::string("No such file or directory opening ") + stream_name);
        }
        auto raw_programs = read_elf(stream, stream_name, section, &verifier_options, platform);
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
        error << "Failed to load eBPF program from " << stream_name;
        *error_message = allocate_string(error.str());
        return 1;
    }

    return 0;
}

static uint32_t
_load_file_to_memory(
    _In_ const std::string& path,
    _Out_ std::string& data,
    _Outptr_result_maybenull_z_ const char** error_message) noexcept
{
    data = "";
    struct stat st;
    if (stat(path.c_str(), &st)) {
        *error_message = allocate_string(std::string("error: No such file or directory opening ") + path);
        return 1;
    }
    if (std::ifstream stream{path, std::ios::in | std::ios::binary}) {
        data.resize(st.st_size);
        if (stream.read(data.data(), data.size())) {
            *error_message = nullptr;
            return 0;
        }
    }
    *error_message = allocate_string(std::string("error: Failed to read file: ") + path);
    return 1;
}

static _Success_(return == 0) uint32_t _verify_section_from_string(
    std::string data,
    _In_z_ const char* name,
    _In_z_ const char* section,
    _In_opt_ const ebpf_program_type_t* program_type,
    bool verbose,
    _Outptr_result_maybenull_z_ const char** report,
    _Outptr_result_maybenull_z_ const char** error_message,
    _Out_opt_ ebpf_api_verifier_stats_t* stats) noexcept
{
    *error_message = nullptr;
    *report = nullptr;

    if (!ElfCheckElf(
            data.size(),
            const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(data.data())),
            static_cast<uint32_t>(data.size()))) {

        *error_message =
            allocate_string(std::string("error: ELF file ") + name + " is malformed: " + _elf_everparse_error);
        return 1;
    }

    auto stream = std::stringstream(data);
    struct _thread_local_storage_cache tls_cache;
    set_global_program_and_attach_type(program_type, nullptr);
    set_verification_in_progress(true);
    return _ebpf_api_elf_verify_section_from_stream(stream, name, section, verbose, report, error_message, stats);
}

_Success_(return == 0) uint32_t ebpf_api_elf_verify_section_from_file(
    _In_z_ const char* file,
    _In_z_ const char* section,
    _In_opt_ const ebpf_program_type_t* program_type,
    bool verbose,
    _Outptr_result_maybenull_z_ const char** report,
    _Outptr_result_maybenull_z_ const char** error_message,
    _Out_opt_ ebpf_api_verifier_stats_t* stats)
{
    *error_message = nullptr;
    *report = nullptr;
    std::string data;
    uint32_t error = _load_file_to_memory(file, data, error_message);
    if (error) {
        return error;
    }
    return _verify_section_from_string(data, file, section, program_type, verbose, report, error_message, stats);
}

_Success_(return == 0) uint32_t ebpf_api_elf_verify_section_from_memory(
    _In_reads_(data_length) const char* data,
    size_t data_length,
    _In_z_ const char* section,
    _In_opt_ const ebpf_program_type_t* program_type,
    bool verbose,
    _Outptr_result_maybenull_z_ const char** report,
    _Outptr_result_maybenull_z_ const char** error_message,
    _Out_opt_ ebpf_api_verifier_stats_t* stats)
{
    return _verify_section_from_string(
        std::string(data, data_length), "memory", section, program_type, verbose, report, error_message, stats);
}
