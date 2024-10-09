// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "Verifier.h"
#include "api_common.hpp"
#include "api_internal.h"
#include "ebpf_api.h"
#include "ebpf_program_types.h"
#include "ebpf_shared_framework.h"
#include "ebpf_tracelog.h"
#include "ebpf_verifier_wrapper.hpp"
#include "elfio_wrapper.hpp"
#define ebpf_inst ebpf_inst_btf
#include "libbtf/btf_map.h"
#include "libbtf/btf_type_data.h"
#undef ebpf_inst
#include "platform.hpp"
#include "windows_platform.hpp"
#include "windows_platform_common.hpp"

#include <ElfWrapper.h>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include <vector>

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

static ebpf_pin_type_t
_get_pin_type_for_btf_map(const libbtf::btf_type_data& btf_data, libbtf::btf_type_id id)
{
    auto map_struct = btf_data.get_kind_type<libbtf::btf_kind_struct>(id);
    for (const auto& member : map_struct.members) {
        if (member.name == "pinning") {
            // This should use value_from_BTF__uint from btf_parser.cpp, but it's static.
            auto pinning_type_id = member.type;
            // Dereference the pointer type.
            pinning_type_id = btf_data.dereference_pointer(pinning_type_id);
            // Get the array type.
            auto pinning_type = btf_data.get_kind_type<libbtf::btf_kind_array>(pinning_type_id);
            // Value is encoded as the number of elements in the array.
            return static_cast<ebpf_pin_type_t>(pinning_type.count_of_elements);
        }
    }
    return LIBBPF_PIN_NONE;
}

/**
 * @brief Invoke the visitor for each symbol in the specified section.
 *
 * @param[in] symbols Symbol table.
 * @param[in] required_section_index Section index to match.
 * @param[in] visitor Visitor to invoke for each symbol. Return false to stop iteration.
 */
static void
_for_each_symbol(
    const ELFIO::const_symbol_section_accessor& symbols,
    ELFIO::Elf_Half required_section_index,
    std::function<bool(const std::string&, ELFIO::Elf64_Addr)> visitor)
{
    for (ELFIO::Elf_Xword i = 0; i < symbols.get_symbols_num(); i++) {
        string symbol_name;
        ELFIO::Elf64_Addr symbol_value{};
        unsigned char symbol_bind{};
        unsigned char symbol_type{};
        ELFIO::Elf_Half symbol_section_index{};
        unsigned char symbol_other{};
        ELFIO::Elf_Xword symbol_size{};

        symbols.get_symbol(
            i, symbol_name, symbol_value, symbol_size, symbol_bind, symbol_type, symbol_section_index, symbol_other);

        if (symbol_section_index != required_section_index) {
            continue;
        }

        if (!visitor(symbol_name, symbol_value)) {
            break;
        }
    }
}

template <typename T>
static vector<T>
vector_of(const ELFIO::section& sec)
{
    auto data = sec.get_data();
    auto size = sec.get_size();
    if ((size % sizeof(T) != 0) || size > UINT32_MAX || !data) {
        throw std::runtime_error("Invalid argument to vector_of");
    }
    return {(T*)data, (T*)(data + size)};
}

/**
 * @brief Parse the BTF data, gather the list of verifier map descriptors, and populate the cache.
 *
 * @param[in] reader Elf reader.
 * @param[in] map_names Mapping from section offset to map name.
 */
static void
_parse_btf_map_info_and_populate_cache(const ELFIO::elfio& reader, const vector<section_offset_to_map_t>& map_names)
{
    ELFIO::section* btf_section = reader.sections[".BTF"];
    if (!btf_section) {
        // It is an error if the BTF section is missing.
        throw std::runtime_error("BTF section is missing");
    }
    std::optional<libbtf::btf_type_data> btf_data = vector_of<byte>(*btf_section);

    std::vector<EbpfMapDescriptor> btf_map_descriptors;
    std::map<std::string, size_t> btf_map_name_to_index;

    auto map_data = parse_btf_map_section(btf_data.value());
    std::map<std::string, size_t> map_offsets;
    for (auto& map : map_data) {
        map_offsets.insert({map.name, btf_map_descriptors.size()});
        btf_map_descriptors.push_back({
            .original_fd = static_cast<int>(map.type_id),
            .type = map.map_type,
            .key_size = map.key_size,
            .value_size = map.value_size,
            .max_entries = map.max_entries,
            .inner_map_fd = map.inner_map_type_id != 0 ? map.inner_map_type_id : -1,
        });
    }
    btf_map_name_to_index = map_offsets;

    // For each map in map_names, find the corresponding map descriptor and cache the map handle.
    for (auto& entry : map_names) {
        uint32_t idx = (uint32_t)btf_map_name_to_index[entry.map_name];
        auto& btf_map_descriptor = btf_map_descriptors[idx];
        // We temporarily stored BTF type ids in the descriptor's fd fields.
        int btf_type_id = btf_map_descriptor.original_fd;
        int btf_inner_type_id = btf_map_descriptor.inner_map_fd;

        auto pin_type = _get_pin_type_for_btf_map(btf_data.value(), btf_type_id);
        cache_map_handle(
            ebpf_handle_invalid,
            map_idx_to_original_fd(idx),
            btf_type_id,
            btf_map_descriptor.type,
            btf_map_descriptor.key_size,
            btf_map_descriptor.value_size,
            btf_map_descriptor.max_entries,
            (uint32_t)ebpf_fd_invalid,
            btf_inner_type_id,
            entry.section_offset,
            pin_type);
    }

    // Cache unnamed maps.
    for (auto& map : map_data) {
        if (map.name.empty()) {
            uint32_t idx = (uint32_t)btf_map_name_to_index[map.name];
            auto& btf_map_descriptor = btf_map_descriptors[idx];
            // We temporarily stored BTF type ids in the descriptor's fd fields.
            int btf_type_id = btf_map_descriptor.original_fd;
            int btf_inner_type_id = btf_map_descriptor.inner_map_fd;

            auto pin_type = _get_pin_type_for_btf_map(btf_data.value(), btf_type_id);
            cache_map_handle(
                ebpf_handle_invalid,
                map_idx_to_original_fd(idx),
                btf_type_id,
                btf_map_descriptor.type,
                btf_map_descriptor.key_size,
                btf_map_descriptor.value_size,
                btf_map_descriptor.max_entries,
                (uint32_t)ebpf_fd_invalid,
                btf_inner_type_id,
                MAXSIZE_T,
                pin_type);
        }
    }

    // Resolve inner_map_fd for each map.
    btf_map_descriptors.clear();
    g_ebpf_platform_windows.resolve_inner_map_references(btf_map_descriptors);
}

// Parse symbols to get map names for all maps sections.
static void
_get_map_names(
    _In_ const ELFIO::elfio& reader,
    _In_ const ELFIO::const_symbol_section_accessor& symbols,
    _Inout_ vector<section_offset_to_map_t>& map_names) noexcept(false)
{
    std::string maps_prefix = "maps/";
    for (const auto& section : reader.sections) {
        std::string name = section->get_name();
        if (name == ".maps" || name == "maps" ||
            (name.length() > 5 && name.compare(0, maps_prefix.length(), maps_prefix) == 0)) {
            _for_each_symbol(
                symbols, section->get_index(), [&](const std::string& symbol_name, ELFIO::Elf64_Addr symbol_value) {
                    map_names.emplace_back(symbol_value, symbol_name);
                    return true;
                });
        }
    }

    ELFIO::section* btf_maps_section = reader.sections[".maps"];
    if (btf_maps_section) {
        _parse_btf_map_info_and_populate_cache(reader, map_names);
    }

    // Verify that returned map descriptors are a superset of map names referenced in the symbol section.
    // Get all map descriptors.
    auto map_descriptors = get_all_map_descriptors();

    // For each map in map_names (from the symbol table), verify that the map is present in map_descriptors (from the
    // BTF data).
    for (const auto& map_name : map_names) {
        bool found = false;
        for (const auto& map_descriptor : map_descriptors) {
            if (map_name.section_offset == map_descriptor.section_offset) {
                found = true;
                break;
            }
        }

        if (!found) {
            throw std::runtime_error(string("Map ") + map_name.map_name + " not found.");
        }
    }
}

static void
_get_map_names(
    std::variant<std::string, std::vector<uint8_t>>& file_or_buffer,
    _Inout_ vector<section_offset_to_map_t>& map_names) noexcept(false)
{
    ELFIO::elfio reader;

    if (std::holds_alternative<std::string>(file_or_buffer)) {
        if (!reader.load(std::get<std::string>(file_or_buffer))) {
            throw std::runtime_error("Can't process ELF file " + std::get<std::string>(file_or_buffer));
        }
    } else {
        std::stringstream buffer_stream(std::string(
            std::get<std::vector<uint8_t>>(file_or_buffer).begin(),
            std::get<std::vector<uint8_t>>(file_or_buffer).end()));
        if (!reader.load(buffer_stream)) {
            throw std::runtime_error("Can't process ELF file from memory");
        }
    }

    ELFIO::const_symbol_section_accessor symbols{reader, reader.sections[".symtab"]};
    _get_map_names(reader, symbols, map_names);
}

_Must_inspect_result_ ebpf_result_t
load_byte_code(
    std::variant<std::string, std::vector<uint8_t>>& file_or_buffer,
    _In_opt_z_ const char* section_name,
    _In_ const ebpf_verifier_options_t* verifier_options,
    _In_z_ const char* pin_root_path,
    _Inout_ std::vector<ebpf_program_t*>& programs,
    _Inout_ std::vector<ebpf_map_t*>& maps,
    _Outptr_result_maybenull_z_ const char** error_message) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_program_t* program = nullptr;
    ebpf_map_t* map = nullptr;
    vector<section_offset_to_map_t> map_names;
    *error_message = nullptr;
    ebpf_program_type_t empty_program_type{};

    try {
        const ebpf_platform_t* platform = &g_ebpf_platform_windows;
        std::string section_name_string;
        if (section_name != nullptr) {
            section_name_string = std::string(section_name);
        }

        std::vector<raw_program> raw_programs;

        // If file_or_buffer is a string, it is a file name.
        if (std::holds_alternative<std::string>(file_or_buffer)) {
            raw_programs =
                read_elf(std::get<std::string>(file_or_buffer), section_name_string, verifier_options, platform);
        } else {
            std::stringstream buffer_stream;
            // If file_or_buffer is a vector, it is a buffer.
            auto& buffer = std::get<std::vector<uint8_t>>(file_or_buffer);
            buffer_stream = std::stringstream(std::string(buffer.begin(), buffer.end()));
            raw_programs = read_elf(buffer_stream, "memory", section_name_string, verifier_options, platform);
        }

        if (raw_programs.size() == 0) {
            result = EBPF_ELF_PARSING_FAILED;
            goto Exit;
        }

        for (auto& raw_program : raw_programs) {
            program = (ebpf_program_t*)ebpf_allocate(sizeof(ebpf_program_t));
            if (program == nullptr) {
                result = EBPF_NO_MEMORY;
                goto Exit;
            }

            program->handle = ebpf_handle_invalid;
            program->program_type = *(const GUID*)raw_program.info.type.platform_specific_data;
            program->autoload = true;

            program->section_name = cxplat_duplicate_string(raw_program.section_name.c_str());
            program->program_name = cxplat_duplicate_string(raw_program.function_name.c_str());
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
            program->instructions = (ebpf_inst*)ebpf_allocate(ebpf_bytes);
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

        _get_map_names(file_or_buffer, map_names);

        auto map_descriptors = get_all_map_descriptors();
        size_t anonymous_map_count = 0;
        for (const auto& descriptor : map_descriptors) {
            bool found = false;
            int index;
            for (index = 0; index < map_names.size(); index++) {
                if (descriptor.section_offset == map_names[index].section_offset) {
                    found = true;
                    break;
                }
            }

            // Handle anonymous maps.
            if (descriptor.section_offset == MAXSIZE_T) {
                std::string name = "__anonymous_map_" + std::to_string(++anonymous_map_count);
                index = static_cast<int>(map_names.size());
                map_names.push_back({descriptor.section_offset, name});
                found = true;
            }

            if (!found) {
                result = EBPF_ELF_PARSING_FAILED;
                goto Exit;
            }

            if (descriptor.pinning != LIBBPF_PIN_NONE && descriptor.pinning != LIBBPF_PIN_BY_NAME) {
                result = EBPF_INVALID_ARGUMENT;
                goto Exit;
            }

            map = (ebpf_map_t*)ebpf_allocate(sizeof(ebpf_map_t));
            if (map == nullptr) {
                result = EBPF_NO_MEMORY;
                goto Exit;
            }
            initialize_map(map, descriptor);
            map->name = cxplat_duplicate_string(map_names[index].map_name.c_str());
            if (map->name == nullptr) {
                result = EBPF_NO_MEMORY;
                goto Exit;
            }
            if (descriptor.pinning == LIBBPF_PIN_BY_NAME) {
                char buffer[EBPF_MAX_PIN_PATH_LENGTH];
                int len = snprintf(buffer, EBPF_MAX_PIN_PATH_LENGTH, "%s/%s", pin_root_path, map->name);
                if (len < 0 || len >= EBPF_MAX_PIN_PATH_LENGTH) {
                    result = EBPF_INVALID_ARGUMENT;
                    goto Exit;
                }
                map->pin_path = cxplat_duplicate_string(buffer);
                if (map->pin_path == nullptr) {
                    result = EBPF_NO_MEMORY;
                    goto Exit;
                }
            }
            maps.emplace_back(map);
            map = nullptr;
        }
    } catch (std::runtime_error& err) {
        auto message = err.what();
        auto message_length = strlen(message) + 1;
        char* error = static_cast<char*>(ebpf_allocate(message_length + 1));
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

    EBPF_RETURN_RESULT(result);
}

static void
_ebpf_add_stat(_Inout_ ebpf_api_program_info_t* info, std::string key, int value) noexcept(false)
{
    ebpf_stat_t* stat = (ebpf_stat_t*)ebpf_allocate(sizeof(*stat));
    if (stat == nullptr) {
        throw std::runtime_error("Out of memory");
    }
    stat->key = cxplat_duplicate_string(key.c_str());
    if (stat->key == nullptr) {
        ebpf_free(stat);
        throw std::runtime_error("Out of memory");
    }
    stat->value = value;
    stat->next = info->stats;
    info->stats = stat;
}

uint32_t
ebpf_api_elf_enumerate_programs(
    _In_z_ const char* file,
    _In_opt_z_ const char* section,
    bool verbose,
    _Outptr_result_maybenull_ ebpf_api_program_info_t** infos,
    _Outptr_result_maybenull_z_ const char** error_message) noexcept
{
    ebpf_verifier_options_t verifier_options{false, false, false, false, true};
    const ebpf_platform_t* platform = &g_ebpf_platform_windows;
    std::ostringstream str;

    *infos = nullptr;
    *error_message = nullptr;
    ebpf_api_program_info_t* info = nullptr;

    ebpf_clear_thread_local_storage();

    try {
        auto raw_programs = read_elf(file, section ? std::string(section) : std::string(), &verifier_options, platform);
        for (const auto& raw_program : raw_programs) {
            info = (ebpf_api_program_info_t*)ebpf_allocate(sizeof(*info));
            if (info == nullptr) {
                throw std::runtime_error("Out of memory");
            }
            memset(info, 0, sizeof(*info));

            if (verbose) {
                std::variant<InstructionSeq, std::string> programOrError = unmarshal(raw_program);
                if (std::holds_alternative<std::string>(programOrError)) {
                    std::cout << "parse failure: " << std::get<std::string>(programOrError) << "\n";
                    ebpf_free(info);
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

            info->section_name = cxplat_duplicate_string(raw_program.section_name.c_str());
            if (info->section_name == nullptr) {
                throw std::runtime_error("Out of memory");
            }

            info->program_name = cxplat_duplicate_string(raw_program.function_name.c_str());
            if (info->program_name == nullptr) {
                throw std::runtime_error("Out of memory");
            }

            // Try to get the program type and expected attach type, and set to zero if we
            // can't, so the caller can set them.
            ebpf_result_t result =
                ebpf_get_program_type_by_name(info->section_name, &info->program_type, &info->expected_attach_type);
            if (result != EBPF_SUCCESS) {
                info->program_type = {};
                info->expected_attach_type = {};
            }

            info->offset_in_section = raw_program.insn_off;
            std::vector<uint8_t> raw_data = convert_ebpf_program_to_bytes(raw_program.prog);
            info->raw_data_size = raw_data.size();
            info->raw_data = (char*)ebpf_allocate(info->raw_data_size);
            if (info->raw_data == nullptr) {
                throw std::runtime_error("Out of memory");
            }
            memcpy(info->raw_data, raw_data.data(), info->raw_data_size);

            info->next = *infos;
            *infos = info;
            info = nullptr;
        }
    } catch (std::runtime_error e) {
        ebpf_free_programs(*infos);
        ebpf_free_programs(info);
        str << "error: " << e.what();
        *error_message = allocate_string(str.str());
        return 1;
    }

    return 0;
}

uint32_t
ebpf_api_elf_disassemble_program(
    _In_z_ const char* file,
    _In_opt_z_ const char* section_name,
    _In_opt_z_ const char* program_name,
    _Outptr_result_maybenull_z_ const char** disassembly,
    _Outptr_result_maybenull_z_ const char** error_message) noexcept
{
    ebpf_verifier_options_t verifier_options = ebpf_verifier_default_options;
    const ebpf_platform_t* platform = &g_ebpf_platform_windows;
    std::ostringstream error;
    std::ostringstream output;

    *disassembly = nullptr;
    *error_message = nullptr;

    ebpf_clear_thread_local_storage();

    try {
        std::string section(section_name ? section_name : "");
        auto raw_programs = read_elf(file, section, &verifier_options, platform);
        auto found_program =
            std::find_if(raw_programs.begin(), raw_programs.end(), [&program_name](const raw_program& program) {
                return (program_name == nullptr) || (program.function_name == program_name);
            });
        if (found_program == raw_programs.end()) {
            if (program_name != nullptr) {
                throw std::runtime_error(std::string("No such program ") + program_name);
            } else {
                throw std::runtime_error(std::string("No programs found"));
            }
        }
        raw_program& raw_program = *found_program;
        std::variant<InstructionSeq, std::string> programOrError = unmarshal(raw_program);
        if (std::holds_alternative<std::string>(programOrError)) {
            error << "parse failure: " << std::get<std::string>(programOrError);
            *error_message = allocate_string(error.str());
            return 1;
        }
        auto& program = std::get<InstructionSeq>(programOrError);
        print(program, output, {}, true);
        *disassembly = allocate_string(output.str());
        if (!*disassembly) {
            return 1;
        }
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
ebpf_api_elf_disassemble_section(
    _In_z_ const char* file,
    _In_z_ const char* section,
    _Outptr_result_maybenull_z_ const char** disassembly,
    _Outptr_result_maybenull_z_ const char** error_message) noexcept
{
    return ebpf_api_elf_disassemble_program(file, section, {}, disassembly, error_message);
}

static uint32_t
_ebpf_api_elf_verify_program_from_stream(
    std::istream& stream,
    const char* stream_name,
    const char* section_name,
    const char* program_name,
    ebpf_verification_verbosity_t verbosity,
    const char** report,
    const char** error_message,
    ebpf_api_verifier_stats_t* stats) noexcept
{
    std::ostringstream error;
    std::ostringstream output;
    *report = nullptr;
    *error_message = nullptr;

    try {
        const ebpf_platform_t* platform = &g_ebpf_platform_windows;
        ebpf_verifier_options_t verifier_options = ebpf_verifier_default_options;
        verifier_options.assume_assertions = verbosity < EBPF_VERIFICATION_VERBOSITY_VERBOSE;
        verifier_options.check_termination = true;
        verifier_options.print_invariants = verbosity >= EBPF_VERIFICATION_VERBOSITY_INFORMATIONAL;
        verifier_options.print_failures = true;
        verifier_options.mock_map_fds = true;
        verifier_options.print_line_info = true;
        if (!stream) {
            throw std::runtime_error(std::string("No such file or directory opening ") + stream_name);
        }
        auto raw_programs = read_elf(stream, stream_name, section_name, &verifier_options, platform);
        std::optional<raw_program> found_program;
        for (auto& program : raw_programs) {
            if ((program_name == nullptr) || (program.function_name == program_name)) {
                found_program = program;
                break;
            }
        }
        if (!found_program) {
            if (program_name != nullptr) {
                throw std::runtime_error(std::string("No such program ") + program_name);
            } else {
                throw std::runtime_error(std::string("No programs found"));
            }
        }
        raw_program raw_program = *found_program;
        std::variant<InstructionSeq, std::string> programOrError = unmarshal(raw_program);
        if (std::holds_alternative<std::string>(programOrError)) {
            error << "parse failure: " << std::get<std::string>(programOrError);
            *error_message = allocate_string(error.str());
            return 1;
        }
        auto& program = std::get<InstructionSeq>(programOrError);

        verifier_options.simplify = false;
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
        if (!*report) {
            return 1;
        }
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

static _Success_(return == 0) uint32_t _verify_program_from_string(
    std::string data,
    _In_z_ const char* name,
    _In_opt_z_ const char* section_name,
    _In_opt_z_ const char* program_name,
    _In_opt_ const ebpf_program_type_t* program_type,
    ebpf_verification_verbosity_t verbosity,
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

    // Clear thread local storage before calling into the verifier.
    // Note that TLS should be cleared here *before* calling into the verifier, not after.
    // Post verification, bpf2c relies on the TLS cache to compute program info hash.
    ebpf_clear_thread_local_storage();

    set_global_program_and_attach_type(program_type, nullptr);
    _verification_in_progress_helper helper;
    return _ebpf_api_elf_verify_program_from_stream(
        stream, name, section_name, program_name, verbosity, report, error_message, stats);
}

_Success_(return == 0) uint32_t ebpf_api_elf_verify_program_from_file(
    _In_z_ const char* file,
    _In_opt_z_ const char* section_name,
    _In_opt_z_ const char* program_name,
    _In_opt_ const ebpf_program_type_t* program_type,
    ebpf_verification_verbosity_t verbosity,
    _Outptr_result_maybenull_z_ const char** report,
    _Outptr_result_maybenull_z_ const char** error_message,
    _Out_opt_ ebpf_api_verifier_stats_t* stats) noexcept
{
    *error_message = nullptr;
    *report = nullptr;
    std::string data;
    uint32_t error = _load_file_to_memory(file, data, error_message);
    if (error) {
        return error;
    }
    return _verify_program_from_string(
        data, file, section_name, program_name, program_type, verbosity, report, error_message, stats);
}

_Success_(return == 0) uint32_t ebpf_api_elf_verify_section_from_file(
    _In_z_ const char* file,
    _In_z_ const char* section,
    _In_opt_ const ebpf_program_type_t* program_type,
    ebpf_verification_verbosity_t verbosity,
    _Outptr_result_maybenull_z_ const char** report,
    _Outptr_result_maybenull_z_ const char** error_message,
    _Out_opt_ ebpf_api_verifier_stats_t* stats) noexcept
{
    return ebpf_api_elf_verify_program_from_file(
        file, section, {}, program_type, verbosity, report, error_message, stats);
}

_Success_(return == 0) uint32_t ebpf_api_elf_verify_program_from_memory(
    _In_reads_(data_length) const char* data,
    size_t data_length,
    _In_opt_z_ const char* section_name,
    _In_opt_z_ const char* program_name,
    _In_opt_ const ebpf_program_type_t* program_type,
    ebpf_verification_verbosity_t verbosity,
    _Outptr_result_maybenull_z_ const char** report,
    _Outptr_result_maybenull_z_ const char** error_message,
    _Out_opt_ ebpf_api_verifier_stats_t* stats) noexcept
{
    return _verify_program_from_string(
        std::string(data, data_length),
        "memory",
        section_name,
        program_name,
        program_type,
        verbosity,
        report,
        error_message,
        stats);
}

_Success_(return == 0) uint32_t ebpf_api_elf_verify_section_from_memory(
    _In_reads_(data_length) const char* data,
    size_t data_length,
    _In_z_ const char* section,
    _In_opt_ const ebpf_program_type_t* program_type,
    ebpf_verification_verbosity_t verbosity,
    _Outptr_result_maybenull_z_ const char** report,
    _Outptr_result_maybenull_z_ const char** error_message,
    _Out_opt_ ebpf_api_verifier_stats_t* stats) noexcept
{
    return ebpf_api_elf_verify_program_from_memory(
        data, data_length, section, {}, program_type, verbosity, report, error_message, stats);
}
