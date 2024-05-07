// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf/libbpf.h"
#include "elf.h"
#include "tokens.h"
#include "utilities.h"

#include <iomanip>
#include <locale>

TOKEN_VALUE g_LevelEnum[2] = {
    {L"normal", VL_NORMAL},
    {L"verbose", VL_VERBOSE},
};

// The following function uses windows specific type as an input to match
// definition of "FN_HANDLE_CMD" in public file of NetSh.h
unsigned long
handle_ebpf_show_disassembly(
    IN LPCWSTR machine,
    _Inout_updates_(argc) LPWSTR* argv,
    IN DWORD current_index,
    IN DWORD argc,
    IN DWORD flags,
    IN LPCVOID data,
    OUT BOOL* done)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    TAG_TYPE tags[] = {
        {TOKEN_FILENAME, NS_REQ_PRESENT, FALSE},
        {TOKEN_SECTION, NS_REQ_ZERO, FALSE},
    };
    unsigned long tag_type[_countof(tags)] = {0};

    unsigned long status =
        PreprocessCommand(nullptr, argv, current_index, argc, tags, _countof(tags), 0, _countof(tags), tag_type);

    std::string filename;
    std::string section = ""; // Use the first code section by default.
    for (int i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
        switch (tag_type[i]) {
        case 0: // FILENAME
        {
            filename = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        }
        case 1: // SECTION
        {
            section = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        }
        default:
            status = ERROR_INVALID_SYNTAX;
            break;
        }
    }
    if (status != NO_ERROR) {
        return status;
    }

    const char* disassembly = nullptr;
    const char* error_message = nullptr;
    if (ebpf_api_elf_disassemble_section(filename.c_str(), section.c_str(), &disassembly, &error_message) != 0) {
        if (error_message != nullptr) {
            std::cerr << error_message << std::endl;
        }
        ebpf_free_string(error_message);
        return ERROR_SUPPRESS_OUTPUT;
    } else {
        std::cout << disassembly << std::endl;
        ebpf_free_string(disassembly);
        return NO_ERROR;
    }
}

static PCSTR
_get_map_type_name(ebpf_map_type_t type)
{
    int index = (type >= _countof(_ebpf_map_display_names)) ? 0 : type;
    return _ebpf_map_display_names[index];
}

// The following function uses windows specific type as an input to match
// definition of "FN_HANDLE_CMD" in public file of NetSh.h
unsigned long
handle_ebpf_show_sections(
    IN LPCWSTR machine,
    _Inout_updates_(argc) LPWSTR* argv,
    IN DWORD current_index,
    IN DWORD argc,
    IN DWORD flags,
    IN LPCVOID data,
    OUT BOOL* done)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    TAG_TYPE tags[] = {
        {TOKEN_FILENAME, NS_REQ_PRESENT, FALSE},
        {TOKEN_SECTION, NS_REQ_ZERO, FALSE},
        {TOKEN_LEVEL, NS_REQ_ZERO, FALSE},
    };
    unsigned long tag_type[_countof(tags)] = {0};

    unsigned long status =
        PreprocessCommand(nullptr, argv, current_index, argc, tags, _countof(tags), 0, _countof(tags), tag_type);

    VERBOSITY_LEVEL level = VL_NORMAL;
    std::string filename;
    std::string section;
    for (int i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
        switch (tag_type[i]) {
        case 0: // FILENAME
        {
            filename = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        }
        case 1: // SECTION
        {
            section = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        }
        case 2: // LEVEL
            status =
                MatchEnumTag(NULL, argv[current_index + i], _countof(g_LevelEnum), g_LevelEnum, (unsigned long*)&level);
            if (status != NO_ERROR) {
                status = ERROR_INVALID_PARAMETER;
            }
            break;

        default:
            status = ERROR_INVALID_SYNTAX;
            break;
        }
    }

    if (status != NO_ERROR) {
        return status;
    }

    // If the user specified a section and no level, default to verbose.
    if (tags[1].bPresent && !tags[2].bPresent) {
        level = VL_VERBOSE;
    }

    ebpf_section_info_t* section_data = nullptr;
    const char* error_message = nullptr;
    if (ebpf_enumerate_sections(filename.c_str(), level == VL_VERBOSE, &section_data, &error_message) != 0) {
        if (error_message != nullptr) {
            std::cerr << error_message << std::endl;
        }
        ebpf_free_string(error_message);
        ebpf_free_sections(section_data);
        return ERROR_SUPPRESS_OUTPUT;
    }

    if (level == VL_NORMAL) {
        std::cout << "\n";
        std::cout << "                                    Size\n";
        std::cout << "             Section       Type  (bytes)\n";
        std::cout << "====================  =========  =======\n";
    }
    for (auto current_section = section_data; current_section != nullptr; current_section = current_section->next) {
        if (!section.empty() && strcmp(current_section->section_name, section.c_str()) != 0) {
            continue;
        }
        auto program_type_name = ebpf_get_program_type_name(&current_section->program_type);
        if (program_type_name == nullptr) {
            program_type_name = "unspec";
        }
        if (level == VL_NORMAL) {
            std::cout << std::setw(20) << std::right << current_section->section_name << "  " << std::setw(9)
                      << program_type_name << "  " << std::setw(7) << current_section->raw_data_size << "\n";
        } else {
            std::cout << "\n";
            std::cout << "Section      : " << current_section->section_name << "\n";
            std::cout << "Program Type : " << program_type_name << "\n";
            std::cout << "Size         : " << current_section->raw_data_size << " bytes\n";
            for (auto stat = current_section->stats; stat != nullptr; stat = stat->next) {
                std::cout << std::setw(13) << std::left << stat->key << ": " << stat->value << "\n";
            }
        }
    }
    ebpf_free_sections(section_data);
    ebpf_free_string(error_message);

    // Show maps.
    std::cout << "\n";
    std::cout << "                     Key  Value      Max\n";
    std::cout << "          Map Type  Size   Size  Entries  Name\n";
    std::cout << "==================  ====  =====  =======  ========\n";
    bpf_object* object = bpf_object__open(filename.c_str());
    if (object == nullptr) {
        std::cout << "Couldn't get maps from " << filename << "\n";
        return ERROR_SUPPRESS_OUTPUT;
    }
    bpf_map* map;
    bpf_object__for_each_map(map, object)
    {
        printf(
            "%18s%6u%7u%9u  %s\n",
            _get_map_type_name(bpf_map__type(map)),
            bpf_map__key_size(map),
            bpf_map__value_size(map),
            bpf_map__max_entries(map),
            bpf_map__name(map));
    }
    bpf_object__close(object);
    return NO_ERROR;
}

// The following function uses windows specific type as an input to match
// definition of "FN_HANDLE_CMD" in public file of NetSh.h
unsigned long
handle_ebpf_show_verification(
    IN LPCWSTR machine,
    _Inout_updates_(argc) LPWSTR* argv,
    IN DWORD current_index,
    IN DWORD argc,
    IN DWORD flags,
    IN LPCVOID data,
    OUT BOOL* done)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    TAG_TYPE tags[] = {
        {TOKEN_FILENAME, NS_REQ_PRESENT, FALSE},
        {TOKEN_SECTION, NS_REQ_ZERO, FALSE},
        {TOKEN_TYPE, NS_REQ_ZERO, FALSE},
        {TOKEN_LEVEL, NS_REQ_ZERO, FALSE},
    };
    const int FILENAME_INDEX = 0;
    const int SECTION_INDEX = 1;
    const int TYPE_INDEX = 2;
    const int LEVEL_INDEX = 3;

    unsigned long tag_type[_countof(tags)] = {0};

    unsigned long status =
        PreprocessCommand(nullptr, argv, current_index, argc, tags, _countof(tags), 0, _countof(tags), tag_type);

    VERBOSITY_LEVEL level = VL_NORMAL;
    std::string filename;
    std::string section = ""; // Use the first code section by default.
    std::string type_name = "";
    ebpf_program_type_t program_type;
    ebpf_attach_type_t attach_type;
    bool program_type_found = false;

    for (int i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
        switch (tag_type[i]) {
        case FILENAME_INDEX: {
            filename = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        }
        case SECTION_INDEX: {
            section = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        }
        case TYPE_INDEX: {
            type_name = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            if (ebpf_get_program_type_by_name(type_name.c_str(), &program_type, &attach_type) != EBPF_SUCCESS) {
                status = ERROR_INVALID_PARAMETER;
            } else {
                program_type_found = true;
            }
            break;
        }
        case LEVEL_INDEX: {
            status =
                MatchEnumTag(NULL, argv[current_index + i], _countof(g_LevelEnum), g_LevelEnum, (unsigned long*)&level);
            if (status != NO_ERROR) {
                status = ERROR_INVALID_PARAMETER;
            }
            break;
        }
        default:
            status = ERROR_INVALID_SYNTAX;
            break;
        }
    }
    if (status != NO_ERROR) {
        return status;
    }

    const char* report;
    const char* error_message;
    ebpf_api_verifier_stats_t stats;

    if (section == "") {
        // If no section name was provided, fetch the first section name.
        ebpf_section_info_t* section_data = nullptr;
        ebpf_result_t result =
            ebpf_enumerate_sections(filename.c_str(), level == VL_VERBOSE, &section_data, &error_message);
        if (result != ERROR_SUCCESS || section_data == nullptr) {
            if (error_message) {
                std::cerr << error_message << std::endl;
            } else {
                std::cerr << "\nNo section(s) found" << std::endl;
            }
            ebpf_free_string(error_message);
            ebpf_free_sections(section_data);
            return ERROR_SUPPRESS_OUTPUT;
        }

        section = section_data->section_name;
        ebpf_free_string(error_message);
        ebpf_free_sections(section_data);
    }

    if (!program_type_found) {
        if (ebpf_get_program_type_by_name(section.c_str(), &program_type, &attach_type) != EBPF_SUCCESS) {
            std::cerr << "\nProgram type for section " << section.c_str() << " not found." << std::endl;
            return ERROR_SUPPRESS_OUTPUT;
        }
    }

    status = ebpf_api_elf_verify_section_from_file(
        filename.c_str(), section.c_str(), &program_type, level == VL_VERBOSE, &report, &error_message, &stats);
    if (status == ERROR_SUCCESS) {
        std::cout << report;
        std::cout << "\nProgram terminates within " << stats.max_loop_count << " loop iterations\n";
        ebpf_free_string(report);
        return NO_ERROR;
    } else {
        if (error_message) {
            std::cerr << error_message << std::endl;
        }
        if (report) {
            std::cerr << "\nVerification report:\n" << report;
            std::cerr << stats.total_warnings << " errors\n\n";
        }
        ebpf_free_string(error_message);
        ebpf_free_string(report);
        return ERROR_SUPPRESS_OUTPUT;
    }
}
