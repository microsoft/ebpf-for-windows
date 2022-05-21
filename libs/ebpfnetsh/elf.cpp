// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iomanip>
#include <locale>
#include <netsh.h>
#include "elf.h"
#include "tokens.h"
#include "utilities.h"

TOKEN_VALUE g_LevelEnum[2] = {
    {L"normal", VL_NORMAL},
    {L"verbose", VL_VERBOSE},
};

DWORD
handle_ebpf_show_disassembly(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    TAG_TYPE tags[] = {
        {TOKEN_FILENAME, NS_REQ_PRESENT, FALSE},
        {TOKEN_SECTION, NS_REQ_ZERO, FALSE},
    };
    ULONG tag_type[_countof(tags)] = {0};

    ULONG status =
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
        std::cerr << error_message << std::endl;
        ebpf_free_string(error_message);
        return ERROR_SUPPRESS_OUTPUT;
    } else {
        std::cout << disassembly << std::endl;
        ebpf_free_string(disassembly);
        return NO_ERROR;
    }
}

DWORD
handle_ebpf_show_sections(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
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
    ULONG tag_type[_countof(tags)] = {0};

    ULONG status =
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
            status = MatchEnumTag(NULL, argv[current_index + i], _countof(g_LevelEnum), g_LevelEnum, (PULONG)&level);
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
        std::cerr << error_message << std::endl;
        ebpf_free_string(error_message);
        ebpf_free_sections(section_data);
        return ERROR_SUPPRESS_OUTPUT;
    }

    if (level == VL_NORMAL) {
        std::cout << "\n";
        std::cout << "             Section       Type  # Maps    Size\n";
        std::cout << "====================  =========  ======  ======\n";
    }
    for (auto current_section = section_data; current_section != nullptr; current_section = current_section->next) {
        if (!section.empty() && strcmp(current_section->section_name, section.c_str()) != 0) {
            continue;
        }
        if (level == VL_NORMAL) {
            std::cout << std::setw(20) << std::right << current_section->section_name << "  " << std::setw(9)
                      << current_section->program_type_name << "  " << std::setw(6) << current_section->map_count
                      << "  " << std::setw(6) << current_section->raw_data_size << "\n";
        } else {
            std::cout << "\n";
            std::cout << "Section      : " << current_section->section_name << "\n";
            std::cout << "Program Type : " << current_section->program_type_name << "\n";
            std::cout << "# Maps       : " << current_section->map_count << "\n";
            std::cout << "Size         : " << current_section->raw_data_size << " bytes\n";
            for (auto stat = current_section->stats; stat != nullptr; stat = stat->next) {
                std::cout << std::setw(13) << std::left << stat->key << ": " << stat->value << "\n";
            }
        }
    }

    ebpf_free_sections(section_data);
    ebpf_free_string(error_message);
    return NO_ERROR;
}

DWORD
handle_ebpf_show_verification(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
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
    ULONG tag_type[_countof(tags)] = {0};

    ULONG status =
        PreprocessCommand(nullptr, argv, current_index, argc, tags, _countof(tags), 0, _countof(tags), tag_type);

    VERBOSITY_LEVEL level = VL_NORMAL;
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
        case 2: // LEVEL
        {
            status = MatchEnumTag(NULL, argv[current_index + i], _countof(g_LevelEnum), g_LevelEnum, (PULONG)&level);
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

    status = ebpf_api_elf_verify_section_from_file(
        filename.c_str(), section.c_str(), level == VL_VERBOSE, &report, &error_message, &stats);
    if (status == ERROR_SUCCESS) {
        std::cout << report;
        std::cout << "\nProgram terminates within " << stats.max_instruction_count << " instructions\n";
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
