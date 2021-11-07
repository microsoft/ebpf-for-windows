// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#include <codecvt>
#include <iomanip>
#include <iostream>
#include <locale>
#include <netsh.h>
#include "elf.h"
#include "ebpf_api.h"
#include "tlv.h"
#include "tokens.h"

TOKEN_VALUE g_LevelEnum[2] = {
    {L"normal", VL_NORMAL},
    {L"verbose", VL_VERBOSE},
};

std::string
down_cast_from_wstring(const std::wstring& wide_string)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
    return converter.to_bytes(wide_string);
}

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

    const tlv_type_length_value_t* section_data = nullptr;

    const char* error_message = nullptr;
    if (ebpf_api_elf_enumerate_sections(
            filename.c_str(), section.c_str(), level == VL_VERBOSE, &section_data, &error_message) != 0) {
        std::cerr << error_message << std::endl;
        ebpf_free_string(error_message);
        ebpf_api_elf_free(section_data);
        return ERROR_SUPPRESS_OUTPUT;
    }

    if (level == VL_NORMAL) {
        std::cout << "\n";
        std::cout << "             Section       Type  # Maps    Size\n";
        std::cout << "====================  =========  ======  ======\n";
    }
    for (auto current_section = tlv_child(section_data); current_section != tlv_next(section_data);
         current_section = tlv_next(current_section)) {
        auto section_name = tlv_child(current_section);
        auto type = tlv_next(section_name);
        auto map_count = tlv_next(type);
        auto program_bytes = tlv_next(map_count);
        auto stats_section = tlv_next(program_bytes);
        if (level == VL_NORMAL) {
            std::cout << std::setw(20) << std::right << tlv_value<std::string>(section_name) << "  " << std::setw(9)
                      << tlv_value<std::string>(type) << "  " << std::setw(6) << tlv_value<size_t>(map_count) << "  "
                      << std::setw(6) << (program_bytes->length - offsetof(tlv_type_length_value_t, value)) / 8 << "\n";
        } else {
            std::cout << "\n";
            std::cout << "Section      : " << tlv_value<std::string>(section_name) << "\n";
            std::cout << "Program Type : " << tlv_value<std::string>(type) << "\n";
            std::cout << "# Maps       : " << tlv_value<size_t>(map_count) << "\n";
            std::cout << "Size         : " << (program_bytes->length - offsetof(tlv_type_length_value_t, value)) / 8
                      << " instructions\n";
            for (auto stat = tlv_child(stats_section); stat != tlv_next(current_section); stat = tlv_next(stat)) {
                auto key = tlv_child(stat);
                auto value = tlv_next(key);
                std::cout << std::setw(13) << std::left << tlv_value<std::string>(key) << ": " << tlv_value<int>(value)
                          << "\n";
            }
        }
    }

    ebpf_api_elf_free(section_data);
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

    status = ebpf_api_elf_verify_section(
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
