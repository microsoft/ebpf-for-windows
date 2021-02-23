// Copyright (C) Microsoft.
// SPDX-License-Identifier: MIT
#include "ebpf_verifier.hpp"
#include "windows/windows_platform.hpp"
#include "asm_ostream.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <netsh.h>
#include "elf.h"
#include "tokens.h"

TOKEN_VALUE g_LevelEnum[2] = {
    { L"normal", VL_NORMAL },
    { L"verbose", VL_VERBOSE },
};

DWORD handle_ebpf_show_disassembly(
    LPCWSTR machine,
    LPWSTR* argv,
    DWORD current_index,
    DWORD argc,
    DWORD flags,
    LPCVOID data,
    BOOL* done)
{
    const ebpf_platform_t* platform = &g_ebpf_platform_windows;

    TAG_TYPE tags[] = {
        {TOKEN_FILENAME, NS_REQ_PRESENT, FALSE},
        {TOKEN_SECTION, NS_REQ_ZERO, FALSE},
    };
    ULONG tag_type[_countof(tags)] = { 0 };

    ULONG status = PreprocessCommand(nullptr,
        argv,
        current_index,
        argc,
        tags,
        _countof(tags),
        0,
        _countof(tags),
        tag_type);

    std::string filename;
    std::string section = ".text";
    for (int i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
        switch (tag_type[i]) {
        case 0: // FILENAME
        {
            std::wstring ws(argv[current_index + i]);
            filename = std::string(ws.begin(), ws.end());
            break;
        }
        case 1: // SECTION
        {
            std::wstring ws(argv[current_index + i]);
            section = std::string(ws.begin(), ws.end());
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

    try {
        ebpf_verifier_options_t verifierOptions = ebpf_verifier_default_options;
        verifierOptions.print_failures = true;
        auto rawPrograms = read_elf(filename, section, &verifierOptions, platform);
        raw_program rawProgram = rawPrograms.back();
        std::variant<InstructionSeq, std::string> programOrError = unmarshal(rawProgram, platform);
        if (std::holds_alternative<std::string>(programOrError)) {
            std::cout << "parse failure: " << std::get<std::string>(programOrError) << "\n";
            return 1;
        }
        auto& program = std::get<InstructionSeq>(programOrError);
        std::cout << "\n";
        print(program, std::cout);
        return NO_ERROR;
    }
    catch (std::exception ex) {
        std::cout << "Failed to load eBPF program from " << filename << "\n";
        return ERROR_SUPPRESS_OUTPUT;
    }
}

DWORD handle_ebpf_show_sections(
    LPCWSTR machine,
    LPWSTR* argv,
    DWORD current_index,
    DWORD argc,
    DWORD flags,
    LPCVOID data,
    BOOL* done)
{
    const ebpf_platform_t* platform = &g_ebpf_platform_windows;

    TAG_TYPE tags[] = {
        {TOKEN_FILENAME, NS_REQ_PRESENT, FALSE},
        {TOKEN_SECTION, NS_REQ_ZERO, FALSE},
        {TOKEN_LEVEL, NS_REQ_ZERO, FALSE},
    };
    ULONG tag_type[_countof(tags)] = { 0 };

    ULONG status = PreprocessCommand(nullptr,
        argv,
        current_index,
        argc,
        tags,
        _countof(tags),
        0,
        _countof(tags),
        tag_type);

    VERBOSITY_LEVEL level = VL_NORMAL;
    std::string filename;
    std::string section;
    for (int i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
        switch (tag_type[i]) {
        case 0: // FILENAME
        {
            std::wstring ws(argv[current_index + i]);
            filename = std::string(ws.begin(), ws.end());
            break;
        }
        case 1: // SECTION
        {
            std::wstring ws(argv[current_index + i]);
            section = std::string(ws.begin(), ws.end());
            break;
        }
        case 2: // LEVEL
            status = MatchEnumTag(NULL,
                argv[current_index + i],
                _countof(g_LevelEnum),
                g_LevelEnum,
                (PULONG)&level);
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

    try {
        auto rawPrograms = read_elf(filename, section, &ebpf_verifier_default_options, platform);
        if (level == VL_NORMAL) {
            std::cout << "\n";
            std::cout << "             Section    Type  # Maps    Size\n";
            std::cout << "====================  ======  ======  ======\n";
        }
        for (const raw_program& rawProgram : rawPrograms) {
            if (level == VL_NORMAL) {
                std::cout << std::setw(20) << std::right << rawProgram.section << "  " <<
                    std::setw(6) << rawProgram.info.type.platform_specific_data << "  " <<
                    std::setw(6) << rawProgram.info.map_descriptors.size() << "  " <<
                    std::setw(6) << rawProgram.prog.size() << "\n";
            } else {
                // Convert the instruction sequence to a control-flow graph
                // in a "passive", non-deterministic form.
                std::variant<InstructionSeq, std::string> programOrError = unmarshal(rawProgram, platform);
                if (std::holds_alternative<std::string>(programOrError)) {
                    std::cout << "parse failure: " << std::get<std::string>(programOrError) << "\n";
                    return 1;
                }
                auto& program = std::get<InstructionSeq>(programOrError);
                cfg_t controlFlowGraph = prepare_cfg(program, rawProgram.info, true);
                std::map<std::string, int> stats = collect_stats(controlFlowGraph);

                std::cout << "\n";
                std::cout << "Section      : " << rawProgram.section << "\n";
                std::cout << "Type         : " << (int)rawProgram.info.type.platform_specific_data << "\n";
                std::cout << "# Maps       : " << rawProgram.info.map_descriptors.size() << "\n";
                std::cout << "Size         : " << rawProgram.prog.size() << " instructions\n";
                for (std::map<std::string, int>::iterator iter = stats.begin(); iter != stats.end(); iter++)
                {
                    std::string key = iter->first;
                    int value = iter->second;
                    std::cout << std::setw(13) << std::left << key << ": " << value << "\n";
                }
            }
        }
        return NO_ERROR;
    }
    catch (std::exception ex) {
        std::cout << "Failed to load ELF file: " << filename << "\n";
        return ERROR_SUPPRESS_OUTPUT;
    }
}

DWORD handle_ebpf_show_verification(
    LPCWSTR machine,
    LPWSTR* argv,
    DWORD current_index,
    DWORD argc,
    DWORD flags,
    LPCVOID data,
    BOOL* done)
{
    const ebpf_platform_t* platform = &g_ebpf_platform_windows;

    TAG_TYPE tags[] = {
            {TOKEN_FILENAME, NS_REQ_PRESENT, FALSE},
            {TOKEN_SECTION, NS_REQ_ZERO, FALSE},
    };
    ULONG tag_type[_countof(tags)] = { 0 };

    ULONG status = PreprocessCommand(nullptr,
        argv,
        current_index,
        argc,
        tags,
        _countof(tags),
        0,
        _countof(tags),
        tag_type);

    std::string filename;
    std::string section = ".text";
    for (int i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
        switch (tag_type[i]) {
        case 0: // FILENAME
        {
            std::wstring ws(argv[current_index + i]);
            filename = std::string(ws.begin(), ws.end());
            break;
        }
        case 1: // SECTION
        {
            std::wstring ws(argv[current_index + i]);
            section = std::string(ws.begin(), ws.end());
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

    try {
        // Analyze the control-flow graph.
        ebpf_verifier_options_t verifierOptions = ebpf_verifier_default_options;
        verifierOptions.print_failures = true;
        auto rawPrograms = read_elf(filename, section, &verifierOptions, platform);
        raw_program rawProgram = rawPrograms.back();
        std::variant<InstructionSeq, std::string> programOrError = unmarshal(rawProgram, platform);
        if (std::holds_alternative<std::string>(programOrError)) {
            std::cout << "parse failure: " << std::get<std::string>(programOrError) << "\n";
            return 1;
        }
        auto& program = std::get<InstructionSeq>(programOrError);

        // Convert the instruction sequence to a control-flow graph
        // in a "passive", non-deterministic form.
        cfg_t controlFlowGraph = prepare_cfg(program, rawProgram.info, true);

        const auto res = run_ebpf_analysis(std::cout, controlFlowGraph, rawProgram.info, &verifierOptions);
        if (!res) {
            std::cout << "\nVerification failed\n";
            return ERROR_SUPPRESS_OUTPUT;
        }

        std::cout << "\nVerification succeeded\n";
        return NO_ERROR;
    }
    catch (std::exception ex) {
        std::cout << "Failed to load eBPF program from " << filename << "\n";
        return ERROR_SUPPRESS_OUTPUT;
    }
}
