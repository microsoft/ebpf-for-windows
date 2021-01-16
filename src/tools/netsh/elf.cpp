// Copyright (C) Microsoft.
// SPDX-License-Identifier: MIT
#include "ebpf_verifier.hpp"
#include "asm_ostream.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <netsh.h>
#include "elf.h"
#include "tokens.h"

typedef enum {
    VL_NORMAL = 0,
    VL_VERBOSE = 1,
} VERBOSITY_LEVEL;

TOKEN_VALUE g_LevelEnum[2] = {
    { L"normal", VL_NORMAL },
    { L"verbose", VL_VERBOSE },
};

DWORD HandleEbpfShowDisassembly(
    LPCWSTR machine,
    LPWSTR* argv,
    DWORD currentIndex,
    DWORD argc,
    DWORD flags,
    LPCVOID data,
    BOOL* done)
{
    TAG_TYPE tags[] = {
        {TOKEN_FILENAME, NS_REQ_PRESENT, FALSE},
        {TOKEN_SECTION, NS_REQ_ZERO, FALSE},
    };
    ULONG tagType[_countof(tags)] = { 0 };

    ULONG status = PreprocessCommand(nullptr,
        argv,
        currentIndex,
        argc,
        tags,
        _countof(tags),
        0,
        _countof(tags),
        tagType);

    std::string filename;
    std::string section = ".text";
    for (int i = 0; (status == NO_ERROR) && ((i + currentIndex) < argc); i++) {
        switch (tagType[i]) {
        case 0: // FILENAME
        {
            std::wstring ws(argv[currentIndex + i]);
            filename = std::string(ws.begin(), ws.end());
            break;
        }
        case 1: // SECTION
        {
            std::wstring ws(argv[currentIndex + i]);
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
        auto raw_progs = read_elf(filename, section, create_map_crab, nullptr);
        raw_program raw_prog = raw_progs.back();
        std::variant<InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog);
        if (std::holds_alternative<std::string>(prog_or_error)) {
            std::cout << "parse failure: " << std::get<std::string>(prog_or_error) << "\n";
            return 1;
        }
        auto& prog = std::get<InstructionSeq>(prog_or_error);
        std::cout << "\n";
        print(prog, std::cout);
        return NO_ERROR;
    }
    catch (std::exception ex) {
        std::cout << "Failed to load eBPF program from " << filename << "\n";
        return ERROR_SUPPRESS_OUTPUT;
    }

}

DWORD HandleEbpfShowSections(
    LPCWSTR machine,
    LPWSTR* argv,
    DWORD currentIndex,
    DWORD argc,
    DWORD flags,
    LPCVOID data,
    BOOL* done)
{
    TAG_TYPE tags[] = {
        {TOKEN_FILENAME, NS_REQ_PRESENT, FALSE},
        {TOKEN_SECTION, NS_REQ_ZERO, FALSE},
        {TOKEN_LEVEL, NS_REQ_ZERO, FALSE},
    };
    ULONG tagType[_countof(tags)] = { 0 };

    ULONG status = PreprocessCommand(nullptr,
        argv,
        currentIndex,
        argc,
        tags,
        _countof(tags),
        0,
        _countof(tags),
        tagType);

    VERBOSITY_LEVEL level = VL_NORMAL;
    std::string filename;
    std::string section;
    for (int i = 0; (status == NO_ERROR) && ((i + currentIndex) < argc); i++) {
        switch (tagType[i]) {
        case 0: // FILENAME
        {
            std::wstring ws(argv[currentIndex + i]);
            filename = std::string(ws.begin(), ws.end());
            break;
        }
        case 1: // SECTION
        {
            std::wstring ws(argv[currentIndex + i]);
            section = std::string(ws.begin(), ws.end());
            break;
        }
        case 2: // LEVEL
            status = MatchEnumTag(NULL,
                argv[currentIndex + i],
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
        auto raw_progs = read_elf(filename, section, create_map_crab, nullptr);
        if (level == VL_NORMAL) {
            std::cout << "\n";
            std::cout << "             Section    Type  # Maps    Size\n";
            std::cout << "====================  ======  ======  ======\n";
        }
        for (const raw_program& raw_prog : raw_progs) {
            if (level == VL_NORMAL) {
                std::cout << std::setw(20) << raw_prog.section << "  " <<
                    std::setw(6) << (int)raw_prog.info.program_type << "  " <<
                    std::setw(6) << raw_prog.info.map_defs.size() << "  " <<
                    std::setw(6) << raw_prog.prog.size() << "\n";
            } else {
                std::cout << "\n";
                std::cout << "Section: " << raw_prog.section << "\n";
                std::cout << "Type:    " << (int)raw_prog.info.program_type << "\n";
                std::cout << "# Maps:  " << raw_prog.info.map_defs.size() << "\n";
                std::cout << "Size:    " << raw_prog.prog.size() << " instructions\n";
            }
        }
        return NO_ERROR;
    }
    catch (std::exception ex) {
        std::cout << "Failed to load ELF file: " << filename << "\n";
        return ERROR_SUPPRESS_OUTPUT;
    }
}

DWORD HandleEbpfShowVerification(
    LPCWSTR machine,
    LPWSTR* argv,
    DWORD currentIndex,
    DWORD argc,
    DWORD flags,
    LPCVOID data,
    BOOL* done)
{
    return ERROR_CALL_NOT_IMPLEMENTED;
}