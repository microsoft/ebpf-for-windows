// Copyright (C) Microsoft.
// SPDX-License-Identifier: MIT
#include <string>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <netsh.h>
#include "programs.h"
#include "tokens.h"

typedef enum {
    PINNED_ANY = 0,
    PINNED_YES = 1,
    PINNED_NO = 2,
} PINNED_CONSTRAINT;

TOKEN_VALUE g_PinnedEnum[] = {
    { L"any", PINNED_ANY },
    { L"yes", PINNED_YES },
    { L"no", PINNED_NO },
};

TOKEN_VALUE g_EbpfProgramTypeEnum[] = {
    { L"xdp", EBPF_PROGRAM_TYPE_XDP },
};

unsigned long HandleEbpfAddProgram(
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
        {TOKEN_TYPE, NS_REQ_ZERO, FALSE},
        {TOKEN_PINNED, NS_REQ_ZERO, FALSE},
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
    EBPF_PROGRAM_TYPE type = EBPF_PROGRAM_TYPE_XDP;
    PINNED_CONSTRAINT pinned = PINNED_ANY;
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
        case 2: // TYPE
            status = MatchEnumTag(NULL,
                argv[currentIndex + i],
                _countof(g_EbpfProgramTypeEnum),
                g_EbpfProgramTypeEnum,
                (PULONG)&type);
            if (status != NO_ERROR) {
                status = ERROR_INVALID_PARAMETER;
            }
            break;
        case 3: // PINNED
            status = MatchEnumTag(NULL,
                argv[currentIndex + i],
                _countof(g_PinnedEnum),
                g_PinnedEnum,
                (PULONG)&pinned);
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

    // TODO: add program
    return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD HandleEbpfDeleteProgram(
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

    // TODO: delete program
    return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD HandleEbpfSetProgram(
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
        {TOKEN_SECTION, NS_REQ_PRESENT, FALSE},
        {TOKEN_PINNED, NS_REQ_ZERO, FALSE},
    };
    ULONG tagType[_countof(tags)] = { 0 };

    ULONG status = PreprocessCommand(nullptr,
        argv,
        currentIndex,
        argc,
        tags,
        _countof(tags),
        0,
        3, // Two required tags plus at least one optional tag.
        tagType);

    std::string filename;
    std::string section = ".text";
    PINNED_CONSTRAINT pinned = PINNED_ANY;
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
        case 2: // PINNED
            status = MatchEnumTag(NULL,
                argv[currentIndex + i],
                _countof(g_PinnedEnum),
                g_PinnedEnum,
                (PULONG)&pinned);
            if ((status != NO_ERROR) || (pinned == PINNED_ANY)) {
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

    // TODO: update program
    return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD HandleEbpfShowPrograms(
    LPCWSTR machine,
    LPWSTR* argv,
    DWORD currentIndex,
    DWORD argc,
    DWORD flags,
    LPCVOID data,
    BOOL* done)
{
    TAG_TYPE tags[] = {
        {TOKEN_TYPE, NS_REQ_ZERO, FALSE},
        {TOKEN_PINNED, NS_REQ_ZERO, FALSE},
        {TOKEN_LEVEL, NS_REQ_ZERO, FALSE},
        {TOKEN_FILENAME, NS_REQ_ZERO, FALSE},
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

    EBPF_PROGRAM_TYPE type = EBPF_PROGRAM_TYPE_XDP;
    PINNED_CONSTRAINT pinned = PINNED_ANY;
    VERBOSITY_LEVEL level = VL_NORMAL;
    std::string filename;
    std::string section = ".text";
    for (int i = 0; (status == NO_ERROR) && ((i + currentIndex) < argc); i++) {
        switch (tagType[i]) {
        case 0: // TYPE
            status = MatchEnumTag(NULL,
                argv[currentIndex + i],
                _countof(g_EbpfProgramTypeEnum),
                g_EbpfProgramTypeEnum,
                (PULONG)&type);
            if (status != NO_ERROR) {
                status = ERROR_INVALID_PARAMETER;
            }
            break;
        case 1: // PINNED
            status = MatchEnumTag(NULL,
                argv[currentIndex + i],
                _countof(g_PinnedEnum),
                g_PinnedEnum,
                (PULONG)&pinned);
            if (status != NO_ERROR) {
                status = ERROR_INVALID_PARAMETER;
            }
            break;
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
        case 3: // FILENAME
        {
            std::wstring ws(argv[currentIndex + i]);
            filename = std::string(ws.begin(), ws.end());
            break;
        }
        case 4: // SECTION
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

    // If the user specified a filename and no level, default to verbose.
    if (tags[3].bPresent && !tags[2].bPresent) {
        level = VL_VERBOSE;
    }

    // TODO: enumerate programs using specified constraints
    return ERROR_CALL_NOT_IMPLEMENTED;
}
