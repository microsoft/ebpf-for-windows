// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <windows.h>
#include <netsh.h> // Must be included after windows.h
#include <string.h>
#include "bpf/bpf.h"
#include "capture_helper.hpp"
#include "catch_wrapper.hpp"
#include "elf.h"

#pragma region
// Mock Netsh.exe APIs.

DWORD WINAPI
PreprocessCommand(
    _In_opt_ HANDLE hModule,
    _Inout_updates_(dwArgCount) LPWSTR* ppwcArguments,
    _In_ DWORD dwCurrentIndex,
    _In_ DWORD dwArgCount,
    _Inout_updates_opt_(dwTagCount) TAG_TYPE* pttTags,
    _In_ DWORD dwTagCount,
    _In_ DWORD dwMinArgs,
    _In_ DWORD dwMaxArgs,
    _Out_writes_opt_(dwArgCount - dwCurrentIndex) DWORD* pdwTagType)
{
    UNREFERENCED_PARAMETER(hModule);

    DWORD argc = dwArgCount - dwCurrentIndex;
    if (argc < dwMinArgs || argc > dwMaxArgs) {
        return ERROR_INVALID_SYNTAX;
    }

    if (!pttTags || !pdwTagType) {
        return ERROR_INVALID_SYNTAX;
    }

    for (DWORD i = 0; i < argc; i++) {
        PWSTR equals = wcschr(ppwcArguments[dwCurrentIndex + i], L'=');
        PWSTR tagName = nullptr;
        if (equals) {
            tagName = _wcsdup(ppwcArguments[dwCurrentIndex + i]);
            if (tagName == nullptr) {
                return ERROR_OUTOFMEMORY;
            }
            tagName[equals - ppwcArguments[dwCurrentIndex + i]] = 0;

            // Advance past the tag.
            ppwcArguments[dwCurrentIndex + i] = ++equals;
        }

        // Find which tag this argument goes with.
        DWORD dwTagIndex;
        for (dwTagIndex = 0; dwTagIndex < dwTagCount; dwTagIndex++) {
            if ((tagName == nullptr && !pttTags[dwTagIndex].bPresent) ||
                (tagName != nullptr && wcsncmp(pttTags[dwTagIndex].pwszTag, tagName, wcslen(tagName)) == 0)) {
                pttTags[dwTagIndex].bPresent = true;
                pdwTagType[i] = dwTagIndex;
                break;
            }
        }
        if (tagName) {
            free((void*)tagName);
        }
        if (dwTagIndex == dwTagCount) {
            // Tag not found.
            return ERROR_INVALID_SYNTAX;
        }
    }

    // See if any required tags are absent.
    for (DWORD i = 0; i < dwTagCount; i++) {
        if (!pttTags[i].bPresent && (pttTags[i].dwRequired & NS_REQ_PRESENT)) {
            return ERROR_INVALID_SYNTAX;
        }
    }

    return NO_ERROR;
}

DWORD
MatchEnumTag(HANDLE hModule, LPCWSTR pwcArg, DWORD dwNumArg, const TOKEN_VALUE* pEnumTable, PDWORD pdwValue)
{
    UNREFERENCED_PARAMETER(hModule);

    for (DWORD i = 0; i < dwNumArg; i++) {
        if (wcscmp(pwcArg, pEnumTable[i].pwszToken) == 0) {
            *pdwValue = pEnumTable[i].dwValue;
            return NO_ERROR;
        }
    }
    return ERROR_NOT_FOUND;
}
#pragma endregion

std::string
_run_netsh_command(
    _In_ FN_HANDLE_CMD* command,
    _In_opt_z_ const wchar_t* arg1,
    _In_opt_z_ const wchar_t* arg2,
    _In_opt_z_ const wchar_t* arg3,
    _Out_ int* result)
{
    capture_helper_t capture;
    errno_t error = capture.begin_capture();
    if (error != NO_ERROR) {
        *result = error;
        return "Couldn't capture output\n";
    }

    // Copy args into an array.
    PWSTR argv[3] = {};
    int argc = 0;
    if (arg1 != nullptr) {
        argv[argc++] = (PWSTR)arg1;
    }
    if (arg2 != nullptr) {
        argv[argc++] = (PWSTR)arg2;
    }
    if (arg3 != nullptr) {
        argv[argc++] = (PWSTR)arg3;
    }

    error = command(nullptr, argv, 0, argc, 0, 0, nullptr);
    if (error != 0) {
        *result = error;
        return capture.get_stderr_contents();
    }

    *result = NO_ERROR;
    return capture.get_stdout_contents();
}
