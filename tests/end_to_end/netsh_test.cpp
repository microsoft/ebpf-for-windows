// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <windows.h>
#include <netsh.h> // Must be included after windows.h
#include "capture_helper.hpp"
#include "catch2\catch.hpp"
#include "elf.h"

#pragma region
// Mock Netsh.exe APIs.

DWORD
PreprocessCommand(
    HANDLE hModule,
    LPWSTR* ppwcArguments,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    TAG_TYPE* pttTags,
    DWORD dwTagCount,
    DWORD dwMinArgs,
    DWORD dwMaxArgs,
    DWORD* pdwTagType)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(ppwcArguments);

    DWORD argc = dwArgCount - dwCurrentIndex;
    if (argc < dwMinArgs || argc > dwMaxArgs) {
        return ERROR_INVALID_SYNTAX;
    }

    // Simplified algorithm is to assume arguments are supplied in the correct order.
    for (DWORD i = 0; i < dwTagCount; i++) {
        if (dwCurrentIndex + i < dwArgCount) {
            pttTags[i].bPresent = true;
            pdwTagType[i] = i;
        } else if (pttTags[i].dwRequired & NS_REQ_PRESENT) {
            return ERROR_INVALID_SYNTAX;
        }
    }

    return NO_ERROR;
}

DWORD
MatchEnumTag(HANDLE hModule, LPCWSTR pwcArg, DWORD dwNumArg, const TOKEN_VALUE* pEnumTable, PDWORD pdwValue)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(pwcArg);
    UNREFERENCED_PARAMETER(dwNumArg);
    UNREFERENCED_PARAMETER(pEnumTable);
    UNREFERENCED_PARAMETER(pdwValue);
    return 0;
}
#pragma endregion

static std::string
_run_netsh_command(
    _In_ FN_HANDLE_CMD* command, _In_z_ const wchar_t* arg1, _In_z_ const wchar_t* arg2, _Out_ int* result)
{
    capture_helper_t capture;
    errno_t error = capture.begin_capture();
    if (error != NO_ERROR) {
        *result = error;
        return "Couldn't capture output\n";
    }

    // Copy args into an array.
    PWSTR argv[2] = {};
    int argc = 0;
    if (arg1 != nullptr) {
        argv[argc++] = (PWSTR)arg1;
    }
    if (arg2 != nullptr) {
        argv[argc++] = (PWSTR)arg2;
    }

    error = command(nullptr, argv, 0, argc, 0, 0, nullptr);
    if (error != 0) {
        *result = error;
        return capture.get_stderr_contents();
    }

    *result = NO_ERROR;
    return capture.get_stdout_contents();
}

TEST_CASE("show disassembly bpf.o", "[netsh][disassembly]")
{
    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_disassembly, L"bpf.o", nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "       0:	r0 = 42\n"
                  "       1:	exit\n\n");
}

TEST_CASE("show disassembly bpf.o nosuchsection", "[netsh][disassembly]")
{
    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_disassembly, L"bpf.o", L"nosuchsection", &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: Can't find section nosuchsection in file bpf.o\n");
}

TEST_CASE("show disassembly nosuchfile.o", "[netsh][disassembly]")
{
    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_disassembly, L"nosuchfile.o", nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: No such file or directory opening nosuchfile.o\n");
}

TEST_CASE("show sections nosuchfile.o", "[netsh][sections]")
{
    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_sections, L"nosuchfile.o", nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: No such file or directory opening nosuchfile.o\n");
}

TEST_CASE("show sections bpf.o", "[netsh][sections]")
{
    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_sections, L"bpf.o", nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "             Section       Type  # Maps    Size\n"
                  "====================  =========  ======  ======\n"
                  "            xdp_prog        xdp       0       2\n");
}

TEST_CASE("show sections bpf.o xdp_prog", "[netsh][sections]")
{
    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_sections, L"bpf.o", L"xdp_prog", &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "Section      : xdp_prog\n"
                  "Program Type : xdp\n"
                  "# Maps       : 0\n"
                  "Size         : 2 instructions\n"
                  "adjust_head  : 0\n"
                  "arith        : 0\n"
                  "arith32      : 0\n"
                  "arith64      : 1\n"
                  "assign       : 1\n"
                  "basic_blocks : 2\n"
                  "call_1       : 0\n"
                  "call_mem     : 0\n"
                  "call_nomem   : 0\n"
                  "joins        : 0\n"
                  "jumps        : 0\n"
                  "load         : 0\n"
                  "load_store   : 0\n"
                  "map_in_map   : 0\n"
                  "other        : 2\n"
                  "packet_access: 0\n"
                  "store        : 0\n");
}
