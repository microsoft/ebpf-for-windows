// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <windows.h>
#include <netsh.h> // Must be included after windows.h
#include "capture_helper.hpp"
#include "catch2\catch.hpp"
#include "elf.h"
#include "programs.h"
#include "test_helper.hpp"

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
    UNREFERENCED_PARAMETER(ppwcArguments);

    DWORD argc = dwArgCount - dwCurrentIndex;
    if (argc < dwMinArgs || argc > dwMaxArgs) {
        return ERROR_INVALID_SYNTAX;
    }

    if (!pttTags || !pdwTagType) {
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
    _test_helper_end_to_end test_helper;

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

TEST_CASE("show verification nosuchfile.o", "[netsh][verification]")
{
    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_verification, L"nosuchfile.o", nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: No such file or directory opening nosuchfile.o\n");
}

TEST_CASE("show verification bpf.o", "[netsh][verification]")
{
    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_verification, L"bpf.o", nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "\n"
                  "0 errors\n"
                  "Verification succeeded\n"
                  "Program terminates within 6 instructions\n");
}

TEST_CASE("show verification droppacket.o", "[netsh][verification]")
{
    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_verification, L"droppacket.o", L"xdp", &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "\n"
                  "0 errors\n"
                  "Verification succeeded\n"
                  "Program terminates within 78 instructions\n");
}

TEST_CASE("show verification droppacket_unsafe.o", "[netsh][verification]")
{
    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_verification, L"droppacket_unsafe.o", L"xdp", &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(
        output == "Verification failed\n"
                  "\n"
                  "Verification report:\n"
                  "\n"
                  "2: r2 = *(u8 *)(r1 + 9)\n"
                  "  Upper bound must be at most packet_size (valid_access(r1, 9:1))\n"
                  "4: r1 = *(u16 *)(r1 + 24)\n"
                  "  Upper bound must be at most packet_size (valid_access(r1, 24:2))\n"
                  "\n"
                  "2 errors\n"
                  "\n");
}

TEST_CASE("show programs", "[netsh][programs]")
{
    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_programs, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);

    // Since we mocked the ioctl, there should be no programs shown.
    REQUIRE(
        output == "\n"
                  "           File Name          Section  Requested Execution Type\n"
                  "====================  ===============  ========================\n");
}