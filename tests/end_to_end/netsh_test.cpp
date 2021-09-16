// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <windows.h>
#include <netsh.h> // Must be included after windows.h
#include <string.h>
#include "bpf.h"
#include "capture_helper.hpp"
#include "catch_wrapper.hpp"
#include "elf.h"
#pragma warning(push)
#pragma warning(disable : 4200)
#include "libbpf.h"
#pragma warning(pop)
#include "links.h"
#include "maps.h"
#include "pins.h"
#include "platform.h"
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

static std::string
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

TEST_CASE("show disassembly bpf.o", "[netsh][disassembly]")
{
    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_disassembly, L"bpf.o", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "       0:	r0 = 42\n"
                  "       1:	exit\n\n");
}

TEST_CASE("show disassembly bpf.o nosuchsection", "[netsh][disassembly]")
{
    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_disassembly, L"bpf.o", L"nosuchsection", nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: Can't find section nosuchsection in file bpf.o\n");
}

TEST_CASE("show disassembly nosuchfile.o", "[netsh][disassembly]")
{
    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_disassembly, L"nosuchfile.o", nullptr, nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: No such file or directory opening nosuchfile.o\n");
}

TEST_CASE("show sections nosuchfile.o", "[netsh][sections]")
{
    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_sections, L"nosuchfile.o", nullptr, nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: No such file or directory opening nosuchfile.o\n");
}

TEST_CASE("show sections bpf.o", "[netsh][sections]")
{
    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_sections, L"bpf.o", nullptr, nullptr, &result);
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
    std::string output = _run_netsh_command(handle_ebpf_show_sections, L"bpf.o", L"xdp_prog", nullptr, &result);
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
    std::string output = _run_netsh_command(handle_ebpf_show_verification, L"nosuchfile.o", nullptr, nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: No such file or directory opening nosuchfile.o\n");
}

TEST_CASE("show verification bpf.o", "[netsh][verification]")
{
    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_verification, L"bpf.o", nullptr, nullptr, &result);
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
    _test_helper_libbpf test_helper;

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_verification, L"droppacket.o", L"xdp", nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "\n"
                  "0 errors\n"
                  "Verification succeeded\n"
                  "Program terminates within 114 instructions\n");
}

TEST_CASE("show verification droppacket_unsafe.o", "[netsh][verification]")
{
    _test_helper_libbpf test_helper;

    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_show_verification, L"droppacket_unsafe.o", L"xdp", nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(
        output == "Verification failed\n"
                  "\n"
                  "Verification report:\n"
                  "\n"
                  "2: r2 = *(u8 *)(r1 + 9)\n"
                  "  Upper bound must be at most packet_size (valid_access(r1.offset+9, width=1))\n"
                  "4: r1 = *(u16 *)(r1 + 24)\n"
                  "  Upper bound must be at most packet_size (valid_access(r1.offset+24, width=2))\n"
                  "\n"
                  "2 errors\n"
                  "\n");
}

TEST_CASE("pin first program", "[netsh][programs]")
{
    _test_helper_libbpf test_helper;

    // Load a program to show.
    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_add_program, L"reflect_packet.o", L"xdp", L"pinpath=reflect", &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 65537\n") == 0);
    REQUIRE(result == NO_ERROR);

    // Show programs in normal (table) format.
    output = _run_netsh_command(handle_ebpf_show_programs, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Name\n"
                  "======  ====  =====  =========  ====================\n"
                  " 65537     1      1  JIT        reflect_packet\n"
                  "131073     0      0  JIT        encap_reflect_packet\n");

    output = _run_netsh_command(handle_ebpf_delete_program, L"65537", nullptr, nullptr, &result);
    REQUIRE(output == "Unpinned 65537 from reflect\n");
    REQUIRE(result == NO_ERROR);
    REQUIRE(bpf_object__next(nullptr) == nullptr);
}

TEST_CASE("pin all programs", "[netsh][programs]")
{
    _test_helper_libbpf test_helper;

    // Load programs to show.
    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_add_program, L"reflect_packet.o", L"pinpath=mypinpath", L"pinned=all", &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 65537\n") == 0);
    REQUIRE(result == NO_ERROR);

    // Show programs in normal (table) format.
    output = _run_netsh_command(handle_ebpf_show_programs, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Name\n"
                  "======  ====  =====  =========  ====================\n"
                  " 65537     1      1  JIT        reflect_packet\n"
                  "131073     1      0  JIT        encap_reflect_packet\n");

    output = _run_netsh_command(handle_ebpf_delete_program, L"65537", nullptr, nullptr, &result);
    REQUIRE(output == "Unpinned 65537 from mypinpath/reflect_packet\n");
    REQUIRE(result == NO_ERROR);
    REQUIRE(bpf_object__next(nullptr) == nullptr);
}

TEST_CASE("show programs", "[netsh][programs]")
{
    _test_helper_libbpf test_helper;

    // Load a program to show.
    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_add_program, L"tail_call.o", L"pinpath=mypinname", nullptr, &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 196609\n") == 0);
    REQUIRE(result == NO_ERROR);

    // Show programs in normal (table) format.
    output = _run_netsh_command(handle_ebpf_show_programs, L"xdp", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Name\n"
                  "======  ====  =====  =========  ====================\n"
                  "196609     1      1  JIT        caller\n"
                  "262145     0      0  JIT        callee\n");

    // Test filtering by "attached=yes".
    output = _run_netsh_command(handle_ebpf_show_programs, L"attached=yes", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Name\n"
                  "======  ====  =====  =========  ====================\n"
                  "196609     1      1  JIT        caller\n");

    // Test filtering by "attached=no".
    output = _run_netsh_command(handle_ebpf_show_programs, L"attached=no", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Name\n"
                  "======  ====  =====  =========  ====================\n"
                  "262145     0      0  JIT        callee\n");

    // Test filtering by "pinned=yes".
    output = _run_netsh_command(handle_ebpf_show_programs, L"pinned=yes", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Name\n"
                  "======  ====  =====  =========  ====================\n"
                  "196609     1      1  JIT        caller\n");

    // Test filtering by "pinned=no".
    output = _run_netsh_command(handle_ebpf_show_programs, L"pinned=no", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Name\n"
                  "======  ====  =====  =========  ====================\n"
                  "262145     0      0  JIT        callee\n");

    // Test verbose output format.
    output = _run_netsh_command(handle_ebpf_show_programs, L"level=verbose", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "ID             : 196609\n"
                  "File name      : tail_call.o\n"
                  "Section        : xdp_prog\n"
                  "Name           : caller\n"
                  "Mode           : JIT\n"
                  "# map IDs      : 2\n"
                  "# pinned paths : 1\n"
                  "# links        : 1\n"
                  "\n"
                  "ID             : 262145\n"
                  "File name      : tail_call.o\n"
                  "Section        : xdp_prog/0\n"
                  "Name           : callee\n"
                  "Mode           : JIT\n"
                  "# map IDs      : 0\n"
                  "# pinned paths : 0\n"
                  "# links        : 0\n");

    output = _run_netsh_command(handle_ebpf_delete_program, L"196609", nullptr, nullptr, &result);
    REQUIRE(output == "Unpinned 196609 from mypinname\n");
    REQUIRE(result == NO_ERROR);
    REQUIRE(bpf_object__next(nullptr) == nullptr);
}

TEST_CASE("set program", "[netsh][programs]")
{
    _test_helper_libbpf test_helper;

    int result;
    std::string output = _run_netsh_command(handle_ebpf_add_program, L"tail_call.o", L"pinned=none", nullptr, &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 196609\n") == 0);
    REQUIRE(result == NO_ERROR);

    // Detach the program. This won't delete the program since
    // the containing object is still associated with the netsh process,
    // and could still be enumerated by it with bpf_object__next().
    output = _run_netsh_command(handle_ebpf_set_program, L"196609", L"", nullptr, &result);
    REQUIRE(output == "");
    REQUIRE(result == ERROR_OKAY);
    REQUIRE(bpf_object__next(nullptr) != nullptr);

    // Try to detach an unattached program.
    output = _run_netsh_command(handle_ebpf_set_program, L"196609", L"", nullptr, &result);
    REQUIRE(output == "error 1168: could not detach program\n");
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);

    RPC_WSTR attach_type_string;
    REQUIRE(UuidToStringW(&EBPF_ATTACH_TYPE_XDP, &attach_type_string) == 0);

    // Attach the program.
    output = _run_netsh_command(handle_ebpf_set_program, L"196609", (PCWSTR)attach_type_string, nullptr, &result);
    REQUIRE(output == "");
    REQUIRE(result == ERROR_OKAY);

    // Detach the program again.
    output = _run_netsh_command(handle_ebpf_set_program, L"196609", L"", nullptr, &result);
    REQUIRE(output == "");
    REQUIRE(result == ERROR_OKAY);

    // Verify we can delete a detached program.
    RpcStringFreeW(&attach_type_string);
    output = _run_netsh_command(handle_ebpf_delete_program, L"196609", nullptr, nullptr, &result);
    REQUIRE(output == "");
    REQUIRE(result == NO_ERROR);
    REQUIRE(bpf_object__next(nullptr) == nullptr);

    // Verify the program ID doesn't exist any more.
    output = _run_netsh_command(handle_ebpf_show_programs, nullptr, nullptr, nullptr, &result);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Name\n"
                  "======  ====  =====  =========  ====================\n");
    REQUIRE(result == NO_ERROR);
}

TEST_CASE("show maps", "[netsh][maps]")
{
    _test_helper_end_to_end test_helper;

    // Create maps to show.
    int outer_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH_OF_MAPS, sizeof(__u32), sizeof(__u32), 2, 0);
    REQUIRE(outer_map_fd > 0);

    int inner_map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32), sizeof(__u32), 1, 0);
    REQUIRE(inner_map_fd > 0);

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_maps, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);

    REQUIRE(
        output == "\n"
                  "                     Key  Value      Max  Inner\n"
                  "          Map Type  Size   Size  Entries     ID\n"
                  "==================  ====  =====  =======  =====\n"
                  "      Hash of maps     4      4        2      0\n"
                  "             Array     4      4        1      0\n");

    Platform::_close(inner_map_fd);
    Platform::_close(outer_map_fd);
}

TEST_CASE("show links", "[netsh][links]")
{
    _test_helper_libbpf test_helper;

    // Load and attach a program.
    int result;
    std::string output = _run_netsh_command(handle_ebpf_add_program, L"tail_call.o", L"pinned=none", nullptr, &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 196609\n") == 0);
    REQUIRE(result == NO_ERROR);

    output = _run_netsh_command(handle_ebpf_show_links, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "   Link  Program\n"
                  "     ID       ID\n"
                  "=======  =======\n"
                  " 327681   196609\n");

    output = _run_netsh_command(handle_ebpf_delete_program, L"196609", nullptr, nullptr, &result);
    REQUIRE(output == "");
    REQUIRE(result == NO_ERROR);
    REQUIRE(bpf_object__next(nullptr) == nullptr);
}

TEST_CASE("show pins", "[netsh][pins]")
{
    _test_helper_libbpf test_helper;

    // Load and pin programs.
    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_add_program, L"tail_call.o", L"pinned=all", L"pinpath=mypinpath", &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 196609\n") == 0);
    REQUIRE(result == NO_ERROR);

    output = _run_netsh_command(handle_ebpf_show_pins, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "     ID     Type  Path\n"
                  "=======  =======  ==============\n"
                  " 262145  Program  mypinpath/callee\n"
                  " 196609  Program  mypinpath/caller\n");

    output = _run_netsh_command(handle_ebpf_delete_program, L"196609", nullptr, nullptr, &result);
    REQUIRE(output == "Unpinned 196609 from mypinpath/caller\n");
    REQUIRE(result == NO_ERROR);
    REQUIRE(bpf_object__next(nullptr) == nullptr);
}

TEST_CASE("delete pinned program", "[netsh][programs]")
{
    _test_helper_libbpf test_helper;

    // Load a program unpinned.
    int result;
    std::string output = _run_netsh_command(handle_ebpf_add_program, L"tail_call.o", L"pinned=none", nullptr, &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 196609\n") == 0);
    REQUIRE(result == NO_ERROR);

    // Pin the program.
    output = _run_netsh_command(handle_ebpf_set_program, L"196609", L"pinpath=mypinname", nullptr, &result);
    REQUIRE(result == ERROR_OKAY);
    REQUIRE(output == "");

    // Verify we can delete a pinned program.
    output = _run_netsh_command(handle_ebpf_delete_program, L"196609", nullptr, nullptr, &result);
    REQUIRE(output == "Unpinned 196609 from mypinname\n");
    REQUIRE(result == NO_ERROR);
    REQUIRE(bpf_object__next(nullptr) == nullptr);

    // Verify the program ID doesn't exist any more.
    output = _run_netsh_command(handle_ebpf_show_programs, nullptr, nullptr, nullptr, &result);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Name\n"
                  "======  ====  =====  =========  ====================\n");
    REQUIRE(result == NO_ERROR);
}

TEST_CASE("unpin program", "[netsh][programs]")
{
    _test_helper_libbpf test_helper;

    // Load a program pinned.
    int result;
    std::string output = _run_netsh_command(handle_ebpf_add_program, L"tail_call.o", L"xdp", L"mypinname", &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 196609\n") == 0);
    REQUIRE(result == NO_ERROR);

    // Unpin the program.
    output = _run_netsh_command(handle_ebpf_set_program, L"196609", L"", nullptr, &result);
    REQUIRE(result == ERROR_OKAY);
    REQUIRE(output == "");

    // Verify we can delete the unpinned program.
    output = _run_netsh_command(handle_ebpf_delete_program, L"196609", nullptr, nullptr, &result);
    REQUIRE(output == "Unpinned 196609 from mypinname\n");
    REQUIRE(result == NO_ERROR);
    REQUIRE(bpf_object__next(nullptr) == nullptr);

    // Verify the program ID doesn't exist any more.
    output = _run_netsh_command(handle_ebpf_show_programs, nullptr, nullptr, nullptr, &result);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Name\n"
                  "======  ====  =====  =========  ====================\n");
    REQUIRE(result == NO_ERROR);
}