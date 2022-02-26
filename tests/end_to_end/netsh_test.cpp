// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <windows.h>
#include <netsh.h> // Must be included after windows.h
#include <string.h>
#include <sstream>
#include <regex>
#include "bpf/bpf.h"
#pragma warning(push)
#pragma warning(disable : 4200)
#include "bpf/libbpf.h"
#pragma warning(pop)
#include "ebpf_epoch.h"
#include "netsh_test_helper.h"
#include "platform.h"
#include "test_helper.hpp"

std::string
strip_paths(const std::string& orignal_string)
{
    std::stringstream input_stream(orignal_string);
    std::stringstream output_stream;
    std::string line;
    while (std::getline(input_stream, line)) {
        auto output = std::regex_replace(line, std::regex("\\\\"), "/");
        output_stream << std::regex_replace(output, std::regex("^.*tests/sample"), "; ./tests/sample") << "\n";
    }
    return output_stream.str();
}

TEST_CASE("show disassembly bpf.o", "[netsh][disassembly]")
{
    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_disassembly, L"bpf.o", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    output = strip_paths(output);
    REQUIRE(
        output == "; ./tests/sample/bpf.c:8\n"
                  ";     return 42;\n"
                  "       0:	r0 = 42\n"
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
                  "Verification succeeded\n"
                  "Program terminates within 157 instructions\n");
}

TEST_CASE("show verification droppacket_unsafe.o", "[netsh][verification]")
{
    _test_helper_libbpf test_helper;

    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_show_verification, L"droppacket_unsafe.o", L"xdp", nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    output = strip_paths(output);
    REQUIRE(
        output == "Verification failed\n"
                  "\n"
                  "Verification report:\n"
                  "\n"
                  "; ./tests/sample/droppacket_unsafe.c:29\n"
                  ";     if (ip_header->Protocol == IPPROTO_UDP) {\n"
                  "2: Upper bound must be at most packet_size (valid_access(r1.offset+9, width=1))\n"
                  "; ./tests/sample/droppacket_unsafe.c:30\n"
                  ";         if (ntohs(udp_header->length) <= sizeof(UDP_HEADER)) {\n"
                  "4: Upper bound must be at most packet_size (valid_access(r1.offset+24, width=2))\n"
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
        _run_netsh_command(handle_ebpf_add_program, L"tail_call.o", L"xdp", L"pinpath=mypinpath", &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 196609\n") == 0);
    REQUIRE(result == NO_ERROR);

    // Show programs in normal (table) format.
    output = _run_netsh_command(handle_ebpf_show_programs, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n"
                  "196609     1      1  JIT        xdp            caller\n"
                  "262145     0      0  JIT        xdp            callee\n");

    output = _run_netsh_command(handle_ebpf_delete_program, L"196609", nullptr, nullptr, &result);
    REQUIRE(output == "Unpinned 196609 from mypinpath\n");
    REQUIRE(result == NO_ERROR);
    REQUIRE(bpf_object__next(nullptr) == nullptr);
}

TEST_CASE("pin all programs", "[netsh][programs]")
{
    _test_helper_libbpf test_helper;

    // Load programs to show.
    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_add_program, L"tail_call.o", L"pinpath=mypinpath", L"pinned=all", &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 196609\n") == 0);
    REQUIRE(result == NO_ERROR);

    // Show programs in normal (table) format.
    output = _run_netsh_command(handle_ebpf_show_programs, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n"
                  "196609     1      1  JIT        xdp            caller\n"
                  "262145     1      0  JIT        xdp            callee\n");

    output = _run_netsh_command(handle_ebpf_delete_program, L"196609", nullptr, nullptr, &result);
    REQUIRE(output == "Unpinned 196609 from mypinpath/xdp_prog\n");
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
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n"
                  "196609     1      1  JIT        xdp            caller\n"
                  "262145     0      0  JIT        xdp            callee\n");

    // Test filtering by "attached=yes".
    output = _run_netsh_command(handle_ebpf_show_programs, L"attached=yes", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n"
                  "196609     1      1  JIT        xdp            caller\n");

    // Test filtering by "attached=no".
    output = _run_netsh_command(handle_ebpf_show_programs, L"attached=no", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n"
                  "262145     0      0  JIT        xdp            callee\n");

    // Test filtering by "pinned=yes".
    output = _run_netsh_command(handle_ebpf_show_programs, L"pinned=yes", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n"
                  "196609     1      1  JIT        xdp            caller\n");

    // Test filtering by "pinned=no".
    output = _run_netsh_command(handle_ebpf_show_programs, L"pinned=no", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n"
                  "262145     0      0  JIT        xdp            callee\n");

    // Test verbose output format.
    output = _run_netsh_command(handle_ebpf_show_programs, L"level=verbose", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "ID             : 196609\n"
                  "File name      : tail_call.o\n"
                  "Section        : xdp_prog\n"
                  "Name           : caller\n"
                  "Program type   : xdp\n"
                  "Mode           : JIT\n"
                  "# map IDs      : 2\n"
                  "# pinned paths : 1\n"
                  "# links        : 1\n"
                  "\n"
                  "ID             : 262145\n"
                  "File name      : tail_call.o\n"
                  "Section        : xdp_prog/0\n"
                  "Name           : callee\n"
                  "Program type   : xdp\n"
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
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n");
    REQUIRE(result == NO_ERROR);
}

TEST_CASE("show maps", "[netsh][maps]")
{
    _test_helper_libbpf test_helper;

    int result;
    std::string output = _run_netsh_command(handle_ebpf_add_program, L"map_in_map.o", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 196609\n") == 0);

    output = _run_netsh_command(handle_ebpf_show_maps, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "                             Key  Value      Max  Inner\n"
                  "    ID            Map Type  Size   Size  Entries     ID  Pins  Name\n"
                  "======  ==================  ====  =====  =======  =====  ====  ========\n"
                  " 65537                Hash     4      4        1     -1     0  inner_map\n"
                  "131073       Array of maps     4      4        1  65537     0  outer_map\n");

    output = _run_netsh_command(handle_ebpf_delete_program, L"196609", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == "Unpinned 196609 from lookup\n");
    REQUIRE(bpf_object__next(nullptr) == nullptr);

    ebpf_epoch_flush();

    output = _run_netsh_command(handle_ebpf_show_maps, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "                             Key  Value      Max  Inner\n"
                  "    ID            Map Type  Size   Size  Entries     ID  Pins  Name\n"
                  "======  ==================  ====  =====  =======  =====  ====  ========\n");
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
                  "   Link  Program  Attach\n"
                  "     ID       ID  Type\n"
                  "=======  =======  =============\n"
                  " 327681   196609  xdp\n");

    output = _run_netsh_command(handle_ebpf_delete_program, L"196609", nullptr, nullptr, &result);
    REQUIRE(output == "");
    REQUIRE(result == NO_ERROR);
    REQUIRE(bpf_object__next(nullptr) == nullptr);

    output = _run_netsh_command(handle_ebpf_show_links, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "   Link  Program  Attach\n"
                  "     ID       ID  Type\n"
                  "=======  =======  =============\n");
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
                  " 196609  Program  mypinpath/xdp_prog\n"
                  " 262145  Program  mypinpath/xdp_prog_0\n");

    output = _run_netsh_command(handle_ebpf_delete_program, L"196609", nullptr, nullptr, &result);
    REQUIRE(output == "Unpinned 196609 from mypinpath/xdp_prog\n");
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
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n");
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
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n");
    REQUIRE(result == NO_ERROR);
}
