// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#pragma warning(push)
#pragma warning(disable : 4200)
#include "bpf/libbpf.h"
#pragma warning(pop)
#include "ebpf_epoch.h"
#include "netsh_test_helper.h"
#include "platform.h"
#include "test_helper.hpp"
#include "usersim/../../src/fault_injection.h"

#include <winsock2.h>
#include <windows.h>
#include <netsh.h>
#include <regex>
#include <sstream>
#include <string.h>

extern std::vector<struct bpf_object*> _ebpf_netsh_objects;

class _test_helper_netsh
{
  public:
    _test_helper_netsh();
    ~_test_helper_netsh();

  private:
    _test_helper_libbpf test_helper_libbpf;
};

_test_helper_netsh::_test_helper_netsh() { _ebpf_netsh_objects.clear(); }

_test_helper_netsh::~_test_helper_netsh()
{
    if (usersim_fault_injection_is_enabled()) {
        for (auto& object : _ebpf_netsh_objects) {
            bpf_object__close(object);
        }
        _ebpf_netsh_objects.clear();
    }
    REQUIRE(_ebpf_netsh_objects.size() == 0);
}

std::string
strip_paths(const std::string& original_string)
{
    std::stringstream input_stream(original_string);
    std::stringstream output_stream;
    std::string line;
    while (std::getline(input_stream, line)) {
        auto output = std::regex_replace(line, std::regex("\\\\"), "/");
        output_stream << std::regex_replace(output, std::regex("^.*tests/sample"), "; ./tests/sample") << "\n";
    }
    return output_stream.str();
}

TEST_CASE("show disassembly bpf_call.o", "[netsh][disassembly]")
{
    // Start the test helper so the netsh command can get helper prototypes.
    _test_helper_netsh test_helper;

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_disassembly, L"bpf_call.o", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    output = strip_paths(output);
    REQUIRE(
        output == "; ./tests/sample/bpf_call.c:24\n"
                  "; SEC(\"xdp_prog\") int func(struct xdp_md* ctx)\n"
                  "       0:	r1 = 0\n"
                  "; ./tests/sample/bpf_call.c:26\n"
                  ";     uint32_t key = 0;\n"
                  "       1:	*(u32 *)(r10 - 4) = r1\n"
                  "       2:	r1 = 42\n"
                  "; ./tests/sample/bpf_call.c:27\n"
                  ";     uint32_t value = 42;\n"
                  "       3:	*(u32 *)(r10 - 8) = r1\n"
                  "       4:	r2 = r10\n"
                  "       5:	r2 += -4\n"
                  "       6:	r3 = r10\n"
                  "       7:	r3 += -8\n"
                  "; ./tests/sample/bpf_call.c:28\n"
                  ";     int result = bpf_map_update_elem(&map, &key, &value, 0);\n"
                  "       8:	r1 = map_fd 1\n"
                  "      10:	r4 = 0\n"
                  "      11:	r0 = bpf_map_update_elem:2(map_fd r1, map_key r2, map_value r3, uint64_t r4)\n"
                  "; ./tests/sample/bpf_call.c:29\n"
                  ";     return result;\n"
                  "      12:	exit\n\n");
}

TEST_CASE("show disassembly bpf.o nosuchsection", "[netsh][disassembly]")
{
    _test_helper_netsh test_helper;

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_disassembly, L"bpf.o", L"nosuchsection", nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: Can't find section nosuchsection in file bpf.o\n");
}

TEST_CASE("show disassembly nosuchfile.o", "[netsh][disassembly]")
{
    _test_helper_netsh test_helper;

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_disassembly, L"nosuchfile.o", nullptr, nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: No such file or directory opening nosuchfile.o\n");
}

TEST_CASE("show sections nosuchfile.o", "[netsh][sections]")
{
    _test_helper_netsh test_helper;

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_sections, L"nosuchfile.o", nullptr, nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: No such file or directory opening nosuchfile.o\n");
}

TEST_CASE("show sections bpf.o", "[netsh][sections]")
{
    _test_helper_netsh test_helper;

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_sections, L"bpf.o", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "                                    Size\n"
                  "             Section       Type  (bytes)\n"
                  "====================  =========  =======\n"
                  "               .text     unspec       16\n"
                  "\n"
                  "                     Key  Value      Max\n"
                  "          Map Type  Size   Size  Entries  Name\n"
                  "==================  ====  =====  =======  ========\n");
}

// Test specifying a section name.
TEST_CASE("show sections bpf.o .text", "[netsh][sections]")
{
    _test_helper_netsh test_helper;

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_sections, L"bpf.o", L".text", nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "Section      : .text\n"
                  "Program Type : unspec\n"
                  "Size         : 16 bytes\n"
                  "Instructions : 2\n"
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
                  "store        : 0\n"
                  "\n"
                  "                     Key  Value      Max\n"
                  "          Map Type  Size   Size  Entries  Name\n"
                  "==================  ====  =====  =======  ========\n");
}

// Test a .sys file.
TEST_CASE("show sections bpf.sys", "[netsh][sections]")
{
    _test_helper_netsh test_helper;

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_sections, L"bpf.sys", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);

    REQUIRE(
        output == "\n"
                  "                                    Size\n"
                  "             Section       Type  (bytes)\n"
                  "====================  =========  =======\n"
                  "               .text        xdp     1768\n"
                  "\n"
                  "                     Key  Value      Max\n"
                  "          Map Type  Size   Size  Entries  Name\n"
                  "==================  ====  =====  =======  ========\n");
}

// Test a DLL with multiple maps in the map section.
TEST_CASE("show sections map_reuse_um.dll", "[netsh][sections]")
{
    _test_helper_netsh test_helper;

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_sections, L"map_reuse_um.dll", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "                                    Size\n"
                  "             Section       Type  (bytes)\n"
                  "====================  =========  =======\n"
                  "            xdp_prog        xdp     1087\n"
                  "\n"
                  "                     Key  Value      Max\n"
                  "          Map Type  Size   Size  Entries  Name\n"
                  "==================  ====  =====  =======  ========\n"
                  "      hash_of_maps     4      4        1  outer_map\n"
                  "             array     4      4        1  port_map\n"
                  "             array     4      4        1  inner_map\n");
}

// Test a .dll file with multiple programs.
TEST_CASE("show sections tail_call_multiple_um.dll", "[netsh][sections]")
{
    _test_helper_netsh test_helper;

    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_show_sections, L"tail_call_multiple_um.dll", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "                                    Size\n"
                  "             Section       Type  (bytes)\n"
                  "====================  =========  =======\n"
                  "            xdp_prog        xdp      413\n"
                  "          xdp_prog/0        xdp      413\n"
                  "          xdp_prog/1        xdp      190\n"
                  "\n"
                  "                     Key  Value      Max\n"
                  "          Map Type  Size   Size  Entries  Name\n"
                  "==================  ====  =====  =======  ========\n"
                  "        prog_array     4      4       10  map\n");
}

// Test a .sys file with multiple programs, including ones with long names.
TEST_CASE("show sections cgroup_sock_addr.sys", "[netsh][sections]")
{
    _test_helper_netsh test_helper;

    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_show_sections, L"cgroup_sock_addr.sys", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "                                    Size\n"
                  "             Section       Type  (bytes)\n"
                  "====================  =========  =======\n"
                  "     cgroup/connect4  sock_addr      531\n"
                  "     cgroup/connect6  sock_addr      606\n"
                  " cgroup/recv_accept4  sock_addr      531\n"
                  " cgroup/recv_accept6  sock_addr      606\n"
                  "\n"
                  "                     Key  Value      Max\n"
                  "          Map Type  Size   Size  Entries  Name\n"
                  "==================  ====  =====  =======  ========\n"
                  "              hash    56      4        1  egress_connection_policy_map\n"
                  "              hash    56      4        1  ingress_connection_policy_map\n");
}

TEST_CASE("show verification nosuchfile.o", "[netsh][verification]")
{
    _test_helper_netsh test_helper;

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_verification, L"nosuchfile.o", nullptr, nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: No such file or directory opening nosuchfile.o\n");
}

TEST_CASE("show verification bpf.o", "[netsh][verification]")
{
    _test_helper_netsh test_helper;

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_verification, L"bpf.o", L".text", L"xdp", &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "\n"
                  "Verification succeeded\n"
                  "Program terminates within 6 instructions\n");
}

TEST_CASE("show verification droppacket.o", "[netsh][verification]")
{
    _test_helper_netsh test_helper;

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
    _test_helper_netsh test_helper;

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
                  "; ./tests/sample/unsafe/droppacket_unsafe.c:41\n"
                  ";     if (ip_header->Protocol == IPPROTO_UDP) {\n"
                  "2: Upper bound must be at most packet_size (valid_access(r1.offset+9, width=1) for read)\n"
                  "; ./tests/sample/unsafe/droppacket_unsafe.c:42\n"
                  ";         if (ntohs(udp_header->length) <= sizeof(UDP_HEADER)) {\n"
                  "4: Upper bound must be at most packet_size (valid_access(r1.offset+24, width=2) for read)\n"
                  "\n"
                  "2 errors\n"
                  "\n");
}

TEST_CASE("show verification printk_unsafe.o", "[netsh][verification]")
{
    _test_helper_netsh test_helper;

    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_show_verification, L"printk_unsafe.o", L"bind", nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    output = strip_paths(output);
    REQUIRE(
        output == "Verification failed\n"
                  "\n"
                  "Verification report:\n"
                  "\n"
                  "; ./tests/sample/unsafe/printk_unsafe.c:22\n"
                  ";     bpf_printk(\"ctx: %u\", (uint64_t)ctx);\n"
                  "7:  (r3.type == number)\n"
                  "\n"
                  "1 errors\n"
                  "\n");
}

void
verify_no_programs_exist()
{
    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_programs, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n");
}

TEST_CASE("pin first program", "[netsh][programs]")
{
    _test_helper_netsh test_helper;

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

    verify_no_programs_exist();
}

TEST_CASE("pin all programs", "[netsh][programs]")
{
    _test_helper_netsh test_helper;

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

    output = _run_netsh_command(handle_ebpf_delete_program, L"262145", nullptr, nullptr, &result);
    REQUIRE(output == "Unpinned 262145 from mypinpath/xdp_prog_0\n");
    REQUIRE(result == NO_ERROR);

    verify_no_programs_exist();
}

TEST_CASE("show programs", "[netsh][programs]")
{
    _test_helper_netsh test_helper;

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
                  "map IDs        : 131073\n"
                  "                 65538\n"
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

    verify_no_programs_exist();
}

TEST_CASE("set program", "[netsh][programs]")
{
    _test_helper_netsh test_helper;

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

    output = _run_netsh_command(handle_ebpf_show_programs, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n"
                  "196609     0      0  JIT        xdp            caller\n"
                  "262145     0      0  JIT        xdp            callee\n");

    // Try to detach an unattached program.
    output = _run_netsh_command(handle_ebpf_set_program, L"196609", L"", nullptr, &result);
    REQUIRE(output == "error 1168: could not detach program\n");
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);

    RPC_WSTR attach_type_string;
    REQUIRE(UuidToStringW(&EBPF_ATTACH_TYPE_XDP, &attach_type_string) == 0);

    // Attach the program.
    output = _run_netsh_command(handle_ebpf_set_program, L"196609", L"xdp", nullptr, &result);
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

    // Verify the program ID doesn't exist any more.
    verify_no_programs_exist();
}

TEST_CASE("show maps", "[netsh][maps]")
{
    _test_helper_netsh test_helper;

    int result;
    std::string output = _run_netsh_command(handle_ebpf_add_program, L"map_in_map_btf.o", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 196609\n") == 0);

    output = _run_netsh_command(handle_ebpf_show_maps, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "                             Key  Value      Max  Inner\n"
                  "    ID            Map Type  Size   Size  Entries     ID  Pins  Name\n"
                  "======  ==================  ====  =====  =======  =====  ====  ========\n"
                  " 65538                hash     4      4        1     -1     0  inner_map\n"
                  "131073       array_of_maps     4      4        1  65538     0  outer_map\n");

    output = _run_netsh_command(handle_ebpf_delete_program, L"196609", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == "Unpinned 196609 from lookup\n");
    verify_no_programs_exist();

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
    _test_helper_netsh test_helper;

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
    verify_no_programs_exist();

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
    _test_helper_netsh test_helper;

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

    output = _run_netsh_command(handle_ebpf_delete_program, L"262145", nullptr, nullptr, &result);
    REQUIRE(output == "Unpinned 262145 from mypinpath/xdp_prog_0\n");
    REQUIRE(result == NO_ERROR);

    verify_no_programs_exist();
}

TEST_CASE("delete pinned program", "[netsh][programs]")
{
    _test_helper_netsh test_helper;

    // Load a program unpinned.
    int result;
    std::string output = _run_netsh_command(handle_ebpf_add_program, L"tail_call.o", L"pinned=none", nullptr, &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 196609\n") == 0);
    REQUIRE(result == NO_ERROR);

    // Pin the program.
    output = _run_netsh_command(handle_ebpf_set_program, L"196609", L"pinpath=mypinname", nullptr, &result);
    REQUIRE(result == ERROR_OKAY);
    REQUIRE(output == "");

    // Pin the program to a second path.
    output = _run_netsh_command(handle_ebpf_set_program, L"196609", L"pinpath=mypinname2", nullptr, &result);
    REQUIRE(result == ERROR_OKAY);
    REQUIRE(output == "");

    // Verify we can delete a pinned program.
    output = _run_netsh_command(handle_ebpf_delete_program, L"196609", nullptr, nullptr, &result);
    REQUIRE(output == "Unpinned 196609 from mypinname\nUnpinned 196609 from mypinname2\n");
    REQUIRE(result == NO_ERROR);

    // Verify the program ID doesn't exist any more.
    verify_no_programs_exist();
}

TEST_CASE("unpin program", "[netsh][programs]")
{
    _test_helper_netsh test_helper;

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

    // Verify the program ID doesn't exist any more.
    verify_no_programs_exist();
}

TEST_CASE("xdp interface parameter", "[netsh][programs]")
{
    _test_helper_netsh test_helper;

    // Load a program pinned.
    int result;

    // Load program with pinpath and loopback interface alias.
    std::string output = run_netsh_command_with_args(
        handle_ebpf_add_program, &result, 4, L"droppacket.o", L"xdp", L"mypinpath", L"Loopback Pseudo-Interface 1");
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 196609\n") == 0);
    REQUIRE(result == NO_ERROR);
    output = _run_netsh_command(handle_ebpf_delete_program, L"196609", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == "Unpinned 196609 from mypinpath\n");
    verify_no_programs_exist();

    // Load program with pinpath and loopback interface name.
    output = run_netsh_command_with_args(
        handle_ebpf_add_program, &result, 4, L"droppacket.o", L"xdp", L"mypinpath", L"loopback_0");
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 196610\n") == 0);
    REQUIRE(result == NO_ERROR);
    output = _run_netsh_command(handle_ebpf_delete_program, L"196610", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == "Unpinned 196610 from mypinpath\n");
    verify_no_programs_exist();

    // Load program with loopback interface index.
    output = _run_netsh_command(handle_ebpf_add_program, L"droppacket.o", L"xdp", L"interface=1", &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 196611\n") == 0);
    REQUIRE(result == NO_ERROR);
    output = _run_netsh_command(handle_ebpf_delete_program, L"196611", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == "Unpinned 196611 from DropPacket\n");
    verify_no_programs_exist();

    // (Negative) Load program with incorrect interface name.
    output = _run_netsh_command(handle_ebpf_add_program, L"droppacket.o", L"xdp", L"interface=foo", &result);
    REQUIRE(strcmp(output.c_str(), "Interface parameter is invalid.\n") == 0);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    verify_no_programs_exist();

    // (Negative) Load program with program type that does not support the interface parameter.
    output = _run_netsh_command(handle_ebpf_add_program, L"bindmonitor.o", L"bind", L"interface=1", &result);
    REQUIRE(
        strcmp(
            output.c_str(), "Interface parameter is not allowed for program types that don't support interfaces.\n") ==
        0);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    verify_no_programs_exist();

    // Add program with no interface parameter.
    output = _run_netsh_command(handle_ebpf_add_program, L"droppacket.o", nullptr, nullptr, &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 196614\n") == 0);
    REQUIRE(result == NO_ERROR);

    // Detach the program.
    output = _run_netsh_command(handle_ebpf_set_program, L"196614", L"", nullptr, &result);
    REQUIRE(output == "");
    REQUIRE(result == ERROR_OKAY);

    output = _run_netsh_command(handle_ebpf_show_programs, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n"
                  "196614     1      0  JIT        xdp            DropPacket\n");

    // Re-attach the program with interface index parameter.
    output = _run_netsh_command(handle_ebpf_set_program, L"196614", nullptr, L"interface=1", &result);
    REQUIRE(output == "");
    REQUIRE(result == ERROR_OKAY);
    output = _run_netsh_command(handle_ebpf_delete_program, L"196614", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);

    ebpf_epoch_flush();
}

TEST_CASE("cgroup_sock_addr compartment parameter", "[netsh][programs]")
{
    _test_helper_netsh test_helper;

    // Load a program pinned.
    int result;

    // Load program with pinpath and compaetment=1.
    std::string output = run_netsh_command_with_args(
        handle_ebpf_add_program, &result, 4, L"cgroup_sock_addr.o", L"cgroup/connect4", L"mypinpath", L"compartment=1");
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 196609\n") == 0);
    REQUIRE(result == NO_ERROR);
    output = _run_netsh_command(handle_ebpf_delete_program, L"196609", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == "Unpinned 196609 from mypinpath\n");
    verify_no_programs_exist();

    // (Negative) Load program with incorrect compartment id.
    output = _run_netsh_command(
        handle_ebpf_add_program, L"cgroup_sock_addr.o", L"cgroup/connect4", L"compartment=0", &result);
    REQUIRE(strcmp(output.c_str(), "Compartment parameter is invalid.\n") == 0);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    verify_no_programs_exist();

    // (Negative) Load program with program type that does not support the compartment parameter.
    output = _run_netsh_command(handle_ebpf_add_program, L"bindmonitor.o", L"bind", L"compartment=1", &result);
    REQUIRE(
        strcmp(
            output.c_str(),
            "Compartment parameter is not allowed for program types that don't support compartments.\n") == 0);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    verify_no_programs_exist();

    ebpf_epoch_flush();
}

TEST_CASE("show processes", "[netsh][processes]")
{
    _test_helper_netsh test_helper;
    int result;
    std::string output = run_netsh_command_with_args(handle_ebpf_show_processes, &result, 0);

    TOKEN_ELEVATION token_elevation = {0};
    DWORD return_length = 0;
    if (!GetTokenInformation(
            GetCurrentProcessToken(), TokenElevation, &token_elevation, sizeof(token_elevation), &return_length) ||
        !token_elevation.TokenIsElevated) {
        REQUIRE(output == "This command requires running as Administrator\n");
        REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    } else {
        // There are no real eBPF handles used in this test so the result should be empty.
        REQUIRE(
            output == "\n"
                      "  PID  Name\n"
                      "=====  ==============\n");
        REQUIRE(result == NO_ERROR);
    }
}