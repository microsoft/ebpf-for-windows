// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#pragma warning(push)
#pragma warning(disable : 4200)
#include "bpf/libbpf.h"
#pragma warning(pop)
#include "cxplat_fault_injection.h"
#include "ebpf_epoch.h"
#include "netsh_test_helper.h"
#include "platform.h"
#include "test_helper.hpp"

#include <winsock2.h>
#include <windows.h>
#include <iostream>
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
    void
    initialize();

  private:
    _test_helper_libbpf test_helper_libbpf;
};

_test_helper_netsh::_test_helper_netsh() { _ebpf_netsh_objects.clear(); }

_test_helper_netsh::~_test_helper_netsh()
{
    if (cxplat_fault_injection_is_enabled()) {
        for (auto& object : _ebpf_netsh_objects) {
            bpf_object__close(object);
        }
        _ebpf_netsh_objects.clear();
    }
    REQUIRE(_ebpf_netsh_objects.size() == 0);
}

void
_test_helper_netsh::initialize()
{
    test_helper_libbpf.initialize();
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

void
test_expected_output_line_by_line(const std::string& expected_output, const std::string& actual_output)
{
    // If the expected and actual output are the same, the test passes.
    if (expected_output == actual_output)
        return;

    std::cerr << "Expected output:\n" << expected_output << "\n";
    std::cerr << "Actual output:\n" << actual_output << "\n";

    // If the expected and actual output are not the same, compare them line by line.
    std::istringstream expected_output_stream(expected_output);
    std::istringstream actual_output_stream(actual_output);

    std::string expected_line;
    std::string actual_line;
    while (std::getline(expected_output_stream, expected_line) && std::getline(actual_output_stream, actual_line)) {
        REQUIRE(expected_line == actual_line);
    }
}

TEST_CASE("show disassembly bpf_call.o", "[netsh][disassembly]")
{
    // Start the test helper so the netsh command can get helper prototypes.
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_disassembly, L"bpf_call.o", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    output = strip_paths(output);
    REQUIRE(
        output == "; ./tests/sample/undocked/bpf_call.c:25\n"
                  "; SEC(\"sample_ext\") int func(sample_program_context_t* ctx)\n"
                  "       0:	r1 = 0\n"
                  "; ./tests/sample/undocked/bpf_call.c:27\n"
                  ";     uint32_t key = 0;\n"
                  "       1:	*(u32 *)(r10 - 4) = r1\n"
                  "       2:	r1 = 42\n"
                  "; ./tests/sample/undocked/bpf_call.c:28\n"
                  ";     uint32_t value = 42;\n"
                  "       3:	*(u32 *)(r10 - 8) = r1\n"
                  "       4:	r2 = r10\n"
                  "       5:	r2 += -4\n"
                  "       6:	r3 = r10\n"
                  "       7:	r3 += -8\n"
                  "; ./tests/sample/undocked/bpf_call.c:29\n"
                  ";     int result = bpf_map_update_elem(&map, &key, &value, 0);\n"
                  "       8:	r1 = map_fd 1\n"
                  "      10:	r4 = 0\n"
                  "      11:	r0 = bpf_map_update_elem:2(map_fd r1, map_key r2, map_value r3, uint64_t r4)\n"
                  "; ./tests/sample/undocked/bpf_call.c:30\n"
                  ";     return result;\n"
                  "      12:	exit\n\n");
}

TEST_CASE("show disassembly bpf.o nosuchsection", "[netsh][disassembly]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_disassembly, L"bpf.o", L"nosuchsection", nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: Can't find section nosuchsection in file bpf.o\n");
}

TEST_CASE("show disassembly nosuchfile.o", "[netsh][disassembly]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_disassembly, L"nosuchfile.o", nullptr, nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: No such file or directory opening nosuchfile.o\n");
}

TEST_CASE("show sections nosuchfile.o", "[netsh][sections]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_sections, L"nosuchfile.o", nullptr, nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: No such file or directory opening nosuchfile.o\n");
}

TEST_CASE("show sections bpf.o", "[netsh][sections]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_sections, L"bpf.o", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "                                                            Size\n"
                  "             Section                 Program       Type  (bytes)\n"
                  "====================  ======================  =========  =======\n"
                  "               .text                    func     unspec       16\n"
                  "\n"
                  "                     Key  Value      Max\n"
                  "          Map Type  Size   Size  Entries  Name\n"
                  "==================  ====  =====  =======  ========\n");
}

// Test specifying a section name.
TEST_CASE("show sections bpf.o .text", "[netsh][sections]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_sections, L"bpf.o", L".text", nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "Section      : .text\n"
                  "Program      : func\n"
                  "Program Type : unspec\n"
                  "Size         : 16 bytes\n"
                  "Instructions : 2\n"
                  "arith        : 0\n"
                  "arith32      : 0\n"
                  "arith64      : 1\n"
                  "assign       : 1\n"
                  "call_1       : 0\n"
                  "call_mem     : 0\n"
                  "call_nomem   : 0\n"
                  "instructions : 4\n"
                  "joins        : 0\n"
                  "jumps        : 0\n"
                  "load         : 0\n"
                  "load_store   : 0\n"
                  "map_in_map   : 0\n"
                  "other        : 3\n"
                  "packet_access: 0\n"
                  "reallocate   : 0\n"
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
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_sections, L"bpf.sys", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);

#if defined(_M_X64) && defined(NDEBUG)
    const int code_size = 1064;
#elif defined(_M_X64) && !defined(NDEBUG)
    const int code_size = 1784;
#elif defined(_M_ARM64) && defined(NDEBUG)
    const int code_size = 1120;
#elif defined(_M_ARM64) && !defined(NDEBUG)
    const int code_size = 5984;
#else
#error "Unsupported architecture"
#endif

    // Expected output is a format string with the code size filled in.
    const std::string expected_output = "\n"
                                        "                                                            Size\n"
                                        "             Section                 Program       Type  (bytes)\n"
                                        "====================  ======================  =========  =======\n"
                                        "               .text                    func       bind  {:7}\n"
                                        "\n"
                                        "                     Key  Value      Max\n"
                                        "          Map Type  Size   Size  Entries  Name\n"
                                        "==================  ====  =====  =======  ========\n";

    REQUIRE(output == std::vformat(expected_output, std::make_format_args(code_size)));
}

// Test a DLL with multiple maps in the map section.
TEST_CASE("show sections map_reuse_um.dll", "[netsh][sections]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_sections, L"map_reuse_um.dll", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);

#if defined(_M_X64) && defined(NDEBUG)
    const int code_size = 312;
    const int old_code_size = 311;
#elif defined(_M_X64) && !defined(NDEBUG)
    const int code_size = 1152;
    const int old_code_size = 1114;
#elif defined(_M_ARM64) && defined(NDEBUG)
    const int code_size = 316;
    const int old_code_size = 316;
#elif defined(_M_ARM64) && !defined(NDEBUG)
    const int code_size = 1020;
    const int old_code_size = 1020;
#else
#error "Unsupported architecture"
#endif

    const std::string expected_output = "\n"
                                        "                                                            Size\n"
                                        "             Section                 Program       Type  (bytes)\n"
                                        "====================  ======================  =========  =======\n"
                                        "          sample_ext           lookup_update     sample  {:7}\n"
                                        "\n"
                                        "                     Key  Value      Max\n"
                                        "          Map Type  Size   Size  Entries  Name\n"
                                        "==================  ====  =====  =======  ========\n"
                                        "      hash_of_maps     4      4        1  outer_map\n"
                                        "             array     4      4        1  port_map\n"
                                        "             array     4      4        1  inner_map\n";

    REQUIRE(
        (output == std::vformat(expected_output, std::make_format_args(code_size)) ||
         output == std::vformat(expected_output, std::make_format_args(old_code_size))));
}

// Test a .dll file with multiple programs.
TEST_CASE("show sections tail_call_multiple_um.dll", "[netsh][sections]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_show_sections, L"tail_call_multiple_um.dll", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);

#if defined(_M_X64) && defined(NDEBUG)
    const int code_size_old[] = {73, 6, 73};
    const int code_size_new[] = {90, 6, 100};
#elif defined(_M_X64) && !defined(NDEBUG)
    const int code_size_old[] = {413, 190, 413};
    const int code_size_new[] = {448, 195, 448};
#elif defined(_M_ARM64) && defined(NDEBUG)
    const int code_size_old[] = {116, 8, 112};
    const int code_size_new[] = {116, 8, 112};
#elif defined(_M_ARM64) && !defined(NDEBUG)
    const int code_size_old[] = {400, 184, 400};
    const int code_size_new[] = {400, 184, 400};
#else
#error "Unsupported architecture"
#endif

    // Issue #3610: Different MSVC versions expect different numbers of bytes for the same program.
    // As a workaround, check for both the expected outputs.
    const std::string expected_output = "\n"
                                        "                                                            Size\n"
                                        "             Section                 Program       Type  (bytes)\n"
                                        "====================  ======================  =========  =======\n"
                                        "        sample_ext/0                 callee0     sample  {:7}\n"
                                        "        sample_ext/1                 callee1     sample  {:7}\n"
                                        "          sample_ext                  caller     sample  {:7}\n"
                                        "\n"
                                        "                     Key  Value      Max\n"
                                        "          Map Type  Size   Size  Entries  Name\n"
                                        "==================  ====  =====  =======  ========\n"
                                        "        prog_array     4      4       10  map\n";

    REQUIRE(
        (output == std::vformat(
                       expected_output, std::make_format_args(code_size_old[0], code_size_old[1], code_size_old[2])) ||
         output == std::vformat(
                       expected_output, std::make_format_args(code_size_new[0], code_size_new[1], code_size_new[2]))));
}

// Test a .sys file with multiple programs, including ones with long names.
TEST_CASE("show sections cgroup_sock_addr.sys", "[netsh][sections]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_show_sections, L"cgroup_sock_addr.sys", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);

#if defined(_M_X64) && defined(NDEBUG)
    const int code_size[] = {333, 350, 333, 350};
#elif defined(_M_X64) && !defined(NDEBUG)
    const int code_size[] = {961, 1036, 961, 1036};
#elif defined(_M_ARM64) && defined(NDEBUG)
    const int code_size[] = {308, 324, 308, 324};
#elif defined(_M_ARM64) && !defined(NDEBUG)
    const int code_size[] = {1044, 1176, 1044, 1176};
#else
#error "Unsupported architecture"
#endif

    const std::string expected_output = "\n"
                                        "                                                            Size\n"
                                        "             Section                 Program       Type  (bytes)\n"
                                        "====================  ======================  =========  =======\n"
                                        "     cgroup/connect4      authorize_connect4  sock_addr  {:7}\n"
                                        "     cgroup/connect6      authorize_connect6  sock_addr  {:7}\n"
                                        " cgroup/recv_accept4  authorize_recv_accept4  sock_addr  {:7}\n"
                                        " cgroup/recv_accept6  authorize_recv_accept6  sock_addr  {:7}\n"
                                        "\n"
                                        "                     Key  Value      Max\n"
                                        "          Map Type  Size   Size  Entries  Name\n"
                                        "==================  ====  =====  =======  ========\n"
                                        "              hash    56      4        1  egress_connection_policy_map\n"
                                        "              hash    56      4        1  ingress_connection_policy_map\n"
                                        "              hash    56      8     1000  socket_cookie_map\n";
    REQUIRE(
        output ==
        std::vformat(expected_output, std::make_format_args(code_size[0], code_size[1], code_size[2], code_size[3])));
}

TEST_CASE("show verification nosuchfile.o", "[netsh][verification]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_verification, L"nosuchfile.o", nullptr, nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: No such file or directory opening nosuchfile.o\n");
}

TEST_CASE("show verification bpf.o", "[netsh][verification]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_show_verification, L"bpf.o", L"program=func", L"type=bind", &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "Verification succeeded\n"
                  "Program terminates within 0 loop iterations\n");
}

TEST_CASE("show verification bindmonitor_bpf2bpf.o", "[netsh][verification]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_show_verification, L"bindmonitor_bpf2bpf.o", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "Verification succeeded\n"
                  "Program terminates within 0 loop iterations\n");
}

TEST_CASE("show verification droppacket.o", "[netsh][verification]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_verification, L"droppacket.o", L"xdp", nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "Verification succeeded\n"
                  "Program terminates within 0 loop iterations\n");
}

TEST_CASE("show verification xdp_adjust_head_unsafe.o", "[netsh][verification]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_show_verification, L"xdp_adjust_head_unsafe.o", L"xdp", nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    output = strip_paths(output);
    REQUIRE(
        output == "Verification failed\n"
                  "\n"
                  "Verification report:\n"
                  "\n"
                  "; ./tests/sample/unsafe/xdp_adjust_head_unsafe.c:43\n"
                  ";     ethernet_header->Type = 0x0800;\n"
                  "\n"
                  "17: Upper bound must be at most packet_size (valid_access(r1.offset+12, width=2) for write)\n"
                  "\n"
                  "1 errors\n"
                  "\n");
}

TEST_CASE("show verification droppacket_unsafe.o", "[netsh][verification]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

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
                  "; ./tests/sample/unsafe/droppacket_unsafe.c:42\n"
                  ";     if (ip_header->Protocol == IPPROTO_UDP) {\n"
                  "\n"
                  "2: Upper bound must be at most packet_size (valid_access(r1.offset+9, width=1) for read)\n"
                  "\n"
                  "; ./tests/sample/unsafe/droppacket_unsafe.c:43\n"
                  ";         if (ntohs(udp_header->length) <= sizeof(UDP_HEADER)) {\n"
                  "\n"
                  "4: Upper bound must be at most packet_size (valid_access(r1.offset+24, width=2) for read)\n"
                  "\n"
                  "2 errors\n"
                  "\n");
}

TEST_CASE("show verification xdp_datasize_unsafe.o", "[netsh][verification]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_show_verification, L"xdp_datasize_unsafe.o", L"xdp", nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    output = strip_paths(output);

    // Perform a line by line comparison to detect any differences.
    std::string expected_output =
        "Verification failed\n"
        "\n"
        "Verification report:\n"
        "\n"
        "; ./tests/sample/unsafe/xdp_datasize_unsafe.c:33\n"
        ";     if (next_header + sizeof(ETHERNET_HEADER) > (char*)ctx->data_end) {\n"
        "\n"
        "4: Invalid type (r3.type in {number, ctx, stack, packet, shared})\n"
        "5: Invalid type (valid_access(r3.offset) for comparison/subtraction)\n"
        "5: Invalid type (r3.type in {number, ctx, stack, packet, shared})\n"
        "5: Cannot subtract pointers to different regions (r3.type == r1.type in {ctx, stack, packet})\n"
        "\n"
        "; ./tests/sample/unsafe/xdp_datasize_unsafe.c:39\n"
        ";     if (ethernet_header->Type != ntohs(ETHERNET_TYPE_IPV4) && ethernet_header->Type != "
        "ntohs(ETHERNET_TYPE_IPV6)) {\n"
        "\n"
        "6: Invalid type (r2.type in {ctx, stack, packet, shared})\n"
        "6: Invalid type (valid_access(r2.offset+12, width=2) for read)\n"
        "8: Invalid type (r1.type == number)\n"
        "10: Invalid type (r1.type == number)\n"
        "\n"
        "; ./tests/sample/unsafe/xdp_datasize_unsafe.c:44\n"
        ";     return rc;\n"
        "\n"
        "12: Invalid type (r0.type == number)\n"
        "\n"
        "9 errors\n"
        "\n";

    // Split both output and expected_output into lines.
    std::istringstream output_stream(output);
    std::istringstream expected_output_stream(expected_output);

    std::string output_line;
    std::string expected_output_line;
    while (std::getline(output_stream, output_line) && std::getline(expected_output_stream, expected_output_line)) {
        REQUIRE(output_line == expected_output_line);
    }
}

TEST_CASE("show verification printk_unsafe.o", "[netsh][verification]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_show_verification, L"printk_unsafe.o", L"bind", nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    output = strip_paths(output);
    std::string expected_output = "Verification failed\n"
                                  "\n"
                                  "Verification report:\n"
                                  "\n"
                                  "; ./tests/sample/unsafe/printk_unsafe.c:22\n"
                                  ";     bpf_printk(\"ctx: %u\", (uint64_t)ctx);\n"
                                  "\n"
                                  "7: Invalid type (r3.type == number)\n"
                                  "\n"
                                  "1 errors\n"
                                  "\n";
    test_expected_output_line_by_line(expected_output, output);
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

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("pin first program", "[netsh][programs]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    // Load a program to show.
    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_add_program, L"tail_call.o", L"sample_ext", L"pinpath=mypinpath", &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 5\n") == 0);
    REQUIRE(result == NO_ERROR);

    // Show programs in normal (table) format.
    output = _run_netsh_command(handle_ebpf_show_programs, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n"
                  "     5     1      1  JIT        sample         caller\n"
                  "     6     0      0  JIT        sample         callee\n");

    output = _run_netsh_command(handle_ebpf_delete_program, L"5", nullptr, nullptr, &result);
    REQUIRE(output == "Unpinned 5 from mypinpath\n");
    REQUIRE(result == NO_ERROR);

    verify_no_programs_exist();
}

TEST_CASE("pin all programs", "[netsh][programs]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    // Load programs to show.
    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_add_program, L"tail_call.o", L"pinpath=mypinpath", L"pinned=all", &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 5\n") == 0);
    REQUIRE(result == NO_ERROR);

    // Show programs in normal (table) format.
    output = _run_netsh_command(handle_ebpf_show_programs, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n"
                  "     5     1      1  JIT        sample         caller\n"
                  "     6     1      0  JIT        sample         callee\n");

    output = _run_netsh_command(handle_ebpf_delete_program, L"5", nullptr, nullptr, &result);
    REQUIRE(output == "Unpinned 5 from mypinpath/sample_ext\n");
    REQUIRE(result == NO_ERROR);

    output = _run_netsh_command(handle_ebpf_delete_program, L"6", nullptr, nullptr, &result);
    REQUIRE(output == "Unpinned 6 from mypinpath/sample_ext_0\n");
    REQUIRE(result == NO_ERROR);

    verify_no_programs_exist();
}

TEST_CASE("show programs", "[netsh][programs]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    // Load a program to show.
    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_add_program, L"tail_call.o", L"pinpath=mypinname", nullptr, &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 5\n") == 0);
    REQUIRE(result == NO_ERROR);

    // Show programs in normal (table) format.
    output = _run_netsh_command(handle_ebpf_show_programs, L"sample_ext", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n"
                  "     5     1      1  JIT        sample         caller\n"
                  "     6     0      0  JIT        sample         callee\n");

    // Test filtering by "attached=yes".
    output = _run_netsh_command(handle_ebpf_show_programs, L"attached=yes", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n"
                  "     5     1      1  JIT        sample         caller\n");

    // Test filtering by "attached=no".
    output = _run_netsh_command(handle_ebpf_show_programs, L"attached=no", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n"
                  "     6     0      0  JIT        sample         callee\n");

    // Test filtering by "pinned=yes".
    output = _run_netsh_command(handle_ebpf_show_programs, L"pinned=yes", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n"
                  "     5     1      1  JIT        sample         caller\n");

    // Test filtering by "pinned=no".
    output = _run_netsh_command(handle_ebpf_show_programs, L"pinned=no", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n"
                  "     6     0      0  JIT        sample         callee\n");

    // Test verbose output format.
    output = _run_netsh_command(handle_ebpf_show_programs, L"level=verbose", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "ID             : 5\n"
                  "File name      : tail_call.o\n"
                  "Section        : sample_ext\n"
                  "Name           : caller\n"
                  "Program type   : sample\n"
                  "Mode           : JIT\n"
                  "# map IDs      : 2\n"
                  "map IDs        : 3\n"
                  "                 4\n"
                  "# pinned paths : 1\n"
                  "# links        : 1\n"
                  "\n"
                  "ID             : 6\n"
                  "File name      : tail_call.o\n"
                  "Section        : sample_ext/0\n"
                  "Name           : callee\n"
                  "Program type   : sample\n"
                  "Mode           : JIT\n"
                  "# map IDs      : 0\n"
                  "# pinned paths : 0\n"
                  "# links        : 0\n");

    output = _run_netsh_command(handle_ebpf_delete_program, L"5", nullptr, nullptr, &result);
    REQUIRE(output == "Unpinned 5 from mypinname\n");
    REQUIRE(result == NO_ERROR);

    verify_no_programs_exist();
}

TEST_CASE("set program", "[netsh][programs]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_add_program, L"tail_call.o", L"pinned=none", nullptr, &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 5\n") == 0);
    REQUIRE(result == NO_ERROR);

    // Detach the program. This won't delete the program since
    // the containing object is still associated with the netsh process,
    // and could still be enumerated by it with bpf_object__next().
    output = _run_netsh_command(handle_ebpf_set_program, L"5", L"", nullptr, &result);
    REQUIRE(output == "");
    REQUIRE(result == ERROR_OKAY);

    output = _run_netsh_command(handle_ebpf_show_programs, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n"
                  "     5     0      0  JIT        sample         caller\n"
                  "     6     0      0  JIT        sample         callee\n");

    // Try to detach an unattached program.
    output = _run_netsh_command(handle_ebpf_set_program, L"5", L"", nullptr, &result);
    REQUIRE(output == "error 1168: could not detach program\n");
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);

    RPC_WSTR attach_type_string;
    REQUIRE(UuidToStringW(&EBPF_ATTACH_TYPE_SAMPLE, &attach_type_string) == 0);

    // Attach the program.
    output = _run_netsh_command(handle_ebpf_set_program, L"5", L"sample_ext", nullptr, &result);
    REQUIRE(output == "");
    REQUIRE(result == ERROR_OKAY);

    // Detach the program again.
    output = _run_netsh_command(handle_ebpf_set_program, L"5", L"", nullptr, &result);
    REQUIRE(output == "");
    REQUIRE(result == ERROR_OKAY);

    // Verify we can delete a detached program.
    RpcStringFreeW(&attach_type_string);
    output = _run_netsh_command(handle_ebpf_delete_program, L"5", nullptr, nullptr, &result);
    REQUIRE(output == "");
    REQUIRE(result == NO_ERROR);

    // Verify the program ID doesn't exist any more.
    verify_no_programs_exist();
}

TEST_CASE("show maps", "[netsh][maps]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_add_program, L"map_in_map_btf.o", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 5\n") == 0);

    output = _run_netsh_command(handle_ebpf_show_maps, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "                              Key  Value      Max  Inner\n"
                  "     ID            Map Type  Size   Size  Entries     ID  Pins  Name\n"
                  "=======  ==================  ====  =====  =======  =====  ====  ========\n"
                  "      3                hash     4      4        1      0     0  inner_map\n"
                  "      4       array_of_maps     4      4        1      3     0  outer_map\n");

    output = _run_netsh_command(handle_ebpf_delete_program, L"5", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == "Unpinned 5 from lookup\n");
    verify_no_programs_exist();

    ebpf_epoch_synchronize();

    output = _run_netsh_command(handle_ebpf_show_maps, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "                              Key  Value      Max  Inner\n"
                  "     ID            Map Type  Size   Size  Entries     ID  Pins  Name\n"
                  "=======  ==================  ====  =====  =======  =====  ====  ========\n");
}

TEST_CASE("show links", "[netsh][links]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    // Load and attach a program.
    int result;
    std::string output = _run_netsh_command(handle_ebpf_add_program, L"tail_call.o", L"pinned=none", nullptr, &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 5\n") == 0);
    REQUIRE(result == NO_ERROR);

    output = _run_netsh_command(handle_ebpf_show_links, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "   Link  Program  Attach\n"
                  "     ID       ID  Type\n"
                  "=======  =======  =============\n"
                  "      7        5  sample_ext\n");

    output = _run_netsh_command(handle_ebpf_delete_program, L"5", nullptr, nullptr, &result);
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
    test_helper.initialize();

    // Load and pin programs.
    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_add_program, L"tail_call.o", L"pinned=all", L"pinpath=mypinpath", &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 5\n") == 0);
    REQUIRE(result == NO_ERROR);

    output = _run_netsh_command(handle_ebpf_show_pins, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "     ID     Type  Path\n"
                  "=======  =======  ==============\n"
                  "      5  Program  mypinpath/sample_ext\n"
                  "      6  Program  mypinpath/sample_ext_0\n");

    output = _run_netsh_command(handle_ebpf_delete_program, L"5", nullptr, nullptr, &result);
    REQUIRE(output == "Unpinned 5 from mypinpath/sample_ext\n");
    REQUIRE(result == NO_ERROR);

    output = _run_netsh_command(handle_ebpf_delete_program, L"6", nullptr, nullptr, &result);
    REQUIRE(output == "Unpinned 6 from mypinpath/sample_ext_0\n");
    REQUIRE(result == NO_ERROR);

    verify_no_programs_exist();
}

TEST_CASE("delete pinned program", "[netsh][programs]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    // Load a program unpinned.
    int result;
    std::string output = _run_netsh_command(handle_ebpf_add_program, L"tail_call.o", L"pinned=none", nullptr, &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 5\n") == 0);
    REQUIRE(result == NO_ERROR);

    // Pin the program.
    output = _run_netsh_command(handle_ebpf_set_program, L"5", L"pinpath=mypinname", nullptr, &result);
    REQUIRE(result == ERROR_OKAY);
    REQUIRE(output == "");

    // Pin the program to a second path.
    output = _run_netsh_command(handle_ebpf_set_program, L"5", L"pinpath=mypinname2", nullptr, &result);
    REQUIRE(result == ERROR_OKAY);
    REQUIRE(output == "");

    // Verify we can delete a pinned program.
    output = _run_netsh_command(handle_ebpf_delete_program, L"5", nullptr, nullptr, &result);
    REQUIRE(output == "Unpinned 5 from mypinname\nUnpinned 5 from mypinname2\n");
    REQUIRE(result == NO_ERROR);

    // Verify the program ID doesn't exist any more.
    verify_no_programs_exist();
}

TEST_CASE("unpin program", "[netsh][programs]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    // Load a program pinned.
    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_add_program, L"tail_call.o", L"sample_ext", L"mypinname", &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 5\n") == 0);
    REQUIRE(result == NO_ERROR);

    // Unpin the program.
    output = _run_netsh_command(handle_ebpf_set_program, L"5", L"", nullptr, &result);
    REQUIRE(result == ERROR_OKAY);
    REQUIRE(output == "");

    // Verify we can delete the unpinned program.
    output = _run_netsh_command(handle_ebpf_delete_program, L"5", nullptr, nullptr, &result);
    REQUIRE(output == "Unpinned 5 from mypinname\n");
    REQUIRE(result == NO_ERROR);

    // Verify the program ID doesn't exist any more.
    verify_no_programs_exist();
}

TEST_CASE("xdp interface parameter", "[netsh][programs]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    // Load a program pinned.
    int result;

    // Load program with pinpath and loopback interface alias.
    std::string output = run_netsh_command_with_args(
        handle_ebpf_add_program, &result, 4, L"droppacket.o", L"xdp", L"mypinpath", L"Loopback Pseudo-Interface 1");
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 5\n") == 0);
    REQUIRE(result == NO_ERROR);
    output = _run_netsh_command(handle_ebpf_delete_program, L"5", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == "Unpinned 5 from mypinpath\n");
    verify_no_programs_exist();

    // Load program with pinpath and loopback interface name.
    output = run_netsh_command_with_args(
        handle_ebpf_add_program, &result, 4, L"droppacket.o", L"xdp", L"mypinpath", L"loopback_0");
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 10\n") == 0);
    REQUIRE(result == NO_ERROR);
    output = _run_netsh_command(handle_ebpf_delete_program, L"10", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == "Unpinned 10 from mypinpath\n");
    verify_no_programs_exist();

    // Load program with loopback interface index.
    output = _run_netsh_command(handle_ebpf_add_program, L"droppacket.o", L"xdp", L"interface=1", &result);
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 15\n") == 0);
    REQUIRE(result == NO_ERROR);
    output = _run_netsh_command(handle_ebpf_delete_program, L"15", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == "Unpinned 15 from DropPacket\n");
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
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 29\n") == 0);
    REQUIRE(result == NO_ERROR);

    // Detach the program.
    output = _run_netsh_command(handle_ebpf_set_program, L"29", L"", nullptr, &result);
    REQUIRE(output == "");
    REQUIRE(result == ERROR_OKAY);

    output = _run_netsh_command(handle_ebpf_show_programs, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n"
                  "    29     1      0  JIT        xdp            DropPacket\n");

    // Re-attach the program with interface index parameter.
    output = _run_netsh_command(handle_ebpf_set_program, L"29", nullptr, L"interface=1", &result);
    REQUIRE(output == "");
    REQUIRE(result == ERROR_OKAY);
    output = _run_netsh_command(handle_ebpf_delete_program, L"29", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);

    ebpf_epoch_synchronize();
}

TEST_CASE("cgroup_sock_addr compartment parameter", "[netsh][programs]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    // Load a program pinned.
    int result;

    // Load program with pinpath and compaetment=1.
    std::string output = run_netsh_command_with_args(
        handle_ebpf_add_program, &result, 4, L"cgroup_sock_addr.o", L"cgroup/connect4", L"mypinpath", L"compartment=1");
    REQUIRE(strcmp(output.c_str(), "Loaded with ID 6\n") == 0);
    REQUIRE(result == NO_ERROR);
    output = _run_netsh_command(handle_ebpf_delete_program, L"6", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == "Unpinned 6 from mypinpath\n");
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

    ebpf_epoch_synchronize();
}
#endif // !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)

TEST_CASE("show processes", "[netsh][processes]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
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

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)

TEST_CASE("pin/unpin program", "[netsh][pin]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
    int result = 0;
    auto output =
        _run_netsh_command(handle_ebpf_add_program, L"bindmonitor.o", nullptr, L"pinpath=bindmonitor", &result);
    REQUIRE(result == EBPF_SUCCESS);
    const char prefix[] = "Loaded with ID";
    REQUIRE(output.substr(0, sizeof(prefix) - 1) == prefix);

    // Get program ID.
    auto id = strtoul(output.c_str() + output.rfind(' '), nullptr, 10);
    auto sid = std::to_wstring(id);
    _run_netsh_command(handle_ebpf_pin_program, sid.c_str(), L"bindmonitorpin", nullptr, &result);
    REQUIRE(result == EBPF_SUCCESS);

    output = _run_netsh_command(handle_ebpf_show_pins, nullptr, nullptr, nullptr, &result);
    REQUIRE(
        output == std::format(
                      "\n"
                      "     ID     Type  Path\n"
                      "=======  =======  ==============\n"
                      "      {0}  Program  bindmonitor\n"
                      "      {0}  Program  bindmonitorpin\n",
                      id));

    _run_netsh_command(handle_ebpf_unpin_program, sid.c_str(), L"random", nullptr, &result);
    REQUIRE(result != EBPF_SUCCESS);

    _run_netsh_command(handle_ebpf_unpin_program, sid.c_str(), L"bindmonitorpin", nullptr, &result);
    REQUIRE(result == EBPF_SUCCESS);

    output = _run_netsh_command(handle_ebpf_show_pins, nullptr, nullptr, nullptr, &result);
    REQUIRE(
        output == std::format(
                      "\n"
                      "     ID     Type  Path\n"
                      "=======  =======  ==============\n"
                      "      {}  Program  bindmonitor\n",
                      id));

    _run_netsh_command(handle_ebpf_delete_program, sid.c_str(), nullptr, nullptr, &result);
}

TEST_CASE("pin/unpin map", "[netsh][pin]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
    int result = 0;
    auto output =
        _run_netsh_command(handle_ebpf_add_program, L"bindmonitor.o", L"bind", L"pinpath=bindmonitor", &result);
    REQUIRE(result == EBPF_SUCCESS);
    const char prefix[] = "Loaded with ID";
    REQUIRE(output.substr(0, sizeof(prefix) - 1) == prefix);
    auto pid = strtoul(output.c_str() + output.rfind(' '), nullptr, 10);

    output = _run_netsh_command(handle_ebpf_show_maps, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == EBPF_SUCCESS);

    // Grab the first map ID.
    auto digit = output.find_first_of("123456789");
    auto id = strtoul(output.c_str() + digit, nullptr, 10);
    REQUIRE(id > 0);
    auto sid = std::to_wstring(id);

    auto offset = output.find("audit_map", digit + 1);
    REQUIRE(offset != std::string::npos);
    auto pins = strtoul(output.c_str() + offset - 4, nullptr, 10);
    REQUIRE(pins == 0);

    // Pin map with default name (map name).
    output = _run_netsh_command(handle_ebpf_pin_map, sid.c_str(), nullptr, nullptr, &result);
    REQUIRE(result == EBPF_SUCCESS);

    output = _run_netsh_command(handle_ebpf_show_maps, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == EBPF_SUCCESS);
    pins = strtoul(output.c_str() + offset - 4, nullptr, 10);
    REQUIRE(pins == 1);

    // Pin map with custom name.
    output = _run_netsh_command(handle_ebpf_pin_map, sid.c_str(), L"custompin", nullptr, &result);
    REQUIRE(result == EBPF_SUCCESS);
    output = _run_netsh_command(handle_ebpf_show_maps, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == EBPF_SUCCESS);
    pins = strtoul(output.c_str() + offset - 4, nullptr, 10);
    REQUIRE(pins == 2);

    // Unpin twice.
    output = _run_netsh_command(handle_ebpf_unpin_map, sid.c_str(), nullptr, nullptr, &result);
    REQUIRE(result == EBPF_SUCCESS);
    output = _run_netsh_command(handle_ebpf_unpin_map, sid.c_str(), L"custompin", nullptr, &result);
    REQUIRE(result == EBPF_SUCCESS);
    output = _run_netsh_command(handle_ebpf_show_maps, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == EBPF_SUCCESS);
    pins = strtoul(output.c_str() + offset - 4, nullptr, 10);
    REQUIRE(pins == 0);

    _run_netsh_command(handle_ebpf_delete_program, std::to_wstring(pid).c_str(), nullptr, nullptr, &result);
}
#endif // !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
