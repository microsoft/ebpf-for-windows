// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include <string>
#include <vector>

#include "bpf_code_generator.h"
#include "capture_helper.hpp"
#include "catch_wrapper.hpp"

#define main test_main
#include "bpf2c.cpp"
#undef main

template <typename stream_t>
std::vector<std::string>
read_contents(const std::string& source)
{
    std::vector<std::string> return_value;
    std::string line;
    stream_t input(source);

    while (std::getline(input, line)) {
        return_value.push_back(line);
    }
    return return_value;
}

std::string
run_test_main(std::vector<const char*> argv)
{
    capture_helper_t capture;
    errno_t error = capture.begin_capture();
    if (error != 0) {
        throw std::runtime_error("capture.begin_capture failed");
    }
    auto return_value = test_main(static_cast<int>(argv.size()), const_cast<char**>(argv.data()));
    if (return_value != 0) {
        throw std::runtime_error("test_main failed");
    }
    return capture.get_stdout_contents();
}

void
run_test_elf(const std::string& elf_file)
{
    std::vector<const char*> argv;
    auto name = elf_file.substr(0, elf_file.find('.'));
    argv.push_back("bpf2c.exe");
    argv.push_back("--bpf");
    argv.push_back(elf_file.c_str());

    auto raw_output = read_contents<std::ifstream>(name + "_raw.txt");
    auto raw_result = read_contents<std::istringstream>(run_test_main(argv));
    REQUIRE(raw_result.size() == raw_output.size());
    for (size_t i = 0; i < raw_result.size(); i++) {
        REQUIRE(raw_output[i] == raw_result[i]);
    }

    argv.push_back("--dll");
    auto dll_output = read_contents<std::ifstream>(name + "_dll.txt");
    auto dll_result = read_contents<std::istringstream>(run_test_main(argv));
    REQUIRE(dll_result.size() == dll_output.size());
    for (size_t i = 0; i < dll_result.size(); i++) {
        REQUIRE(dll_output[i] == dll_result[i]);
    }
    argv.pop_back();

    argv.push_back("--sys");
    auto sys_output = read_contents<std::ifstream>(name + "_sys.txt");
    auto sys_result = read_contents<std::istringstream>(run_test_main(argv));
    REQUIRE(sys_result.size() == sys_output.size());
    for (size_t i = 0; i < sys_result.size(); i++) {
        REQUIRE(sys_output[i] == sys_result[i]);
    }
    argv.pop_back();
}

#define DECLARE_TEST(FILE) \
    TEST_CASE(FILE, "[elf_bpf_code_gen]") { run_test_elf(FILE ".o"); }

DECLARE_TEST("bindmonitor")
DECLARE_TEST("bindmonitor_ringbuf")
DECLARE_TEST("bindmonitor_tailcall")
DECLARE_TEST("bpf")
DECLARE_TEST("bpf_call")
DECLARE_TEST("cgroup_sock_addr")
DECLARE_TEST("decap_permit_packet")
DECLARE_TEST("divide_by_zero")
DECLARE_TEST("droppacket")
DECLARE_TEST("droppacket_unsafe")
DECLARE_TEST("encap_reflect_packet")
DECLARE_TEST("map")
DECLARE_TEST("map_in_map")
DECLARE_TEST("map_in_map_v2")
DECLARE_TEST("map_reuse")
DECLARE_TEST("map_reuse_2")
DECLARE_TEST("printk")
DECLARE_TEST("printk_legacy")
DECLARE_TEST("printk_unsafe")
DECLARE_TEST("reflect_packet")
DECLARE_TEST("tail_call")
DECLARE_TEST("tail_call_bad")
DECLARE_TEST("tail_call_map")
DECLARE_TEST("tail_call_multiple")
DECLARE_TEST("test_sample_ebpf")
DECLARE_TEST("test_utility_helpers")
