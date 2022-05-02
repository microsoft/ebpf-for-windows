// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#define CATCH_CONFIG_MAIN

#include <string>
#include <vector>

#include "bpf_code_generator.h"
#include "capture_helper.hpp"
#include "catch_wrapper.hpp"

#define main test_main
#define ENABLE_SKIP_VERIFY
#include "bpf2c.cpp"
#undef main

template <typename stream_t>
std::vector<std::string>
read_contents(const std::string& source, std::function<std::string(const std::string&)> transform)
{
    std::vector<std::string> return_value;
    std::string line;
    stream_t input(source);

    while (std::getline(input, line)) {
        return_value.push_back(transform(line));
    }
    return return_value;
}

std::string
transform_line_directives(const std::string& string)
{
    if (!string.starts_with("#line")) {
        return string;
    }
    if (string.find("\"") == std::string::npos) {
        return string;
    }
    if (string.find("\\") == std::string::npos) {
        // Already trimmed.
        return string;
    }

    return string.substr(0, string.find("\"") + 1) + string.substr(string.find_last_of("\\") + 1);
}

std::tuple<std::string, std::string, int>
run_test_main(std::vector<const char*> argv)
{
    capture_helper_t capture;
    errno_t error = capture.begin_capture();
    if (error != 0) {
        throw std::runtime_error("capture.begin_capture failed");
    }
    auto return_value = test_main(static_cast<int>(argv.size()), const_cast<char**>(argv.data()));

    return {
        return_value == 0 ? capture.get_stdout_contents() : "",
        return_value != 0 ? capture.get_stderr_contents() : "",
        return_value};
}

void
run_test_elf(const std::string& elf_file, bool verify, bool expect_failure = false)
{
    std::vector<const char*> argv;
    auto name = elf_file.substr(0, elf_file.find('.'));
    argv.push_back("bpf2c.exe");
    if (!verify) {
        argv.push_back("--no-verify");
    }
    argv.push_back("--bpf");
    argv.push_back(elf_file.c_str());
    argv.push_back("--hash");
    argv.push_back("none");

    auto test = [&](const char* option, const char* suffix) {
        if (option) {
            argv.push_back(option);
        }
        auto [out, err, result_value] = run_test_main(argv);
        if (expect_failure) {
            REQUIRE(result_value != 0);
            REQUIRE(err != "");
        } else {
            auto raw_output = read_contents<std::ifstream>(name + suffix, transform_line_directives);
            auto raw_result = read_contents<std::istringstream>(out, transform_line_directives);

            REQUIRE(raw_result.size() == raw_output.size());
            for (size_t i = 0; i < raw_result.size(); i++) {
                REQUIRE(raw_output[i] == raw_result[i]);
            }
        }
        if (option) {
            argv.pop_back();
        }
    };

    test(nullptr, "_raw.txt");
    test("--dll", "_dll.txt");
    test("--sys", "_sys.txt");
}

#define DECLARE_TEST(FILE, VERIFY) \
    TEST_CASE(FILE, "[elf_bpf_code_gen]") { run_test_elf(FILE ".o", VERIFY); }

#define DECLARE_TEST_VERIFICATION_FAILURE(FILE) \
    TEST_CASE(FILE " verification failure", "[elf_bpf_code_gen]") { run_test_elf(FILE ".o", true, true); }

DECLARE_TEST("bindmonitor", true)
DECLARE_TEST("bindmonitor_ringbuf", true)
DECLARE_TEST("bindmonitor_tailcall", true)
DECLARE_TEST("bpf", true)
DECLARE_TEST("bpf_call", true)
DECLARE_TEST("cgroup_sock_addr", true)
DECLARE_TEST("decap_permit_packet", true)
DECLARE_TEST("divide_by_zero", true)
DECLARE_TEST("droppacket", true)
DECLARE_TEST("encap_reflect_packet", true)
DECLARE_TEST("map", false)
DECLARE_TEST("map_in_map", true)
DECLARE_TEST("map_in_map_v2", true)
DECLARE_TEST("map_reuse", true)
DECLARE_TEST("map_reuse_2", true)
DECLARE_TEST("printk", true)
DECLARE_TEST("printk_legacy", true)
DECLARE_TEST("reflect_packet", true)
DECLARE_TEST("tail_call", true)
DECLARE_TEST("tail_call_bad", true)
DECLARE_TEST("tail_call_map", true)
DECLARE_TEST("tail_call_multiple", true)
DECLARE_TEST("test_sample_ebpf", true)
DECLARE_TEST("test_utility_helpers", true)
DECLARE_TEST("sockops", true)

DECLARE_TEST_VERIFICATION_FAILURE("droppacket_unsafe")
DECLARE_TEST_VERIFICATION_FAILURE("printk_unsafe")
