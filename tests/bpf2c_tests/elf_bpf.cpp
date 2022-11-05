// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#define CATCH_CONFIG_MAIN

#include <optional>
#include <string>
#include <vector>

#include "bpf_code_generator.h"
#include "capture_helper.hpp"
#include "catch_wrapper.hpp"

#define main test_main
#define ENABLE_SKIP_VERIFY
#include "bpf2c.cpp"
#undef main

#define INDENT "    "

template <typename stream_t>
std::vector<std::string>
read_contents(const std::string& source, std::vector<std::function<std::string(const std::string&)>> transforms)
{
    std::vector<std::string> return_value;
    std::string line;
    stream_t input(source);

    while (std::getline(input, line)) {
        for (auto& transform : transforms) {
            line = transform(line);
        }
        return_value.push_back(line);
    }
    return return_value;
}

template <char separator>
std::string
transform_line_directives(const std::string& string)
{
    if (!string.starts_with("#line")) {
        return string;
    }
    if (string.find("\"") == std::string::npos) {
        return string;
    }
    if ((string.find(separator) == std::string::npos)) {
        // Already trimmed.
        return string;
    }

    return string.substr(0, string.find("\"") + 1) + string.substr(string.find_last_of(separator) + 1);
}

// Workaround for: https://github.com/microsoft/ebpf-for-windows/issues/1060
std::string
transform_fix_opcode_comment(const std::string& string)
{
    if (!string.starts_with(INDENT INDENT "// EBPF_OP_")) {
        return string;
    } else {
        return string.substr(sizeof(INDENT) - 1);
    }
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

enum class _test_mode
{
    Verify,
    NoVerify,
    VerifyFail,
    UseHash,
    FileNotFound,
};

void
run_test_elf(const std::string& elf_file, _test_mode test_mode, const std::optional<std::string>& type)
{
    std::vector<const char*> argv;
    auto name = elf_file.substr(0, elf_file.find('.'));
    argv.push_back("bpf2c.exe");
    if (test_mode == _test_mode::NoVerify) {
        argv.push_back("--no-verify");
    }
    argv.push_back("--bpf");
    argv.push_back(elf_file.c_str());
    if (test_mode == _test_mode::UseHash) {
        argv.push_back("--hash");
        argv.push_back("SHA256");
    } else {
        argv.push_back("--hash");
        argv.push_back("none");
    }
    if (type) {
        argv.push_back("--type");
        argv.push_back(type.value().c_str());
    }

    auto test = [&](const char* option, const char* suffix) {
        if (option) {
            argv.push_back(option);
        }
        auto [out, err, result_value] = run_test_main(argv);
        switch (test_mode) {
        case _test_mode::Verify:
        case _test_mode::NoVerify: {
            auto expected_output = read_contents<std::ifstream>(
                std::string("expected\\") + name + suffix,
                {transform_line_directives<'\\'>, transform_line_directives<'/'>, transform_fix_opcode_comment});
            auto actual_output = read_contents<std::istringstream>(
                out, {transform_line_directives<'\\'>, transform_line_directives<'/'>});

            REQUIRE(actual_output.size() == expected_output.size());
            for (size_t i = 0; i < actual_output.size(); i++) {
                REQUIRE(expected_output[i] == actual_output[i]);
            }
        } break;
        case _test_mode::VerifyFail:
        case _test_mode::FileNotFound: {
            REQUIRE(result_value != 0);
            REQUIRE(err != "");
        } break;
        case _test_mode::UseHash:
            REQUIRE(result_value == 0);
            REQUIRE(out != "");
        }
        if (option) {
            argv.pop_back();
        }
    };

    test(nullptr, "_raw.c");
    test("--dll", "_dll.c");
    test("--sys", "_sys.c");
}

#define DECLARE_TEST(FILE, MODE) \
    TEST_CASE(FILE " " #MODE, "[elf_bpf_code_gen]") { run_test_elf(FILE ".o", MODE, std::nullopt); }

#define DECLARE_TEST_CUSTOM_PROGRAM_TYPE(FILE, MODE, TYPE) \
    TEST_CASE(FILE "-custom-" #MODE, "[elf_bpf_code_gen]") { run_test_elf(FILE ".o", MODE, TYPE); }

DECLARE_TEST("bindmonitor", _test_mode::Verify)
DECLARE_TEST("bindmonitor_ringbuf", _test_mode::Verify)
DECLARE_TEST("bindmonitor_tailcall", _test_mode::Verify)
DECLARE_TEST_CUSTOM_PROGRAM_TYPE("bpf", _test_mode::Verify, std::string("xdp"))
DECLARE_TEST("bpf_call", _test_mode::Verify)
DECLARE_TEST("cgroup_sock_addr", _test_mode::Verify)
DECLARE_TEST("cgroup_sock_addr2", _test_mode::Verify)
DECLARE_TEST("decap_permit_packet", _test_mode::Verify)
DECLARE_TEST("divide_by_zero", _test_mode::Verify)
DECLARE_TEST("droppacket", _test_mode::Verify)
DECLARE_TEST("encap_reflect_packet", _test_mode::Verify)
DECLARE_TEST("map", _test_mode::NoVerify)
DECLARE_TEST("map_in_map", _test_mode::Verify)
DECLARE_TEST("map_in_map_v2", _test_mode::Verify)
DECLARE_TEST("map_reuse", _test_mode::Verify)
DECLARE_TEST("map_reuse_2", _test_mode::Verify)
DECLARE_TEST("printk", _test_mode::Verify)
DECLARE_TEST("printk_legacy", _test_mode::Verify)
DECLARE_TEST("reflect_packet", _test_mode::Verify)
DECLARE_TEST("tail_call", _test_mode::Verify)
DECLARE_TEST("tail_call_bad", _test_mode::Verify)
DECLARE_TEST("tail_call_map", _test_mode::Verify)
DECLARE_TEST("tail_call_multiple", _test_mode::Verify)
DECLARE_TEST("test_sample_ebpf", _test_mode::Verify)
DECLARE_TEST("test_utility_helpers", _test_mode::Verify)
DECLARE_TEST("sockops", _test_mode::Verify)

DECLARE_TEST("empty", _test_mode::NoVerify)
DECLARE_TEST("droppacket_unsafe", _test_mode::VerifyFail)
DECLARE_TEST("printk_unsafe", _test_mode::VerifyFail)
DECLARE_TEST("no_such_file", _test_mode::FileNotFound)
DECLARE_TEST_CUSTOM_PROGRAM_TYPE("bpf", _test_mode::UseHash, std::string("xdp"))

DECLARE_TEST("bpf", _test_mode::VerifyFail)
DECLARE_TEST_CUSTOM_PROGRAM_TYPE("bpf", _test_mode::VerifyFail, std::string("invalid"))

TEST_CASE("help", "[bpf2c_cli]")
{
    std::vector<const char*> argv;
    argv.push_back("bpf2c.exe");
    argv.push_back("--help");

    auto [out, err, result_value] = run_test_main(argv);
    REQUIRE(result_value != 0);
    std::vector<std::string> options = {"--sys", "--dll", "--no-verify", "--bpf", "--hash", "--help"};
    for (const auto& option : options) {
        REQUIRE(err.find(option) != std::string::npos);
    }
}

TEST_CASE("bad --bpf", "[bpf2c_cli]")
{
    std::vector<const char*> argv;
    argv.push_back("bpf2c.exe");
    argv.push_back("--bpf");

    auto [out, err, result_value] = run_test_main(argv);
    REQUIRE(result_value != 0);
    REQUIRE(!err.empty());
}

TEST_CASE("bad --hash", "[bpf2c_cli]")
{
    std::vector<const char*> argv;
    argv.push_back("bpf2c.exe");
    argv.push_back("--hash");

    auto [out, err, result_value] = run_test_main(argv);
    REQUIRE(result_value != 0);
    REQUIRE(!err.empty());
}
