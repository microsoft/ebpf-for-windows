// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * This program reads BPF instructions from stdin and memory contents from
 * the first argument. It then executes the BPF program and prints the
 * value of r0 at the end of execution.
 * The program is intended to be used with the bpf conformance test suite.
 */

#include "bpf_code_generator.h"

#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

const char copyright_notice[] = "// Copyright (c) eBPF for Windows contributors\n// SPDX-License-Identifier: MIT\n";

const char bpf2c_plugin[] =
#include "bpf2c_test.template"
    ;

void
emit_skeleton(const std::string& c_name, const std::string& code, std::ostream& out)
{
    auto output = std::regex_replace(code, std::regex(std::string("___METADATA_TABLE___")), c_name);
    output = output.substr(strlen(copyright_notice) + 1);
    out << output << std::endl;
}

#define SEPARATOR "\\"

/**
 * @brief Read in a string of hex bytes and return a vector of bytes.
 *
 * @param[in] input String containing hex bytes.
 * @return Vector of bytes.
 */
std::vector<uint8_t>
base16_decode(const std::string& input)
{
    std::vector<uint8_t> output;
    std::stringstream ss(input);
    std::string value;
    output.reserve(input.size() / 3);
    while (std::getline(ss, value, ' ')) {
        try {
            output.push_back(static_cast<uint8_t>(std::stoi(value, nullptr, 16)));
        } catch (...) {
            // Ignore invalid values.
        }
    }
    return output;
}

/**
 * @brief Convert a vector of bytes to a vector of ebpf_inst.
 *
 * @param[in] bytes Vector of bytes.
 * @return Vector of ebpf_inst.
 */
std::vector<ebpf_inst>
bytes_to_ebpf_inst(std::vector<uint8_t> bytes)
{
    std::vector<ebpf_inst> instructions(bytes.size() / sizeof(ebpf_inst));
    memcpy(instructions.data(), bytes.data(), bytes.size());
    return instructions;
}

std::string
env_or_default(const char* environment_variable, const char* default_value)
{
    std::string return_value = default_value;
    char* buffer = nullptr;
    size_t buffer_size = 0;
    if (_dupenv_s(&buffer, &buffer_size, environment_variable) == 0) {
        if (buffer != nullptr) {
            return_value = buffer;
        }
        free(buffer);
    }

    return return_value;
}

void
generate_c_file(const std::vector<ebpf_inst>& program, const std::filesystem::path& file_path)
{
    std::filesystem::path c_file_path = file_path.string() + ".cpp";
    std::ofstream c_file(c_file_path);
    emit_skeleton("test", bpf2c_plugin, c_file);
    bpf_code_generator code("test", program);
    code.generate("test");
    code.emit_c_code(c_file);
    c_file.flush();
    c_file.close();
}

void
compile_c_file(const std::filesystem::path& file_path, const std::string& include_string)
{
    std::string cc = env_or_default("CC", "cl.exe");
    std::string cxxflags = env_or_default("CXXFLAGS", "/EHsc /nologo");

    std::filesystem::path c_file = file_path.string() + ".cpp";
    std::filesystem::path log_file = file_path.string() + ".log";
    std::string compile_command =
        cc + " " + cxxflags + " -I" + include_string + " " + c_file.string() + " 2>&1 >" + log_file.string();
    if (system(compile_command.c_str()) != 0) {
        std::ifstream log(file_path.stem().string() + ".log");
        std::string line;
        std::ostringstream error;
        while (std::getline(log, line)) {
            error << line << std::endl;
        }
        throw std::runtime_error("Failed to compile: " + error.str());
    }
}

void
execute(const std::filesystem::path& file_path, const std::string& memory_string)
{
    std::string test_string = file_path.string() + " " + "\"" + memory_string + "\"";
    if (system(test_string.c_str()) != 0) {
        throw std::runtime_error("Failed to execute test");
    }
}

/**
 * @brief This program reads BPF instructions from stdin and memory contents from
 * the first argument. It then executes the BPF program and prints the
 * value of r0 at the end of execution.
 */
int
main(int argc, char** argv)
{
    try {
        bool debug = false;
        std::vector<std::string> args(argv, argv + argc);
        if (args.size() > 0) {
            args.erase(args.begin());
        }

        std::filesystem::path include_string;
        std::string program_string;
        std::string memory_string;

        if (args.size() > 0 && args[0] == "--help") {
            std::cout
                << "usage: " << argv[0]
                << " [--program <base16 program bytes>] [<base16 memory bytes>] [--debug] [--include <include_path}]"
                << std::endl;
            return 1;
        }

        if (args.size() > 1 && args[0] == "--program") {
            args.erase(args.begin());
            program_string = args[0];
            args.erase(args.begin());
        } else {
            std::getline(std::cin, program_string);
        }

        // Next parameter is optional memory contents.
        if (args.size() > 0 && !args[0].starts_with("--")) {
            memory_string = args[0];
            args.erase(args.begin());
        }

        if (args.size() > 0 && args[0] == "--debug") {
            debug = true;
            args.erase(args.begin());
        }

        if (args.size() > 0 && args[0] == "--include") {
            args.erase(args.begin());
            include_string = args.front();
            args.erase(args.begin());
        }

        if (args.size() > 0 && args[0].size() > 0) {
            std::cerr << "Unexpected arguments: " << args[0] << std::endl;
            return 1;
        }

        std::vector<ebpf_inst> program = bytes_to_ebpf_inst(base16_decode(program_string));

        size_t memory_byte_count = base16_decode(memory_string).size();

        program.insert(program.begin(), {0xb7, 0x2, 0x0, 0x0, static_cast<int32_t>(memory_byte_count)}); // mov r2, size

        size_t name = std::hash<std::string>{}(program_string);
        auto temp_file_path = std::filesystem::temp_directory_path() / std::to_string(name);
        std::filesystem::current_path(std::filesystem::temp_directory_path());

        generate_c_file(program, temp_file_path);
        compile_c_file(temp_file_path, include_string.string());
        execute(temp_file_path, memory_string);

        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
}
