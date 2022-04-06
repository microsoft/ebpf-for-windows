// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <functional>
#include <fstream>
#include <iostream>
#include <map>
#include <regex>
#include <string>
#include <sstream>
#include <tuple>
#include <vector>

#include "bpf_code_generator.h"
#include "ebpf_api.h"

const char copyright_notice[] = "// Copyright (c) Microsoft Corporation\n// SPDX-License-Identifier: MIT\n";

const char bpf2c_driver[] =
#include "bpf2c_driver.template"
    ;

const char bpf2c_dll[] =
#include "bpf2c_dll.template"
    ;

void
emit_skeleton(const std::string& c_name, const std::string& code)
{
    auto output = std::regex_replace(code, std::regex(std::string("___METADATA_TABLE___")), c_name);
    output = output.substr(strlen(copyright_notice) + 1);
    std::cout << output << std::endl;
}

std::string
load_file_to_memory(const std::string& path)
{
    struct stat st;
    if (stat(path.c_str(), &st)) {
        throw std::runtime_error(std::string("Failed to read file: ") + path);
    }
    if (std::ifstream stream{path, std::ios::in | std::ios::binary}) {
        std::string data;
        data.resize(st.st_size);
        if (!stream.read(data.data(), data.size())) {
            throw std::runtime_error(std::string("Failed to read file: ") + path);
        }
        return data;
    }
    throw std::runtime_error(std::string("Failed to read file: ") + path);
}

int
main(int argc, char** argv)
{
    try {
        enum class output_type
        {
            Bare,
            KernelPE,
            UserPE,
        } type = output_type::Bare;
        std::string verifier_output_file;
        std::string file;
        std::vector<std::string> sections;
        bool verify_programs = true;
        std::map<std::string, std::tuple<std::string, std::function<void(std::vector<std::string>::iterator&)>>>
            options = {
                {"--sys",
                 {"Generate code for a Windows driver",
                  [&](std::vector<std::string>::iterator&) { type = output_type::KernelPE; }}},
                {"--dll",
                 {"Generate code for a Windows DLL",
                  [&](std::vector<std::string>::iterator&) { type = output_type::UserPE; }}},
#if defined(ENABLE_SKIP_VERIFY)
                {"--no-verify",
                 {"Skip validate code using verifier",
                  [&](std::vector<std::string>::iterator&) { verify_programs = false; }}},
#endif
                {"--bpf",
                 {"Input ELF file containing BPF byte code",
                  [&](std::vector<std::string>::iterator& it) { file = *(++it); }}},
                {"--section",
                 {"Space separated list of sections to process ",
                  [&](std::vector<std::string>::iterator& it) {
                      while ((*it).find("--") == std::string::npos)
                          sections.push_back(*(++it));
                  }}},
                {"--help",
                 {"This help menu",
                  [&](std::vector<std::string>::iterator&) {
                      std::cout << argv[0]
                                << " is a tool to generate C code"
                                   "from an ELF file containing BPF byte code."
                                << std::endl;
                      std::cout << "Options are:" << std::endl;
                      for (auto [option, tuple] : options) {
                          auto [help, _] = tuple;
                          std::cout << option.c_str() << "\t" << help.c_str() << std::endl;
                      }
                      return 1;
                  }}},
            };

        std::vector<std::string> parameters(argv + 1, argv + argc);

        for (auto iter = parameters.begin(); iter < parameters.end(); ++iter) {
            auto option = options.find(*iter);
            if (option == options.end()) {
                option = options.find("--help");
            }
            auto [_, function] = option->second;
            function(iter);
        }

        std::string c_name = file.substr(file.find_last_of("\\") + 1);
        c_name = c_name.substr(0, c_name.find("."));
        auto data = load_file_to_memory(file);
        auto stream = std::stringstream(data);
        // TODO: Issue #834 - validate the ELF is well formed
        bpf_code_generator generator(stream, c_name);

        // Special case of no section name.
        if (sections.size() == 0) {
            sections = generator.program_sections();
        }

        // Parse global data.
        generator.parse();

        // Parse per-section data.
        for (const auto& section : sections) {
            ebpf_program_type_t program_type;
            ebpf_attach_type_t attach_type;
            if (ebpf_get_program_type_by_name(section.c_str(), &program_type, &attach_type) != EBPF_SUCCESS) {
                throw std::runtime_error(std::string("Cannot get program / attach type for section ") + section);
            }
            const char* report = nullptr;
            const char* error_message = nullptr;
            ebpf_api_verifier_stats_t stats;
            if (verify_programs &&
                ebpf_api_elf_verify_section_from_memory(
                    data.c_str(), data.size(), section.c_str(), false, &report, &error_message, &stats) != 0) {
                throw std::runtime_error(
                    std::string("Verification failed for ") + section + std::string(" with error ") +
                    std::string(error_message) + std::string("\n Report:\n") + std::string(report));
            }
            generator.parse(section, program_type, attach_type);
        }

        for (const auto& section : sections) {
            generator.generate(section);
        }

        std::cout << copyright_notice << std::endl;
        std::cout << "// Do not alter this generated file." << std::endl;
        std::cout << "// This file was generated from " << file << std::endl << std::endl;
        switch (type) {
        case output_type::Bare:
            break;
        case output_type::KernelPE:
            emit_skeleton(c_name, bpf2c_driver);
            break;
        case output_type::UserPE:
            emit_skeleton(c_name, bpf2c_dll);
            break;
        }
        generator.emit_c_code(std::cout);
    } catch (std::runtime_error err) {
        std::cerr << err.what() << std::endl;
        return 1;
    }
    return 0;
}
