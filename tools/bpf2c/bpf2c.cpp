// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <functional>
#include <fstream>
#include <iostream>
#include <map>
#include <regex>
#include <string>
#include <tuple>
#include <vector>
#include "bpf_code_generator.h"

const char bpf2c_driver[] =
#include "bpf2c_driver.template"
    ;

const char bpf2c_dll[] =
#include "bpf2c_dll.template"
    ;

void
emit_skeleton(const std::string& c_name, const std::string& code)
{
    std::cout << std::regex_replace(code, std::regex(std::string("___METADATA_TABLE___")), c_name) << std::endl;
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
        std::map<std::string, std::tuple<std::string, std::function<void(std::vector<std::string>::iterator&)>>>
            options = {
                {"--sys",
                 {"Generate code for a Windows driver",
                  [&](std::vector<std::string>::iterator&) { type = output_type::KernelPE; }}},
                {"--dll",
                 {"Generate code for a Windows DLL",
                  [&](std::vector<std::string>::iterator&) { type = output_type::UserPE; }}},
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

        bpf_code_generator generator(file, c_name);

        // Special case of no section name.
        if (sections.size() == 0) {
            sections = generator.program_sections();
        }

        for (const auto& section : sections) {
            generator.parse(section);
            generator.generate();
        }

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
