// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_code_generator.h"

int
main(int argc, char** argv)
{
    try {

        if (argc == 1) {
            std::cerr << "Usage: " << argv[0] << " <ELF file> <section name1> .. <section nameN> " << std::endl;
            return 1;
        }

        std::string file = argv[1];
        std::string c_name = file.substr(file.find_last_of("\\") + 1);
        c_name = c_name.substr(0, file.find("."));

        bpf_code_generator generator(file, c_name);
        // Special case of just the program name
        if (argc == 2) {
            auto sections = generator.program_sections();
            for (const auto& section : sections) {
                generator.parse(section);
                generator.generate();
            }
        } else {
            for (size_t i = 2; i < argc; i++) {
                generator.parse(argv[i]);
                generator.generate();
            }
        }
        generator.emit_c_code(std::cout);
    } catch (std::runtime_error err) {
        std::cerr << err.what() << std::endl;
        return 1;
    }
    return 0;
}
