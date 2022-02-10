// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_code_generator.h"

int
main(int argc, char** argv)
{
    try {

        if (argc != 3) {
            std::cerr << "Usage: " << argv[0] << " <ELF file> <section name>" << std::endl;
            return 1;
        }

        bpf_code_generator generator(argv[1], argv[2]);
        generator.parse();
        generator.generate();
    } catch (std::runtime_error err) {
        std::cerr << err.what() << std::endl;
        return 1;
    }
    return 0;
}
