// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <string>
#include "export_program_info.h"
#include <iostream>

int
main(int argc, char** argv)
{
    bool clear = false;
    if (argc != 1 && argc != 2) {
        print_help(argv[0]);
        return 1;
    }
    if (argc == 2) {
        std::string option(argv[1]);
        if (option == "--clear") {
            clear = true;
        } else {
            print_help(argv[0]);
            return 1;
        }
    }

    if (!clear) {
        std::cout << "Exporting program information." << std::endl;
        export_all_program_information();
        std::cout << "Exporting section information." << std::endl;
        export_all_section_information();
        std::cout << "Exporting global helper information." << std::endl;
        export_global_helper_information();
    } else {
        clear_all_ebpf_stores();
    }

    return 0;
}