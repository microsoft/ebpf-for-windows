// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "export_program_info.h"
#include <iostream>
#include <string>

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
        uint32_t status;

        std::cout << "Exporting program information." << std::endl;
        status = export_all_program_information();
        if (status != ERROR_SUCCESS) {
            std::cout << "Failed export_all_program_information() - ERROR #" << status << std::endl;
        }

        std::cout << "Exporting section information." << std::endl;
        status = export_all_section_information();
        if (status != ERROR_SUCCESS) {
            std::cout << "Failed export_all_section_information() - ERROR #" << status << std::endl;
        }

        std::cout << "Exporting global helper information." << std::endl;
        status = export_global_helper_information();
        if (status != ERROR_SUCCESS) {
            std::cout << "Failed export_global_helper_information() - ERROR #" << status << std::endl;
        }
    } else {
        clear_all_ebpf_stores();
    }

    return 0;
}
