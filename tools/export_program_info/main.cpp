// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "export_program_info.h"

#include <iostream>
#include <string>
#include <winerror.h>

int
main(int argc, char** argv)
{
    bool clear = false;

    if (argc > 2) {
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

    uint32_t status;
    if (!clear) {

        std::cout << "Exporting program information." << std::endl;
        status = export_all_program_information();
        if (status != ERROR_SUCCESS) {
            std::cout << "Failed export_all_program_information() - ERROR #" << status << std::endl;
            return 1;
        }

        std::cout << "Exporting section information." << std::endl;
        status = export_all_section_information();
        if (status != ERROR_SUCCESS) {
            std::cout << "Failed export_all_section_information() - ERROR #" << status << std::endl;
            return 1;
        }

        std::cout << "Exporting global helper information." << std::endl;
        status = export_global_helper_information();
        if (status != ERROR_SUCCESS) {
            std::cout << "Failed export_global_helper_information() - ERROR #" << status << std::endl;
            return 1;
        }
    } else {
        std::cout << "Clearing eBPF store." << std::endl;
        status = clear_ebpf_store();
        if (status != EBPF_SUCCESS) {
            std::cout << "Failed clear_ebpf_store() - ERROR #" << status << std::endl;
            return 1;
        }
    }

    return 0;
}
