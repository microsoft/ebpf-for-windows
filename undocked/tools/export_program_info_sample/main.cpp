// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "export_program_info_sample.h"

#include <iostream>
#include <string>
#include <winerror.h>

int
main(int argc, char** argv)
{
    uint32_t status;
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

    if (!clear) {
        std::cout << "Exporting program information for sample extension." << std::endl;
        status = export_program_information();
        if (status != ERROR_SUCCESS) {
            std::cout << "Failed export_program_information() - ERROR #" << status << std::endl;
        }

        std::cout << "Exporting section information for sample extension." << std::endl;
        status = export_section_information();
        if (status != ERROR_SUCCESS) {
            std::cout << "Failed export_section_information() - ERROR #" << status << std::endl;
        }
    } else {
        std::cout << "Clearing eBPF store for sample extension." << std::endl;
        status = clear_ebpf_store();
        if (status != EBPF_SUCCESS) {
            std::cout << "Failed clear_ebpf_store() - ERROR #" << status << std::endl;
        }
    }

    return 0;
}
