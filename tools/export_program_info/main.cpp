// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "export_program_info.h"

#include <iostream>
#include <string>
#include <winerror.h>

int
main(int argc, char** argv)
{
    bool clear = false;

    ebpf_store_key_t root_key = nullptr;
    if (argc != 1 && argc != 2 && argc != 4) {
        print_help(argv[0]);
        return 1;
    }
    if (argc >= 2) {
        std::string option(argv[1]);
        if (option == "--clear") {
            clear = true;
        } else {
            print_help(argv[0]);
            return 1;
        }
        if (argc == 4) {
            std::string hive_option(argv[2]);
            std::string hive(argv[3]);
            if (hive_option != "--hive" || (hive != "HKLM" && hive != "HKCU")) {
                print_help(argv[0]);
                return 1;
            }
            root_key = hive == "HKLM" ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
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
        status = clear_ebpf_store(root_key);
        if (status != EBPF_SUCCESS) {
            std::cout << "Failed clear_ebpf_store() - ERROR #" << status << std::endl;
            return 1;
        }
    }

    return 0;
}
