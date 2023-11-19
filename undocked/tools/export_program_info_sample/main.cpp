// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "export_program_info_sample.h"

#include <iostream>
#include <string>
#include <winerror.h>

int
main()
{
    uint32_t status;

    std::cout << "Exporting program information for sample extension." << std::endl;
    status = export_all_program_information();
    if (status != ERROR_SUCCESS) {
        std::cout << "Failed export_all_program_information() - ERROR #" << status << std::endl;
    }

    std::cout << "Exporting section information for sample extension." << std::endl;
    status = export_all_section_information();
    if (status != ERROR_SUCCESS) {
        std::cout << "Failed export_all_section_information() - ERROR #" << status << std::endl;
    }

    return 0;
}
