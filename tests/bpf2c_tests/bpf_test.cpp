// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <stdint.h>
#include <stdbool.h>
#include <string>
#include <sstream>
#include <vector>
#include <iostream>

extern "C" uint64_t
test(void* data);

int
main(int argc, char** argv)
{
    uint64_t expected_result = 0;
    std::vector<uint8_t> mem;

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " expected_result data" << std::endl;
        return -1;
    }
    expected_result = strtoull(argv[1], NULL, 16);
    if (argc == 3) {
        std::string byte;
        std::stringstream data_string(argv[2]);
        while (std::getline(data_string, byte, ' ')) {
            mem.push_back(static_cast<uint8_t>(std::stoi(byte)));
        }
    }
    uint64_t actual_result = test(mem.data());
    if (expected_result != actual_result) {
        std::cerr << "Expected result = " << expected_result << " Actual result = " << actual_result << std::endl;
        return 1;
    }
    return 0;
}