// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf2c.h"
#include "test_helpers.h"

#include <cmath>
#include <iostream>
#include <map>
#include <sstream>
#include <string.h>
#include <string>
#include <vector>

// #define UNREFERENCED_PARAMETER(P) (P)

#if !defined(C_NAME)
#define C_NAME test_metadata_table
#endif

extern "C" metadata_table_t C_NAME;

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
            if (byte.empty()) {
                continue;
            }
            mem.push_back(static_cast<uint8_t>(std::strtoul(byte.c_str(), NULL, 16)));
        }
    }
    helper_function_entry_t* helper_function_entries = nullptr;
    size_t helper_function_entry_count = 0;
    map_entry_t* map_entries = nullptr;
    size_t map_entry_count = 0;
    program_entry_t* program_entries = nullptr;
    std::vector<program_runtime_context_t> runtime_contexts;
    std::vector<std::vector<helper_function_data_t>> helper_function_array;
    size_t program_entry_count = 0;

    C_NAME.maps(&map_entries, &map_entry_count);
    C_NAME.programs(&program_entries, &program_entry_count);
    runtime_contexts.resize(program_entry_count);
    helper_function_array.resize(program_entry_count);

    if (map_entry_count != 0) {
        std::cout << "bpf_test doesn't support maps yet." << std::endl;
        return -1;
    }

    for (size_t i = 0; i < program_entry_count; i++) {
        helper_function_entries = program_entries[i].helpers;
        helper_function_entry_count = program_entries[i].helper_count;

        program_runtime_context_t* runtime_context = &runtime_contexts[i];
        helper_function_array[i].resize(helper_function_entry_count);
        runtime_context->helper_data = helper_function_array[i].data();

        for (size_t j = 0; j < helper_function_entry_count; j++) {
            if (helper_function_entries[j].helper_id == -1) {
                std::cout << "bpf_test doesn't support resolving helpers by name yet." << std::endl;
                return -1;
            }
            if (helper_functions.find(helper_function_entries[j].helper_id) == helper_functions.end()) {
                std::cout << "bpf_test doesn't support helper id=" << helper_function_entries[j].helper_id << std::endl;
                return -1;
            } else {
                runtime_context->helper_data[j].address =
                    reinterpret_cast<helper_function_t>(helper_functions[helper_function_entries[j].helper_id]);
                // helper_function_entries[j].address =
                //     reinterpret_cast<helper_function_t>(helper_functions[helper_function_entries[j].helper_id]);
                if (runtime_context->helper_data[j].address == reinterpret_cast<helper_function_t>(unwind)) {
                    runtime_context->helper_data[j].tail_call = true;
                }
                // if (helper_function_entries[j].address == reinterpret_cast<helper_function_t>(unwind)) {
                //     helper_function_entries[j].tail_call = true;
                // }
            }
        }
    }

    std::cout << "bpf_test doesn't support programs yet." << std::endl;
    uint64_t actual_result = program_entries[0].function(mem.data(), &runtime_contexts[0]);
    if (expected_result != actual_result) {
        std::cerr << argv[0] << " Expected result = " << expected_result << " Actual result = " << actual_result
                  << std::endl;
        return 1;
    }
    return 0;
}
