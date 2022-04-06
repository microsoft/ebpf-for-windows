// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <cmath>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include <string.h>

extern "C"
{
#include "bpf2c.h"
}

#if !defined(C_NAME)
#define C_NAME test_metadata_table
#endif

extern "C" metadata_table_t C_NAME;

static uint64_t
gather_bytes(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    return ((uint64_t)a << 32) | ((uint32_t)b << 24) | ((uint32_t)c << 16) | ((uint16_t)d << 8) | e;
};

static uint64_t
memfrob(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    uint8_t* p = reinterpret_cast<uint8_t*>(a);
    for (uint64_t i = 0; i < b; i++) {
        p[i] ^= 42;
    }
    return 0;
};

static uint64_t
trash_registers(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    /* Overwrite all caller-save registers */
    // asm("mov $0xf0, %rax;"
    //     "mov $0xf1, %rcx;"
    //     "mov $0xf2, %rdx;"
    //     "mov $0xf3, %rsi;"
    //     "mov $0xf4, %rdi;"
    //     "mov $0xf5, %r8;"
    //     "mov $0xf6, %r9;"
    //     "mov $0xf7, %r10;"
    //     "mov $0xf8, %r11;");
    return 0;
}

static uint64_t
sqrti(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    return static_cast<uint64_t>(std::sqrt(a));
}

static uint64_t
strcmp_ext(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    return strcmp(reinterpret_cast<char*>(a), reinterpret_cast<char*>(b));
}

static uint64_t
unwind(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    return a;
}

std::map<uint32_t, uint64_t (*)(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5)> helper_functions = {
    {0, gather_bytes},
    {1, memfrob},
    {2, trash_registers},
    {3, sqrti},
    {4, strcmp_ext},
    {5, unwind},
};

extern "C" void
division_by_zero(uint32_t address)
{
    std::cerr << "BPF program hit divide by zero at PC=" << address << std::endl;
}

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
            if (byte.empty())
                continue;
            mem.push_back(static_cast<uint8_t>(std::strtoul(byte.c_str(), NULL, 16)));
        }
    }
    helper_function_entry_t* helper_function_entries = nullptr;
    size_t helper_function_entry_count = 0;
    map_entry_t* map_entries = nullptr;
    size_t map_entry_count = 0;
    program_entry_t* program_entries = nullptr;
    size_t program_entry_count = 0;

    C_NAME.maps(&map_entries, &map_entry_count);
    C_NAME.programs(&program_entries, &program_entry_count);

    if (map_entry_count != 0) {
        std::cout << "bpf_test doesn't support maps yet." << std::endl;
        return -1;
    }

    for (size_t i = 0; i < program_entry_count; i++) {
        helper_function_entries = program_entries[i].helpers;
        helper_function_entry_count = program_entries[i].helper_count;

        for (size_t j = 0; j < helper_function_entry_count; j++) {
            if (helper_function_entries[j].helper_id == -1) {
                std::cout << "bpf_test doesn't support resolving helpers by name yet." << std::endl;
                return -1;
            }
            if (helper_functions.find(helper_function_entries[j].helper_id) == helper_functions.end()) {
                std::cout << "bpf_test doesn't support helper id=" << helper_function_entries[j].helper_id << std::endl;
                return -1;
            } else {
                helper_function_entries[j].address = helper_functions[helper_function_entries[j].helper_id];
                if (helper_function_entries[j].address == unwind) {
                    helper_function_entries[j].tail_call = true;
                }
            }
        }
    }

    uint64_t actual_result = program_entries[0].function(mem.data());
    if (expected_result != actual_result) {
        std::cerr << argv[0] << " Expected result = " << expected_result << " Actual result = " << actual_result
                  << std::endl;
        return 1;
    }
    return 0;
}
