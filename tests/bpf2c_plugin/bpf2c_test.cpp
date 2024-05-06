// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf2c.h"

#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <sstream>
#include <stdio.h>
#include <string>
#include <vector>
#include <winnt.h>

#define metadata_table ___METADATA_TABLE___##_metadata_table
extern metadata_table_t metadata_table;

static uint64_t
_gather_bytes(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    return ((uint64_t)(a & 0xff) << 32) | ((uint64_t)(b & 0xff) << 24) | ((uint64_t)(c & 0xff) << 16) |
           ((uint64_t)(d & 0xff) << 8) | (e & 0xff);
}

static uint64_t
_memfrob(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    UNREFERENCED_PARAMETER(c);
    UNREFERENCED_PARAMETER(d);
    UNREFERENCED_PARAMETER(e);

    uint8_t* p = reinterpret_cast<uint8_t*>(a);
    for (uint64_t i = 0; i < b; i++) {
        p[i] ^= 42;
    }
    return 0;
}

static uint64_t
_no_op(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    UNREFERENCED_PARAMETER(a);
    UNREFERENCED_PARAMETER(b);
    UNREFERENCED_PARAMETER(c);
    UNREFERENCED_PARAMETER(d);
    UNREFERENCED_PARAMETER(e);

    return 0;
}

static uint64_t
_sqrti(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    UNREFERENCED_PARAMETER(b);
    UNREFERENCED_PARAMETER(c);
    UNREFERENCED_PARAMETER(d);
    UNREFERENCED_PARAMETER(e);

    return static_cast<uint64_t>(std::sqrt(a));
}

static uint64_t
_strcmp_ext(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    UNREFERENCED_PARAMETER(c);
    UNREFERENCED_PARAMETER(d);
    UNREFERENCED_PARAMETER(e);
    return strcmp(reinterpret_cast<char*>(a), reinterpret_cast<char*>(b));
}

static uint64_t
_unwind(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    UNREFERENCED_PARAMETER(b);
    UNREFERENCED_PARAMETER(c);
    UNREFERENCED_PARAMETER(d);
    UNREFERENCED_PARAMETER(e);
    return a;
}

static std::map<uint32_t, uint64_t (*)(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5)>
    _helper_functions = {
        {0, _gather_bytes},
        {1, _memfrob},
        {2, _no_op},
        {3, _sqrti},
        {4, _strcmp_ext},
        {5, _unwind},
};

/**
 * @brief Read in a string of hex bytes and return a vector of bytes.
 *
 * @param[in] input String containing hex bytes.
 * @return Vector of bytes.
 */
static std::vector<uint8_t>
_base16_decode(const std::string& input)
{
    std::vector<uint8_t> output;
    std::stringstream ss(input);
    std::string value;
    while (std::getline(ss, value, ' ')) {
        try {
            output.push_back(std::stoi(value, nullptr, 16));
        } catch (...) {
            // Ignore invalid values.
        }
    }
    return output;
}

int
main(int argc, char** argv)
{
    std::vector<std::string> args(argv, argv + argc);
    if (args.size() > 0) {
        args.erase(args.begin());
    }

    std::string memory_string;
    std::vector<uint8_t> memory;

    if (args.size() > 0 && args[0] == "--help") {
        std::cout << "usage: " << argv[0] << " [<base16 memory bytes>]" << std::endl;
        return 1;
    }

    if (args.size() > 0) {
        memory_string = args[0];
        args.erase(args.begin());
    }

    if (args.size() > 0) {
        std::cerr << "Too many arguments" << std::endl;
        return 1;
    }

    memory = _base16_decode(memory_string);

    program_entry_t* program_entries = nullptr;
    size_t program_entry_count = 0;
    metadata_table.programs(&program_entries, &program_entry_count);

    if (program_entry_count != 1) {
        std::cerr << "Expected 1 program, found " << program_entry_count << std::endl;
        return 1;
    }
    helper_function_entry_t* helper_function_entries = nullptr;

    for (size_t i = 0; i < program_entry_count; i++) {
        helper_function_entry_t* helper_function_entries = program_entries[i].helpers;
        size_t helper_function_entry_count = program_entries[i].helper_count;

        for (size_t j = 0; j < helper_function_entry_count; j++) {
            if (helper_function_entries[j].helper_id == -1) {
                std::cout << "bpf_test doesn't support resolving helpers by name yet." << std::endl;
                return -1;
            }
            if (_helper_functions.find(helper_function_entries[j].helper_id) == _helper_functions.end()) {
                std::cout << "bpf_test doesn't support helper id=" << helper_function_entries[j].helper_id << std::endl;
                return -1;
            } else {
                helper_function_entries[j].address = _helper_functions[helper_function_entries[j].helper_id];
                if (helper_function_entries[j].address == _unwind) {
                    helper_function_entries[j].tail_call = true;
                }
            }
        }
    }

    std::cout << std::hex << program_entries[0].function(memory.data()) << std::endl;
    return 0;
}
