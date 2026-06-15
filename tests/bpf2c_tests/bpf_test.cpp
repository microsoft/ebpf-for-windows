// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf2c.h"
#include "sample_ext_helpers.h"
#include "test_helpers.h"

#include <cmath>
#include <iostream>
#include <map>
#include <sstream>
#include <string.h>
#include <string>
#include <vector>

#if !defined(C_NAME)
#define C_NAME test_metadata_table
#endif

extern "C" metadata_table_t C_NAME;

static uint64_t
_my_driver_lookup(
    uint64_t key, uint64_t value, uint64_t value_size, uint64_t reserved1, uint64_t reserved2, _In_opt_ void* context)
{
    UNREFERENCED_PARAMETER(reserved1);
    UNREFERENCED_PARAMETER(reserved2);
    UNREFERENCED_PARAMETER(context);

    if (value != 0 && value_size >= sizeof(uint64_t)) {
        *reinterpret_cast<uint64_t*>(value) = key;
    }

    return key + value_size;
}

static std::string
_btf_resolved_function_key(_In_ const GUID& module_guid, _In_z_ const char* name)
{
    return std::string(reinterpret_cast<const char*>(&module_guid), sizeof(module_guid)) + name;
}

static const GUID _sample_ext_btf_module_guid = SAMPLE_EXT_BTF_MODULE_GUID_INITIALIZER;

static std::map<std::string, helper_function_t> _btf_resolved_functions = {
    {_btf_resolved_function_key(_sample_ext_btf_module_guid, SAMPLE_EXT_BTF_FUNCTION_NAME), _my_driver_lookup},
};

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
    std::vector<std::vector<btf_resolved_function_data_t>> btf_resolved_function_array;
    size_t program_entry_count = 0;

    C_NAME.maps(&map_entries, &map_entry_count);
    C_NAME.programs(&program_entries, &program_entry_count);
    runtime_contexts.resize(program_entry_count);
    helper_function_array.resize(program_entry_count);
    btf_resolved_function_array.resize(program_entry_count);

    if (map_entry_count != 0) {
        std::cout << "bpf_test doesn't support maps yet." << std::endl;
        return -1;
    }

    for (size_t i = 0; i < program_entry_count; i++) {
        helper_function_entries = program_entries[i].helpers;
        helper_function_entry_count = program_entries[i].helper_count;
        auto* btf_resolved_function_entries = program_entries[i].btf_resolved_functions;
        size_t btf_resolved_function_entry_count = program_entries[i].btf_resolved_function_count;

        program_runtime_context_t* runtime_context = &runtime_contexts[i];
        helper_function_array[i].resize(helper_function_entry_count);
        runtime_context->helper_data = helper_function_array[i].data();
        btf_resolved_function_array[i].resize(btf_resolved_function_entry_count);
        runtime_context->btf_resolved_function_data = btf_resolved_function_array[i].data();

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
            }
        }

        for (size_t j = 0; j < btf_resolved_function_entry_count; j++) {
            auto function = _btf_resolved_functions.find(_btf_resolved_function_key(
                btf_resolved_function_entries[j].module_guid, btf_resolved_function_entries[j].name));
            if (function == _btf_resolved_functions.end()) {
                std::cout << "bpf_test doesn't support BTF-resolved function " << btf_resolved_function_entries[j].name
                          << std::endl;
                return -1;
            }

            runtime_context->btf_resolved_function_data[j].address = function->second;
        }
    }

    uint64_t actual_result = program_entries[0].function(mem.data(), &runtime_contexts[0]);
    if (expected_result != actual_result) {
        std::cerr << argv[0] << " Expected result = " << expected_result << " Actual result = " << actual_result
                  << std::endl;
        return 1;
    }
    return 0;
}
