// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <Windows.h>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <map>
#include <ranges>
#include <sstream>
#include <thread>
#include <vector>

#undef max
#include "bpf_code_generator.h"

#if defined(_DEBUG)
#pragma comment(lib, "clang_rt.fuzzer_MTd-x86_64.lib")
#pragma comment(lib, "sancovd.lib")
#else
#pragma comment(lib, "clang_rt.fuzzer_MD-x86_64.lib")
#pragma comment(lib, "libsancov.lib")
#endif

#ifdef __cplusplus
#define FUZZ_EXPORT extern "C" __declspec(dllexport)
#else #define FUZZ_EXPORT __declspec(dllexport)
#endif

FUZZ_EXPORT int __cdecl LLVMFuzzerInitialize(int*, char***) { return 0; }

FUZZ_EXPORT int __cdecl LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    try {

        std::string random_buffer(data, data + size);
        std::stringstream output;
        auto stream = std::stringstream(random_buffer);
        bpf_code_generator code_gen(stream, "c_name");
        code_gen.parse();
        auto sections = code_gen.program_sections();
        for (auto& section : sections) {
            code_gen.generate(section);
        }

        code_gen.emit_c_code(output);
    } catch (std::runtime_error&) {
    }

    return 0; // Non-zero return values are reserved for future use.
}
