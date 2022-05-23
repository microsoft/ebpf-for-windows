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
#include <ebpf_api.h>

#undef max

#if defined(_DEBUG)
#pragma comment(lib, "clang_rt.fuzzer_MDd-x86_64.lib")
#pragma comment(lib, "libsancov.lib")
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
        const char* report = nullptr;
        ;
        const char* error_message = nullptr;
        ebpf_api_elf_verify_section_from_memory((const char*)data, size, "", false, &report, &error_message, nullptr);
        free((void*)report);
        free((void*)error_message);
    } catch (std::runtime_error&) {
    }

    return 0; // Non-zero return values are reserved for future use.
}
