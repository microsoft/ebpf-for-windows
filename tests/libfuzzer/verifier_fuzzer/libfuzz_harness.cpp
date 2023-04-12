// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_api.h"
#include "libfuzzer.h"

#include <chrono>
#include <cstdlib>

bool use_ebpf_store = true;

FUZZ_EXPORT int __cdecl LLVMFuzzerInitialize(int*, char***) { return 0; }

FUZZ_EXPORT int __cdecl LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    ebpf_watchdog_timer_t watchdog_timer;
    try {
        const char* report = nullptr;
        const char* error_message = nullptr;
        ebpf_api_elf_verify_section_from_memory(
            reinterpret_cast<const char*>(data), size, "", nullptr, false, &report, &error_message, nullptr);
        free(const_cast<char*>(report));
        free(const_cast<char*>(error_message));
    } catch (std::runtime_error&) {
    }

    return 0; // Non-zero return values are reserved for future use.
}
