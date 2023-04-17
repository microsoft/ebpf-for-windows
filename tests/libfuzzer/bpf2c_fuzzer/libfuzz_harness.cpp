// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include "bpf_code_generator.h"
#include "libfuzzer.h"

#include <Windows.h>
#include <ElfWrapper.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <ranges>
#include <sstream>
#include <vector>
#undef max

#define elf_everparse_error ElfEverParseError
#define elf_everparse_verify ElfCheckElf

extern "C" void
elf_everparse_error(_In_ const char* struct_name, _In_ const char* field_name, _In_ const char* reason);

void
elf_everparse_error(_In_ const char* struct_name, _In_ const char* field_name, _In_ const char* reason)
{
    UNREFERENCED_PARAMETER(struct_name);
    UNREFERENCED_PARAMETER(field_name);
    UNREFERENCED_PARAMETER(reason);
}

FUZZ_EXPORT int __cdecl LLVMFuzzerInitialize(int*, char***) { return 0; }

FUZZ_EXPORT int __cdecl LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    ebpf_watchdog_timer_t watchdog_timer;

    try {
        if (!ElfCheckElf(size, const_cast<uint8_t*>(data), static_cast<uint32_t>(size))) {
            return 0;
        }

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
