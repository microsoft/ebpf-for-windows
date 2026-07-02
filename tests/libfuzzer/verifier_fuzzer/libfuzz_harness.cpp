// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "api_internal.h"
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "ebpf_api.h"
#undef max
#include "libfuzzer.h"
#include "test_helper.hpp"

bool use_ebpf_store = true;
extern "C" size_t cxplat_fuzzing_memory_limit;
extern bool g_ebpf_fuzzing_enabled;

FUZZ_EXPORT int __cdecl LLVMFuzzerInitialize(int*, char***)
{
    cxplat_fuzzing_memory_limit = 1024 * 1024;
    g_ebpf_fuzzing_enabled = true;
    return 0;
}

// Treat the input data as an ELF file, load it, and fuzz the verifier/load path.
FUZZ_EXPORT int __cdecl LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    ebpf_watchdog_timer_t watchdog_timer;
    try {
        _test_helper_libbpf test_helper;
        test_helper.initialize();

        bpf_object_open_opts opts = {};
        opts.sz = sizeof(opts);
        opts.object_name = "test";
        bpf_object* bpf_object = bpf_object__open_mem(data, size, &opts);

        if (!bpf_object) {
            return 0;
        }

        bpf_object->execution_type = EBPF_EXECUTION_INTERPRET;

        (void)bpf_object__load(bpf_object);

        bpf_object__close(bpf_object);

    } catch (std::runtime_error&) {
    }

    return 0; // Non-zero return values are reserved for future use.
}
