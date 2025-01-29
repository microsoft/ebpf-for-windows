// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_CORE_HELPER_FUZZER

#include "fuzz_helper_function.hpp"

std::unique_ptr<bpf_sock_addr_t> _fuzz_helper_function_sock_addr;

FUZZ_EXPORT int __cdecl LLVMFuzzerInitialize(int*, char***)
{
    // Setup fuzz_state to fuzz the general helper functions.
    _fuzz_helper_function_sock_addr =
        std::make_unique<bpf_sock_addr_t>(ebpf_general_helper_function_module_id.Guid);

    // Ensure that the ebpfcore runtime is stopped before the usersim runtime.
    atexit([]() { _fuzz_helper_function_sock_addr.reset(); });
    return 0;
}

FUZZ_EXPORT int __cdecl LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    ebpf_watchdog_timer_t watchdog_timer;

    return _fuzz_helper_function_sock_addr->fuzz(data, size);
}
