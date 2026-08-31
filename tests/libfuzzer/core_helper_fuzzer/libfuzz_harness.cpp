// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_CORE_HELPER_FUZZER

#include "fuzz_helper_function.hpp"

typedef fuzz_helper_function<bpf_sock_addr_t> fuzz_helper_function_sock_addr_t;
std::unique_ptr<fuzz_helper_function_sock_addr_t> _fuzz_helper_function_sock_addr;

typedef fuzz_helper_function<bpf_sock_ops_t> fuzz_helper_function_sock_ops_t;
std::unique_ptr<fuzz_helper_function_sock_ops_t> _fuzz_helper_function_sock_ops;
std::unique_ptr<class _fuzz_core_lifetime> _fuzz_core_lifetime;

class _fuzz_core_lifetime
{
  public:
    _fuzz_core_lifetime()
    {
        ebpf_result_t result = ebpf_core_initiate();
        if (result != EBPF_SUCCESS) {
            throw std::runtime_error("ebpf_core_initiate failed");
        }
    }

    ~_fuzz_core_lifetime() { ebpf_core_terminate(); }
};

int selected_program_type = 0;
FUZZ_EXPORT int __cdecl LLVMFuzzerInitialize(int* argc, char*** argv)
{
    for (int i = 1; i < *argc; i++) {
        if (strcmp((*argv)[i], "-helper") == 0 && i + 1 < *argc) {
            const char* helper_arg = (*argv)[i + 1];
            if (strcmp(helper_arg, "sockaddr") == 0) {
                selected_program_type = 1;
            } else if (strcmp(helper_arg, "sockops") == 0) {
                selected_program_type = 2;
            }

            // Remove the flag and its argument from argv.
            for (int j = i; j < *argc - 2; j++) {
                (*argv)[j] = (*argv)[j + 2];
            }
            *argc -= 2;
            break; // process only one occurrence
        }
    }

    _fuzz_core_lifetime = std::make_unique<class _fuzz_core_lifetime>();

    if (selected_program_type == 1) {
        _fuzz_helper_function_sock_addr =
            std::make_unique<fuzz_helper_function_sock_addr_t>(ebpf_general_helper_function_module_id.Guid, false);
    } else if (selected_program_type == 2) {
        _fuzz_helper_function_sock_ops =
            std::make_unique<fuzz_helper_function_sock_ops_t>(ebpf_general_helper_function_module_id.Guid, false);
    } else {
        // default
        _fuzz_helper_function_sock_addr =
            std::make_unique<fuzz_helper_function_sock_addr_t>(ebpf_general_helper_function_module_id.Guid, false);
        _fuzz_helper_function_sock_ops =
            std::make_unique<fuzz_helper_function_sock_ops_t>(ebpf_general_helper_function_module_id.Guid, false);
    }

    atexit([]() {
        _fuzz_helper_function_sock_ops.reset();
        _fuzz_helper_function_sock_addr.reset();
        _fuzz_core_lifetime.reset();
    });

    return 0;
}

FUZZ_EXPORT int __cdecl LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    ebpf_watchdog_timer_t watchdog_timer;

    if (selected_program_type == 1) {
        return _fuzz_helper_function_sock_addr->fuzz(data, size);
    } else if (selected_program_type == 2) {
        return _fuzz_helper_function_sock_ops->fuzz(data, size);
    } else {
        // default
        int ret = 0;
        ret = _fuzz_helper_function_sock_addr->fuzz(data, size);
        if (ret != 0) {
            return ret;
        }
        ret = _fuzz_helper_function_sock_ops->fuzz(data, size);
        if (ret != 0) {
            return ret;
        }
        return ret;
    }
}
