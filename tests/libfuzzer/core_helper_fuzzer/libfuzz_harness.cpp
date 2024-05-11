// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_CORE_HELPER_FUZZER

#include "fuzz_helper_function.hpp"

struct fuzz_xdp_md_helper_t : public xdp_md_helper_t
{
  public:
    fuzz_xdp_md_helper_t() : xdp_md_helper_t(packet) {}

  private:
    uint8_t packet_buffer[MAX_BUFFER_SIZE] = {0};

    std::vector<uint8_t> packet{packet_buffer, packet_buffer + sizeof(packet_buffer)};
};

typedef fuzz_helper_function<fuzz_xdp_md_helper_t> fuzz_helper_function_xdp_t;
std::unique_ptr<fuzz_helper_function_xdp_t> _fuzz_helper_function_xdp;

FUZZ_EXPORT int __cdecl LLVMFuzzerInitialize(int*, char***)
{
    // Setup fuzz_state to fuzz the general helper functions.
    _fuzz_helper_function_xdp =
        std::make_unique<fuzz_helper_function_xdp_t>(ebpf_general_helper_function_module_id.Guid);

    // Ensure that the ebpfcore runtime is stopped before the usersim runtime.
    atexit([]() { _fuzz_helper_function_xdp.reset(); });
    return 0;
}

FUZZ_EXPORT int __cdecl LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    ebpf_watchdog_timer_t watchdog_timer;

    return _fuzz_helper_function_xdp->fuzz(data, size);
}
