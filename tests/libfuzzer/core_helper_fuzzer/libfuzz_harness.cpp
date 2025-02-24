// Copyright (c) eBPF for Windows contributors
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

typedef fuzz_helper_function<bpf_sock_addr_t> fuzz_helper_function__sock_addr_t;
std::unique_ptr<fuzz_helper_function__sock_addr_t> _fuzz_helper_function_sock_addr;

typedef fuzz_helper_function<bpf_sock_ops_t> fuzz_helper_function__sock_ops_t;
std::unique_ptr<fuzz_helper_function__sock_ops_t> _fuzz_helper_function_sock_ops;

int selected_program_type = 0;
FUZZ_EXPORT int __cdecl LLVMFuzzerInitialize(int *argc, char ***argv)
{
    for (int i = 1; i < *argc; i++) {
        if (strcmp((*argv)[i], "--helper") == 0 && i + 1 < *argc) {
            const char* helper_arg = (*argv)[i + 1];
            if (strcmp(helper_arg, "xdp") == 0) {
                selected_program_type = 1;
                _fuzz_helper_function_xdp =
                    std::make_unique<fuzz_helper_function_xdp_t>(ebpf_general_helper_function_module_id.Guid);
                atexit([]() { _fuzz_helper_function_xdp.reset(); });
            } else if (strcmp(helper_arg, "sockaddr") == 0) {
                selected_program_type = 2;
                _fuzz_helper_function_sock_addr =
                    std::make_unique<fuzz_helper_function__sock_addr_t>(ebpf_general_helper_function_module_id.Guid);
                atexit([]() { _fuzz_helper_function_sock_addr.reset(); });
            } else if (strcmp(helper_arg, "sockops") == 0) {
                selected_program_type = 3;
                _fuzz_helper_function_sock_ops =
                    std::make_unique<fuzz_helper_function__sock_ops_t>(ebpf_general_helper_function_module_id.Guid);
                atexit([]() { _fuzz_helper_function_sock_ops.reset(); });
            }
            break; // process only one occurrence
        }
    }
    return 0;
}

FUZZ_EXPORT int __cdecl LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    ebpf_watchdog_timer_t watchdog_timer;

    if (selected_program_type == 1) {
      return  _fuzz_helper_function_sock_ops->fuzz(data, size);
    } else if (selected_program_type == 2) {
      return _fuzz_helper_function_sock_addr->fuzz(data, size);
    } else if (selected_program_type == 3) {
      return _fuzz_helper_function_xdp->fuzz(data, size);
    }

    return 0;
}
