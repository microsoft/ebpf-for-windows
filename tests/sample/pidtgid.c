// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Whenever this sample program changes, bpf2c_tests will fail unless the
// expected files in tests\bpf2c_tests\expected are updated. The following
// script can be used to regenerate the expected files:
//     generate_expected_bpf2c_output.ps1
//
// Usage:
// .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>
// Example:
// .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\

#include "bpf_endian.h"
#include "bpf_helpers.h"

struct value
{
    uint32_t context_pid;
    uint32_t current_pid;
    uint32_t current_tid;
} value;

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, struct value);
    __uint(max_entries, 1);
} pidtgid_map SEC(".maps");

SEC("bind")
int
func(bind_md_t* ctx)
{
    const uint16_t ebpf_test_port = 0x3bbf; // Host byte order.
    struct sockaddr_in
    {
        uint16_t sin_family;
        uint16_t sin_port;
        uint32_t sin_addr;
        uint64_t sin_zero;
    };
    struct sockaddr_in* sockaddr = (struct sockaddr_in*)ctx->socket_address;

    if (ctx->socket_address_length >= sizeof(struct sockaddr_in) && sockaddr->sin_port == ebpf_test_port) {
        uint64_t pid_tgid = bpf_get_current_pid_tgid();
        struct value value = {
            .context_pid = ctx->process_id, .current_pid = pid_tgid >> 32, .current_tid = pid_tgid & 0xFFFFFFFF};
        uint32_t key = 0;
        bpf_map_update_elem(&pidtgid_map, &key, &value, 0);
    }

    return BIND_PERMIT;
}
