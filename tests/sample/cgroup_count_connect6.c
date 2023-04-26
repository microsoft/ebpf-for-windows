// Copyright (c) Microsoft Corporation
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
#include "net/ip.h"
#include "socket_tests_common.h"

SEC("maps")
struct bpf_map_def connect6_count_map = {
    .type = BPF_MAP_TYPE_HASH, .key_size = sizeof(uint16_t), .value_size = sizeof(uint64_t), .max_entries = 1};

const uint16_t remote_port = SOCKET_TEST_PORT;

SEC("cgroup/connect6")
int
count_tcp_connect6(bpf_sock_addr_t* ctx)
{
    int retval = 0;
    if (ctx->protocol != IPPROTO_TCP) {
        retval = BPF_SOCK_ADDR_VERDICT_PROCEED;
        goto exit;
    }

    // IP address, port #s in the context are in network byte order.
    if (ctx->user_port != ntohs(remote_port)) {
        retval = BPF_SOCK_ADDR_VERDICT_PROCEED;
        goto exit;
    }

    // Get the current counter value (create new entry if not present).
    uint16_t key = remote_port;
    uint64_t value = 0;
    uint64_t* count = bpf_map_lookup_elem(&connect6_count_map, &key);
    if (!count) {
        value = 1;
        bpf_map_update_elem(&connect6_count_map, &key, &value, 0);
    } else {
        *count += 1;
    }

    // Fail all connect attempts at our port.  This ensures that we are invoked for every connect attempt as we need
    // to show steady increments in the count in our 'connect attempts' map.  Our user mode counterpart monitors this
    // count to verify our continued invocation, especially after an extension restart.
    retval = BPF_SOCK_ADDR_VERDICT_REJECT;

exit:
    return retval;
}
