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

const uint16_t remote_port = SOCKET_TEST_PORT;
const uint16_t redirect_offset = 1000;

SEC("cgroup/connect4")
int
tcp_mt_connect4(bpf_sock_addr_t* ctx)
{
    int retval = 0;
    if (ctx->protocol != IPPROTO_TCP) {
        retval = BPF_SOCK_ADDR_VERDICT_PROCEED;
        goto exit;
    }

    // IP address, port #s in the context are in network byte order.
    if (ctx->user_port < htons(remote_port)) {

        // Not one of ours, allow.
        retval = BPF_SOCK_ADDR_VERDICT_PROCEED;
        goto exit;
    }

    // Randomly distibute our actions over the range of incoming port values.
    if (!(ntohs(ctx->user_port) % 3)) {
        retval = BPF_SOCK_ADDR_VERDICT_REJECT;
        goto exit;
    }

    if (!(ntohs(ctx->user_port) % 2)) {
        retval = BPF_SOCK_ADDR_VERDICT_PROCEED;
        goto exit;
    }

    // For all other port values, redirect the port to some arbitrary value.
    // REDIRECT uses the same return value as PROCEED except it updates the IP
    // address and/or port as required. (We only update the port here.)
    ctx->user_port += htons(redirect_offset);
    retval = BPF_SOCK_ADDR_VERDICT_PROCEED;

exit:
    return retval;
}
