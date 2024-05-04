// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

struct tcphdr
{
    uint16_t source;
    uint16_t dest;
    uint32_t seq;     // Sequence Number
    uint32_t ack_seq; // Acknowledgement Number

    // List bits in each byte from right (low) to left (high).
    uint16_t ns : 1;
    uint16_t reserved : 3;
    uint16_t doff : 4; // Data Offset

    uint16_t fin : 1;
    uint16_t syn : 1;
    uint16_t rst : 1;
    uint16_t psh : 1;
    uint16_t ack : 1;
    uint16_t urg : 1;
    uint16_t ece : 1;
    uint16_t cwr : 1;

    uint16_t window;  // Window Size
    uint16_t check;   // Checksum
    uint16_t urg_ptr; // Urgent Pointer
};

// Verify the bit fields give the correct header size.
#ifndef C_ASSERT
#define C_ASSERT(e) typedef char __C_ASSERT__[(e) ? 1 : -1]
#endif
C_ASSERT(sizeof(struct tcphdr) == 20);
