// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

struct tcphdr
{
    uint16_t source;
    uint16_t dest;
    uint32_t sequence_number;
    uint32_t ack_number;
    unsigned int data_offset : 4;
    unsigned int reserved : 3;
    unsigned int ns : 1;
    unsigned int cwr : 1;
    unsigned int ece : 1;
    unsigned int urg : 1;
    unsigned int ack : 1;
    unsigned int psh : 1;
    unsigned int rst : 1;
    unsigned int syn : 1;
    unsigned int fin : 1;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

// Verify the bit fields give the correct header size.
#ifndef C_ASSERT
#define C_ASSERT(e) typedef char __C_ASSERT__[(e) ? 1 : -1]
#endif
C_ASSERT(sizeof(struct tcphdr) == 20);
