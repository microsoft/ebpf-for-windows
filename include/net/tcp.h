// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

struct tcphdr
{
    uint16_t source;
    uint16_t dest;
    uint32_t sequence_number;
    uint32_t ack_number;
    uint16_t data_offset : 4;
    uint16_t reserved : 3;
    uint16_t ns : 1;
    uint16_t cwr : 1;
    uint16_t ece : 1;
    uint16_t urg : 1;
    uint16_t ack : 1;
    uint16_t psh : 1;
    uint16_t rst : 1;
    uint16_t syn : 1;
    uint16_t fin : 1;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

// Verify the bit fields give the correct header size.
#ifndef C_ASSERT
#define C_ASSERT(e) typedef char __C_ASSERT__[(e) ? 1 : -1]
#endif
C_ASSERT(sizeof(struct tcphdr) == 20);
