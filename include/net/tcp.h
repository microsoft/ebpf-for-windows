// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#pragma pack(push)
#pragma pack(1)
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
#pragma pack(pop)

#ifndef FIELD_OFFSET
#define FIELD_OFFSET(type, field) ((long)&(((type*)0)->field))
#endif

// check the offset of each field
static_assert(FIELD_OFFSET(struct tcphdr, source) == 0, "source offset mismatch");
static_assert(FIELD_OFFSET(struct tcphdr, dest) == 2, "dest offset mismatch");
static_assert(FIELD_OFFSET(struct tcphdr, seq) == 4, "seq offset mismatch");
static_assert(FIELD_OFFSET(struct tcphdr, ack_seq) == 8, "ack_seq offset mismatch");
// Skip bit fields
static_assert(FIELD_OFFSET(struct tcphdr, window) == 14, "window offset mismatch");
static_assert(FIELD_OFFSET(struct tcphdr, check) == 16, "check offset mismatch");
static_assert(FIELD_OFFSET(struct tcphdr, urg_ptr) == 18, "urg_ptr offset mismatch");
