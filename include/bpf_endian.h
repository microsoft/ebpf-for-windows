// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include <stdint.h>

inline __attribute__((always_inline)) uint16_t
bpf_ntohs(uint16_t us)
{
    return us << 8 | us >> 8;
}

#define bpf_htons(x) bpf_ntohs(x)

#ifndef ntohs
#define ntohs bpf_ntohs
#endif
#ifndef htons
#define htons bpf_htons
#endif

inline __attribute__((always_inline)) uint32_t
bpf_ntohl(uint32_t x)
{
    return (
        (((x) >> 24) & 0x000000FFL) | (((x) >> 8) & 0x0000FF00L) | (((x) << 8) & 0x00FF0000L) |
        (((x) << 24) & 0xFF000000L));
}

#define bpf_htonl(x) bpf_ntohl(x)

#ifndef ntohl
#define ntohl bpf_ntohl
#endif
#ifndef htonl
#define htonl bpf_htonl
#endif
