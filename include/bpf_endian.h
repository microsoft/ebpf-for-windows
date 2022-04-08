// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include <stdint.h>

inline uint16_t
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
