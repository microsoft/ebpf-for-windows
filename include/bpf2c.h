// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include <stdint.h>
#define UBPF_STACK_SIZE 512

#define IMMEDIATE(X) (int32_t) X
#define OFFSET(X) (int16_t) X
#define POINTER(X) (uint64_t)(&X)

#define htobe16(X) swap16(X)
#define htobe32(X) swap32(X)
#define htobe64(X) swap64(X)

#define htole16(X) (X)
#define htole32(X) (X)
#define htole64(X) (X)

inline uint16_t
swap16(uint16_t value)
{
    return value << 8 | value >> 8;
}

inline uint32_t
swap32(uint32_t value)
{
    return swap16(value >> 16) | ((uint32_t)swap16(value & ((1 << 16) - 1))) << 16;
}

inline uint64_t
swap64(uint64_t value)
{
    return swap32(value >> 32) | ((uint64_t)swap32(value & ((1ull << 32ull) - 1))) << 32;
}
