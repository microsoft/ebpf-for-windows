// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "ebpf_structs.h"
#define UBPF_STACK_SIZE 512

#define IMMEDIATE(X) (int32_t) X
#define OFFSET(X) (int16_t) X
#define POINTER(X) (uint64_t)(X)

#define htobe16(X) swap16(X)
#define htobe32(X) swap32(X)
#define htobe64(X) swap64(X)

#define htole16(X) (X)
#define htole32(X) (X)
#define htole64(X) (X)

typedef struct _helper_function_entry
{
    uint64_t (*address)(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
    uint32_t helper_id;
    const char* name;
    bool tail_call;
} helper_function_entry_t;

typedef struct _map_entry
{
    void* address;
    ebpf_map_definition_in_file_t definition;
    const char* name;
} map_entry_t;

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
