// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#if defined(NO_CRT)
typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
#define bool _Bool
#define false 0
#define true 1
#define UINT32_MAX ((uint32_t)0xFFFFFFFF)

#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#endif

#include "ebpf_structs.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define UBPF_STACK_SIZE 512

#define IMMEDIATE(X) (int32_t) X
#define OFFSET(X) (int16_t) X
#define POINTER(X) (uint64_t)(X)

#if !defined(htobe16)
#define htobe16(X) swap16(X)
#define htobe32(X) swap32(X)
#define htobe64(X) swap64(X)

#define htole16(X) (X)
#define htole32(X) (X)
#define htole64(X) (X)
#endif

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

    typedef struct _program_entry
    {
        uint64_t (*function)(void*);
        const char* section_name;
        const char* function_name;
        size_t bpf_instruction_count;
    } program_entry_t;

    typedef struct _metadata_table
    {
        void (*programs)(program_entry_t** programs, size_t* count);
        void (*maps)(map_entry_t** maps, size_t* count);
        void (*helpers)(helper_function_entry_t** helpers, size_t* count);
    } metadata_table_t;

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

    void
    division_by_zero(uint32_t address);

#ifdef __cplusplus
}
#endif
