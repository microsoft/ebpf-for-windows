// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#if defined(BPF2C_DRIVER_CODE)
#include <guiddef.h>

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
GUID bpf2c_npi_id = {/* c847aac8-a6f2-4b53-aea3-f4a94b9a80cb */
                     0xc847aac8,
                     0xa6f2,
                     0x4b53,
                     {0xae, 0xa3, 0xf4, 0xa9, 0x4b, 0x9a, 0x80, 0xcb}};

#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#endif

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief eBPF Map Definition as it appears in the maps section of an ELF file.
     */
    typedef struct _ebpf_map_definition
    {
        uint32_t size;        ///< Size in bytes of the ebpf_map_definition_t structure.
        uint32_t type;        ///< Type of map.
        uint32_t key_size;    ///< Size in bytes of a map key.
        uint32_t value_size;  ///< Size in bytes of a map value.
        uint32_t max_entries; ///< Maximum number of entries allowed in the map.
    } ebpf_map_definition_t;

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
        ebpf_map_definition_t definition;
        const char* name;
    } map_entry_t;

    typedef struct _program_entry
    {
        uint64_t (*function)(void*);
        const char* name;
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
