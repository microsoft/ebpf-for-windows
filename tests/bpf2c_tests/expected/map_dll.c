// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from map.o

#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>

#include <stdio.h>

#include "bpf2c.h"

#define metadata_table map##_metadata_table
extern metadata_table_t metadata_table;

BOOL APIENTRY
DllMain(_In_ HMODULE hModule, unsigned int ul_reason_for_call, _In_ void* lpReserved)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

void
division_by_zero(uint32_t address)
{
    fprintf(stderr, "Divide by zero at address %d\n", address);
}

#define FIND_METADATA_ENTRTY(NAME, X) \
    if (std::string(NAME) == #X)      \
        return &X;

metadata_table_t*
get_metadata_table()
{
    return &metadata_table;
}

#include "bpf2c.h"

static void
_get_hash(_Outptr_result_buffer_maybenull_(*size) const uint8_t** hash, _Out_ size_t* size)
{
    *hash = NULL;
    *size = 0;
}
static map_entry_t _maps[] = {
    {NULL,
     {
         BPF_MAP_TYPE_STACK, // Type of map.
         0,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         10,                 // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         PIN_NONE,           // Pinning type for the map.
         0,                  // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "STACK_map"},
    {NULL,
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         4,                 // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         10,                // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         PIN_NONE,          // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "HASH_map"},
    {NULL,
     {
         BPF_MAP_TYPE_PERCPU_HASH, // Type of map.
         4,                        // Size in bytes of a map key.
         4,                        // Size in bytes of a map value.
         10,                       // Maximum number of entries allowed in the map.
         0,                        // Inner map index.
         PIN_NONE,                 // Pinning type for the map.
         0,                        // Identifier for a map template.
         0,                        // The id of the inner map template.
     },
     "PERCPU_HASH_map"},
    {NULL,
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         10,                 // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         PIN_NONE,           // Pinning type for the map.
         0,                  // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "ARRAY_map"},
    {NULL,
     {
         BPF_MAP_TYPE_PERCPU_ARRAY, // Type of map.
         4,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         10,                        // Maximum number of entries allowed in the map.
         0,                         // Inner map index.
         PIN_NONE,                  // Pinning type for the map.
         0,                         // Identifier for a map template.
         0,                         // The id of the inner map template.
     },
     "PERCPU_ARRAY_map"},
    {NULL,
     {
         BPF_MAP_TYPE_LRU_HASH, // Type of map.
         4,                     // Size in bytes of a map key.
         4,                     // Size in bytes of a map value.
         10,                    // Maximum number of entries allowed in the map.
         0,                     // Inner map index.
         PIN_NONE,              // Pinning type for the map.
         0,                     // Identifier for a map template.
         0,                     // The id of the inner map template.
     },
     "LRU_HASH_map"},
    {NULL,
     {
         BPF_MAP_TYPE_LRU_PERCPU_HASH, // Type of map.
         4,                            // Size in bytes of a map key.
         4,                            // Size in bytes of a map value.
         10,                           // Maximum number of entries allowed in the map.
         0,                            // Inner map index.
         PIN_NONE,                     // Pinning type for the map.
         0,                            // Identifier for a map template.
         0,                            // The id of the inner map template.
     },
     "LRU_PERCPU_HASH_map"},
    {NULL,
     {
         BPF_MAP_TYPE_QUEUE, // Type of map.
         0,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         10,                 // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         PIN_NONE,           // Pinning type for the map.
         0,                  // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "QUEUE_map"},
};

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 8;
}

static helper_function_entry_t test_maps_helpers[] = {
    {NULL, 2, "helper_id_2"},
    {NULL, 1, "helper_id_1"},
    {NULL, 12, "helper_id_12"},
    {NULL, 3, "helper_id_3"},
    {NULL, 13, "helper_id_13"},
    {NULL, 18, "helper_id_18"},
    {NULL, 14, "helper_id_14"},
    {NULL, 17, "helper_id_17"},
    {NULL, 16, "helper_id_16"},
    {NULL, 15, "helper_id_15"},
};

static GUID test_maps_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID test_maps_attach_type_guid = {0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t test_maps_maps[] = {
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
};

static uint64_t
test_maps(void* context)
{
#line 173 "sample/map.c"
    // Prologue
#line 173 "sample/map.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 173 "sample/map.c"
    register uint64_t r0 = 0;
#line 173 "sample/map.c"
    register uint64_t r1 = 0;
#line 173 "sample/map.c"
    register uint64_t r2 = 0;
#line 173 "sample/map.c"
    register uint64_t r3 = 0;
#line 173 "sample/map.c"
    register uint64_t r4 = 0;
#line 173 "sample/map.c"
    register uint64_t r5 = 0;
#line 173 "sample/map.c"
    register uint64_t r6 = 0;
#line 173 "sample/map.c"
    register uint64_t r7 = 0;
#line 173 "sample/map.c"
    register uint64_t r8 = 0;
#line 173 "sample/map.c"
    register uint64_t r9 = 0;
#line 173 "sample/map.c"
    register uint64_t r10 = 0;

#line 173 "sample/map.c"
    r1 = (uintptr_t)context;
#line 173 "sample/map.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r1 src=r0 offset=0 imm=0
#line 173 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r1 offset=-4 imm=0
#line 52 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=2 dst=r1 src=r0 offset=0 imm=1
#line 52 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=3 dst=r10 src=r1 offset=-68 imm=0
#line 53 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=4 dst=r2 src=r10 offset=0 imm=0
#line 53 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=5 dst=r2 src=r0 offset=0 imm=-4
#line 53 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=6 dst=r3 src=r10 offset=0 imm=0
#line 53 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r3 src=r0 offset=0 imm=-68
#line 53 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=8 dst=r1 src=r0 offset=0 imm=0
#line 56 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_MOV64_IMM pc=10 dst=r4 src=r0 offset=0 imm=0
#line 56 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=11 dst=r0 src=r0 offset=0 imm=2
#line 56 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 56 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 56 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 56 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=12 dst=r6 src=r0 offset=0 imm=0
#line 56 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=13 dst=r3 src=r6 offset=0 imm=0
#line 56 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=14 dst=r3 src=r0 offset=0 imm=32
#line 56 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=15 dst=r3 src=r0 offset=0 imm=32
#line 56 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=16 dst=r3 src=r0 offset=9 imm=-1
#line 57 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 57 "sample/map.c"
        goto label_1;
        // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1684369010
#line 57 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-40 imm=0
#line 58 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=20 dst=r1 src=r0 offset=0 imm=544040300
#line 58 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=22 dst=r10 src=r1 offset=-48 imm=0
#line 58 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=23 dst=r1 src=r0 offset=0 imm=1633972341
#line 58 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=25 dst=r0 src=r0 offset=45 imm=0
#line 58 "sample/map.c"
    goto label_3;
label_1:
    // EBPF_OP_MOV64_REG pc=26 dst=r2 src=r10 offset=0 imm=0
#line 58 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=27 dst=r2 src=r0 offset=0 imm=-4
#line 58 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=28 dst=r1 src=r0 offset=0 imm=0
#line 62 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=30 dst=r0 src=r0 offset=0 imm=1
#line 62 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 62 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 62 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 62 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=31 dst=r0 src=r0 offset=21 imm=0
#line 63 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 63 "sample/map.c"
        goto label_2;
        // EBPF_OP_MOV64_IMM pc=32 dst=r1 src=r0 offset=0 imm=76
#line 63 "sample/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=33 dst=r10 src=r1 offset=-32 imm=0
#line 64 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=34 dst=r1 src=r0 offset=0 imm=1684369010
#line 64 "sample/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=36 dst=r10 src=r1 offset=-40 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=37 dst=r1 src=r0 offset=0 imm=544040300
#line 64 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=39 dst=r10 src=r1 offset=-48 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=40 dst=r1 src=r0 offset=0 imm=1802465132
#line 64 "sample/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=42 dst=r10 src=r1 offset=-56 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=43 dst=r1 src=r0 offset=0 imm=1600548962
#line 64 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=45 dst=r10 src=r1 offset=-64 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=46 dst=r1 src=r10 offset=0 imm=0
#line 64 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=47 dst=r1 src=r0 offset=0 imm=-64
#line 64 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=48 dst=r2 src=r0 offset=0 imm=34
#line 64 "sample/map.c"
    r2 = IMMEDIATE(34);
    // EBPF_OP_CALL pc=49 dst=r0 src=r0 offset=0 imm=12
#line 64 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 64 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 64 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 64 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=50 dst=r6 src=r0 offset=0 imm=-1
#line 64 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=52 dst=r0 src=r0 offset=26 imm=0
#line 64 "sample/map.c"
    goto label_4;
label_2:
    // EBPF_OP_MOV64_REG pc=53 dst=r2 src=r10 offset=0 imm=0
#line 64 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=54 dst=r2 src=r0 offset=0 imm=-4
#line 64 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=55 dst=r1 src=r0 offset=0 imm=0
#line 68 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=57 dst=r0 src=r0 offset=0 imm=3
#line 68 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 68 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 68 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 68 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=58 dst=r6 src=r0 offset=0 imm=0
#line 68 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=59 dst=r3 src=r6 offset=0 imm=0
#line 68 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=60 dst=r3 src=r0 offset=0 imm=32
#line 68 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=61 dst=r3 src=r0 offset=0 imm=32
#line 68 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=62 dst=r3 src=r0 offset=41 imm=-1
#line 69 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 69 "sample/map.c"
        goto label_7;
        // EBPF_OP_LDDW pc=63 dst=r1 src=r0 offset=0 imm=1684369010
#line 69 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=65 dst=r10 src=r1 offset=-40 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=66 dst=r1 src=r0 offset=0 imm=544040300
#line 70 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=68 dst=r10 src=r1 offset=-48 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=69 dst=r1 src=r0 offset=0 imm=1701602660
#line 70 "sample/map.c"
    r1 = (uint64_t)7304668671210448228;
label_3:
    // EBPF_OP_STXDW pc=71 dst=r10 src=r1 offset=-56 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=72 dst=r1 src=r0 offset=0 imm=1600548962
#line 70 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=74 dst=r10 src=r1 offset=-64 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=75 dst=r1 src=r10 offset=0 imm=0
#line 70 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=76 dst=r1 src=r0 offset=0 imm=-64
#line 70 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=77 dst=r2 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=78 dst=r0 src=r0 offset=0 imm=13
#line 70 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 70 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 70 "sample/map.c"
        return 0;
label_4:
    // EBPF_OP_MOV64_IMM pc=79 dst=r1 src=r0 offset=0 imm=100
#line 70 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=80 dst=r10 src=r1 offset=-28 imm=0
#line 176 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=81 dst=r1 src=r0 offset=0 imm=622879845
#line 176 "sample/map.c"
    r1 = IMMEDIATE(622879845);
    // EBPF_OP_STXW pc=82 dst=r10 src=r1 offset=-32 imm=0
#line 176 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=83 dst=r1 src=r0 offset=0 imm=1701978184
#line 176 "sample/map.c"
    r1 = (uint64_t)7958552634295722056;
    // EBPF_OP_STXDW pc=85 dst=r10 src=r1 offset=-40 imm=0
#line 176 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=86 dst=r1 src=r0 offset=0 imm=1885433120
#line 176 "sample/map.c"
    r1 = (uint64_t)5999155482795797792;
    // EBPF_OP_STXDW pc=88 dst=r10 src=r1 offset=-48 imm=0
#line 176 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=89 dst=r1 src=r0 offset=0 imm=1279349317
#line 176 "sample/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=91 dst=r10 src=r1 offset=-56 imm=0
#line 176 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=92 dst=r1 src=r0 offset=0 imm=1953719636
#line 176 "sample/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=94 dst=r10 src=r1 offset=-64 imm=0
#line 176 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=95 dst=r3 src=r6 offset=0 imm=0
#line 176 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=96 dst=r3 src=r0 offset=0 imm=32
#line 176 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=97 dst=r3 src=r0 offset=0 imm=32
#line 176 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=98 dst=r1 src=r10 offset=0 imm=0
#line 176 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=99 dst=r1 src=r0 offset=0 imm=-64
#line 176 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=100 dst=r2 src=r0 offset=0 imm=38
#line 176 "sample/map.c"
    r2 = IMMEDIATE(38);
label_5:
    // EBPF_OP_CALL pc=101 dst=r0 src=r0 offset=0 imm=13
#line 176 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 176 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 176 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 176 "sample/map.c"
        return 0;
label_6:
    // EBPF_OP_MOV64_REG pc=102 dst=r0 src=r6 offset=0 imm=0
#line 189 "sample/map.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=103 dst=r0 src=r0 offset=0 imm=0
#line 189 "sample/map.c"
    return r0;
label_7:
    // EBPF_OP_MOV64_IMM pc=104 dst=r1 src=r0 offset=0 imm=0
#line 189 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=105 dst=r10 src=r1 offset=-4 imm=0
#line 52 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=106 dst=r1 src=r0 offset=0 imm=1
#line 52 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=107 dst=r10 src=r1 offset=-68 imm=0
#line 53 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=108 dst=r2 src=r10 offset=0 imm=0
#line 53 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=109 dst=r2 src=r0 offset=0 imm=-4
#line 53 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=110 dst=r3 src=r10 offset=0 imm=0
#line 53 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=111 dst=r3 src=r0 offset=0 imm=-68
#line 53 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=112 dst=r1 src=r0 offset=0 imm=0
#line 56 "sample/map.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_MOV64_IMM pc=114 dst=r4 src=r0 offset=0 imm=0
#line 56 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=115 dst=r0 src=r0 offset=0 imm=2
#line 56 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 56 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 56 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 56 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=116 dst=r6 src=r0 offset=0 imm=0
#line 56 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=117 dst=r3 src=r6 offset=0 imm=0
#line 56 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=118 dst=r3 src=r0 offset=0 imm=32
#line 56 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=119 dst=r3 src=r0 offset=0 imm=32
#line 56 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=120 dst=r3 src=r0 offset=9 imm=-1
#line 57 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 57 "sample/map.c"
        goto label_8;
        // EBPF_OP_LDDW pc=121 dst=r1 src=r0 offset=0 imm=1684369010
#line 57 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=123 dst=r10 src=r1 offset=-40 imm=0
#line 58 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=124 dst=r1 src=r0 offset=0 imm=544040300
#line 58 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=126 dst=r10 src=r1 offset=-48 imm=0
#line 58 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=127 dst=r1 src=r0 offset=0 imm=1633972341
#line 58 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=129 dst=r0 src=r0 offset=45 imm=0
#line 58 "sample/map.c"
    goto label_10;
label_8:
    // EBPF_OP_MOV64_REG pc=130 dst=r2 src=r10 offset=0 imm=0
#line 58 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=131 dst=r2 src=r0 offset=0 imm=-4
#line 58 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=132 dst=r1 src=r0 offset=0 imm=0
#line 62 "sample/map.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_CALL pc=134 dst=r0 src=r0 offset=0 imm=1
#line 62 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 62 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 62 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 62 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=135 dst=r0 src=r0 offset=21 imm=0
#line 63 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 63 "sample/map.c"
        goto label_9;
        // EBPF_OP_MOV64_IMM pc=136 dst=r1 src=r0 offset=0 imm=76
#line 63 "sample/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=137 dst=r10 src=r1 offset=-32 imm=0
#line 64 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=138 dst=r1 src=r0 offset=0 imm=1684369010
#line 64 "sample/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=140 dst=r10 src=r1 offset=-40 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=141 dst=r1 src=r0 offset=0 imm=544040300
#line 64 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=143 dst=r10 src=r1 offset=-48 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=144 dst=r1 src=r0 offset=0 imm=1802465132
#line 64 "sample/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=146 dst=r10 src=r1 offset=-56 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=147 dst=r1 src=r0 offset=0 imm=1600548962
#line 64 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=149 dst=r10 src=r1 offset=-64 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=150 dst=r1 src=r10 offset=0 imm=0
#line 64 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=151 dst=r1 src=r0 offset=0 imm=-64
#line 64 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=152 dst=r2 src=r0 offset=0 imm=34
#line 64 "sample/map.c"
    r2 = IMMEDIATE(34);
    // EBPF_OP_CALL pc=153 dst=r0 src=r0 offset=0 imm=12
#line 64 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 64 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 64 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 64 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=154 dst=r6 src=r0 offset=0 imm=-1
#line 64 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=156 dst=r0 src=r0 offset=26 imm=0
#line 64 "sample/map.c"
    goto label_11;
label_9:
    // EBPF_OP_MOV64_REG pc=157 dst=r2 src=r10 offset=0 imm=0
#line 64 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=158 dst=r2 src=r0 offset=0 imm=-4
#line 64 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=159 dst=r1 src=r0 offset=0 imm=0
#line 68 "sample/map.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_CALL pc=161 dst=r0 src=r0 offset=0 imm=3
#line 68 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 68 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 68 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 68 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=162 dst=r6 src=r0 offset=0 imm=0
#line 68 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=163 dst=r3 src=r6 offset=0 imm=0
#line 68 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=164 dst=r3 src=r0 offset=0 imm=32
#line 68 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=165 dst=r3 src=r0 offset=0 imm=32
#line 68 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=166 dst=r3 src=r0 offset=42 imm=-1
#line 69 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 69 "sample/map.c"
        goto label_12;
        // EBPF_OP_LDDW pc=167 dst=r1 src=r0 offset=0 imm=1684369010
#line 69 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=169 dst=r10 src=r1 offset=-40 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=170 dst=r1 src=r0 offset=0 imm=544040300
#line 70 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=172 dst=r10 src=r1 offset=-48 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=173 dst=r1 src=r0 offset=0 imm=1701602660
#line 70 "sample/map.c"
    r1 = (uint64_t)7304668671210448228;
label_10:
    // EBPF_OP_STXDW pc=175 dst=r10 src=r1 offset=-56 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=176 dst=r1 src=r0 offset=0 imm=1600548962
#line 70 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=178 dst=r10 src=r1 offset=-64 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=179 dst=r1 src=r10 offset=0 imm=0
#line 70 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=180 dst=r1 src=r0 offset=0 imm=-64
#line 70 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=181 dst=r2 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=182 dst=r0 src=r0 offset=0 imm=13
#line 70 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 70 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 70 "sample/map.c"
        return 0;
label_11:
    // EBPF_OP_MOV64_IMM pc=183 dst=r1 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=184 dst=r10 src=r1 offset=-20 imm=0
#line 177 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=185 dst=r1 src=r0 offset=0 imm=1680154724
#line 177 "sample/map.c"
    r1 = IMMEDIATE(1680154724);
    // EBPF_OP_STXW pc=186 dst=r10 src=r1 offset=-24 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=187 dst=r1 src=r0 offset=0 imm=1952805408
#line 177 "sample/map.c"
    r1 = (uint64_t)7308905094058439200;
    // EBPF_OP_STXDW pc=189 dst=r10 src=r1 offset=-32 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=190 dst=r1 src=r0 offset=0 imm=1599426627
#line 177 "sample/map.c"
    r1 = (uint64_t)5211580972890673219;
    // EBPF_OP_STXDW pc=192 dst=r10 src=r1 offset=-40 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=193 dst=r1 src=r0 offset=0 imm=1885433120
#line 177 "sample/map.c"
    r1 = (uint64_t)5928232584757734688;
    // EBPF_OP_STXDW pc=195 dst=r10 src=r1 offset=-48 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=196 dst=r1 src=r0 offset=0 imm=1279349317
#line 177 "sample/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=198 dst=r10 src=r1 offset=-56 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=199 dst=r1 src=r0 offset=0 imm=1953719636
#line 177 "sample/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=201 dst=r10 src=r1 offset=-64 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=202 dst=r3 src=r6 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=203 dst=r3 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=204 dst=r3 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=205 dst=r1 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=206 dst=r1 src=r0 offset=0 imm=-64
#line 177 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=207 dst=r2 src=r0 offset=0 imm=45
#line 177 "sample/map.c"
    r2 = IMMEDIATE(45);
    // EBPF_OP_JA pc=208 dst=r0 src=r0 offset=-108 imm=0
#line 177 "sample/map.c"
    goto label_5;
label_12:
    // EBPF_OP_MOV64_IMM pc=209 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=210 dst=r10 src=r1 offset=-4 imm=0
#line 52 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=211 dst=r1 src=r0 offset=0 imm=1
#line 52 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=212 dst=r10 src=r1 offset=-68 imm=0
#line 53 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=213 dst=r2 src=r10 offset=0 imm=0
#line 53 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=214 dst=r2 src=r0 offset=0 imm=-4
#line 53 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=215 dst=r3 src=r10 offset=0 imm=0
#line 53 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=216 dst=r3 src=r0 offset=0 imm=-68
#line 53 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=217 dst=r1 src=r0 offset=0 imm=0
#line 56 "sample/map.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_MOV64_IMM pc=219 dst=r4 src=r0 offset=0 imm=0
#line 56 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=220 dst=r0 src=r0 offset=0 imm=2
#line 56 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 56 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 56 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 56 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=221 dst=r6 src=r0 offset=0 imm=0
#line 56 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=222 dst=r3 src=r6 offset=0 imm=0
#line 56 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=223 dst=r3 src=r0 offset=0 imm=32
#line 56 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=224 dst=r3 src=r0 offset=0 imm=32
#line 56 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=225 dst=r3 src=r0 offset=9 imm=-1
#line 57 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 57 "sample/map.c"
        goto label_13;
        // EBPF_OP_LDDW pc=226 dst=r1 src=r0 offset=0 imm=1684369010
#line 57 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=228 dst=r10 src=r1 offset=-40 imm=0
#line 58 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=229 dst=r1 src=r0 offset=0 imm=544040300
#line 58 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=231 dst=r10 src=r1 offset=-48 imm=0
#line 58 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=232 dst=r1 src=r0 offset=0 imm=1633972341
#line 58 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=234 dst=r0 src=r0 offset=45 imm=0
#line 58 "sample/map.c"
    goto label_15;
label_13:
    // EBPF_OP_MOV64_REG pc=235 dst=r2 src=r10 offset=0 imm=0
#line 58 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=236 dst=r2 src=r0 offset=0 imm=-4
#line 58 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=237 dst=r1 src=r0 offset=0 imm=0
#line 62 "sample/map.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_CALL pc=239 dst=r0 src=r0 offset=0 imm=1
#line 62 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 62 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 62 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 62 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=240 dst=r0 src=r0 offset=21 imm=0
#line 63 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 63 "sample/map.c"
        goto label_14;
        // EBPF_OP_MOV64_IMM pc=241 dst=r1 src=r0 offset=0 imm=76
#line 63 "sample/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=242 dst=r10 src=r1 offset=-32 imm=0
#line 64 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=243 dst=r1 src=r0 offset=0 imm=1684369010
#line 64 "sample/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=245 dst=r10 src=r1 offset=-40 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=246 dst=r1 src=r0 offset=0 imm=544040300
#line 64 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=248 dst=r10 src=r1 offset=-48 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=249 dst=r1 src=r0 offset=0 imm=1802465132
#line 64 "sample/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=251 dst=r10 src=r1 offset=-56 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=252 dst=r1 src=r0 offset=0 imm=1600548962
#line 64 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=254 dst=r10 src=r1 offset=-64 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=255 dst=r1 src=r10 offset=0 imm=0
#line 64 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=256 dst=r1 src=r0 offset=0 imm=-64
#line 64 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=257 dst=r2 src=r0 offset=0 imm=34
#line 64 "sample/map.c"
    r2 = IMMEDIATE(34);
    // EBPF_OP_CALL pc=258 dst=r0 src=r0 offset=0 imm=12
#line 64 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 64 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 64 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 64 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=259 dst=r6 src=r0 offset=0 imm=-1
#line 64 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=261 dst=r0 src=r0 offset=26 imm=0
#line 64 "sample/map.c"
    goto label_16;
label_14:
    // EBPF_OP_MOV64_REG pc=262 dst=r2 src=r10 offset=0 imm=0
#line 64 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=263 dst=r2 src=r0 offset=0 imm=-4
#line 64 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=264 dst=r1 src=r0 offset=0 imm=0
#line 68 "sample/map.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_CALL pc=266 dst=r0 src=r0 offset=0 imm=3
#line 68 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 68 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 68 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 68 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=267 dst=r6 src=r0 offset=0 imm=0
#line 68 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=268 dst=r3 src=r6 offset=0 imm=0
#line 68 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=269 dst=r3 src=r0 offset=0 imm=32
#line 68 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=270 dst=r3 src=r0 offset=0 imm=32
#line 68 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=271 dst=r3 src=r0 offset=41 imm=-1
#line 69 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 69 "sample/map.c"
        goto label_17;
        // EBPF_OP_LDDW pc=272 dst=r1 src=r0 offset=0 imm=1684369010
#line 69 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=274 dst=r10 src=r1 offset=-40 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=275 dst=r1 src=r0 offset=0 imm=544040300
#line 70 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=277 dst=r10 src=r1 offset=-48 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=278 dst=r1 src=r0 offset=0 imm=1701602660
#line 70 "sample/map.c"
    r1 = (uint64_t)7304668671210448228;
label_15:
    // EBPF_OP_STXDW pc=280 dst=r10 src=r1 offset=-56 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=281 dst=r1 src=r0 offset=0 imm=1600548962
#line 70 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=283 dst=r10 src=r1 offset=-64 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=284 dst=r1 src=r10 offset=0 imm=0
#line 70 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=285 dst=r1 src=r0 offset=0 imm=-64
#line 70 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=286 dst=r2 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=287 dst=r0 src=r0 offset=0 imm=13
#line 70 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 70 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 70 "sample/map.c"
        return 0;
label_16:
    // EBPF_OP_MOV64_IMM pc=288 dst=r1 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=289 dst=r10 src=r1 offset=-26 imm=0
#line 178 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-26)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=290 dst=r1 src=r0 offset=0 imm=25637
#line 178 "sample/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=291 dst=r10 src=r1 offset=-28 imm=0
#line 178 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=292 dst=r1 src=r0 offset=0 imm=543450478
#line 178 "sample/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=293 dst=r10 src=r1 offset=-32 imm=0
#line 178 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=294 dst=r1 src=r0 offset=0 imm=1914722625
#line 178 "sample/map.c"
    r1 = (uint64_t)8247626271654172993;
    // EBPF_OP_STXDW pc=296 dst=r10 src=r1 offset=-40 imm=0
#line 178 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=297 dst=r1 src=r0 offset=0 imm=1885433120
#line 178 "sample/map.c"
    r1 = (uint64_t)5931875266780556576;
    // EBPF_OP_STXDW pc=299 dst=r10 src=r1 offset=-48 imm=0
#line 178 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=300 dst=r1 src=r0 offset=0 imm=1279349317
#line 178 "sample/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=302 dst=r10 src=r1 offset=-56 imm=0
#line 178 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=303 dst=r1 src=r0 offset=0 imm=1953719636
#line 178 "sample/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=305 dst=r10 src=r1 offset=-64 imm=0
#line 178 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=306 dst=r3 src=r6 offset=0 imm=0
#line 178 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=307 dst=r3 src=r0 offset=0 imm=32
#line 178 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=308 dst=r3 src=r0 offset=0 imm=32
#line 178 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=309 dst=r1 src=r10 offset=0 imm=0
#line 178 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=310 dst=r1 src=r0 offset=0 imm=-64
#line 178 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=311 dst=r2 src=r0 offset=0 imm=39
#line 178 "sample/map.c"
    r2 = IMMEDIATE(39);
    // EBPF_OP_JA pc=312 dst=r0 src=r0 offset=-212 imm=0
#line 178 "sample/map.c"
    goto label_5;
label_17:
    // EBPF_OP_MOV64_IMM pc=313 dst=r1 src=r0 offset=0 imm=0
#line 178 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=314 dst=r10 src=r1 offset=-4 imm=0
#line 52 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=315 dst=r1 src=r0 offset=0 imm=1
#line 52 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=316 dst=r10 src=r1 offset=-68 imm=0
#line 53 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=317 dst=r2 src=r10 offset=0 imm=0
#line 53 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=318 dst=r2 src=r0 offset=0 imm=-4
#line 53 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=319 dst=r3 src=r10 offset=0 imm=0
#line 53 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=320 dst=r3 src=r0 offset=0 imm=-68
#line 53 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=321 dst=r1 src=r0 offset=0 imm=0
#line 56 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=323 dst=r4 src=r0 offset=0 imm=0
#line 56 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=324 dst=r0 src=r0 offset=0 imm=2
#line 56 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 56 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 56 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 56 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=325 dst=r6 src=r0 offset=0 imm=0
#line 56 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=326 dst=r3 src=r6 offset=0 imm=0
#line 56 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=327 dst=r3 src=r0 offset=0 imm=32
#line 56 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=328 dst=r3 src=r0 offset=0 imm=32
#line 56 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=329 dst=r3 src=r0 offset=9 imm=-1
#line 57 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 57 "sample/map.c"
        goto label_18;
        // EBPF_OP_LDDW pc=330 dst=r1 src=r0 offset=0 imm=1684369010
#line 57 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=332 dst=r10 src=r1 offset=-40 imm=0
#line 58 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=333 dst=r1 src=r0 offset=0 imm=544040300
#line 58 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=335 dst=r10 src=r1 offset=-48 imm=0
#line 58 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=336 dst=r1 src=r0 offset=0 imm=1633972341
#line 58 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=338 dst=r0 src=r0 offset=45 imm=0
#line 58 "sample/map.c"
    goto label_20;
label_18:
    // EBPF_OP_MOV64_REG pc=339 dst=r2 src=r10 offset=0 imm=0
#line 58 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=340 dst=r2 src=r0 offset=0 imm=-4
#line 58 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=341 dst=r1 src=r0 offset=0 imm=0
#line 62 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_CALL pc=343 dst=r0 src=r0 offset=0 imm=1
#line 62 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 62 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 62 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 62 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=344 dst=r0 src=r0 offset=21 imm=0
#line 63 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 63 "sample/map.c"
        goto label_19;
        // EBPF_OP_MOV64_IMM pc=345 dst=r1 src=r0 offset=0 imm=76
#line 63 "sample/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=346 dst=r10 src=r1 offset=-32 imm=0
#line 64 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=347 dst=r1 src=r0 offset=0 imm=1684369010
#line 64 "sample/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=349 dst=r10 src=r1 offset=-40 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=350 dst=r1 src=r0 offset=0 imm=544040300
#line 64 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=352 dst=r10 src=r1 offset=-48 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=353 dst=r1 src=r0 offset=0 imm=1802465132
#line 64 "sample/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=355 dst=r10 src=r1 offset=-56 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=356 dst=r1 src=r0 offset=0 imm=1600548962
#line 64 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=358 dst=r10 src=r1 offset=-64 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=359 dst=r1 src=r10 offset=0 imm=0
#line 64 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=360 dst=r1 src=r0 offset=0 imm=-64
#line 64 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=361 dst=r2 src=r0 offset=0 imm=34
#line 64 "sample/map.c"
    r2 = IMMEDIATE(34);
    // EBPF_OP_CALL pc=362 dst=r0 src=r0 offset=0 imm=12
#line 64 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 64 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 64 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 64 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=363 dst=r6 src=r0 offset=0 imm=-1
#line 64 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=365 dst=r0 src=r0 offset=26 imm=0
#line 64 "sample/map.c"
    goto label_21;
label_19:
    // EBPF_OP_MOV64_REG pc=366 dst=r2 src=r10 offset=0 imm=0
#line 64 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=367 dst=r2 src=r0 offset=0 imm=-4
#line 64 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=368 dst=r1 src=r0 offset=0 imm=0
#line 68 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_CALL pc=370 dst=r0 src=r0 offset=0 imm=3
#line 68 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 68 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 68 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 68 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=371 dst=r6 src=r0 offset=0 imm=0
#line 68 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=372 dst=r3 src=r6 offset=0 imm=0
#line 68 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=373 dst=r3 src=r0 offset=0 imm=32
#line 68 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=374 dst=r3 src=r0 offset=0 imm=32
#line 68 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=375 dst=r3 src=r0 offset=42 imm=-1
#line 69 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 69 "sample/map.c"
        goto label_22;
        // EBPF_OP_LDDW pc=376 dst=r1 src=r0 offset=0 imm=1684369010
#line 69 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=378 dst=r10 src=r1 offset=-40 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=379 dst=r1 src=r0 offset=0 imm=544040300
#line 70 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=381 dst=r10 src=r1 offset=-48 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=382 dst=r1 src=r0 offset=0 imm=1701602660
#line 70 "sample/map.c"
    r1 = (uint64_t)7304668671210448228;
label_20:
    // EBPF_OP_STXDW pc=384 dst=r10 src=r1 offset=-56 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=385 dst=r1 src=r0 offset=0 imm=1600548962
#line 70 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=387 dst=r10 src=r1 offset=-64 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=388 dst=r1 src=r10 offset=0 imm=0
#line 70 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=389 dst=r1 src=r0 offset=0 imm=-64
#line 70 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=390 dst=r2 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=391 dst=r0 src=r0 offset=0 imm=13
#line 70 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 70 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 70 "sample/map.c"
        return 0;
label_21:
    // EBPF_OP_MOV64_IMM pc=392 dst=r1 src=r0 offset=0 imm=100
#line 70 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=393 dst=r10 src=r1 offset=-20 imm=0
#line 179 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=394 dst=r1 src=r0 offset=0 imm=622879845
#line 179 "sample/map.c"
    r1 = IMMEDIATE(622879845);
    // EBPF_OP_STXW pc=395 dst=r10 src=r1 offset=-24 imm=0
#line 179 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=396 dst=r1 src=r0 offset=0 imm=1701978201
#line 179 "sample/map.c"
    r1 = (uint64_t)7958552634295722073;
    // EBPF_OP_STXDW pc=398 dst=r10 src=r1 offset=-32 imm=0
#line 179 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=399 dst=r1 src=r0 offset=0 imm=1599426627
#line 179 "sample/map.c"
    r1 = (uint64_t)4706915001281368131;
    // EBPF_OP_STXDW pc=401 dst=r10 src=r1 offset=-40 imm=0
#line 179 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=402 dst=r1 src=r0 offset=0 imm=1885433120
#line 179 "sample/map.c"
    r1 = (uint64_t)5928232584757734688;
    // EBPF_OP_STXDW pc=404 dst=r10 src=r1 offset=-48 imm=0
#line 179 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=405 dst=r1 src=r0 offset=0 imm=1279349317
#line 179 "sample/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=407 dst=r10 src=r1 offset=-56 imm=0
#line 179 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=408 dst=r1 src=r0 offset=0 imm=1953719636
#line 179 "sample/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=410 dst=r10 src=r1 offset=-64 imm=0
#line 179 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=411 dst=r3 src=r6 offset=0 imm=0
#line 179 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=412 dst=r3 src=r0 offset=0 imm=32
#line 179 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=413 dst=r3 src=r0 offset=0 imm=32
#line 179 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=414 dst=r1 src=r10 offset=0 imm=0
#line 179 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=415 dst=r1 src=r0 offset=0 imm=-64
#line 179 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=416 dst=r2 src=r0 offset=0 imm=46
#line 179 "sample/map.c"
    r2 = IMMEDIATE(46);
    // EBPF_OP_JA pc=417 dst=r0 src=r0 offset=-317 imm=0
#line 179 "sample/map.c"
    goto label_5;
label_22:
    // EBPF_OP_MOV64_IMM pc=418 dst=r1 src=r0 offset=0 imm=0
#line 179 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=419 dst=r10 src=r1 offset=-4 imm=0
#line 52 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=420 dst=r1 src=r0 offset=0 imm=1
#line 52 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=421 dst=r10 src=r1 offset=-68 imm=0
#line 53 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=422 dst=r2 src=r10 offset=0 imm=0
#line 53 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=423 dst=r2 src=r0 offset=0 imm=-4
#line 53 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=424 dst=r3 src=r10 offset=0 imm=0
#line 53 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=425 dst=r3 src=r0 offset=0 imm=-68
#line 53 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=426 dst=r1 src=r0 offset=0 imm=0
#line 56 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=428 dst=r4 src=r0 offset=0 imm=0
#line 56 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=429 dst=r0 src=r0 offset=0 imm=2
#line 56 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 56 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 56 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 56 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=430 dst=r6 src=r0 offset=0 imm=0
#line 56 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=431 dst=r3 src=r6 offset=0 imm=0
#line 56 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=432 dst=r3 src=r0 offset=0 imm=32
#line 56 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=433 dst=r3 src=r0 offset=0 imm=32
#line 56 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=434 dst=r3 src=r0 offset=9 imm=-1
#line 57 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 57 "sample/map.c"
        goto label_23;
        // EBPF_OP_LDDW pc=435 dst=r1 src=r0 offset=0 imm=1684369010
#line 57 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=437 dst=r10 src=r1 offset=-40 imm=0
#line 58 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=438 dst=r1 src=r0 offset=0 imm=544040300
#line 58 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=440 dst=r10 src=r1 offset=-48 imm=0
#line 58 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=441 dst=r1 src=r0 offset=0 imm=1633972341
#line 58 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=443 dst=r0 src=r0 offset=45 imm=0
#line 58 "sample/map.c"
    goto label_25;
label_23:
    // EBPF_OP_MOV64_REG pc=444 dst=r2 src=r10 offset=0 imm=0
#line 58 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=445 dst=r2 src=r0 offset=0 imm=-4
#line 58 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=446 dst=r1 src=r0 offset=0 imm=0
#line 62 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_CALL pc=448 dst=r0 src=r0 offset=0 imm=1
#line 62 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 62 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 62 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 62 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=449 dst=r0 src=r0 offset=21 imm=0
#line 63 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 63 "sample/map.c"
        goto label_24;
        // EBPF_OP_MOV64_IMM pc=450 dst=r1 src=r0 offset=0 imm=76
#line 63 "sample/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=451 dst=r10 src=r1 offset=-32 imm=0
#line 64 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=452 dst=r1 src=r0 offset=0 imm=1684369010
#line 64 "sample/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=454 dst=r10 src=r1 offset=-40 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=455 dst=r1 src=r0 offset=0 imm=544040300
#line 64 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=457 dst=r10 src=r1 offset=-48 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=458 dst=r1 src=r0 offset=0 imm=1802465132
#line 64 "sample/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=460 dst=r10 src=r1 offset=-56 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=461 dst=r1 src=r0 offset=0 imm=1600548962
#line 64 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=463 dst=r10 src=r1 offset=-64 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=464 dst=r1 src=r10 offset=0 imm=0
#line 64 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=465 dst=r1 src=r0 offset=0 imm=-64
#line 64 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=466 dst=r2 src=r0 offset=0 imm=34
#line 64 "sample/map.c"
    r2 = IMMEDIATE(34);
    // EBPF_OP_CALL pc=467 dst=r0 src=r0 offset=0 imm=12
#line 64 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 64 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 64 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 64 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=468 dst=r6 src=r0 offset=0 imm=-1
#line 64 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=470 dst=r0 src=r0 offset=26 imm=0
#line 64 "sample/map.c"
    goto label_26;
label_24:
    // EBPF_OP_MOV64_REG pc=471 dst=r2 src=r10 offset=0 imm=0
#line 64 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=472 dst=r2 src=r0 offset=0 imm=-4
#line 64 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=473 dst=r1 src=r0 offset=0 imm=0
#line 68 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_CALL pc=475 dst=r0 src=r0 offset=0 imm=3
#line 68 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 68 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 68 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 68 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=476 dst=r6 src=r0 offset=0 imm=0
#line 68 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=477 dst=r3 src=r6 offset=0 imm=0
#line 68 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=478 dst=r3 src=r0 offset=0 imm=32
#line 68 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=479 dst=r3 src=r0 offset=0 imm=32
#line 68 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=480 dst=r3 src=r0 offset=40 imm=-1
#line 69 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 69 "sample/map.c"
        goto label_27;
        // EBPF_OP_LDDW pc=481 dst=r1 src=r0 offset=0 imm=1684369010
#line 69 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=483 dst=r10 src=r1 offset=-40 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=484 dst=r1 src=r0 offset=0 imm=544040300
#line 70 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=486 dst=r10 src=r1 offset=-48 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=487 dst=r1 src=r0 offset=0 imm=1701602660
#line 70 "sample/map.c"
    r1 = (uint64_t)7304668671210448228;
label_25:
    // EBPF_OP_STXDW pc=489 dst=r10 src=r1 offset=-56 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=490 dst=r1 src=r0 offset=0 imm=1600548962
#line 70 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=492 dst=r10 src=r1 offset=-64 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=493 dst=r1 src=r10 offset=0 imm=0
#line 70 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=494 dst=r1 src=r0 offset=0 imm=-64
#line 70 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=495 dst=r2 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=496 dst=r0 src=r0 offset=0 imm=13
#line 70 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 70 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 70 "sample/map.c"
        return 0;
label_26:
    // EBPF_OP_MOV64_IMM pc=497 dst=r1 src=r0 offset=0 imm=100
#line 70 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=498 dst=r10 src=r1 offset=-24 imm=0
#line 180 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=499 dst=r1 src=r0 offset=0 imm=1852994932
#line 180 "sample/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=501 dst=r10 src=r1 offset=-32 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=502 dst=r1 src=r0 offset=0 imm=1396787295
#line 180 "sample/map.c"
    r1 = (uint64_t)7309940640182257759;
    // EBPF_OP_STXDW pc=504 dst=r10 src=r1 offset=-40 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=505 dst=r1 src=r0 offset=0 imm=1885433120
#line 180 "sample/map.c"
    r1 = (uint64_t)6148060143522245920;
    // EBPF_OP_STXDW pc=507 dst=r10 src=r1 offset=-48 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=508 dst=r1 src=r0 offset=0 imm=1279349317
#line 180 "sample/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=510 dst=r10 src=r1 offset=-56 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=511 dst=r1 src=r0 offset=0 imm=1953719636
#line 180 "sample/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=513 dst=r10 src=r1 offset=-64 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=514 dst=r3 src=r6 offset=0 imm=0
#line 180 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=515 dst=r3 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=516 dst=r3 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=517 dst=r1 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=518 dst=r1 src=r0 offset=0 imm=-64
#line 180 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=519 dst=r2 src=r0 offset=0 imm=42
#line 180 "sample/map.c"
    r2 = IMMEDIATE(42);
    // EBPF_OP_JA pc=520 dst=r0 src=r0 offset=-420 imm=0
#line 180 "sample/map.c"
    goto label_5;
label_27:
    // EBPF_OP_MOV64_IMM pc=521 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=522 dst=r10 src=r1 offset=-4 imm=0
#line 52 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=523 dst=r1 src=r0 offset=0 imm=1
#line 52 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=524 dst=r10 src=r1 offset=-68 imm=0
#line 53 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=525 dst=r2 src=r10 offset=0 imm=0
#line 53 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=526 dst=r2 src=r0 offset=0 imm=-4
#line 53 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=527 dst=r3 src=r10 offset=0 imm=0
#line 53 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=528 dst=r3 src=r0 offset=0 imm=-68
#line 53 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=529 dst=r1 src=r0 offset=0 imm=0
#line 56 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=531 dst=r4 src=r0 offset=0 imm=0
#line 56 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=532 dst=r0 src=r0 offset=0 imm=2
#line 56 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 56 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 56 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 56 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=533 dst=r6 src=r0 offset=0 imm=0
#line 56 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=534 dst=r3 src=r6 offset=0 imm=0
#line 56 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=535 dst=r3 src=r0 offset=0 imm=32
#line 56 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=536 dst=r3 src=r0 offset=0 imm=32
#line 56 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=537 dst=r3 src=r0 offset=9 imm=-1
#line 57 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 57 "sample/map.c"
        goto label_28;
        // EBPF_OP_LDDW pc=538 dst=r1 src=r0 offset=0 imm=1684369010
#line 57 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=540 dst=r10 src=r1 offset=-40 imm=0
#line 58 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=541 dst=r1 src=r0 offset=0 imm=544040300
#line 58 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=543 dst=r10 src=r1 offset=-48 imm=0
#line 58 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=544 dst=r1 src=r0 offset=0 imm=1633972341
#line 58 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=546 dst=r0 src=r0 offset=45 imm=0
#line 58 "sample/map.c"
    goto label_30;
label_28:
    // EBPF_OP_MOV64_REG pc=547 dst=r2 src=r10 offset=0 imm=0
#line 58 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=548 dst=r2 src=r0 offset=0 imm=-4
#line 58 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=549 dst=r1 src=r0 offset=0 imm=0
#line 62 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=551 dst=r0 src=r0 offset=0 imm=1
#line 62 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 62 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 62 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 62 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=552 dst=r0 src=r0 offset=21 imm=0
#line 63 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 63 "sample/map.c"
        goto label_29;
        // EBPF_OP_MOV64_IMM pc=553 dst=r1 src=r0 offset=0 imm=76
#line 63 "sample/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=554 dst=r10 src=r1 offset=-32 imm=0
#line 64 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=555 dst=r1 src=r0 offset=0 imm=1684369010
#line 64 "sample/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=557 dst=r10 src=r1 offset=-40 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=558 dst=r1 src=r0 offset=0 imm=544040300
#line 64 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=560 dst=r10 src=r1 offset=-48 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=561 dst=r1 src=r0 offset=0 imm=1802465132
#line 64 "sample/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=563 dst=r10 src=r1 offset=-56 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=564 dst=r1 src=r0 offset=0 imm=1600548962
#line 64 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=566 dst=r10 src=r1 offset=-64 imm=0
#line 64 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=567 dst=r1 src=r10 offset=0 imm=0
#line 64 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=568 dst=r1 src=r0 offset=0 imm=-64
#line 64 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=569 dst=r2 src=r0 offset=0 imm=34
#line 64 "sample/map.c"
    r2 = IMMEDIATE(34);
    // EBPF_OP_CALL pc=570 dst=r0 src=r0 offset=0 imm=12
#line 64 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 64 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 64 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 64 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=571 dst=r6 src=r0 offset=0 imm=-1
#line 64 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=573 dst=r0 src=r0 offset=26 imm=0
#line 64 "sample/map.c"
    goto label_31;
label_29:
    // EBPF_OP_MOV64_REG pc=574 dst=r2 src=r10 offset=0 imm=0
#line 64 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=575 dst=r2 src=r0 offset=0 imm=-4
#line 64 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=576 dst=r1 src=r0 offset=0 imm=0
#line 68 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=578 dst=r0 src=r0 offset=0 imm=3
#line 68 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 68 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 68 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 68 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=579 dst=r6 src=r0 offset=0 imm=0
#line 68 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=580 dst=r3 src=r6 offset=0 imm=0
#line 68 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=581 dst=r3 src=r0 offset=0 imm=32
#line 68 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=582 dst=r3 src=r0 offset=0 imm=32
#line 68 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=583 dst=r3 src=r0 offset=43 imm=-1
#line 69 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 69 "sample/map.c"
        goto label_32;
        // EBPF_OP_LDDW pc=584 dst=r1 src=r0 offset=0 imm=1684369010
#line 69 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=586 dst=r10 src=r1 offset=-40 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=587 dst=r1 src=r0 offset=0 imm=544040300
#line 70 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=589 dst=r10 src=r1 offset=-48 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=590 dst=r1 src=r0 offset=0 imm=1701602660
#line 70 "sample/map.c"
    r1 = (uint64_t)7304668671210448228;
label_30:
    // EBPF_OP_STXDW pc=592 dst=r10 src=r1 offset=-56 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=593 dst=r1 src=r0 offset=0 imm=1600548962
#line 70 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=595 dst=r10 src=r1 offset=-64 imm=0
#line 70 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=596 dst=r1 src=r10 offset=0 imm=0
#line 70 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=597 dst=r1 src=r0 offset=0 imm=-64
#line 70 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=598 dst=r2 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=599 dst=r0 src=r0 offset=0 imm=13
#line 70 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 70 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 70 "sample/map.c"
        return 0;
label_31:
    // EBPF_OP_MOV64_IMM pc=600 dst=r1 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=601 dst=r10 src=r1 offset=-16 imm=0
#line 181 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=602 dst=r1 src=r0 offset=0 imm=1701737077
#line 181 "sample/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=604 dst=r10 src=r1 offset=-24 imm=0
#line 181 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=605 dst=r1 src=r0 offset=0 imm=1213415752
#line 181 "sample/map.c"
    r1 = (uint64_t)8387235364025352520;
    // EBPF_OP_STXDW pc=607 dst=r10 src=r1 offset=-32 imm=0
#line 181 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=608 dst=r1 src=r0 offset=0 imm=1380274271
#line 181 "sample/map.c"
    r1 = (uint64_t)6869485056696864863;
    // EBPF_OP_STXDW pc=610 dst=r10 src=r1 offset=-40 imm=0
#line 181 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=611 dst=r1 src=r0 offset=0 imm=1885433120
#line 181 "sample/map.c"
    r1 = (uint64_t)6148060143522245920;
    // EBPF_OP_STXDW pc=613 dst=r10 src=r1 offset=-48 imm=0
#line 181 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=614 dst=r1 src=r0 offset=0 imm=1279349317
#line 181 "sample/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=616 dst=r10 src=r1 offset=-56 imm=0
#line 181 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=617 dst=r1 src=r0 offset=0 imm=1953719636
#line 181 "sample/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=619 dst=r10 src=r1 offset=-64 imm=0
#line 181 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=620 dst=r3 src=r6 offset=0 imm=0
#line 181 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=621 dst=r3 src=r0 offset=0 imm=32
#line 181 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=622 dst=r3 src=r0 offset=0 imm=32
#line 181 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=623 dst=r1 src=r10 offset=0 imm=0
#line 181 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=624 dst=r1 src=r0 offset=0 imm=-64
#line 181 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=625 dst=r2 src=r0 offset=0 imm=49
#line 181 "sample/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=626 dst=r0 src=r0 offset=-526 imm=0
#line 181 "sample/map.c"
    goto label_5;
label_32:
    // EBPF_OP_MOV64_IMM pc=627 dst=r8 src=r0 offset=0 imm=0
#line 181 "sample/map.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=628 dst=r10 src=r8 offset=-4 imm=0
#line 181 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r8;
    // EBPF_OP_MOV64_IMM pc=629 dst=r1 src=r0 offset=0 imm=1
#line 181 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=630 dst=r10 src=r1 offset=-68 imm=0
#line 81 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=631 dst=r9 src=r0 offset=0 imm=11
#line 81 "sample/map.c"
    r9 = IMMEDIATE(11);
label_33:
    // EBPF_OP_MOV64_REG pc=632 dst=r2 src=r10 offset=0 imm=0
#line 81 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=633 dst=r2 src=r0 offset=0 imm=-4
#line 81 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=634 dst=r3 src=r10 offset=0 imm=0
#line 81 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=635 dst=r3 src=r0 offset=0 imm=-68
#line 81 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=636 dst=r1 src=r0 offset=0 imm=0
#line 86 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=638 dst=r4 src=r0 offset=0 imm=0
#line 86 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=639 dst=r0 src=r0 offset=0 imm=2
#line 86 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 86 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 86 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 86 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=640 dst=r6 src=r0 offset=0 imm=0
#line 86 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=641 dst=r7 src=r6 offset=0 imm=0
#line 86 "sample/map.c"
    r7 = r6;
    // EBPF_OP_LSH64_IMM pc=642 dst=r7 src=r0 offset=0 imm=32
#line 86 "sample/map.c"
    r7 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=643 dst=r7 src=r0 offset=0 imm=32
#line 86 "sample/map.c"
    r7 = (int64_t)r7 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=644 dst=r8 src=r7 offset=72 imm=0
#line 87 "sample/map.c"
    if ((int64_t)r8 > (int64_t)r7)
#line 87 "sample/map.c"
        goto label_37;
        // EBPF_OP_LDXW pc=645 dst=r1 src=r10 offset=-4 imm=0
#line 85 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ADD64_IMM pc=646 dst=r1 src=r0 offset=0 imm=1
#line 85 "sample/map.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=647 dst=r10 src=r1 offset=-4 imm=0
#line 85 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_LSH64_IMM pc=648 dst=r1 src=r0 offset=0 imm=32
#line 85 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=649 dst=r1 src=r0 offset=0 imm=32
#line 85 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JGT_REG pc=650 dst=r9 src=r1 offset=-19 imm=0
#line 85 "sample/map.c"
    if (r9 > r1)
#line 85 "sample/map.c"
        goto label_33;
        // EBPF_OP_MOV64_IMM pc=651 dst=r8 src=r0 offset=0 imm=0
#line 85 "sample/map.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=652 dst=r10 src=r8 offset=-4 imm=0
#line 85 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r8;
    // EBPF_OP_MOV64_IMM pc=653 dst=r1 src=r0 offset=0 imm=1
#line 85 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=654 dst=r10 src=r1 offset=-68 imm=0
#line 81 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=655 dst=r9 src=r0 offset=0 imm=11
#line 81 "sample/map.c"
    r9 = IMMEDIATE(11);
label_34:
    // EBPF_OP_MOV64_REG pc=656 dst=r2 src=r10 offset=0 imm=0
#line 81 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=657 dst=r2 src=r0 offset=0 imm=-4
#line 81 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=658 dst=r3 src=r10 offset=0 imm=0
#line 81 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=659 dst=r3 src=r0 offset=0 imm=-68
#line 81 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=660 dst=r1 src=r0 offset=0 imm=0
#line 86 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=662 dst=r4 src=r0 offset=0 imm=0
#line 86 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=663 dst=r0 src=r0 offset=0 imm=2
#line 86 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 86 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 86 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 86 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=664 dst=r6 src=r0 offset=0 imm=0
#line 86 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=665 dst=r7 src=r6 offset=0 imm=0
#line 86 "sample/map.c"
    r7 = r6;
    // EBPF_OP_LSH64_IMM pc=666 dst=r7 src=r0 offset=0 imm=32
#line 86 "sample/map.c"
    r7 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=667 dst=r7 src=r0 offset=0 imm=32
#line 86 "sample/map.c"
    r7 = (int64_t)r7 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=668 dst=r8 src=r7 offset=85 imm=0
#line 87 "sample/map.c"
    if ((int64_t)r8 > (int64_t)r7)
#line 87 "sample/map.c"
        goto label_38;
        // EBPF_OP_LDXW pc=669 dst=r1 src=r10 offset=-4 imm=0
#line 85 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ADD64_IMM pc=670 dst=r1 src=r0 offset=0 imm=1
#line 85 "sample/map.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=671 dst=r10 src=r1 offset=-4 imm=0
#line 85 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_LSH64_IMM pc=672 dst=r1 src=r0 offset=0 imm=32
#line 85 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=673 dst=r1 src=r0 offset=0 imm=32
#line 85 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JGT_REG pc=674 dst=r9 src=r1 offset=-19 imm=0
#line 85 "sample/map.c"
    if (r9 > r1)
#line 85 "sample/map.c"
        goto label_34;
        // EBPF_OP_MOV64_IMM pc=675 dst=r1 src=r0 offset=0 imm=0
#line 85 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=676 dst=r10 src=r1 offset=-4 imm=0
#line 137 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=677 dst=r2 src=r10 offset=0 imm=0
#line 137 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=678 dst=r2 src=r0 offset=0 imm=-4
#line 137 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=679 dst=r1 src=r0 offset=0 imm=0
#line 137 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=681 dst=r0 src=r0 offset=0 imm=18
#line 137 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 137 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 137 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 137 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=682 dst=r6 src=r0 offset=0 imm=0
#line 137 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=683 dst=r4 src=r6 offset=0 imm=0
#line 137 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=684 dst=r4 src=r0 offset=0 imm=32
#line 137 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=685 dst=r1 src=r4 offset=0 imm=0
#line 137 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=686 dst=r1 src=r0 offset=0 imm=32
#line 137 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=687 dst=r2 src=r0 offset=0 imm=-7
#line 137 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=689 dst=r1 src=r2 offset=105 imm=0
#line 137 "sample/map.c"
    if (r1 == r2)
#line 137 "sample/map.c"
        goto label_40;
label_35:
    // EBPF_OP_MOV64_IMM pc=690 dst=r1 src=r0 offset=0 imm=100
#line 137 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=691 dst=r10 src=r1 offset=-16 imm=0
#line 137 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=692 dst=r1 src=r0 offset=0 imm=1852994932
#line 137 "sample/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=694 dst=r10 src=r1 offset=-24 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=695 dst=r1 src=r0 offset=0 imm=622883948
#line 137 "sample/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=697 dst=r10 src=r1 offset=-32 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=698 dst=r1 src=r0 offset=0 imm=543649385
#line 137 "sample/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=700 dst=r10 src=r1 offset=-40 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=701 dst=r1 src=r0 offset=0 imm=2019893357
#line 137 "sample/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=703 dst=r10 src=r1 offset=-48 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=704 dst=r1 src=r0 offset=0 imm=1801807216
#line 137 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=706 dst=r10 src=r1 offset=-56 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=707 dst=r1 src=r0 offset=0 imm=1600548962
#line 137 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=709 dst=r10 src=r1 offset=-64 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=710 dst=r4 src=r0 offset=0 imm=32
#line 137 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=711 dst=r1 src=r10 offset=0 imm=0
#line 137 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=712 dst=r1 src=r0 offset=0 imm=-64
#line 137 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=713 dst=r2 src=r0 offset=0 imm=50
#line 137 "sample/map.c"
    r2 = IMMEDIATE(50);
label_36:
    // EBPF_OP_MOV64_IMM pc=714 dst=r3 src=r0 offset=0 imm=-7
#line 137 "sample/map.c"
    r3 = IMMEDIATE(-7);
    // EBPF_OP_CALL pc=715 dst=r0 src=r0 offset=0 imm=14
#line 137 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 137 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 137 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 137 "sample/map.c"
        return 0;
        // EBPF_OP_JA pc=716 dst=r0 src=r0 offset=104 imm=0
#line 137 "sample/map.c"
    goto label_44;
label_37:
    // EBPF_OP_LDDW pc=717 dst=r1 src=r0 offset=0 imm=1684369010
#line 137 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=719 dst=r10 src=r1 offset=-40 imm=0
#line 88 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=720 dst=r1 src=r0 offset=0 imm=544040300
#line 88 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=722 dst=r10 src=r1 offset=-48 imm=0
#line 88 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=723 dst=r1 src=r0 offset=0 imm=1633972341
#line 88 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_STXDW pc=725 dst=r10 src=r1 offset=-56 imm=0
#line 88 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=726 dst=r1 src=r0 offset=0 imm=1600548962
#line 88 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=728 dst=r10 src=r1 offset=-64 imm=0
#line 88 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=729 dst=r1 src=r10 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=730 dst=r1 src=r0 offset=0 imm=-64
#line 88 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=731 dst=r2 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=732 dst=r3 src=r7 offset=0 imm=0
#line 88 "sample/map.c"
    r3 = r7;
    // EBPF_OP_CALL pc=733 dst=r0 src=r0 offset=0 imm=13
#line 88 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_IMM pc=734 dst=r1 src=r0 offset=0 imm=100
#line 88 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=735 dst=r10 src=r1 offset=-28 imm=0
#line 183 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=736 dst=r1 src=r0 offset=0 imm=622879845
#line 183 "sample/map.c"
    r1 = IMMEDIATE(622879845);
    // EBPF_OP_STXW pc=737 dst=r10 src=r1 offset=-32 imm=0
#line 183 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=738 dst=r1 src=r0 offset=0 imm=1701978184
#line 183 "sample/map.c"
    r1 = (uint64_t)7958552634295722056;
    // EBPF_OP_STXDW pc=740 dst=r10 src=r1 offset=-40 imm=0
#line 183 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=741 dst=r1 src=r0 offset=0 imm=1431456800
#line 183 "sample/map.c"
    r1 = (uint64_t)5999155752924761120;
    // EBPF_OP_STXDW pc=743 dst=r10 src=r1 offset=-48 imm=0
#line 183 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=744 dst=r1 src=r0 offset=0 imm=1919903264
#line 183 "sample/map.c"
    r1 = (uint64_t)8097873591115146784;
    // EBPF_OP_STXDW pc=746 dst=r10 src=r1 offset=-56 imm=0
#line 183 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=747 dst=r1 src=r0 offset=0 imm=1953719636
#line 183 "sample/map.c"
    r1 = (uint64_t)6148060143590532436;
    // EBPF_OP_STXDW pc=749 dst=r10 src=r1 offset=-64 imm=0
#line 183 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=750 dst=r1 src=r10 offset=0 imm=0
#line 183 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=751 dst=r1 src=r0 offset=0 imm=-64
#line 88 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=752 dst=r2 src=r0 offset=0 imm=38
#line 183 "sample/map.c"
    r2 = IMMEDIATE(38);
    // EBPF_OP_JA pc=753 dst=r0 src=r0 offset=39 imm=0
#line 183 "sample/map.c"
    goto label_39;
label_38:
    // EBPF_OP_LDDW pc=754 dst=r1 src=r0 offset=0 imm=1684369010
#line 183 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=756 dst=r10 src=r1 offset=-40 imm=0
#line 88 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=757 dst=r1 src=r0 offset=0 imm=544040300
#line 88 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=759 dst=r10 src=r1 offset=-48 imm=0
#line 88 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=760 dst=r1 src=r0 offset=0 imm=1633972341
#line 88 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_STXDW pc=762 dst=r10 src=r1 offset=-56 imm=0
#line 88 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=763 dst=r1 src=r0 offset=0 imm=1600548962
#line 88 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=765 dst=r10 src=r1 offset=-64 imm=0
#line 88 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=766 dst=r1 src=r10 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=767 dst=r1 src=r0 offset=0 imm=-64
#line 88 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=768 dst=r2 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=769 dst=r3 src=r7 offset=0 imm=0
#line 88 "sample/map.c"
    r3 = r7;
    // EBPF_OP_CALL pc=770 dst=r0 src=r0 offset=0 imm=13
#line 88 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_IMM pc=771 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=772 dst=r10 src=r1 offset=-20 imm=0
#line 184 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=773 dst=r1 src=r0 offset=0 imm=1680154724
#line 184 "sample/map.c"
    r1 = IMMEDIATE(1680154724);
    // EBPF_OP_STXW pc=774 dst=r10 src=r1 offset=-24 imm=0
#line 184 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=775 dst=r1 src=r0 offset=0 imm=1952805408
#line 184 "sample/map.c"
    r1 = (uint64_t)7308905094058439200;
    // EBPF_OP_STXDW pc=777 dst=r10 src=r1 offset=-32 imm=0
#line 184 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=778 dst=r1 src=r0 offset=0 imm=1599426627
#line 184 "sample/map.c"
    r1 = (uint64_t)5211580972890673219;
    // EBPF_OP_STXDW pc=780 dst=r10 src=r1 offset=-40 imm=0
#line 184 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=781 dst=r1 src=r0 offset=0 imm=1431456800
#line 184 "sample/map.c"
    r1 = (uint64_t)5928232854886698016;
    // EBPF_OP_STXDW pc=783 dst=r10 src=r1 offset=-48 imm=0
#line 184 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=784 dst=r1 src=r0 offset=0 imm=1919903264
#line 184 "sample/map.c"
    r1 = (uint64_t)8097873591115146784;
    // EBPF_OP_STXDW pc=786 dst=r10 src=r1 offset=-56 imm=0
#line 184 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=787 dst=r1 src=r0 offset=0 imm=1953719636
#line 184 "sample/map.c"
    r1 = (uint64_t)6148060143590532436;
    // EBPF_OP_STXDW pc=789 dst=r10 src=r1 offset=-64 imm=0
#line 184 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=790 dst=r1 src=r10 offset=0 imm=0
#line 184 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=791 dst=r1 src=r0 offset=0 imm=-64
#line 88 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=792 dst=r2 src=r0 offset=0 imm=45
#line 184 "sample/map.c"
    r2 = IMMEDIATE(45);
label_39:
    // EBPF_OP_MOV64_REG pc=793 dst=r3 src=r7 offset=0 imm=0
#line 184 "sample/map.c"
    r3 = r7;
    // EBPF_OP_JA pc=794 dst=r0 src=r0 offset=-694 imm=0
#line 184 "sample/map.c"
    goto label_5;
label_40:
    // EBPF_OP_LDXW pc=795 dst=r3 src=r10 offset=-4 imm=0
#line 137 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=796 dst=r3 src=r0 offset=47 imm=0
#line 137 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 137 "sample/map.c"
        goto label_45;
label_41:
    // EBPF_OP_LDDW pc=797 dst=r1 src=r0 offset=0 imm=1852404835
#line 137 "sample/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=799 dst=r10 src=r1 offset=-32 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=800 dst=r1 src=r0 offset=0 imm=543434016
#line 137 "sample/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=802 dst=r10 src=r1 offset=-40 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=803 dst=r1 src=r0 offset=0 imm=1701978221
#line 137 "sample/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=805 dst=r10 src=r1 offset=-48 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=806 dst=r1 src=r0 offset=0 imm=1801807216
#line 137 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=808 dst=r10 src=r1 offset=-56 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=809 dst=r1 src=r0 offset=0 imm=1600548962
#line 137 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=811 dst=r10 src=r1 offset=-64 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=812 dst=r1 src=r0 offset=0 imm=0
#line 137 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=813 dst=r10 src=r1 offset=-24 imm=0
#line 137 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint8_t)r1;
    // EBPF_OP_MOV64_REG pc=814 dst=r1 src=r10 offset=0 imm=0
#line 137 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=815 dst=r1 src=r0 offset=0 imm=-64
#line 137 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=816 dst=r2 src=r0 offset=0 imm=41
#line 137 "sample/map.c"
    r2 = IMMEDIATE(41);
label_42:
    // EBPF_OP_MOV64_IMM pc=817 dst=r4 src=r0 offset=0 imm=0
#line 137 "sample/map.c"
    r4 = IMMEDIATE(0);
label_43:
    // EBPF_OP_CALL pc=818 dst=r0 src=r0 offset=0 imm=14
#line 137 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 137 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 137 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 137 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=819 dst=r6 src=r0 offset=0 imm=-1
#line 137 "sample/map.c"
    r6 = (uint64_t)4294967295;
label_44:
    // EBPF_OP_MOV64_REG pc=821 dst=r3 src=r6 offset=0 imm=0
#line 186 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=822 dst=r3 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=823 dst=r3 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=824 dst=r3 src=r0 offset=627 imm=-1
#line 186 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 186 "sample/map.c"
        goto label_68;
        // EBPF_OP_LDDW pc=825 dst=r1 src=r0 offset=0 imm=1684369010
#line 186 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=827 dst=r10 src=r1 offset=-32 imm=0
#line 186 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=828 dst=r1 src=r0 offset=0 imm=541414725
#line 186 "sample/map.c"
    r1 = (uint64_t)8463501140578096453;
    // EBPF_OP_STXDW pc=830 dst=r10 src=r1 offset=-40 imm=0
#line 186 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=831 dst=r1 src=r0 offset=0 imm=1634541682
#line 186 "sample/map.c"
    r1 = (uint64_t)6147730633380405362;
    // EBPF_OP_STXDW pc=833 dst=r10 src=r1 offset=-48 imm=0
#line 186 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=834 dst=r1 src=r0 offset=0 imm=1330667336
#line 186 "sample/map.c"
    r1 = (uint64_t)8027138915134627656;
    // EBPF_OP_STXDW pc=836 dst=r10 src=r1 offset=-56 imm=0
#line 186 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=837 dst=r1 src=r0 offset=0 imm=1953719636
#line 186 "sample/map.c"
    r1 = (uint64_t)6004793778491319636;
    // EBPF_OP_STXDW pc=839 dst=r10 src=r1 offset=-64 imm=0
#line 186 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=840 dst=r1 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=841 dst=r1 src=r0 offset=0 imm=-64
#line 186 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=842 dst=r2 src=r0 offset=0 imm=40
#line 186 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_JA pc=843 dst=r0 src=r0 offset=-743 imm=0
#line 186 "sample/map.c"
    goto label_5;
label_45:
    // EBPF_OP_MOV64_IMM pc=844 dst=r7 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=845 dst=r10 src=r7 offset=-4 imm=0
#line 138 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=846 dst=r2 src=r10 offset=0 imm=0
#line 138 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=847 dst=r2 src=r0 offset=0 imm=-4
#line 138 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=848 dst=r1 src=r0 offset=0 imm=0
#line 138 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=850 dst=r0 src=r0 offset=0 imm=17
#line 138 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 138 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 138 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 138 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=851 dst=r6 src=r0 offset=0 imm=0
#line 138 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=852 dst=r4 src=r6 offset=0 imm=0
#line 138 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=853 dst=r4 src=r0 offset=0 imm=32
#line 138 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=854 dst=r1 src=r4 offset=0 imm=0
#line 138 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=855 dst=r1 src=r0 offset=0 imm=32
#line 138 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=856 dst=r2 src=r0 offset=0 imm=-7
#line 138 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=858 dst=r1 src=r2 offset=24 imm=0
#line 138 "sample/map.c"
    if (r1 == r2)
#line 138 "sample/map.c"
        goto label_47;
label_46:
    // EBPF_OP_STXB pc=859 dst=r10 src=r7 offset=-16 imm=0
#line 138 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint8_t)r7;
    // EBPF_OP_LDDW pc=860 dst=r1 src=r0 offset=0 imm=1701737077
#line 138 "sample/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=862 dst=r10 src=r1 offset=-24 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=863 dst=r1 src=r0 offset=0 imm=1680154740
#line 138 "sample/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=865 dst=r10 src=r1 offset=-32 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=866 dst=r1 src=r0 offset=0 imm=1914726254
#line 138 "sample/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=868 dst=r10 src=r1 offset=-40 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=869 dst=r1 src=r0 offset=0 imm=1886938400
#line 138 "sample/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=871 dst=r10 src=r1 offset=-48 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=872 dst=r1 src=r0 offset=0 imm=1601204080
#line 138 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=874 dst=r10 src=r1 offset=-56 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=875 dst=r1 src=r0 offset=0 imm=1600548962
#line 138 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=877 dst=r10 src=r1 offset=-64 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=878 dst=r4 src=r0 offset=0 imm=32
#line 138 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=879 dst=r1 src=r10 offset=0 imm=0
#line 138 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=880 dst=r1 src=r0 offset=0 imm=-64
#line 138 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=881 dst=r2 src=r0 offset=0 imm=49
#line 138 "sample/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=882 dst=r0 src=r0 offset=-169 imm=0
#line 138 "sample/map.c"
    goto label_36;
label_47:
    // EBPF_OP_LDXW pc=883 dst=r3 src=r10 offset=-4 imm=0
#line 138 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=884 dst=r3 src=r0 offset=19 imm=0
#line 138 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 138 "sample/map.c"
        goto label_49;
label_48:
    // EBPF_OP_LDDW pc=885 dst=r1 src=r0 offset=0 imm=1735289204
#line 138 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=887 dst=r10 src=r1 offset=-32 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=888 dst=r1 src=r0 offset=0 imm=1696621605
#line 138 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=890 dst=r10 src=r1 offset=-40 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=891 dst=r1 src=r0 offset=0 imm=1952805408
#line 138 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=893 dst=r10 src=r1 offset=-48 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=894 dst=r1 src=r0 offset=0 imm=1601204080
#line 138 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=896 dst=r10 src=r1 offset=-56 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=897 dst=r1 src=r0 offset=0 imm=1600548962
#line 138 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=899 dst=r10 src=r1 offset=-64 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=900 dst=r1 src=r10 offset=0 imm=0
#line 138 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=901 dst=r1 src=r0 offset=0 imm=-64
#line 138 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=902 dst=r2 src=r0 offset=0 imm=40
#line 138 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_JA pc=903 dst=r0 src=r0 offset=-87 imm=0
#line 138 "sample/map.c"
    goto label_42;
label_49:
    // EBPF_OP_MOV64_IMM pc=904 dst=r7 src=r0 offset=0 imm=0
#line 138 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=905 dst=r10 src=r7 offset=-4 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=906 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=907 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=908 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=910 dst=r3 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=911 dst=r0 src=r0 offset=0 imm=16
#line 141 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=912 dst=r6 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=913 dst=r1 src=r6 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=914 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=915 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=916 dst=r1 src=r0 offset=33 imm=0
#line 141 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 141 "sample/map.c"
        goto label_53;
label_50:
    // EBPF_OP_MOV64_IMM pc=917 dst=r1 src=r0 offset=0 imm=25637
#line 141 "sample/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=918 dst=r10 src=r1 offset=-12 imm=0
#line 141 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=919 dst=r1 src=r0 offset=0 imm=543450478
#line 141 "sample/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=920 dst=r10 src=r1 offset=-16 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=921 dst=r1 src=r0 offset=0 imm=1914725413
#line 141 "sample/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=923 dst=r10 src=r1 offset=-24 imm=0
#line 141 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=924 dst=r1 src=r0 offset=0 imm=1667592312
#line 141 "sample/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=926 dst=r10 src=r1 offset=-32 imm=0
#line 141 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=927 dst=r1 src=r0 offset=0 imm=543649385
#line 141 "sample/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=929 dst=r10 src=r1 offset=-40 imm=0
#line 141 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=930 dst=r1 src=r0 offset=0 imm=1852383341
#line 141 "sample/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=932 dst=r10 src=r1 offset=-48 imm=0
#line 141 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=933 dst=r1 src=r0 offset=0 imm=1752397168
#line 141 "sample/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=935 dst=r10 src=r1 offset=-56 imm=0
#line 141 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=936 dst=r1 src=r0 offset=0 imm=1600548962
#line 141 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=938 dst=r10 src=r1 offset=-64 imm=0
#line 141 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_STXB pc=939 dst=r10 src=r7 offset=-10 imm=0
#line 141 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-10)) = (uint8_t)r7;
    // EBPF_OP_LDXW pc=940 dst=r3 src=r10 offset=-4 imm=0
#line 141 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=941 dst=r5 src=r6 offset=0 imm=0
#line 141 "sample/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=942 dst=r5 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r5 <<= IMMEDIATE(32);
label_51:
    // EBPF_OP_ARSH64_IMM pc=943 dst=r5 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r5 = (int64_t)r5 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=944 dst=r1 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=945 dst=r1 src=r0 offset=0 imm=-64
#line 141 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=946 dst=r2 src=r0 offset=0 imm=55
#line 141 "sample/map.c"
    r2 = IMMEDIATE(55);
    // EBPF_OP_MOV64_IMM pc=947 dst=r4 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r4 = IMMEDIATE(0);
label_52:
    // EBPF_OP_CALL pc=948 dst=r0 src=r0 offset=0 imm=15
#line 141 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_JA pc=949 dst=r0 src=r0 offset=-129 imm=0
#line 141 "sample/map.c"
    goto label_44;
label_53:
    // EBPF_OP_MOV64_IMM pc=950 dst=r1 src=r0 offset=0 imm=1
#line 141 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=951 dst=r10 src=r1 offset=-4 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=952 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=953 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=954 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=956 dst=r3 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=957 dst=r0 src=r0 offset=0 imm=16
#line 141 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=958 dst=r6 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=959 dst=r1 src=r6 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=960 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=961 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=962 dst=r1 src=r0 offset=1 imm=0
#line 141 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 141 "sample/map.c"
        goto label_54;
        // EBPF_OP_JA pc=963 dst=r0 src=r0 offset=-47 imm=0
#line 141 "sample/map.c"
    goto label_50;
label_54:
    // EBPF_OP_MOV64_IMM pc=964 dst=r1 src=r0 offset=0 imm=2
#line 141 "sample/map.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=965 dst=r10 src=r1 offset=-4 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=966 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=967 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=968 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=970 dst=r3 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=971 dst=r0 src=r0 offset=0 imm=16
#line 141 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=972 dst=r6 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=973 dst=r1 src=r6 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=974 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=975 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=976 dst=r1 src=r0 offset=-60 imm=0
#line 141 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 141 "sample/map.c"
        goto label_50;
        // EBPF_OP_MOV64_IMM pc=977 dst=r1 src=r0 offset=0 imm=3
#line 141 "sample/map.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=978 dst=r10 src=r1 offset=-4 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=979 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=980 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=981 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=983 dst=r3 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=984 dst=r0 src=r0 offset=0 imm=16
#line 141 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=985 dst=r6 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=986 dst=r1 src=r6 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=987 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=988 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=989 dst=r1 src=r0 offset=-73 imm=0
#line 141 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 141 "sample/map.c"
        goto label_50;
        // EBPF_OP_MOV64_IMM pc=990 dst=r1 src=r0 offset=0 imm=4
#line 141 "sample/map.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=991 dst=r10 src=r1 offset=-4 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=992 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=993 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=994 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=996 dst=r3 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=997 dst=r0 src=r0 offset=0 imm=16
#line 141 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=998 dst=r6 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=999 dst=r1 src=r6 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1000 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1001 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1002 dst=r1 src=r0 offset=-86 imm=0
#line 141 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 141 "sample/map.c"
        goto label_50;
        // EBPF_OP_MOV64_IMM pc=1003 dst=r1 src=r0 offset=0 imm=5
#line 141 "sample/map.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=1004 dst=r10 src=r1 offset=-4 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1005 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1006 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1007 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1009 dst=r3 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1010 dst=r0 src=r0 offset=0 imm=16
#line 141 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1011 dst=r6 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1012 dst=r1 src=r6 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1013 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1014 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1015 dst=r1 src=r0 offset=-99 imm=0
#line 141 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 141 "sample/map.c"
        goto label_50;
        // EBPF_OP_MOV64_IMM pc=1016 dst=r1 src=r0 offset=0 imm=6
#line 141 "sample/map.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=1017 dst=r10 src=r1 offset=-4 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1018 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1019 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1020 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1022 dst=r3 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1023 dst=r0 src=r0 offset=0 imm=16
#line 141 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1024 dst=r6 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1025 dst=r1 src=r6 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1026 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1027 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1028 dst=r1 src=r0 offset=-112 imm=0
#line 141 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 141 "sample/map.c"
        goto label_50;
        // EBPF_OP_MOV64_IMM pc=1029 dst=r1 src=r0 offset=0 imm=7
#line 141 "sample/map.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=1030 dst=r10 src=r1 offset=-4 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1031 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1032 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1033 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1035 dst=r3 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1036 dst=r0 src=r0 offset=0 imm=16
#line 141 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1037 dst=r6 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1038 dst=r1 src=r6 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1039 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1040 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1041 dst=r1 src=r0 offset=-125 imm=0
#line 141 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 141 "sample/map.c"
        goto label_50;
        // EBPF_OP_MOV64_IMM pc=1042 dst=r1 src=r0 offset=0 imm=8
#line 141 "sample/map.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=1043 dst=r10 src=r1 offset=-4 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1044 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1045 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1046 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1048 dst=r3 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1049 dst=r0 src=r0 offset=0 imm=16
#line 141 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1050 dst=r6 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1051 dst=r1 src=r6 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1052 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1053 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1054 dst=r1 src=r0 offset=-138 imm=0
#line 141 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 141 "sample/map.c"
        goto label_50;
        // EBPF_OP_MOV64_IMM pc=1055 dst=r1 src=r0 offset=0 imm=9
#line 141 "sample/map.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=1056 dst=r10 src=r1 offset=-4 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1057 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1058 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1059 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1061 dst=r3 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1062 dst=r0 src=r0 offset=0 imm=16
#line 141 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1063 dst=r6 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1064 dst=r1 src=r6 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1065 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1066 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1067 dst=r1 src=r0 offset=-151 imm=0
#line 141 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 141 "sample/map.c"
        goto label_50;
        // EBPF_OP_MOV64_IMM pc=1068 dst=r7 src=r0 offset=0 imm=10
#line 141 "sample/map.c"
    r7 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=1069 dst=r10 src=r7 offset=-4 imm=0
#line 144 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1070 dst=r2 src=r10 offset=0 imm=0
#line 144 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1071 dst=r2 src=r0 offset=0 imm=-4
#line 144 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=1072 dst=r8 src=r0 offset=0 imm=0
#line 144 "sample/map.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=1073 dst=r1 src=r0 offset=0 imm=0
#line 144 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1075 dst=r3 src=r0 offset=0 imm=0
#line 144 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1076 dst=r0 src=r0 offset=0 imm=16
#line 144 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 144 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 144 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 144 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1077 dst=r6 src=r0 offset=0 imm=0
#line 144 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1078 dst=r5 src=r6 offset=0 imm=0
#line 144 "sample/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1079 dst=r5 src=r0 offset=0 imm=32
#line 144 "sample/map.c"
    r5 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1080 dst=r1 src=r5 offset=0 imm=0
#line 144 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1081 dst=r1 src=r0 offset=0 imm=32
#line 144 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1082 dst=r2 src=r0 offset=0 imm=-29
#line 144 "sample/map.c"
    r2 = (uint64_t)4294967267;
    // EBPF_OP_JEQ_REG pc=1084 dst=r1 src=r2 offset=30 imm=0
#line 144 "sample/map.c"
    if (r1 == r2)
#line 144 "sample/map.c"
        goto label_55;
        // EBPF_OP_STXB pc=1085 dst=r10 src=r8 offset=-10 imm=0
#line 144 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-10)) = (uint8_t)r8;
    // EBPF_OP_MOV64_IMM pc=1086 dst=r1 src=r0 offset=0 imm=25637
#line 144 "sample/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1087 dst=r10 src=r1 offset=-12 imm=0
#line 144 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1088 dst=r1 src=r0 offset=0 imm=543450478
#line 144 "sample/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1089 dst=r10 src=r1 offset=-16 imm=0
#line 144 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1090 dst=r1 src=r0 offset=0 imm=1914725413
#line 144 "sample/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1092 dst=r10 src=r1 offset=-24 imm=0
#line 144 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1093 dst=r1 src=r0 offset=0 imm=1667592312
#line 144 "sample/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1095 dst=r10 src=r1 offset=-32 imm=0
#line 144 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1096 dst=r1 src=r0 offset=0 imm=543649385
#line 144 "sample/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1098 dst=r10 src=r1 offset=-40 imm=0
#line 144 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1099 dst=r1 src=r0 offset=0 imm=1852383341
#line 144 "sample/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1101 dst=r10 src=r1 offset=-48 imm=0
#line 144 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1102 dst=r1 src=r0 offset=0 imm=1752397168
#line 144 "sample/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1104 dst=r10 src=r1 offset=-56 imm=0
#line 144 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1105 dst=r1 src=r0 offset=0 imm=1600548962
#line 144 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1107 dst=r10 src=r1 offset=-64 imm=0
#line 144 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=1108 dst=r3 src=r10 offset=-4 imm=0
#line 144 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ARSH64_IMM pc=1109 dst=r5 src=r0 offset=0 imm=32
#line 144 "sample/map.c"
    r5 = (int64_t)r5 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1110 dst=r1 src=r10 offset=0 imm=0
#line 144 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1111 dst=r1 src=r0 offset=0 imm=-64
#line 144 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1112 dst=r2 src=r0 offset=0 imm=55
#line 144 "sample/map.c"
    r2 = IMMEDIATE(55);
    // EBPF_OP_MOV64_IMM pc=1113 dst=r4 src=r0 offset=0 imm=-29
#line 144 "sample/map.c"
    r4 = IMMEDIATE(-29);
    // EBPF_OP_JA pc=1114 dst=r0 src=r0 offset=-167 imm=0
#line 144 "sample/map.c"
    goto label_52;
label_55:
    // EBPF_OP_STXW pc=1115 dst=r10 src=r7 offset=-4 imm=0
#line 145 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1116 dst=r2 src=r10 offset=0 imm=0
#line 145 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1117 dst=r2 src=r0 offset=0 imm=-4
#line 145 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1118 dst=r1 src=r0 offset=0 imm=0
#line 145 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1120 dst=r3 src=r0 offset=0 imm=2
#line 145 "sample/map.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_CALL pc=1121 dst=r0 src=r0 offset=0 imm=16
#line 145 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 145 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 145 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 145 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1122 dst=r6 src=r0 offset=0 imm=0
#line 145 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1123 dst=r5 src=r6 offset=0 imm=0
#line 145 "sample/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1124 dst=r5 src=r0 offset=0 imm=32
#line 145 "sample/map.c"
    r5 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1125 dst=r1 src=r5 offset=0 imm=0
#line 145 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1126 dst=r1 src=r0 offset=0 imm=32
#line 145 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1127 dst=r1 src=r0 offset=26 imm=0
#line 145 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 145 "sample/map.c"
        goto label_56;
        // EBPF_OP_MOV64_IMM pc=1128 dst=r1 src=r0 offset=0 imm=25637
#line 145 "sample/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1129 dst=r10 src=r1 offset=-12 imm=0
#line 145 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1130 dst=r1 src=r0 offset=0 imm=543450478
#line 145 "sample/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1131 dst=r10 src=r1 offset=-16 imm=0
#line 145 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1132 dst=r1 src=r0 offset=0 imm=1914725413
#line 145 "sample/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1134 dst=r10 src=r1 offset=-24 imm=0
#line 145 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1135 dst=r1 src=r0 offset=0 imm=1667592312
#line 145 "sample/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1137 dst=r10 src=r1 offset=-32 imm=0
#line 145 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1138 dst=r1 src=r0 offset=0 imm=543649385
#line 145 "sample/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1140 dst=r10 src=r1 offset=-40 imm=0
#line 145 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1141 dst=r1 src=r0 offset=0 imm=1852383341
#line 145 "sample/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1143 dst=r10 src=r1 offset=-48 imm=0
#line 145 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1144 dst=r1 src=r0 offset=0 imm=1752397168
#line 145 "sample/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1146 dst=r10 src=r1 offset=-56 imm=0
#line 145 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1147 dst=r1 src=r0 offset=0 imm=1600548962
#line 145 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1149 dst=r10 src=r1 offset=-64 imm=0
#line 145 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=1150 dst=r1 src=r0 offset=0 imm=0
#line 145 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1151 dst=r10 src=r1 offset=-10 imm=0
#line 145 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-10)) = (uint8_t)r1;
    // EBPF_OP_LDXW pc=1152 dst=r3 src=r10 offset=-4 imm=0
#line 145 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JA pc=1153 dst=r0 src=r0 offset=-211 imm=0
#line 145 "sample/map.c"
    goto label_51;
label_56:
    // EBPF_OP_MOV64_IMM pc=1154 dst=r1 src=r0 offset=0 imm=0
#line 145 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1155 dst=r10 src=r1 offset=-4 imm=0
#line 147 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1156 dst=r2 src=r10 offset=0 imm=0
#line 147 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1157 dst=r2 src=r0 offset=0 imm=-4
#line 147 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1158 dst=r1 src=r0 offset=0 imm=0
#line 147 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1160 dst=r0 src=r0 offset=0 imm=18
#line 147 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 147 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 147 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 147 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1161 dst=r6 src=r0 offset=0 imm=0
#line 147 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1162 dst=r4 src=r6 offset=0 imm=0
#line 147 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1163 dst=r4 src=r0 offset=0 imm=32
#line 147 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1164 dst=r1 src=r4 offset=0 imm=0
#line 147 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1165 dst=r1 src=r0 offset=0 imm=32
#line 147 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1166 dst=r1 src=r0 offset=27 imm=0
#line 147 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 147 "sample/map.c"
        goto label_58;
        // EBPF_OP_MOV64_IMM pc=1167 dst=r1 src=r0 offset=0 imm=100
#line 147 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=1168 dst=r10 src=r1 offset=-16 imm=0
#line 147 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=1169 dst=r1 src=r0 offset=0 imm=1852994932
#line 147 "sample/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=1171 dst=r10 src=r1 offset=-24 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1172 dst=r1 src=r0 offset=0 imm=622883948
#line 147 "sample/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=1174 dst=r10 src=r1 offset=-32 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1175 dst=r1 src=r0 offset=0 imm=543649385
#line 147 "sample/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=1177 dst=r10 src=r1 offset=-40 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1178 dst=r1 src=r0 offset=0 imm=2019893357
#line 147 "sample/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=1180 dst=r10 src=r1 offset=-48 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1181 dst=r1 src=r0 offset=0 imm=1801807216
#line 147 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1183 dst=r10 src=r1 offset=-56 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1184 dst=r1 src=r0 offset=0 imm=1600548962
#line 147 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1186 dst=r10 src=r1 offset=-64 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1187 dst=r4 src=r0 offset=0 imm=32
#line 147 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1188 dst=r1 src=r10 offset=0 imm=0
#line 147 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1189 dst=r1 src=r0 offset=0 imm=-64
#line 147 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1190 dst=r2 src=r0 offset=0 imm=50
#line 147 "sample/map.c"
    r2 = IMMEDIATE(50);
label_57:
    // EBPF_OP_MOV64_IMM pc=1191 dst=r3 src=r0 offset=0 imm=0
#line 147 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1192 dst=r0 src=r0 offset=0 imm=14
#line 147 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 147 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 147 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 147 "sample/map.c"
        return 0;
        // EBPF_OP_JA pc=1193 dst=r0 src=r0 offset=-373 imm=0
#line 147 "sample/map.c"
    goto label_44;
label_58:
    // EBPF_OP_LDXW pc=1194 dst=r3 src=r10 offset=-4 imm=0
#line 147 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1195 dst=r3 src=r0 offset=22 imm=1
#line 147 "sample/map.c"
    if (r3 == IMMEDIATE(1))
#line 147 "sample/map.c"
        goto label_59;
        // EBPF_OP_MOV64_IMM pc=1196 dst=r1 src=r0 offset=0 imm=0
#line 147 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1197 dst=r10 src=r1 offset=-24 imm=0
#line 147 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=1198 dst=r1 src=r0 offset=0 imm=1852404835
#line 147 "sample/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=1200 dst=r10 src=r1 offset=-32 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1201 dst=r1 src=r0 offset=0 imm=543434016
#line 147 "sample/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=1203 dst=r10 src=r1 offset=-40 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1204 dst=r1 src=r0 offset=0 imm=1701978221
#line 147 "sample/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=1206 dst=r10 src=r1 offset=-48 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1207 dst=r1 src=r0 offset=0 imm=1801807216
#line 147 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1209 dst=r10 src=r1 offset=-56 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1210 dst=r1 src=r0 offset=0 imm=1600548962
#line 147 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1212 dst=r10 src=r1 offset=-64 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1213 dst=r1 src=r10 offset=0 imm=0
#line 147 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1214 dst=r1 src=r0 offset=0 imm=-64
#line 147 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1215 dst=r2 src=r0 offset=0 imm=41
#line 147 "sample/map.c"
    r2 = IMMEDIATE(41);
    // EBPF_OP_MOV64_IMM pc=1216 dst=r4 src=r0 offset=0 imm=1
#line 147 "sample/map.c"
    r4 = IMMEDIATE(1);
    // EBPF_OP_JA pc=1217 dst=r0 src=r0 offset=-400 imm=0
#line 147 "sample/map.c"
    goto label_43;
label_59:
    // EBPF_OP_MOV64_IMM pc=1218 dst=r7 src=r0 offset=0 imm=0
#line 147 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1219 dst=r10 src=r7 offset=-4 imm=0
#line 150 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1220 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1221 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1222 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1224 dst=r0 src=r0 offset=0 imm=17
#line 150 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 150 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 150 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1225 dst=r6 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1226 dst=r1 src=r6 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1227 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1228 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1229 dst=r1 src=r0 offset=26 imm=0
#line 150 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 150 "sample/map.c"
        goto label_61;
label_60:
    // EBPF_OP_LDDW pc=1230 dst=r1 src=r0 offset=0 imm=1701737077
#line 150 "sample/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=1232 dst=r10 src=r1 offset=-24 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1233 dst=r1 src=r0 offset=0 imm=1680154740
#line 150 "sample/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=1235 dst=r10 src=r1 offset=-32 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1236 dst=r1 src=r0 offset=0 imm=1914726254
#line 150 "sample/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=1238 dst=r10 src=r1 offset=-40 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1239 dst=r1 src=r0 offset=0 imm=1886938400
#line 150 "sample/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=1241 dst=r10 src=r1 offset=-48 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1242 dst=r1 src=r0 offset=0 imm=1601204080
#line 150 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1244 dst=r10 src=r1 offset=-56 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1245 dst=r1 src=r0 offset=0 imm=1600548962
#line 150 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1247 dst=r10 src=r1 offset=-64 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_STXB pc=1248 dst=r10 src=r7 offset=-16 imm=0
#line 150 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint8_t)r7;
    // EBPF_OP_MOV64_REG pc=1249 dst=r4 src=r6 offset=0 imm=0
#line 150 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1250 dst=r4 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=1251 dst=r4 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1252 dst=r1 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1253 dst=r1 src=r0 offset=0 imm=-64
#line 150 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1254 dst=r2 src=r0 offset=0 imm=49
#line 150 "sample/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=1255 dst=r0 src=r0 offset=-65 imm=0
#line 150 "sample/map.c"
    goto label_57;
label_61:
    // EBPF_OP_MOV64_IMM pc=1256 dst=r4 src=r0 offset=0 imm=1
#line 150 "sample/map.c"
    r4 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=1257 dst=r3 src=r10 offset=-4 imm=0
#line 150 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1258 dst=r3 src=r0 offset=19 imm=1
#line 150 "sample/map.c"
    if (r3 == IMMEDIATE(1))
#line 150 "sample/map.c"
        goto label_63;
label_62:
    // EBPF_OP_LDDW pc=1259 dst=r1 src=r0 offset=0 imm=1735289204
#line 150 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1261 dst=r10 src=r1 offset=-32 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1262 dst=r1 src=r0 offset=0 imm=1696621605
#line 150 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1264 dst=r10 src=r1 offset=-40 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1265 dst=r1 src=r0 offset=0 imm=1952805408
#line 150 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1267 dst=r10 src=r1 offset=-48 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1268 dst=r1 src=r0 offset=0 imm=1601204080
#line 150 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1270 dst=r10 src=r1 offset=-56 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1271 dst=r1 src=r0 offset=0 imm=1600548962
#line 150 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1273 dst=r10 src=r1 offset=-64 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1274 dst=r1 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1275 dst=r1 src=r0 offset=0 imm=-64
#line 150 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1276 dst=r2 src=r0 offset=0 imm=40
#line 150 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_JA pc=1277 dst=r0 src=r0 offset=-460 imm=0
#line 150 "sample/map.c"
    goto label_43;
label_63:
    // EBPF_OP_MOV64_IMM pc=1278 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1279 dst=r10 src=r1 offset=-4 imm=0
#line 150 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1280 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1281 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1282 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1284 dst=r0 src=r0 offset=0 imm=17
#line 150 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 150 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 150 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1285 dst=r6 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1286 dst=r1 src=r6 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1287 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1288 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1289 dst=r1 src=r0 offset=1 imm=0
#line 150 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 150 "sample/map.c"
        goto label_64;
        // EBPF_OP_JA pc=1290 dst=r0 src=r0 offset=-61 imm=0
#line 150 "sample/map.c"
    goto label_60;
label_64:
    // EBPF_OP_MOV64_IMM pc=1291 dst=r4 src=r0 offset=0 imm=2
#line 150 "sample/map.c"
    r4 = IMMEDIATE(2);
    // EBPF_OP_LDXW pc=1292 dst=r3 src=r10 offset=-4 imm=0
#line 150 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1293 dst=r3 src=r0 offset=-35 imm=2
#line 150 "sample/map.c"
    if (r3 != IMMEDIATE(2))
#line 150 "sample/map.c"
        goto label_62;
        // EBPF_OP_MOV64_IMM pc=1294 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1295 dst=r10 src=r1 offset=-4 imm=0
#line 150 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1296 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1297 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1298 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1300 dst=r0 src=r0 offset=0 imm=17
#line 150 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 150 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 150 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1301 dst=r6 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1302 dst=r1 src=r6 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1303 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1304 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1305 dst=r1 src=r0 offset=-76 imm=0
#line 150 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 150 "sample/map.c"
        goto label_60;
        // EBPF_OP_MOV64_IMM pc=1306 dst=r4 src=r0 offset=0 imm=3
#line 150 "sample/map.c"
    r4 = IMMEDIATE(3);
    // EBPF_OP_LDXW pc=1307 dst=r3 src=r10 offset=-4 imm=0
#line 150 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1308 dst=r3 src=r0 offset=-50 imm=3
#line 150 "sample/map.c"
    if (r3 != IMMEDIATE(3))
#line 150 "sample/map.c"
        goto label_62;
        // EBPF_OP_MOV64_IMM pc=1309 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1310 dst=r10 src=r1 offset=-4 imm=0
#line 150 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1311 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1312 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1313 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1315 dst=r0 src=r0 offset=0 imm=17
#line 150 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 150 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 150 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1316 dst=r6 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1317 dst=r1 src=r6 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1318 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1319 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1320 dst=r1 src=r0 offset=-91 imm=0
#line 150 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 150 "sample/map.c"
        goto label_60;
        // EBPF_OP_MOV64_IMM pc=1321 dst=r4 src=r0 offset=0 imm=4
#line 150 "sample/map.c"
    r4 = IMMEDIATE(4);
    // EBPF_OP_LDXW pc=1322 dst=r3 src=r10 offset=-4 imm=0
#line 150 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1323 dst=r3 src=r0 offset=-65 imm=4
#line 150 "sample/map.c"
    if (r3 != IMMEDIATE(4))
#line 150 "sample/map.c"
        goto label_62;
        // EBPF_OP_MOV64_IMM pc=1324 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1325 dst=r10 src=r1 offset=-4 imm=0
#line 150 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1326 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1327 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1328 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1330 dst=r0 src=r0 offset=0 imm=17
#line 150 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 150 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 150 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1331 dst=r6 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1332 dst=r1 src=r6 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1333 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1334 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1335 dst=r1 src=r0 offset=-106 imm=0
#line 150 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 150 "sample/map.c"
        goto label_60;
        // EBPF_OP_MOV64_IMM pc=1336 dst=r4 src=r0 offset=0 imm=5
#line 150 "sample/map.c"
    r4 = IMMEDIATE(5);
    // EBPF_OP_LDXW pc=1337 dst=r3 src=r10 offset=-4 imm=0
#line 150 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1338 dst=r3 src=r0 offset=-80 imm=5
#line 150 "sample/map.c"
    if (r3 != IMMEDIATE(5))
#line 150 "sample/map.c"
        goto label_62;
        // EBPF_OP_MOV64_IMM pc=1339 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1340 dst=r10 src=r1 offset=-4 imm=0
#line 150 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1341 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1342 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1343 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1345 dst=r0 src=r0 offset=0 imm=17
#line 150 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 150 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 150 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1346 dst=r6 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1347 dst=r1 src=r6 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1348 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1349 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1350 dst=r1 src=r0 offset=-121 imm=0
#line 150 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 150 "sample/map.c"
        goto label_60;
        // EBPF_OP_MOV64_IMM pc=1351 dst=r4 src=r0 offset=0 imm=6
#line 150 "sample/map.c"
    r4 = IMMEDIATE(6);
    // EBPF_OP_LDXW pc=1352 dst=r3 src=r10 offset=-4 imm=0
#line 150 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1353 dst=r3 src=r0 offset=-95 imm=6
#line 150 "sample/map.c"
    if (r3 != IMMEDIATE(6))
#line 150 "sample/map.c"
        goto label_62;
        // EBPF_OP_MOV64_IMM pc=1354 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1355 dst=r10 src=r1 offset=-4 imm=0
#line 150 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1356 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1357 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1358 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1360 dst=r0 src=r0 offset=0 imm=17
#line 150 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 150 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 150 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1361 dst=r6 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1362 dst=r1 src=r6 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1363 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1364 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1365 dst=r1 src=r0 offset=-136 imm=0
#line 150 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 150 "sample/map.c"
        goto label_60;
        // EBPF_OP_MOV64_IMM pc=1366 dst=r4 src=r0 offset=0 imm=7
#line 150 "sample/map.c"
    r4 = IMMEDIATE(7);
    // EBPF_OP_LDXW pc=1367 dst=r3 src=r10 offset=-4 imm=0
#line 150 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1368 dst=r3 src=r0 offset=-110 imm=7
#line 150 "sample/map.c"
    if (r3 != IMMEDIATE(7))
#line 150 "sample/map.c"
        goto label_62;
        // EBPF_OP_MOV64_IMM pc=1369 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1370 dst=r10 src=r1 offset=-4 imm=0
#line 150 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1371 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1372 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1373 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1375 dst=r0 src=r0 offset=0 imm=17
#line 150 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 150 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 150 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1376 dst=r6 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1377 dst=r1 src=r6 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1378 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1379 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1380 dst=r1 src=r0 offset=-151 imm=0
#line 150 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 150 "sample/map.c"
        goto label_60;
        // EBPF_OP_MOV64_IMM pc=1381 dst=r4 src=r0 offset=0 imm=8
#line 150 "sample/map.c"
    r4 = IMMEDIATE(8);
    // EBPF_OP_LDXW pc=1382 dst=r3 src=r10 offset=-4 imm=0
#line 150 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1383 dst=r3 src=r0 offset=-125 imm=8
#line 150 "sample/map.c"
    if (r3 != IMMEDIATE(8))
#line 150 "sample/map.c"
        goto label_62;
        // EBPF_OP_MOV64_IMM pc=1384 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1385 dst=r10 src=r1 offset=-4 imm=0
#line 150 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1386 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1387 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1388 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1390 dst=r0 src=r0 offset=0 imm=17
#line 150 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 150 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 150 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1391 dst=r6 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1392 dst=r1 src=r6 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1393 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1394 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1395 dst=r1 src=r0 offset=-166 imm=0
#line 150 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 150 "sample/map.c"
        goto label_60;
        // EBPF_OP_MOV64_IMM pc=1396 dst=r4 src=r0 offset=0 imm=9
#line 150 "sample/map.c"
    r4 = IMMEDIATE(9);
    // EBPF_OP_LDXW pc=1397 dst=r3 src=r10 offset=-4 imm=0
#line 150 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1398 dst=r3 src=r0 offset=-140 imm=9
#line 150 "sample/map.c"
    if (r3 != IMMEDIATE(9))
#line 150 "sample/map.c"
        goto label_62;
        // EBPF_OP_MOV64_IMM pc=1399 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1400 dst=r10 src=r1 offset=-4 imm=0
#line 150 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1401 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1402 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1403 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1405 dst=r0 src=r0 offset=0 imm=17
#line 150 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 150 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 150 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1406 dst=r6 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1407 dst=r1 src=r6 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1408 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1409 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1410 dst=r1 src=r0 offset=-181 imm=0
#line 150 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 150 "sample/map.c"
        goto label_60;
        // EBPF_OP_MOV64_IMM pc=1411 dst=r4 src=r0 offset=0 imm=10
#line 150 "sample/map.c"
    r4 = IMMEDIATE(10);
    // EBPF_OP_LDXW pc=1412 dst=r3 src=r10 offset=-4 imm=0
#line 150 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1413 dst=r3 src=r0 offset=-155 imm=10
#line 150 "sample/map.c"
    if (r3 != IMMEDIATE(10))
#line 150 "sample/map.c"
        goto label_62;
        // EBPF_OP_MOV64_IMM pc=1414 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1415 dst=r10 src=r1 offset=-4 imm=0
#line 153 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1416 dst=r2 src=r10 offset=0 imm=0
#line 153 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1417 dst=r2 src=r0 offset=0 imm=-4
#line 153 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1418 dst=r1 src=r0 offset=0 imm=0
#line 153 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1420 dst=r0 src=r0 offset=0 imm=18
#line 153 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 153 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 153 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 153 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1421 dst=r6 src=r0 offset=0 imm=0
#line 153 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1422 dst=r4 src=r6 offset=0 imm=0
#line 153 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1423 dst=r4 src=r0 offset=0 imm=32
#line 153 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1424 dst=r1 src=r4 offset=0 imm=0
#line 153 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1425 dst=r1 src=r0 offset=0 imm=32
#line 153 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1426 dst=r2 src=r0 offset=0 imm=-7
#line 153 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1428 dst=r1 src=r2 offset=1 imm=0
#line 153 "sample/map.c"
    if (r1 == r2)
#line 153 "sample/map.c"
        goto label_65;
        // EBPF_OP_JA pc=1429 dst=r0 src=r0 offset=-740 imm=0
#line 153 "sample/map.c"
    goto label_35;
label_65:
    // EBPF_OP_LDXW pc=1430 dst=r3 src=r10 offset=-4 imm=0
#line 153 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1431 dst=r3 src=r0 offset=1 imm=0
#line 153 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 153 "sample/map.c"
        goto label_66;
        // EBPF_OP_JA pc=1432 dst=r0 src=r0 offset=-636 imm=0
#line 153 "sample/map.c"
    goto label_41;
label_66:
    // EBPF_OP_MOV64_IMM pc=1433 dst=r7 src=r0 offset=0 imm=0
#line 153 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1434 dst=r10 src=r7 offset=-4 imm=0
#line 154 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1435 dst=r2 src=r10 offset=0 imm=0
#line 154 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1436 dst=r2 src=r0 offset=0 imm=-4
#line 154 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1437 dst=r1 src=r0 offset=0 imm=0
#line 154 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1439 dst=r0 src=r0 offset=0 imm=17
#line 154 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 154 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 154 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 154 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1440 dst=r6 src=r0 offset=0 imm=0
#line 154 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1441 dst=r4 src=r6 offset=0 imm=0
#line 154 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1442 dst=r4 src=r0 offset=0 imm=32
#line 154 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1443 dst=r1 src=r4 offset=0 imm=0
#line 154 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1444 dst=r1 src=r0 offset=0 imm=32
#line 154 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1445 dst=r2 src=r0 offset=0 imm=-7
#line 154 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1447 dst=r1 src=r2 offset=1 imm=0
#line 154 "sample/map.c"
    if (r1 == r2)
#line 154 "sample/map.c"
        goto label_67;
        // EBPF_OP_JA pc=1448 dst=r0 src=r0 offset=-590 imm=0
#line 154 "sample/map.c"
    goto label_46;
label_67:
    // EBPF_OP_LDXW pc=1449 dst=r3 src=r10 offset=-4 imm=0
#line 154 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1450 dst=r3 src=r0 offset=1 imm=0
#line 154 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 154 "sample/map.c"
        goto label_68;
        // EBPF_OP_JA pc=1451 dst=r0 src=r0 offset=-567 imm=0
#line 154 "sample/map.c"
    goto label_48;
label_68:
    // EBPF_OP_MOV64_IMM pc=1452 dst=r1 src=r0 offset=0 imm=0
#line 154 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1453 dst=r10 src=r1 offset=-4 imm=0
#line 137 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1454 dst=r2 src=r10 offset=0 imm=0
#line 137 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1455 dst=r2 src=r0 offset=0 imm=-4
#line 137 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1456 dst=r1 src=r0 offset=0 imm=0
#line 137 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=1458 dst=r0 src=r0 offset=0 imm=18
#line 137 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 137 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 137 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 137 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1459 dst=r7 src=r0 offset=0 imm=0
#line 137 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1460 dst=r4 src=r7 offset=0 imm=0
#line 137 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=1461 dst=r4 src=r0 offset=0 imm=32
#line 137 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1462 dst=r1 src=r4 offset=0 imm=0
#line 137 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1463 dst=r1 src=r0 offset=0 imm=32
#line 137 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1464 dst=r2 src=r0 offset=0 imm=-7
#line 137 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1466 dst=r1 src=r2 offset=27 imm=0
#line 137 "sample/map.c"
    if (r1 == r2)
#line 137 "sample/map.c"
        goto label_71;
label_69:
    // EBPF_OP_MOV64_IMM pc=1467 dst=r1 src=r0 offset=0 imm=100
#line 137 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=1468 dst=r10 src=r1 offset=-16 imm=0
#line 137 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=1469 dst=r1 src=r0 offset=0 imm=1852994932
#line 137 "sample/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=1471 dst=r10 src=r1 offset=-24 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1472 dst=r1 src=r0 offset=0 imm=622883948
#line 137 "sample/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=1474 dst=r10 src=r1 offset=-32 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1475 dst=r1 src=r0 offset=0 imm=543649385
#line 137 "sample/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=1477 dst=r10 src=r1 offset=-40 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1478 dst=r1 src=r0 offset=0 imm=2019893357
#line 137 "sample/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=1480 dst=r10 src=r1 offset=-48 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1481 dst=r1 src=r0 offset=0 imm=1801807216
#line 137 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1483 dst=r10 src=r1 offset=-56 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1484 dst=r1 src=r0 offset=0 imm=1600548962
#line 137 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1486 dst=r10 src=r1 offset=-64 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1487 dst=r4 src=r0 offset=0 imm=32
#line 137 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1488 dst=r1 src=r10 offset=0 imm=0
#line 137 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1489 dst=r1 src=r0 offset=0 imm=-64
#line 137 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1490 dst=r2 src=r0 offset=0 imm=50
#line 137 "sample/map.c"
    r2 = IMMEDIATE(50);
label_70:
    // EBPF_OP_MOV64_IMM pc=1491 dst=r3 src=r0 offset=0 imm=-7
#line 137 "sample/map.c"
    r3 = IMMEDIATE(-7);
    // EBPF_OP_CALL pc=1492 dst=r0 src=r0 offset=0 imm=14
#line 137 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 137 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 137 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 137 "sample/map.c"
        return 0;
        // EBPF_OP_JA pc=1493 dst=r0 src=r0 offset=26 imm=0
#line 137 "sample/map.c"
    goto label_75;
label_71:
    // EBPF_OP_LDXW pc=1494 dst=r3 src=r10 offset=-4 imm=0
#line 137 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1495 dst=r3 src=r0 offset=50 imm=0
#line 137 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 137 "sample/map.c"
        goto label_76;
label_72:
    // EBPF_OP_LDDW pc=1496 dst=r1 src=r0 offset=0 imm=1852404835
#line 137 "sample/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=1498 dst=r10 src=r1 offset=-32 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1499 dst=r1 src=r0 offset=0 imm=543434016
#line 137 "sample/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=1501 dst=r10 src=r1 offset=-40 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1502 dst=r1 src=r0 offset=0 imm=1701978221
#line 137 "sample/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=1504 dst=r10 src=r1 offset=-48 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1505 dst=r1 src=r0 offset=0 imm=1801807216
#line 137 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1507 dst=r10 src=r1 offset=-56 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1508 dst=r1 src=r0 offset=0 imm=1600548962
#line 137 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1510 dst=r10 src=r1 offset=-64 imm=0
#line 137 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=1511 dst=r1 src=r0 offset=0 imm=0
#line 137 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1512 dst=r10 src=r1 offset=-24 imm=0
#line 137 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint8_t)r1;
    // EBPF_OP_MOV64_REG pc=1513 dst=r1 src=r10 offset=0 imm=0
#line 137 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1514 dst=r1 src=r0 offset=0 imm=-64
#line 137 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1515 dst=r2 src=r0 offset=0 imm=41
#line 137 "sample/map.c"
    r2 = IMMEDIATE(41);
label_73:
    // EBPF_OP_MOV64_IMM pc=1516 dst=r4 src=r0 offset=0 imm=0
#line 137 "sample/map.c"
    r4 = IMMEDIATE(0);
label_74:
    // EBPF_OP_CALL pc=1517 dst=r0 src=r0 offset=0 imm=14
#line 137 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 137 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 137 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 137 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=1518 dst=r7 src=r0 offset=0 imm=-1
#line 137 "sample/map.c"
    r7 = (uint64_t)4294967295;
label_75:
    // EBPF_OP_MOV64_IMM pc=1520 dst=r6 src=r0 offset=0 imm=0
#line 137 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_MOV64_REG pc=1521 dst=r3 src=r7 offset=0 imm=0
#line 187 "sample/map.c"
    r3 = r7;
    // EBPF_OP_LSH64_IMM pc=1522 dst=r3 src=r0 offset=0 imm=32
#line 187 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=1523 dst=r3 src=r0 offset=0 imm=32
#line 187 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=1524 dst=r3 src=r0 offset=-1423 imm=-1
#line 187 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 187 "sample/map.c"
        goto label_6;
        // EBPF_OP_LDDW pc=1525 dst=r1 src=r0 offset=0 imm=1684369010
#line 187 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=1527 dst=r10 src=r1 offset=-32 imm=0
#line 187 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1528 dst=r1 src=r0 offset=0 imm=541803329
#line 187 "sample/map.c"
    r1 = (uint64_t)8463501140578485057;
    // EBPF_OP_STXDW pc=1530 dst=r10 src=r1 offset=-40 imm=0
#line 187 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1531 dst=r1 src=r0 offset=0 imm=1634541682
#line 187 "sample/map.c"
    r1 = (uint64_t)6076235989295898738;
    // EBPF_OP_STXDW pc=1533 dst=r10 src=r1 offset=-48 imm=0
#line 187 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1534 dst=r1 src=r0 offset=0 imm=1330667336
#line 187 "sample/map.c"
    r1 = (uint64_t)8027138915134627656;
    // EBPF_OP_STXDW pc=1536 dst=r10 src=r1 offset=-56 imm=0
#line 187 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1537 dst=r1 src=r0 offset=0 imm=1953719636
#line 187 "sample/map.c"
    r1 = (uint64_t)6004793778491319636;
    // EBPF_OP_STXDW pc=1539 dst=r10 src=r1 offset=-64 imm=0
#line 187 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1540 dst=r1 src=r10 offset=0 imm=0
#line 187 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1541 dst=r1 src=r0 offset=0 imm=-64
#line 187 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1542 dst=r2 src=r0 offset=0 imm=40
#line 187 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_CALL pc=1543 dst=r0 src=r0 offset=0 imm=13
#line 187 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 187 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 187 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 187 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1544 dst=r6 src=r7 offset=0 imm=0
#line 187 "sample/map.c"
    r6 = r7;
    // EBPF_OP_JA pc=1545 dst=r0 src=r0 offset=-1444 imm=0
#line 187 "sample/map.c"
    goto label_6;
label_76:
    // EBPF_OP_MOV64_IMM pc=1546 dst=r6 src=r0 offset=0 imm=0
#line 187 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1547 dst=r10 src=r6 offset=-4 imm=0
#line 138 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=1548 dst=r2 src=r10 offset=0 imm=0
#line 138 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1549 dst=r2 src=r0 offset=0 imm=-4
#line 138 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1550 dst=r1 src=r0 offset=0 imm=0
#line 138 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=1552 dst=r0 src=r0 offset=0 imm=17
#line 138 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 138 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 138 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 138 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1553 dst=r7 src=r0 offset=0 imm=0
#line 138 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1554 dst=r4 src=r7 offset=0 imm=0
#line 138 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=1555 dst=r4 src=r0 offset=0 imm=32
#line 138 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1556 dst=r1 src=r4 offset=0 imm=0
#line 138 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1557 dst=r1 src=r0 offset=0 imm=32
#line 138 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1558 dst=r2 src=r0 offset=0 imm=-7
#line 138 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1560 dst=r1 src=r2 offset=24 imm=0
#line 138 "sample/map.c"
    if (r1 == r2)
#line 138 "sample/map.c"
        goto label_78;
label_77:
    // EBPF_OP_STXB pc=1561 dst=r10 src=r6 offset=-16 imm=0
#line 138 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint8_t)r6;
    // EBPF_OP_LDDW pc=1562 dst=r1 src=r0 offset=0 imm=1701737077
#line 138 "sample/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=1564 dst=r10 src=r1 offset=-24 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1565 dst=r1 src=r0 offset=0 imm=1680154740
#line 138 "sample/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=1567 dst=r10 src=r1 offset=-32 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1568 dst=r1 src=r0 offset=0 imm=1914726254
#line 138 "sample/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=1570 dst=r10 src=r1 offset=-40 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1571 dst=r1 src=r0 offset=0 imm=1886938400
#line 138 "sample/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=1573 dst=r10 src=r1 offset=-48 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1574 dst=r1 src=r0 offset=0 imm=1601204080
#line 138 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1576 dst=r10 src=r1 offset=-56 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1577 dst=r1 src=r0 offset=0 imm=1600548962
#line 138 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1579 dst=r10 src=r1 offset=-64 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1580 dst=r4 src=r0 offset=0 imm=32
#line 138 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1581 dst=r1 src=r10 offset=0 imm=0
#line 138 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1582 dst=r1 src=r0 offset=0 imm=-64
#line 138 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1583 dst=r2 src=r0 offset=0 imm=49
#line 138 "sample/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=1584 dst=r0 src=r0 offset=-94 imm=0
#line 138 "sample/map.c"
    goto label_70;
label_78:
    // EBPF_OP_LDXW pc=1585 dst=r3 src=r10 offset=-4 imm=0
#line 138 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1586 dst=r3 src=r0 offset=19 imm=0
#line 138 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 138 "sample/map.c"
        goto label_80;
label_79:
    // EBPF_OP_LDDW pc=1587 dst=r1 src=r0 offset=0 imm=1735289204
#line 138 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1589 dst=r10 src=r1 offset=-32 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1590 dst=r1 src=r0 offset=0 imm=1696621605
#line 138 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1592 dst=r10 src=r1 offset=-40 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1593 dst=r1 src=r0 offset=0 imm=1952805408
#line 138 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1595 dst=r10 src=r1 offset=-48 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1596 dst=r1 src=r0 offset=0 imm=1601204080
#line 138 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1598 dst=r10 src=r1 offset=-56 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1599 dst=r1 src=r0 offset=0 imm=1600548962
#line 138 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1601 dst=r10 src=r1 offset=-64 imm=0
#line 138 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1602 dst=r1 src=r10 offset=0 imm=0
#line 138 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1603 dst=r1 src=r0 offset=0 imm=-64
#line 138 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1604 dst=r2 src=r0 offset=0 imm=40
#line 138 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_JA pc=1605 dst=r0 src=r0 offset=-90 imm=0
#line 138 "sample/map.c"
    goto label_73;
label_80:
    // EBPF_OP_MOV64_IMM pc=1606 dst=r6 src=r0 offset=0 imm=0
#line 138 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1607 dst=r10 src=r6 offset=-4 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=1608 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1609 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1610 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=1612 dst=r3 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1613 dst=r0 src=r0 offset=0 imm=16
#line 141 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1614 dst=r7 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1615 dst=r1 src=r7 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1616 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1617 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1618 dst=r1 src=r0 offset=33 imm=0
#line 141 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 141 "sample/map.c"
        goto label_84;
label_81:
    // EBPF_OP_MOV64_IMM pc=1619 dst=r1 src=r0 offset=0 imm=25637
#line 141 "sample/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1620 dst=r10 src=r1 offset=-12 imm=0
#line 141 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1621 dst=r1 src=r0 offset=0 imm=543450478
#line 141 "sample/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1622 dst=r10 src=r1 offset=-16 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1623 dst=r1 src=r0 offset=0 imm=1914725413
#line 141 "sample/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1625 dst=r10 src=r1 offset=-24 imm=0
#line 141 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1626 dst=r1 src=r0 offset=0 imm=1667592312
#line 141 "sample/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1628 dst=r10 src=r1 offset=-32 imm=0
#line 141 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1629 dst=r1 src=r0 offset=0 imm=543649385
#line 141 "sample/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1631 dst=r10 src=r1 offset=-40 imm=0
#line 141 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1632 dst=r1 src=r0 offset=0 imm=1852383341
#line 141 "sample/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1634 dst=r10 src=r1 offset=-48 imm=0
#line 141 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1635 dst=r1 src=r0 offset=0 imm=1752397168
#line 141 "sample/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1637 dst=r10 src=r1 offset=-56 imm=0
#line 141 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1638 dst=r1 src=r0 offset=0 imm=1600548962
#line 141 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1640 dst=r10 src=r1 offset=-64 imm=0
#line 141 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_STXB pc=1641 dst=r10 src=r6 offset=-10 imm=0
#line 141 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-10)) = (uint8_t)r6;
    // EBPF_OP_LDXW pc=1642 dst=r3 src=r10 offset=-4 imm=0
#line 141 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=1643 dst=r5 src=r7 offset=0 imm=0
#line 141 "sample/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=1644 dst=r5 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r5 <<= IMMEDIATE(32);
label_82:
    // EBPF_OP_ARSH64_IMM pc=1645 dst=r5 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r5 = (int64_t)r5 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1646 dst=r1 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1647 dst=r1 src=r0 offset=0 imm=-64
#line 141 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1648 dst=r2 src=r0 offset=0 imm=55
#line 141 "sample/map.c"
    r2 = IMMEDIATE(55);
    // EBPF_OP_MOV64_IMM pc=1649 dst=r4 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r4 = IMMEDIATE(0);
label_83:
    // EBPF_OP_CALL pc=1650 dst=r0 src=r0 offset=0 imm=15
#line 141 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_JA pc=1651 dst=r0 src=r0 offset=-132 imm=0
#line 141 "sample/map.c"
    goto label_75;
label_84:
    // EBPF_OP_MOV64_IMM pc=1652 dst=r1 src=r0 offset=0 imm=1
#line 141 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=1653 dst=r10 src=r1 offset=-4 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1654 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1655 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1656 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=1658 dst=r3 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1659 dst=r0 src=r0 offset=0 imm=16
#line 141 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1660 dst=r7 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1661 dst=r1 src=r7 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1662 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1663 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1664 dst=r1 src=r0 offset=1 imm=0
#line 141 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 141 "sample/map.c"
        goto label_85;
        // EBPF_OP_JA pc=1665 dst=r0 src=r0 offset=-47 imm=0
#line 141 "sample/map.c"
    goto label_81;
label_85:
    // EBPF_OP_MOV64_IMM pc=1666 dst=r1 src=r0 offset=0 imm=2
#line 141 "sample/map.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=1667 dst=r10 src=r1 offset=-4 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1668 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1669 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1670 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=1672 dst=r3 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1673 dst=r0 src=r0 offset=0 imm=16
#line 141 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1674 dst=r7 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1675 dst=r1 src=r7 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1676 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1677 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1678 dst=r1 src=r0 offset=-60 imm=0
#line 141 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 141 "sample/map.c"
        goto label_81;
        // EBPF_OP_MOV64_IMM pc=1679 dst=r1 src=r0 offset=0 imm=3
#line 141 "sample/map.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=1680 dst=r10 src=r1 offset=-4 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1681 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1682 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1683 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=1685 dst=r3 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1686 dst=r0 src=r0 offset=0 imm=16
#line 141 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1687 dst=r7 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1688 dst=r1 src=r7 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1689 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1690 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1691 dst=r1 src=r0 offset=-73 imm=0
#line 141 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 141 "sample/map.c"
        goto label_81;
        // EBPF_OP_MOV64_IMM pc=1692 dst=r1 src=r0 offset=0 imm=4
#line 141 "sample/map.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=1693 dst=r10 src=r1 offset=-4 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1694 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1695 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1696 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=1698 dst=r3 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1699 dst=r0 src=r0 offset=0 imm=16
#line 141 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1700 dst=r7 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1701 dst=r1 src=r7 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1702 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1703 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1704 dst=r1 src=r0 offset=-86 imm=0
#line 141 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 141 "sample/map.c"
        goto label_81;
        // EBPF_OP_MOV64_IMM pc=1705 dst=r1 src=r0 offset=0 imm=5
#line 141 "sample/map.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=1706 dst=r10 src=r1 offset=-4 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1707 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1708 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1709 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=1711 dst=r3 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1712 dst=r0 src=r0 offset=0 imm=16
#line 141 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1713 dst=r7 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1714 dst=r1 src=r7 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1715 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1716 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1717 dst=r1 src=r0 offset=-99 imm=0
#line 141 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 141 "sample/map.c"
        goto label_81;
        // EBPF_OP_MOV64_IMM pc=1718 dst=r1 src=r0 offset=0 imm=6
#line 141 "sample/map.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=1719 dst=r10 src=r1 offset=-4 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1720 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1721 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1722 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=1724 dst=r3 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1725 dst=r0 src=r0 offset=0 imm=16
#line 141 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1726 dst=r7 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1727 dst=r1 src=r7 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1728 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1729 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1730 dst=r1 src=r0 offset=-112 imm=0
#line 141 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 141 "sample/map.c"
        goto label_81;
        // EBPF_OP_MOV64_IMM pc=1731 dst=r1 src=r0 offset=0 imm=7
#line 141 "sample/map.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=1732 dst=r10 src=r1 offset=-4 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1733 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1734 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1735 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=1737 dst=r3 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1738 dst=r0 src=r0 offset=0 imm=16
#line 141 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1739 dst=r7 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1740 dst=r1 src=r7 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1741 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1742 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1743 dst=r1 src=r0 offset=-125 imm=0
#line 141 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 141 "sample/map.c"
        goto label_81;
        // EBPF_OP_MOV64_IMM pc=1744 dst=r1 src=r0 offset=0 imm=8
#line 141 "sample/map.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=1745 dst=r10 src=r1 offset=-4 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1746 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1747 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1748 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=1750 dst=r3 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1751 dst=r0 src=r0 offset=0 imm=16
#line 141 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1752 dst=r7 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1753 dst=r1 src=r7 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1754 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1755 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1756 dst=r1 src=r0 offset=-138 imm=0
#line 141 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 141 "sample/map.c"
        goto label_81;
        // EBPF_OP_MOV64_IMM pc=1757 dst=r1 src=r0 offset=0 imm=9
#line 141 "sample/map.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=1758 dst=r10 src=r1 offset=-4 imm=0
#line 141 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1759 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1760 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1761 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=1763 dst=r3 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1764 dst=r0 src=r0 offset=0 imm=16
#line 141 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 141 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 141 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1765 dst=r7 src=r0 offset=0 imm=0
#line 141 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1766 dst=r1 src=r7 offset=0 imm=0
#line 141 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1767 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1768 dst=r1 src=r0 offset=0 imm=32
#line 141 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1769 dst=r1 src=r0 offset=-151 imm=0
#line 141 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 141 "sample/map.c"
        goto label_81;
        // EBPF_OP_MOV64_IMM pc=1770 dst=r6 src=r0 offset=0 imm=10
#line 141 "sample/map.c"
    r6 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=1771 dst=r10 src=r6 offset=-4 imm=0
#line 144 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=1772 dst=r2 src=r10 offset=0 imm=0
#line 144 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1773 dst=r2 src=r0 offset=0 imm=-4
#line 144 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=1774 dst=r8 src=r0 offset=0 imm=0
#line 144 "sample/map.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=1775 dst=r1 src=r0 offset=0 imm=0
#line 144 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=1777 dst=r3 src=r0 offset=0 imm=0
#line 144 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1778 dst=r0 src=r0 offset=0 imm=16
#line 144 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 144 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 144 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 144 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1779 dst=r7 src=r0 offset=0 imm=0
#line 144 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1780 dst=r5 src=r7 offset=0 imm=0
#line 144 "sample/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=1781 dst=r5 src=r0 offset=0 imm=32
#line 144 "sample/map.c"
    r5 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1782 dst=r1 src=r5 offset=0 imm=0
#line 144 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1783 dst=r1 src=r0 offset=0 imm=32
#line 144 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1784 dst=r2 src=r0 offset=0 imm=-29
#line 144 "sample/map.c"
    r2 = (uint64_t)4294967267;
    // EBPF_OP_JEQ_REG pc=1786 dst=r1 src=r2 offset=30 imm=0
#line 144 "sample/map.c"
    if (r1 == r2)
#line 144 "sample/map.c"
        goto label_86;
        // EBPF_OP_STXB pc=1787 dst=r10 src=r8 offset=-10 imm=0
#line 144 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-10)) = (uint8_t)r8;
    // EBPF_OP_MOV64_IMM pc=1788 dst=r1 src=r0 offset=0 imm=25637
#line 144 "sample/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1789 dst=r10 src=r1 offset=-12 imm=0
#line 144 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1790 dst=r1 src=r0 offset=0 imm=543450478
#line 144 "sample/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1791 dst=r10 src=r1 offset=-16 imm=0
#line 144 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1792 dst=r1 src=r0 offset=0 imm=1914725413
#line 144 "sample/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1794 dst=r10 src=r1 offset=-24 imm=0
#line 144 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1795 dst=r1 src=r0 offset=0 imm=1667592312
#line 144 "sample/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1797 dst=r10 src=r1 offset=-32 imm=0
#line 144 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1798 dst=r1 src=r0 offset=0 imm=543649385
#line 144 "sample/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1800 dst=r10 src=r1 offset=-40 imm=0
#line 144 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1801 dst=r1 src=r0 offset=0 imm=1852383341
#line 144 "sample/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1803 dst=r10 src=r1 offset=-48 imm=0
#line 144 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1804 dst=r1 src=r0 offset=0 imm=1752397168
#line 144 "sample/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1806 dst=r10 src=r1 offset=-56 imm=0
#line 144 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1807 dst=r1 src=r0 offset=0 imm=1600548962
#line 144 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1809 dst=r10 src=r1 offset=-64 imm=0
#line 144 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=1810 dst=r3 src=r10 offset=-4 imm=0
#line 144 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ARSH64_IMM pc=1811 dst=r5 src=r0 offset=0 imm=32
#line 144 "sample/map.c"
    r5 = (int64_t)r5 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1812 dst=r1 src=r10 offset=0 imm=0
#line 144 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1813 dst=r1 src=r0 offset=0 imm=-64
#line 144 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1814 dst=r2 src=r0 offset=0 imm=55
#line 144 "sample/map.c"
    r2 = IMMEDIATE(55);
    // EBPF_OP_MOV64_IMM pc=1815 dst=r4 src=r0 offset=0 imm=-29
#line 144 "sample/map.c"
    r4 = IMMEDIATE(-29);
    // EBPF_OP_JA pc=1816 dst=r0 src=r0 offset=-167 imm=0
#line 144 "sample/map.c"
    goto label_83;
label_86:
    // EBPF_OP_STXW pc=1817 dst=r10 src=r6 offset=-4 imm=0
#line 145 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=1818 dst=r2 src=r10 offset=0 imm=0
#line 145 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1819 dst=r2 src=r0 offset=0 imm=-4
#line 145 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1820 dst=r1 src=r0 offset=0 imm=0
#line 145 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=1822 dst=r3 src=r0 offset=0 imm=2
#line 145 "sample/map.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_CALL pc=1823 dst=r0 src=r0 offset=0 imm=16
#line 145 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 145 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 145 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 145 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1824 dst=r7 src=r0 offset=0 imm=0
#line 145 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1825 dst=r5 src=r7 offset=0 imm=0
#line 145 "sample/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=1826 dst=r5 src=r0 offset=0 imm=32
#line 145 "sample/map.c"
    r5 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1827 dst=r1 src=r5 offset=0 imm=0
#line 145 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1828 dst=r1 src=r0 offset=0 imm=32
#line 145 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1829 dst=r1 src=r0 offset=26 imm=0
#line 145 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 145 "sample/map.c"
        goto label_87;
        // EBPF_OP_MOV64_IMM pc=1830 dst=r1 src=r0 offset=0 imm=25637
#line 145 "sample/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1831 dst=r10 src=r1 offset=-12 imm=0
#line 145 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1832 dst=r1 src=r0 offset=0 imm=543450478
#line 145 "sample/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1833 dst=r10 src=r1 offset=-16 imm=0
#line 145 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1834 dst=r1 src=r0 offset=0 imm=1914725413
#line 145 "sample/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1836 dst=r10 src=r1 offset=-24 imm=0
#line 145 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1837 dst=r1 src=r0 offset=0 imm=1667592312
#line 145 "sample/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1839 dst=r10 src=r1 offset=-32 imm=0
#line 145 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1840 dst=r1 src=r0 offset=0 imm=543649385
#line 145 "sample/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1842 dst=r10 src=r1 offset=-40 imm=0
#line 145 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1843 dst=r1 src=r0 offset=0 imm=1852383341
#line 145 "sample/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1845 dst=r10 src=r1 offset=-48 imm=0
#line 145 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1846 dst=r1 src=r0 offset=0 imm=1752397168
#line 145 "sample/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1848 dst=r10 src=r1 offset=-56 imm=0
#line 145 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1849 dst=r1 src=r0 offset=0 imm=1600548962
#line 145 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1851 dst=r10 src=r1 offset=-64 imm=0
#line 145 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=1852 dst=r1 src=r0 offset=0 imm=0
#line 145 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1853 dst=r10 src=r1 offset=-10 imm=0
#line 145 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-10)) = (uint8_t)r1;
    // EBPF_OP_LDXW pc=1854 dst=r3 src=r10 offset=-4 imm=0
#line 145 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JA pc=1855 dst=r0 src=r0 offset=-211 imm=0
#line 145 "sample/map.c"
    goto label_82;
label_87:
    // EBPF_OP_MOV64_IMM pc=1856 dst=r1 src=r0 offset=0 imm=0
#line 145 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1857 dst=r10 src=r1 offset=-4 imm=0
#line 147 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1858 dst=r2 src=r10 offset=0 imm=0
#line 147 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1859 dst=r2 src=r0 offset=0 imm=-4
#line 147 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1860 dst=r1 src=r0 offset=0 imm=0
#line 147 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=1862 dst=r0 src=r0 offset=0 imm=18
#line 147 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 147 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 147 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 147 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1863 dst=r7 src=r0 offset=0 imm=0
#line 147 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1864 dst=r4 src=r7 offset=0 imm=0
#line 147 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=1865 dst=r4 src=r0 offset=0 imm=32
#line 147 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1866 dst=r1 src=r4 offset=0 imm=0
#line 147 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1867 dst=r1 src=r0 offset=0 imm=32
#line 147 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1868 dst=r1 src=r0 offset=27 imm=0
#line 147 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 147 "sample/map.c"
        goto label_89;
        // EBPF_OP_MOV64_IMM pc=1869 dst=r1 src=r0 offset=0 imm=100
#line 147 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=1870 dst=r10 src=r1 offset=-16 imm=0
#line 147 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=1871 dst=r1 src=r0 offset=0 imm=1852994932
#line 147 "sample/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=1873 dst=r10 src=r1 offset=-24 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1874 dst=r1 src=r0 offset=0 imm=622883948
#line 147 "sample/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=1876 dst=r10 src=r1 offset=-32 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1877 dst=r1 src=r0 offset=0 imm=543649385
#line 147 "sample/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=1879 dst=r10 src=r1 offset=-40 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1880 dst=r1 src=r0 offset=0 imm=2019893357
#line 147 "sample/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=1882 dst=r10 src=r1 offset=-48 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1883 dst=r1 src=r0 offset=0 imm=1801807216
#line 147 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1885 dst=r10 src=r1 offset=-56 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1886 dst=r1 src=r0 offset=0 imm=1600548962
#line 147 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1888 dst=r10 src=r1 offset=-64 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1889 dst=r4 src=r0 offset=0 imm=32
#line 147 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1890 dst=r1 src=r10 offset=0 imm=0
#line 147 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1891 dst=r1 src=r0 offset=0 imm=-64
#line 147 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1892 dst=r2 src=r0 offset=0 imm=50
#line 147 "sample/map.c"
    r2 = IMMEDIATE(50);
label_88:
    // EBPF_OP_MOV64_IMM pc=1893 dst=r3 src=r0 offset=0 imm=0
#line 147 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1894 dst=r0 src=r0 offset=0 imm=14
#line 147 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 147 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 147 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 147 "sample/map.c"
        return 0;
        // EBPF_OP_JA pc=1895 dst=r0 src=r0 offset=-376 imm=0
#line 147 "sample/map.c"
    goto label_75;
label_89:
    // EBPF_OP_LDXW pc=1896 dst=r3 src=r10 offset=-4 imm=0
#line 147 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1897 dst=r3 src=r0 offset=22 imm=10
#line 147 "sample/map.c"
    if (r3 == IMMEDIATE(10))
#line 147 "sample/map.c"
        goto label_90;
        // EBPF_OP_MOV64_IMM pc=1898 dst=r1 src=r0 offset=0 imm=0
#line 147 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1899 dst=r10 src=r1 offset=-24 imm=0
#line 147 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=1900 dst=r1 src=r0 offset=0 imm=1852404835
#line 147 "sample/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=1902 dst=r10 src=r1 offset=-32 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1903 dst=r1 src=r0 offset=0 imm=543434016
#line 147 "sample/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=1905 dst=r10 src=r1 offset=-40 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1906 dst=r1 src=r0 offset=0 imm=1701978221
#line 147 "sample/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=1908 dst=r10 src=r1 offset=-48 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1909 dst=r1 src=r0 offset=0 imm=1801807216
#line 147 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1911 dst=r10 src=r1 offset=-56 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1912 dst=r1 src=r0 offset=0 imm=1600548962
#line 147 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1914 dst=r10 src=r1 offset=-64 imm=0
#line 147 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1915 dst=r1 src=r10 offset=0 imm=0
#line 147 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1916 dst=r1 src=r0 offset=0 imm=-64
#line 147 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1917 dst=r2 src=r0 offset=0 imm=41
#line 147 "sample/map.c"
    r2 = IMMEDIATE(41);
    // EBPF_OP_MOV64_IMM pc=1918 dst=r4 src=r0 offset=0 imm=10
#line 147 "sample/map.c"
    r4 = IMMEDIATE(10);
    // EBPF_OP_JA pc=1919 dst=r0 src=r0 offset=-403 imm=0
#line 147 "sample/map.c"
    goto label_74;
label_90:
    // EBPF_OP_MOV64_IMM pc=1920 dst=r6 src=r0 offset=0 imm=0
#line 147 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1921 dst=r10 src=r6 offset=-4 imm=0
#line 150 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=1922 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1923 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1924 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=1926 dst=r0 src=r0 offset=0 imm=17
#line 150 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 150 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 150 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1927 dst=r7 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1928 dst=r1 src=r7 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1929 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1930 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1931 dst=r1 src=r0 offset=26 imm=0
#line 150 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 150 "sample/map.c"
        goto label_92;
label_91:
    // EBPF_OP_LDDW pc=1932 dst=r1 src=r0 offset=0 imm=1701737077
#line 150 "sample/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=1934 dst=r10 src=r1 offset=-24 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1935 dst=r1 src=r0 offset=0 imm=1680154740
#line 150 "sample/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=1937 dst=r10 src=r1 offset=-32 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1938 dst=r1 src=r0 offset=0 imm=1914726254
#line 150 "sample/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=1940 dst=r10 src=r1 offset=-40 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1941 dst=r1 src=r0 offset=0 imm=1886938400
#line 150 "sample/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=1943 dst=r10 src=r1 offset=-48 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1944 dst=r1 src=r0 offset=0 imm=1601204080
#line 150 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1946 dst=r10 src=r1 offset=-56 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1947 dst=r1 src=r0 offset=0 imm=1600548962
#line 150 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1949 dst=r10 src=r1 offset=-64 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_STXB pc=1950 dst=r10 src=r6 offset=-16 imm=0
#line 150 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint8_t)r6;
    // EBPF_OP_MOV64_REG pc=1951 dst=r4 src=r7 offset=0 imm=0
#line 150 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=1952 dst=r4 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=1953 dst=r4 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1954 dst=r1 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1955 dst=r1 src=r0 offset=0 imm=-64
#line 150 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1956 dst=r2 src=r0 offset=0 imm=49
#line 150 "sample/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=1957 dst=r0 src=r0 offset=-65 imm=0
#line 150 "sample/map.c"
    goto label_88;
label_92:
    // EBPF_OP_MOV64_IMM pc=1958 dst=r4 src=r0 offset=0 imm=10
#line 150 "sample/map.c"
    r4 = IMMEDIATE(10);
    // EBPF_OP_LDXW pc=1959 dst=r3 src=r10 offset=-4 imm=0
#line 150 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1960 dst=r3 src=r0 offset=19 imm=10
#line 150 "sample/map.c"
    if (r3 == IMMEDIATE(10))
#line 150 "sample/map.c"
        goto label_94;
label_93:
    // EBPF_OP_LDDW pc=1961 dst=r1 src=r0 offset=0 imm=1735289204
#line 150 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1963 dst=r10 src=r1 offset=-32 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1964 dst=r1 src=r0 offset=0 imm=1696621605
#line 150 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1966 dst=r10 src=r1 offset=-40 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1967 dst=r1 src=r0 offset=0 imm=1952805408
#line 150 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1969 dst=r10 src=r1 offset=-48 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1970 dst=r1 src=r0 offset=0 imm=1601204080
#line 150 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1972 dst=r10 src=r1 offset=-56 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1973 dst=r1 src=r0 offset=0 imm=1600548962
#line 150 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1975 dst=r10 src=r1 offset=-64 imm=0
#line 150 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1976 dst=r1 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1977 dst=r1 src=r0 offset=0 imm=-64
#line 150 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1978 dst=r2 src=r0 offset=0 imm=40
#line 150 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_JA pc=1979 dst=r0 src=r0 offset=-463 imm=0
#line 150 "sample/map.c"
    goto label_74;
label_94:
    // EBPF_OP_MOV64_IMM pc=1980 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1981 dst=r10 src=r1 offset=-4 imm=0
#line 150 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1982 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1983 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1984 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=1986 dst=r0 src=r0 offset=0 imm=17
#line 150 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 150 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 150 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1987 dst=r7 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1988 dst=r1 src=r7 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1989 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1990 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1991 dst=r1 src=r0 offset=1 imm=0
#line 150 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 150 "sample/map.c"
        goto label_95;
        // EBPF_OP_JA pc=1992 dst=r0 src=r0 offset=-61 imm=0
#line 150 "sample/map.c"
    goto label_91;
label_95:
    // EBPF_OP_MOV64_IMM pc=1993 dst=r4 src=r0 offset=0 imm=9
#line 150 "sample/map.c"
    r4 = IMMEDIATE(9);
    // EBPF_OP_LDXW pc=1994 dst=r3 src=r10 offset=-4 imm=0
#line 150 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1995 dst=r3 src=r0 offset=-35 imm=9
#line 150 "sample/map.c"
    if (r3 != IMMEDIATE(9))
#line 150 "sample/map.c"
        goto label_93;
        // EBPF_OP_MOV64_IMM pc=1996 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1997 dst=r10 src=r1 offset=-4 imm=0
#line 150 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1998 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1999 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2000 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=2002 dst=r0 src=r0 offset=0 imm=17
#line 150 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 150 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 150 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2003 dst=r7 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2004 dst=r1 src=r7 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=2005 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=2006 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=2007 dst=r1 src=r0 offset=-76 imm=0
#line 150 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 150 "sample/map.c"
        goto label_91;
        // EBPF_OP_MOV64_IMM pc=2008 dst=r4 src=r0 offset=0 imm=8
#line 150 "sample/map.c"
    r4 = IMMEDIATE(8);
    // EBPF_OP_LDXW pc=2009 dst=r3 src=r10 offset=-4 imm=0
#line 150 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=2010 dst=r3 src=r0 offset=-50 imm=8
#line 150 "sample/map.c"
    if (r3 != IMMEDIATE(8))
#line 150 "sample/map.c"
        goto label_93;
        // EBPF_OP_MOV64_IMM pc=2011 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2012 dst=r10 src=r1 offset=-4 imm=0
#line 150 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2013 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2014 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2015 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=2017 dst=r0 src=r0 offset=0 imm=17
#line 150 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 150 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 150 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2018 dst=r7 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2019 dst=r1 src=r7 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=2020 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=2021 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=2022 dst=r1 src=r0 offset=-91 imm=0
#line 150 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 150 "sample/map.c"
        goto label_91;
        // EBPF_OP_MOV64_IMM pc=2023 dst=r4 src=r0 offset=0 imm=7
#line 150 "sample/map.c"
    r4 = IMMEDIATE(7);
    // EBPF_OP_LDXW pc=2024 dst=r3 src=r10 offset=-4 imm=0
#line 150 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=2025 dst=r3 src=r0 offset=-65 imm=7
#line 150 "sample/map.c"
    if (r3 != IMMEDIATE(7))
#line 150 "sample/map.c"
        goto label_93;
        // EBPF_OP_MOV64_IMM pc=2026 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2027 dst=r10 src=r1 offset=-4 imm=0
#line 150 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2028 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2029 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2030 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=2032 dst=r0 src=r0 offset=0 imm=17
#line 150 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 150 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 150 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2033 dst=r7 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2034 dst=r1 src=r7 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=2035 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=2036 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=2037 dst=r1 src=r0 offset=-106 imm=0
#line 150 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 150 "sample/map.c"
        goto label_91;
        // EBPF_OP_MOV64_IMM pc=2038 dst=r4 src=r0 offset=0 imm=6
#line 150 "sample/map.c"
    r4 = IMMEDIATE(6);
    // EBPF_OP_LDXW pc=2039 dst=r3 src=r10 offset=-4 imm=0
#line 150 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=2040 dst=r3 src=r0 offset=-80 imm=6
#line 150 "sample/map.c"
    if (r3 != IMMEDIATE(6))
#line 150 "sample/map.c"
        goto label_93;
        // EBPF_OP_MOV64_IMM pc=2041 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2042 dst=r10 src=r1 offset=-4 imm=0
#line 150 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2043 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2044 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2045 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=2047 dst=r0 src=r0 offset=0 imm=17
#line 150 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 150 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 150 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2048 dst=r7 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2049 dst=r1 src=r7 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=2050 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=2051 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=2052 dst=r1 src=r0 offset=-121 imm=0
#line 150 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 150 "sample/map.c"
        goto label_91;
        // EBPF_OP_MOV64_IMM pc=2053 dst=r4 src=r0 offset=0 imm=5
#line 150 "sample/map.c"
    r4 = IMMEDIATE(5);
    // EBPF_OP_LDXW pc=2054 dst=r3 src=r10 offset=-4 imm=0
#line 150 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=2055 dst=r3 src=r0 offset=-95 imm=5
#line 150 "sample/map.c"
    if (r3 != IMMEDIATE(5))
#line 150 "sample/map.c"
        goto label_93;
        // EBPF_OP_MOV64_IMM pc=2056 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2057 dst=r10 src=r1 offset=-4 imm=0
#line 150 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2058 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2059 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2060 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=2062 dst=r0 src=r0 offset=0 imm=17
#line 150 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 150 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 150 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2063 dst=r7 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2064 dst=r1 src=r7 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=2065 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=2066 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=2067 dst=r1 src=r0 offset=-136 imm=0
#line 150 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 150 "sample/map.c"
        goto label_91;
        // EBPF_OP_MOV64_IMM pc=2068 dst=r4 src=r0 offset=0 imm=4
#line 150 "sample/map.c"
    r4 = IMMEDIATE(4);
    // EBPF_OP_LDXW pc=2069 dst=r3 src=r10 offset=-4 imm=0
#line 150 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=2070 dst=r3 src=r0 offset=-110 imm=4
#line 150 "sample/map.c"
    if (r3 != IMMEDIATE(4))
#line 150 "sample/map.c"
        goto label_93;
        // EBPF_OP_MOV64_IMM pc=2071 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2072 dst=r10 src=r1 offset=-4 imm=0
#line 150 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2073 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2074 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2075 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=2077 dst=r0 src=r0 offset=0 imm=17
#line 150 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 150 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 150 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2078 dst=r7 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2079 dst=r1 src=r7 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=2080 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=2081 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=2082 dst=r1 src=r0 offset=-151 imm=0
#line 150 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 150 "sample/map.c"
        goto label_91;
        // EBPF_OP_MOV64_IMM pc=2083 dst=r4 src=r0 offset=0 imm=3
#line 150 "sample/map.c"
    r4 = IMMEDIATE(3);
    // EBPF_OP_LDXW pc=2084 dst=r3 src=r10 offset=-4 imm=0
#line 150 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=2085 dst=r3 src=r0 offset=-125 imm=3
#line 150 "sample/map.c"
    if (r3 != IMMEDIATE(3))
#line 150 "sample/map.c"
        goto label_93;
        // EBPF_OP_MOV64_IMM pc=2086 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2087 dst=r10 src=r1 offset=-4 imm=0
#line 150 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2088 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2089 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2090 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=2092 dst=r0 src=r0 offset=0 imm=17
#line 150 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 150 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 150 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2093 dst=r7 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2094 dst=r1 src=r7 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=2095 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=2096 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=2097 dst=r1 src=r0 offset=-166 imm=0
#line 150 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 150 "sample/map.c"
        goto label_91;
        // EBPF_OP_MOV64_IMM pc=2098 dst=r4 src=r0 offset=0 imm=2
#line 150 "sample/map.c"
    r4 = IMMEDIATE(2);
    // EBPF_OP_LDXW pc=2099 dst=r3 src=r10 offset=-4 imm=0
#line 150 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=2100 dst=r3 src=r0 offset=-140 imm=2
#line 150 "sample/map.c"
    if (r3 != IMMEDIATE(2))
#line 150 "sample/map.c"
        goto label_93;
        // EBPF_OP_MOV64_IMM pc=2101 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2102 dst=r10 src=r1 offset=-4 imm=0
#line 150 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2103 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2104 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2105 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=2107 dst=r0 src=r0 offset=0 imm=17
#line 150 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 150 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 150 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2108 dst=r7 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2109 dst=r1 src=r7 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=2110 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=2111 dst=r1 src=r0 offset=0 imm=32
#line 150 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=2112 dst=r1 src=r0 offset=-181 imm=0
#line 150 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 150 "sample/map.c"
        goto label_91;
        // EBPF_OP_MOV64_IMM pc=2113 dst=r4 src=r0 offset=0 imm=1
#line 150 "sample/map.c"
    r4 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=2114 dst=r3 src=r10 offset=-4 imm=0
#line 150 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=2115 dst=r3 src=r0 offset=-155 imm=1
#line 150 "sample/map.c"
    if (r3 != IMMEDIATE(1))
#line 150 "sample/map.c"
        goto label_93;
        // EBPF_OP_MOV64_IMM pc=2116 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2117 dst=r10 src=r1 offset=-4 imm=0
#line 153 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2118 dst=r2 src=r10 offset=0 imm=0
#line 153 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2119 dst=r2 src=r0 offset=0 imm=-4
#line 153 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2120 dst=r1 src=r0 offset=0 imm=0
#line 153 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=2122 dst=r0 src=r0 offset=0 imm=18
#line 153 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 153 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 153 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 153 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2123 dst=r7 src=r0 offset=0 imm=0
#line 153 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2124 dst=r4 src=r7 offset=0 imm=0
#line 153 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2125 dst=r4 src=r0 offset=0 imm=32
#line 153 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=2126 dst=r1 src=r4 offset=0 imm=0
#line 153 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2127 dst=r1 src=r0 offset=0 imm=32
#line 153 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=2128 dst=r2 src=r0 offset=0 imm=-7
#line 153 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=2130 dst=r1 src=r2 offset=1 imm=0
#line 153 "sample/map.c"
    if (r1 == r2)
#line 153 "sample/map.c"
        goto label_96;
        // EBPF_OP_JA pc=2131 dst=r0 src=r0 offset=-665 imm=0
#line 153 "sample/map.c"
    goto label_69;
label_96:
    // EBPF_OP_LDXW pc=2132 dst=r3 src=r10 offset=-4 imm=0
#line 153 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2133 dst=r3 src=r0 offset=1 imm=0
#line 153 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 153 "sample/map.c"
        goto label_97;
        // EBPF_OP_JA pc=2134 dst=r0 src=r0 offset=-639 imm=0
#line 153 "sample/map.c"
    goto label_72;
label_97:
    // EBPF_OP_MOV64_IMM pc=2135 dst=r6 src=r0 offset=0 imm=0
#line 153 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2136 dst=r10 src=r6 offset=-4 imm=0
#line 154 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2137 dst=r2 src=r10 offset=0 imm=0
#line 154 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2138 dst=r2 src=r0 offset=0 imm=-4
#line 154 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2139 dst=r1 src=r0 offset=0 imm=0
#line 154 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=2141 dst=r0 src=r0 offset=0 imm=17
#line 154 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 154 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 154 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 154 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2142 dst=r7 src=r0 offset=0 imm=0
#line 154 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2143 dst=r4 src=r7 offset=0 imm=0
#line 154 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2144 dst=r4 src=r0 offset=0 imm=32
#line 154 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=2145 dst=r1 src=r4 offset=0 imm=0
#line 154 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2146 dst=r1 src=r0 offset=0 imm=32
#line 154 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=2147 dst=r2 src=r0 offset=0 imm=-7
#line 154 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=2149 dst=r1 src=r2 offset=1 imm=0
#line 154 "sample/map.c"
    if (r1 == r2)
#line 154 "sample/map.c"
        goto label_98;
        // EBPF_OP_JA pc=2150 dst=r0 src=r0 offset=-590 imm=0
#line 154 "sample/map.c"
    goto label_77;
label_98:
    // EBPF_OP_LDXW pc=2151 dst=r3 src=r10 offset=-4 imm=0
#line 154 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2152 dst=r3 src=r0 offset=1 imm=0
#line 154 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 154 "sample/map.c"
        goto label_99;
        // EBPF_OP_JA pc=2153 dst=r0 src=r0 offset=-567 imm=0
#line 154 "sample/map.c"
    goto label_79;
label_99:
    // EBPF_OP_MOV64_IMM pc=2154 dst=r6 src=r0 offset=0 imm=0
#line 154 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_JA pc=2155 dst=r0 src=r0 offset=-2054 imm=0
#line 154 "sample/map.c"
    goto label_6;
#line 154 "sample/map.c"
}
#line __LINE__ __FILE__

static program_entry_t _programs[] = {
    {
        test_maps,
        "xdp_prog",
        "test_maps",
        test_maps_maps,
        8,
        test_maps_helpers,
        10,
        2156,
        &test_maps_program_type_guid,
        &test_maps_attach_type_guid,
    },
};

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 1;
}

metadata_table_t map_metadata_table = {_get_programs, _get_maps, _get_hash};
