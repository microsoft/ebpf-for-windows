// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from map.o

#include "bpf2c.h"

static void
_get_hash(_Outptr_result_buffer_maybenull_(*size) const uint8_t** hash, _Out_ size_t* size)
{
    *hash = NULL;
    *size = 0;
}
#pragma data_seg(push, "maps")
static map_entry_t _maps[] = {
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
};
#pragma data_seg(pop)

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
    {NULL, 4, "helper_id_4"},
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

#pragma code_seg(push, "xdp_prog")
static uint64_t
test_maps(void* context)
#line 286 "sample/map.c"
{
#line 286 "sample/map.c"
    // Prologue
#line 286 "sample/map.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 286 "sample/map.c"
    register uint64_t r0 = 0;
#line 286 "sample/map.c"
    register uint64_t r1 = 0;
#line 286 "sample/map.c"
    register uint64_t r2 = 0;
#line 286 "sample/map.c"
    register uint64_t r3 = 0;
#line 286 "sample/map.c"
    register uint64_t r4 = 0;
#line 286 "sample/map.c"
    register uint64_t r5 = 0;
#line 286 "sample/map.c"
    register uint64_t r6 = 0;
#line 286 "sample/map.c"
    register uint64_t r7 = 0;
#line 286 "sample/map.c"
    register uint64_t r8 = 0;
#line 286 "sample/map.c"
    register uint64_t r10 = 0;

#line 286 "sample/map.c"
    r1 = (uintptr_t)context;
#line 286 "sample/map.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r1 src=r0 offset=0 imm=0
#line 286 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r1 offset=-4 imm=0
#line 66 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=2 dst=r1 src=r0 offset=0 imm=1
#line 66 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=3 dst=r10 src=r1 offset=-68 imm=0
#line 67 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=4 dst=r2 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=5 dst=r2 src=r0 offset=0 imm=-4
#line 67 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=6 dst=r3 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r3 src=r0 offset=0 imm=-68
#line 67 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=8 dst=r1 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=10 dst=r4 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=11 dst=r0 src=r0 offset=0 imm=2
#line 70 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 70 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 70 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=12 dst=r6 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=13 dst=r3 src=r6 offset=0 imm=0
#line 70 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=14 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=15 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=16 dst=r3 src=r0 offset=9 imm=-1
#line 71 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 71 "sample/map.c"
        goto label_2;
label_1:
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1684369010
#line 71 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-40 imm=0
#line 71 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=20 dst=r1 src=r0 offset=0 imm=544040300
#line 71 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=22 dst=r10 src=r1 offset=-48 imm=0
#line 71 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=23 dst=r1 src=r0 offset=0 imm=1633972341
#line 71 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=25 dst=r0 src=r0 offset=45 imm=0
#line 71 "sample/map.c"
    goto label_5;
label_2:
    // EBPF_OP_MOV64_REG pc=26 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=27 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=28 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=30 dst=r0 src=r0 offset=0 imm=1
#line 76 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=31 dst=r0 src=r0 offset=21 imm=0
#line 77 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 77 "sample/map.c"
        goto label_4;
        // EBPF_OP_MOV64_IMM pc=32 dst=r1 src=r0 offset=0 imm=76
#line 77 "sample/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=33 dst=r10 src=r1 offset=-32 imm=0
#line 78 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=34 dst=r1 src=r0 offset=0 imm=1684369010
#line 78 "sample/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=36 dst=r10 src=r1 offset=-40 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=37 dst=r1 src=r0 offset=0 imm=544040300
#line 78 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=39 dst=r10 src=r1 offset=-48 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=40 dst=r1 src=r0 offset=0 imm=1802465132
#line 78 "sample/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=42 dst=r10 src=r1 offset=-56 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=43 dst=r1 src=r0 offset=0 imm=1600548962
#line 78 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=45 dst=r10 src=r1 offset=-64 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=46 dst=r1 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=47 dst=r1 src=r0 offset=0 imm=-64
#line 78 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=48 dst=r2 src=r0 offset=0 imm=34
#line 78 "sample/map.c"
    r2 = IMMEDIATE(34);
label_3:
    // EBPF_OP_CALL pc=49 dst=r0 src=r0 offset=0 imm=12
#line 78 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 78 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 78 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 78 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=50 dst=r6 src=r0 offset=0 imm=-1
#line 78 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=52 dst=r0 src=r0 offset=26 imm=0
#line 78 "sample/map.c"
    goto label_6;
label_4:
    // EBPF_OP_MOV64_REG pc=53 dst=r2 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=54 dst=r2 src=r0 offset=0 imm=-4
#line 78 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=55 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=57 dst=r0 src=r0 offset=0 imm=3
#line 82 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=58 dst=r6 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=59 dst=r3 src=r6 offset=0 imm=0
#line 82 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=60 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=61 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=62 dst=r3 src=r0 offset=41 imm=-1
#line 83 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 83 "sample/map.c"
        goto label_10;
        // EBPF_OP_LDDW pc=63 dst=r1 src=r0 offset=0 imm=1684369010
#line 83 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=65 dst=r10 src=r1 offset=-40 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=66 dst=r1 src=r0 offset=0 imm=544040300
#line 84 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=68 dst=r10 src=r1 offset=-48 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=69 dst=r1 src=r0 offset=0 imm=1701602660
#line 84 "sample/map.c"
    r1 = (uint64_t)7304668671210448228;
label_5:
    // EBPF_OP_STXDW pc=71 dst=r10 src=r1 offset=-56 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=72 dst=r1 src=r0 offset=0 imm=1600548962
#line 84 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=74 dst=r10 src=r1 offset=-64 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=75 dst=r1 src=r10 offset=0 imm=0
#line 84 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=76 dst=r1 src=r0 offset=0 imm=-64
#line 84 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=77 dst=r2 src=r0 offset=0 imm=32
#line 84 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=78 dst=r0 src=r0 offset=0 imm=13
#line 84 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 84 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 84 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 84 "sample/map.c"
        return 0;
label_6:
    // EBPF_OP_MOV64_IMM pc=79 dst=r1 src=r0 offset=0 imm=100
#line 84 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=80 dst=r10 src=r1 offset=-28 imm=0
#line 289 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=81 dst=r1 src=r0 offset=0 imm=622879845
#line 289 "sample/map.c"
    r1 = IMMEDIATE(622879845);
    // EBPF_OP_STXW pc=82 dst=r10 src=r1 offset=-32 imm=0
#line 289 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=83 dst=r1 src=r0 offset=0 imm=1701978184
#line 289 "sample/map.c"
    r1 = (uint64_t)7958552634295722056;
    // EBPF_OP_STXDW pc=85 dst=r10 src=r1 offset=-40 imm=0
#line 289 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=86 dst=r1 src=r0 offset=0 imm=1885433120
#line 289 "sample/map.c"
    r1 = (uint64_t)5999155482795797792;
    // EBPF_OP_STXDW pc=88 dst=r10 src=r1 offset=-48 imm=0
#line 289 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=89 dst=r1 src=r0 offset=0 imm=1279349317
#line 289 "sample/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=91 dst=r10 src=r1 offset=-56 imm=0
#line 289 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=92 dst=r1 src=r0 offset=0 imm=1953719636
#line 289 "sample/map.c"
    r1 = (uint64_t)5639992313069659476;
label_7:
    // EBPF_OP_STXDW pc=94 dst=r10 src=r1 offset=-64 imm=0
#line 289 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=95 dst=r3 src=r6 offset=0 imm=0
#line 289 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=96 dst=r3 src=r0 offset=0 imm=32
#line 289 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=97 dst=r3 src=r0 offset=0 imm=32
#line 289 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=98 dst=r1 src=r10 offset=0 imm=0
#line 289 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=99 dst=r1 src=r0 offset=0 imm=-64
#line 289 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=100 dst=r2 src=r0 offset=0 imm=38
#line 289 "sample/map.c"
    r2 = IMMEDIATE(38);
label_8:
    // EBPF_OP_CALL pc=101 dst=r0 src=r0 offset=0 imm=13
#line 289 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 289 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 289 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 289 "sample/map.c"
        return 0;
label_9:
    // EBPF_OP_MOV64_REG pc=102 dst=r0 src=r6 offset=0 imm=0
#line 302 "sample/map.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=103 dst=r0 src=r0 offset=0 imm=0
#line 302 "sample/map.c"
    return r0;
label_10:
    // EBPF_OP_MOV64_REG pc=104 dst=r2 src=r10 offset=0 imm=0
#line 302 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=105 dst=r2 src=r0 offset=0 imm=-4
#line 302 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=106 dst=r3 src=r10 offset=0 imm=0
#line 302 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=107 dst=r3 src=r0 offset=0 imm=-68
#line 302 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=108 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=110 dst=r4 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=111 dst=r0 src=r0 offset=0 imm=2
#line 88 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=112 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=113 dst=r3 src=r6 offset=0 imm=0
#line 88 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=114 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=115 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=116 dst=r3 src=r0 offset=1 imm=-1
#line 89 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 89 "sample/map.c"
        goto label_11;
        // EBPF_OP_JA pc=117 dst=r0 src=r0 offset=-101 imm=0
#line 89 "sample/map.c"
    goto label_1;
label_11:
    // EBPF_OP_MOV64_REG pc=118 dst=r2 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=119 dst=r2 src=r0 offset=0 imm=-4
#line 89 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=120 dst=r1 src=r0 offset=0 imm=0
#line 99 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=122 dst=r0 src=r0 offset=0 imm=4
#line 99 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 99 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 99 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 99 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=123 dst=r0 src=r0 offset=23 imm=0
#line 100 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 100 "sample/map.c"
        goto label_12;
        // EBPF_OP_MOV64_IMM pc=124 dst=r1 src=r0 offset=0 imm=0
#line 100 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=125 dst=r10 src=r1 offset=-20 imm=0
#line 101 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=126 dst=r1 src=r0 offset=0 imm=1280070990
#line 101 "sample/map.c"
    r1 = IMMEDIATE(1280070990);
    // EBPF_OP_STXW pc=127 dst=r10 src=r1 offset=-24 imm=0
#line 101 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=128 dst=r1 src=r0 offset=0 imm=1920300133
#line 101 "sample/map.c"
    r1 = (uint64_t)2334102031925867621;
    // EBPF_OP_STXDW pc=130 dst=r10 src=r1 offset=-32 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=131 dst=r1 src=r0 offset=0 imm=1818582885
#line 101 "sample/map.c"
    r1 = (uint64_t)8223693201956233061;
    // EBPF_OP_STXDW pc=133 dst=r10 src=r1 offset=-40 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=134 dst=r1 src=r0 offset=0 imm=1683973230
#line 101 "sample/map.c"
    r1 = (uint64_t)8387229063778886766;
    // EBPF_OP_STXDW pc=136 dst=r10 src=r1 offset=-48 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=137 dst=r1 src=r0 offset=0 imm=1802465132
#line 101 "sample/map.c"
    r1 = (uint64_t)7016450394082471788;
    // EBPF_OP_STXDW pc=139 dst=r10 src=r1 offset=-56 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=140 dst=r1 src=r0 offset=0 imm=1600548962
#line 101 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=142 dst=r10 src=r1 offset=-64 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=143 dst=r1 src=r10 offset=0 imm=0
#line 101 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=144 dst=r1 src=r0 offset=0 imm=-64
#line 101 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=145 dst=r2 src=r0 offset=0 imm=45
#line 101 "sample/map.c"
    r2 = IMMEDIATE(45);
    // EBPF_OP_JA pc=146 dst=r0 src=r0 offset=-98 imm=0
#line 101 "sample/map.c"
    goto label_3;
label_12:
    // EBPF_OP_MOV64_IMM pc=147 dst=r1 src=r0 offset=0 imm=0
#line 101 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=148 dst=r10 src=r1 offset=-4 imm=0
#line 66 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=149 dst=r1 src=r0 offset=0 imm=1
#line 66 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=150 dst=r10 src=r1 offset=-68 imm=0
#line 67 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=151 dst=r2 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=152 dst=r2 src=r0 offset=0 imm=-4
#line 67 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=153 dst=r3 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=154 dst=r3 src=r0 offset=0 imm=-68
#line 67 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=155 dst=r1 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_MOV64_IMM pc=157 dst=r4 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=158 dst=r0 src=r0 offset=0 imm=2
#line 70 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 70 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 70 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=159 dst=r6 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=160 dst=r3 src=r6 offset=0 imm=0
#line 70 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=161 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=162 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=163 dst=r3 src=r0 offset=9 imm=-1
#line 71 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 71 "sample/map.c"
        goto label_14;
label_13:
    // EBPF_OP_LDDW pc=164 dst=r1 src=r0 offset=0 imm=1684369010
#line 71 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=166 dst=r10 src=r1 offset=-40 imm=0
#line 71 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=167 dst=r1 src=r0 offset=0 imm=544040300
#line 71 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=169 dst=r10 src=r1 offset=-48 imm=0
#line 71 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=170 dst=r1 src=r0 offset=0 imm=1633972341
#line 71 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=172 dst=r0 src=r0 offset=45 imm=0
#line 71 "sample/map.c"
    goto label_17;
label_14:
    // EBPF_OP_MOV64_REG pc=173 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=174 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=175 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=177 dst=r0 src=r0 offset=0 imm=1
#line 76 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=178 dst=r0 src=r0 offset=21 imm=0
#line 77 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 77 "sample/map.c"
        goto label_16;
        // EBPF_OP_MOV64_IMM pc=179 dst=r1 src=r0 offset=0 imm=76
#line 77 "sample/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=180 dst=r10 src=r1 offset=-32 imm=0
#line 78 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=181 dst=r1 src=r0 offset=0 imm=1684369010
#line 78 "sample/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=183 dst=r10 src=r1 offset=-40 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=184 dst=r1 src=r0 offset=0 imm=544040300
#line 78 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=186 dst=r10 src=r1 offset=-48 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=187 dst=r1 src=r0 offset=0 imm=1802465132
#line 78 "sample/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=189 dst=r10 src=r1 offset=-56 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=190 dst=r1 src=r0 offset=0 imm=1600548962
#line 78 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=192 dst=r10 src=r1 offset=-64 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=193 dst=r1 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=194 dst=r1 src=r0 offset=0 imm=-64
#line 78 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=195 dst=r2 src=r0 offset=0 imm=34
#line 78 "sample/map.c"
    r2 = IMMEDIATE(34);
label_15:
    // EBPF_OP_CALL pc=196 dst=r0 src=r0 offset=0 imm=12
#line 78 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 78 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 78 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 78 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=197 dst=r6 src=r0 offset=0 imm=-1
#line 78 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=199 dst=r0 src=r0 offset=26 imm=0
#line 78 "sample/map.c"
    goto label_18;
label_16:
    // EBPF_OP_MOV64_REG pc=200 dst=r2 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=201 dst=r2 src=r0 offset=0 imm=-4
#line 78 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=202 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=204 dst=r0 src=r0 offset=0 imm=3
#line 82 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=205 dst=r6 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=206 dst=r3 src=r6 offset=0 imm=0
#line 82 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=207 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=208 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=209 dst=r3 src=r0 offset=42 imm=-1
#line 83 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 83 "sample/map.c"
        goto label_20;
        // EBPF_OP_LDDW pc=210 dst=r1 src=r0 offset=0 imm=1684369010
#line 83 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=212 dst=r10 src=r1 offset=-40 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=213 dst=r1 src=r0 offset=0 imm=544040300
#line 84 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=215 dst=r10 src=r1 offset=-48 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=216 dst=r1 src=r0 offset=0 imm=1701602660
#line 84 "sample/map.c"
    r1 = (uint64_t)7304668671210448228;
label_17:
    // EBPF_OP_STXDW pc=218 dst=r10 src=r1 offset=-56 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=219 dst=r1 src=r0 offset=0 imm=1600548962
#line 84 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=221 dst=r10 src=r1 offset=-64 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=222 dst=r1 src=r10 offset=0 imm=0
#line 84 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=223 dst=r1 src=r0 offset=0 imm=-64
#line 84 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=224 dst=r2 src=r0 offset=0 imm=32
#line 84 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=225 dst=r0 src=r0 offset=0 imm=13
#line 84 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 84 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 84 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 84 "sample/map.c"
        return 0;
label_18:
    // EBPF_OP_MOV64_IMM pc=226 dst=r1 src=r0 offset=0 imm=0
#line 84 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=227 dst=r10 src=r1 offset=-20 imm=0
#line 290 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=228 dst=r1 src=r0 offset=0 imm=1680154724
#line 290 "sample/map.c"
    r1 = IMMEDIATE(1680154724);
    // EBPF_OP_STXW pc=229 dst=r10 src=r1 offset=-24 imm=0
#line 290 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=230 dst=r1 src=r0 offset=0 imm=1952805408
#line 290 "sample/map.c"
    r1 = (uint64_t)7308905094058439200;
    // EBPF_OP_STXDW pc=232 dst=r10 src=r1 offset=-32 imm=0
#line 290 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=233 dst=r1 src=r0 offset=0 imm=1599426627
#line 290 "sample/map.c"
    r1 = (uint64_t)5211580972890673219;
    // EBPF_OP_STXDW pc=235 dst=r10 src=r1 offset=-40 imm=0
#line 290 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=236 dst=r1 src=r0 offset=0 imm=1885433120
#line 290 "sample/map.c"
    r1 = (uint64_t)5928232584757734688;
    // EBPF_OP_STXDW pc=238 dst=r10 src=r1 offset=-48 imm=0
#line 290 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=239 dst=r1 src=r0 offset=0 imm=1279349317
#line 290 "sample/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=241 dst=r10 src=r1 offset=-56 imm=0
#line 290 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=242 dst=r1 src=r0 offset=0 imm=1953719636
#line 290 "sample/map.c"
    r1 = (uint64_t)5639992313069659476;
label_19:
    // EBPF_OP_STXDW pc=244 dst=r10 src=r1 offset=-64 imm=0
#line 290 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=245 dst=r3 src=r6 offset=0 imm=0
#line 290 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=246 dst=r3 src=r0 offset=0 imm=32
#line 290 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=247 dst=r3 src=r0 offset=0 imm=32
#line 290 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=248 dst=r1 src=r10 offset=0 imm=0
#line 290 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=249 dst=r1 src=r0 offset=0 imm=-64
#line 290 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=250 dst=r2 src=r0 offset=0 imm=45
#line 290 "sample/map.c"
    r2 = IMMEDIATE(45);
    // EBPF_OP_JA pc=251 dst=r0 src=r0 offset=-151 imm=0
#line 290 "sample/map.c"
    goto label_8;
label_20:
    // EBPF_OP_MOV64_REG pc=252 dst=r2 src=r10 offset=0 imm=0
#line 290 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=253 dst=r2 src=r0 offset=0 imm=-4
#line 290 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=254 dst=r3 src=r10 offset=0 imm=0
#line 290 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=255 dst=r3 src=r0 offset=0 imm=-68
#line 290 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=256 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_MOV64_IMM pc=258 dst=r4 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=259 dst=r0 src=r0 offset=0 imm=2
#line 88 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=260 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=261 dst=r3 src=r6 offset=0 imm=0
#line 88 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=262 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=263 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=264 dst=r3 src=r0 offset=1 imm=-1
#line 89 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 89 "sample/map.c"
        goto label_21;
        // EBPF_OP_JA pc=265 dst=r0 src=r0 offset=-102 imm=0
#line 89 "sample/map.c"
    goto label_13;
label_21:
    // EBPF_OP_MOV64_REG pc=266 dst=r2 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=267 dst=r2 src=r0 offset=0 imm=-4
#line 89 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=268 dst=r1 src=r0 offset=0 imm=0
#line 99 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=270 dst=r0 src=r0 offset=0 imm=4
#line 99 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 99 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 99 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 99 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=271 dst=r0 src=r0 offset=23 imm=0
#line 100 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 100 "sample/map.c"
        goto label_22;
        // EBPF_OP_MOV64_IMM pc=272 dst=r1 src=r0 offset=0 imm=0
#line 100 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=273 dst=r10 src=r1 offset=-20 imm=0
#line 101 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=274 dst=r1 src=r0 offset=0 imm=1280070990
#line 101 "sample/map.c"
    r1 = IMMEDIATE(1280070990);
    // EBPF_OP_STXW pc=275 dst=r10 src=r1 offset=-24 imm=0
#line 101 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=276 dst=r1 src=r0 offset=0 imm=1920300133
#line 101 "sample/map.c"
    r1 = (uint64_t)2334102031925867621;
    // EBPF_OP_STXDW pc=278 dst=r10 src=r1 offset=-32 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=279 dst=r1 src=r0 offset=0 imm=1818582885
#line 101 "sample/map.c"
    r1 = (uint64_t)8223693201956233061;
    // EBPF_OP_STXDW pc=281 dst=r10 src=r1 offset=-40 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=282 dst=r1 src=r0 offset=0 imm=1683973230
#line 101 "sample/map.c"
    r1 = (uint64_t)8387229063778886766;
    // EBPF_OP_STXDW pc=284 dst=r10 src=r1 offset=-48 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=285 dst=r1 src=r0 offset=0 imm=1802465132
#line 101 "sample/map.c"
    r1 = (uint64_t)7016450394082471788;
    // EBPF_OP_STXDW pc=287 dst=r10 src=r1 offset=-56 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=288 dst=r1 src=r0 offset=0 imm=1600548962
#line 101 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=290 dst=r10 src=r1 offset=-64 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=291 dst=r1 src=r10 offset=0 imm=0
#line 101 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=292 dst=r1 src=r0 offset=0 imm=-64
#line 101 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=293 dst=r2 src=r0 offset=0 imm=45
#line 101 "sample/map.c"
    r2 = IMMEDIATE(45);
    // EBPF_OP_JA pc=294 dst=r0 src=r0 offset=-99 imm=0
#line 101 "sample/map.c"
    goto label_15;
label_22:
    // EBPF_OP_MOV64_IMM pc=295 dst=r1 src=r0 offset=0 imm=0
#line 101 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=296 dst=r10 src=r1 offset=-4 imm=0
#line 66 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=297 dst=r1 src=r0 offset=0 imm=1
#line 66 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=298 dst=r10 src=r1 offset=-68 imm=0
#line 67 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=299 dst=r2 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=300 dst=r2 src=r0 offset=0 imm=-4
#line 67 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=301 dst=r3 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=302 dst=r3 src=r0 offset=0 imm=-68
#line 67 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=303 dst=r1 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_MOV64_IMM pc=305 dst=r4 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=306 dst=r0 src=r0 offset=0 imm=2
#line 70 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 70 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 70 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=307 dst=r6 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=308 dst=r3 src=r6 offset=0 imm=0
#line 70 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=309 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=310 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=311 dst=r3 src=r0 offset=1 imm=-1
#line 71 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 71 "sample/map.c"
        goto label_23;
        // EBPF_OP_JA pc=312 dst=r0 src=r0 offset=60 imm=0
#line 71 "sample/map.c"
    goto label_26;
label_23:
    // EBPF_OP_MOV64_REG pc=313 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=314 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=315 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_CALL pc=317 dst=r0 src=r0 offset=0 imm=1
#line 76 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=318 dst=r0 src=r0 offset=21 imm=0
#line 77 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 77 "sample/map.c"
        goto label_24;
        // EBPF_OP_MOV64_IMM pc=319 dst=r1 src=r0 offset=0 imm=76
#line 77 "sample/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=320 dst=r10 src=r1 offset=-32 imm=0
#line 78 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=321 dst=r1 src=r0 offset=0 imm=1684369010
#line 78 "sample/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=323 dst=r10 src=r1 offset=-40 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=324 dst=r1 src=r0 offset=0 imm=544040300
#line 78 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=326 dst=r10 src=r1 offset=-48 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=327 dst=r1 src=r0 offset=0 imm=1802465132
#line 78 "sample/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=329 dst=r10 src=r1 offset=-56 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=330 dst=r1 src=r0 offset=0 imm=1600548962
#line 78 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=332 dst=r10 src=r1 offset=-64 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=333 dst=r1 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=334 dst=r1 src=r0 offset=0 imm=-64
#line 78 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=335 dst=r2 src=r0 offset=0 imm=34
#line 78 "sample/map.c"
    r2 = IMMEDIATE(34);
    // EBPF_OP_CALL pc=336 dst=r0 src=r0 offset=0 imm=12
#line 78 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 78 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 78 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 78 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=337 dst=r6 src=r0 offset=0 imm=-1
#line 78 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=339 dst=r0 src=r0 offset=49 imm=0
#line 78 "sample/map.c"
    goto label_28;
label_24:
    // EBPF_OP_MOV64_REG pc=340 dst=r2 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=341 dst=r2 src=r0 offset=0 imm=-4
#line 78 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=342 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_CALL pc=344 dst=r0 src=r0 offset=0 imm=3
#line 82 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=345 dst=r6 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=346 dst=r3 src=r6 offset=0 imm=0
#line 82 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=347 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=348 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=349 dst=r3 src=r0 offset=9 imm=-1
#line 83 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 83 "sample/map.c"
        goto label_25;
        // EBPF_OP_LDDW pc=350 dst=r1 src=r0 offset=0 imm=1684369010
#line 83 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=352 dst=r10 src=r1 offset=-40 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=353 dst=r1 src=r0 offset=0 imm=544040300
#line 84 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=355 dst=r10 src=r1 offset=-48 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=356 dst=r1 src=r0 offset=0 imm=1701602660
#line 84 "sample/map.c"
    r1 = (uint64_t)7304668671210448228;
    // EBPF_OP_JA pc=358 dst=r0 src=r0 offset=22 imm=0
#line 84 "sample/map.c"
    goto label_27;
label_25:
    // EBPF_OP_MOV64_REG pc=359 dst=r2 src=r10 offset=0 imm=0
#line 84 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=360 dst=r2 src=r0 offset=0 imm=-4
#line 84 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=361 dst=r3 src=r10 offset=0 imm=0
#line 84 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=362 dst=r3 src=r0 offset=0 imm=-68
#line 84 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_MOV64_IMM pc=363 dst=r7 src=r0 offset=0 imm=0
#line 84 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=364 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_MOV64_IMM pc=366 dst=r4 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=367 dst=r0 src=r0 offset=0 imm=2
#line 88 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=368 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=369 dst=r3 src=r6 offset=0 imm=0
#line 88 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=370 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=371 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=372 dst=r3 src=r0 offset=41 imm=-1
#line 89 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 89 "sample/map.c"
        goto label_29;
label_26:
    // EBPF_OP_LDDW pc=373 dst=r1 src=r0 offset=0 imm=1684369010
#line 89 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=375 dst=r10 src=r1 offset=-40 imm=0
#line 89 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=376 dst=r1 src=r0 offset=0 imm=544040300
#line 89 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=378 dst=r10 src=r1 offset=-48 imm=0
#line 89 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=379 dst=r1 src=r0 offset=0 imm=1633972341
#line 89 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
label_27:
    // EBPF_OP_STXDW pc=381 dst=r10 src=r1 offset=-56 imm=0
#line 89 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=382 dst=r1 src=r0 offset=0 imm=1600548962
#line 89 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=384 dst=r10 src=r1 offset=-64 imm=0
#line 89 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=385 dst=r1 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=386 dst=r1 src=r0 offset=0 imm=-64
#line 89 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=387 dst=r2 src=r0 offset=0 imm=32
#line 89 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=388 dst=r0 src=r0 offset=0 imm=13
#line 89 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 89 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 89 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 89 "sample/map.c"
        return 0;
label_28:
    // EBPF_OP_MOV64_IMM pc=389 dst=r1 src=r0 offset=0 imm=0
#line 89 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=390 dst=r10 src=r1 offset=-26 imm=0
#line 291 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-26)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=391 dst=r1 src=r0 offset=0 imm=25637
#line 291 "sample/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=392 dst=r10 src=r1 offset=-28 imm=0
#line 291 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=393 dst=r1 src=r0 offset=0 imm=543450478
#line 291 "sample/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=394 dst=r10 src=r1 offset=-32 imm=0
#line 291 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=395 dst=r1 src=r0 offset=0 imm=1914722625
#line 291 "sample/map.c"
    r1 = (uint64_t)8247626271654172993;
    // EBPF_OP_STXDW pc=397 dst=r10 src=r1 offset=-40 imm=0
#line 291 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=398 dst=r1 src=r0 offset=0 imm=1885433120
#line 291 "sample/map.c"
    r1 = (uint64_t)5931875266780556576;
    // EBPF_OP_STXDW pc=400 dst=r10 src=r1 offset=-48 imm=0
#line 291 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=401 dst=r1 src=r0 offset=0 imm=1279349317
#line 291 "sample/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=403 dst=r10 src=r1 offset=-56 imm=0
#line 291 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=404 dst=r1 src=r0 offset=0 imm=1953719636
#line 291 "sample/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=406 dst=r10 src=r1 offset=-64 imm=0
#line 291 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=407 dst=r3 src=r6 offset=0 imm=0
#line 291 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=408 dst=r3 src=r0 offset=0 imm=32
#line 291 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=409 dst=r3 src=r0 offset=0 imm=32
#line 291 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=410 dst=r1 src=r10 offset=0 imm=0
#line 291 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=411 dst=r1 src=r0 offset=0 imm=-64
#line 291 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=412 dst=r2 src=r0 offset=0 imm=39
#line 291 "sample/map.c"
    r2 = IMMEDIATE(39);
    // EBPF_OP_JA pc=413 dst=r0 src=r0 offset=-313 imm=0
#line 291 "sample/map.c"
    goto label_8;
label_29:
    // EBPF_OP_STXW pc=414 dst=r10 src=r7 offset=-4 imm=0
#line 66 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=415 dst=r1 src=r0 offset=0 imm=1
#line 66 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=416 dst=r10 src=r1 offset=-68 imm=0
#line 67 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=417 dst=r2 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=418 dst=r2 src=r0 offset=0 imm=-4
#line 67 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=419 dst=r3 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=420 dst=r3 src=r0 offset=0 imm=-68
#line 67 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=421 dst=r1 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_MOV64_IMM pc=423 dst=r4 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=424 dst=r0 src=r0 offset=0 imm=2
#line 70 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 70 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 70 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=425 dst=r6 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=426 dst=r3 src=r6 offset=0 imm=0
#line 70 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=427 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=428 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=429 dst=r3 src=r0 offset=1 imm=-1
#line 71 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 71 "sample/map.c"
        goto label_30;
        // EBPF_OP_JA pc=430 dst=r0 src=r0 offset=60 imm=0
#line 71 "sample/map.c"
    goto label_33;
label_30:
    // EBPF_OP_MOV64_REG pc=431 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=432 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=433 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_CALL pc=435 dst=r0 src=r0 offset=0 imm=1
#line 76 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=436 dst=r0 src=r0 offset=21 imm=0
#line 77 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 77 "sample/map.c"
        goto label_31;
        // EBPF_OP_MOV64_IMM pc=437 dst=r1 src=r0 offset=0 imm=76
#line 77 "sample/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=438 dst=r10 src=r1 offset=-32 imm=0
#line 78 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=439 dst=r1 src=r0 offset=0 imm=1684369010
#line 78 "sample/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=441 dst=r10 src=r1 offset=-40 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=442 dst=r1 src=r0 offset=0 imm=544040300
#line 78 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=444 dst=r10 src=r1 offset=-48 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=445 dst=r1 src=r0 offset=0 imm=1802465132
#line 78 "sample/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=447 dst=r10 src=r1 offset=-56 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=448 dst=r1 src=r0 offset=0 imm=1600548962
#line 78 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=450 dst=r10 src=r1 offset=-64 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=451 dst=r1 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=452 dst=r1 src=r0 offset=0 imm=-64
#line 78 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=453 dst=r2 src=r0 offset=0 imm=34
#line 78 "sample/map.c"
    r2 = IMMEDIATE(34);
    // EBPF_OP_CALL pc=454 dst=r0 src=r0 offset=0 imm=12
#line 78 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 78 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 78 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 78 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=455 dst=r6 src=r0 offset=0 imm=-1
#line 78 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=457 dst=r0 src=r0 offset=49 imm=0
#line 78 "sample/map.c"
    goto label_35;
label_31:
    // EBPF_OP_MOV64_REG pc=458 dst=r2 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=459 dst=r2 src=r0 offset=0 imm=-4
#line 78 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=460 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_CALL pc=462 dst=r0 src=r0 offset=0 imm=3
#line 82 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=463 dst=r6 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=464 dst=r3 src=r6 offset=0 imm=0
#line 82 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=465 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=466 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=467 dst=r3 src=r0 offset=9 imm=-1
#line 83 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 83 "sample/map.c"
        goto label_32;
        // EBPF_OP_LDDW pc=468 dst=r1 src=r0 offset=0 imm=1684369010
#line 83 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=470 dst=r10 src=r1 offset=-40 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=471 dst=r1 src=r0 offset=0 imm=544040300
#line 84 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=473 dst=r10 src=r1 offset=-48 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=474 dst=r1 src=r0 offset=0 imm=1701602660
#line 84 "sample/map.c"
    r1 = (uint64_t)7304668671210448228;
    // EBPF_OP_JA pc=476 dst=r0 src=r0 offset=22 imm=0
#line 84 "sample/map.c"
    goto label_34;
label_32:
    // EBPF_OP_MOV64_REG pc=477 dst=r2 src=r10 offset=0 imm=0
#line 84 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=478 dst=r2 src=r0 offset=0 imm=-4
#line 84 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=479 dst=r3 src=r10 offset=0 imm=0
#line 84 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=480 dst=r3 src=r0 offset=0 imm=-68
#line 84 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_MOV64_IMM pc=481 dst=r7 src=r0 offset=0 imm=0
#line 84 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=482 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_MOV64_IMM pc=484 dst=r4 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=485 dst=r0 src=r0 offset=0 imm=2
#line 88 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=486 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=487 dst=r3 src=r6 offset=0 imm=0
#line 88 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=488 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=489 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=490 dst=r3 src=r0 offset=42 imm=-1
#line 89 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 89 "sample/map.c"
        goto label_36;
label_33:
    // EBPF_OP_LDDW pc=491 dst=r1 src=r0 offset=0 imm=1684369010
#line 89 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=493 dst=r10 src=r1 offset=-40 imm=0
#line 89 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=494 dst=r1 src=r0 offset=0 imm=544040300
#line 89 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=496 dst=r10 src=r1 offset=-48 imm=0
#line 89 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=497 dst=r1 src=r0 offset=0 imm=1633972341
#line 89 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
label_34:
    // EBPF_OP_STXDW pc=499 dst=r10 src=r1 offset=-56 imm=0
#line 89 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=500 dst=r1 src=r0 offset=0 imm=1600548962
#line 89 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=502 dst=r10 src=r1 offset=-64 imm=0
#line 89 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=503 dst=r1 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=504 dst=r1 src=r0 offset=0 imm=-64
#line 89 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=505 dst=r2 src=r0 offset=0 imm=32
#line 89 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=506 dst=r0 src=r0 offset=0 imm=13
#line 89 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 89 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 89 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 89 "sample/map.c"
        return 0;
label_35:
    // EBPF_OP_MOV64_IMM pc=507 dst=r1 src=r0 offset=0 imm=100
#line 89 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=508 dst=r10 src=r1 offset=-20 imm=0
#line 292 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=509 dst=r1 src=r0 offset=0 imm=622879845
#line 292 "sample/map.c"
    r1 = IMMEDIATE(622879845);
    // EBPF_OP_STXW pc=510 dst=r10 src=r1 offset=-24 imm=0
#line 292 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=511 dst=r1 src=r0 offset=0 imm=1701978201
#line 292 "sample/map.c"
    r1 = (uint64_t)7958552634295722073;
    // EBPF_OP_STXDW pc=513 dst=r10 src=r1 offset=-32 imm=0
#line 292 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=514 dst=r1 src=r0 offset=0 imm=1599426627
#line 292 "sample/map.c"
    r1 = (uint64_t)4706915001281368131;
    // EBPF_OP_STXDW pc=516 dst=r10 src=r1 offset=-40 imm=0
#line 292 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=517 dst=r1 src=r0 offset=0 imm=1885433120
#line 292 "sample/map.c"
    r1 = (uint64_t)5928232584757734688;
    // EBPF_OP_STXDW pc=519 dst=r10 src=r1 offset=-48 imm=0
#line 292 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=520 dst=r1 src=r0 offset=0 imm=1279349317
#line 292 "sample/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=522 dst=r10 src=r1 offset=-56 imm=0
#line 292 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=523 dst=r1 src=r0 offset=0 imm=1953719636
#line 292 "sample/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=525 dst=r10 src=r1 offset=-64 imm=0
#line 292 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=526 dst=r3 src=r6 offset=0 imm=0
#line 292 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=527 dst=r3 src=r0 offset=0 imm=32
#line 292 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=528 dst=r3 src=r0 offset=0 imm=32
#line 292 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=529 dst=r1 src=r10 offset=0 imm=0
#line 292 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=530 dst=r1 src=r0 offset=0 imm=-64
#line 292 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=531 dst=r2 src=r0 offset=0 imm=46
#line 292 "sample/map.c"
    r2 = IMMEDIATE(46);
    // EBPF_OP_JA pc=532 dst=r0 src=r0 offset=-432 imm=0
#line 292 "sample/map.c"
    goto label_8;
label_36:
    // EBPF_OP_STXW pc=533 dst=r10 src=r7 offset=-4 imm=0
#line 66 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=534 dst=r1 src=r0 offset=0 imm=1
#line 66 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=535 dst=r10 src=r1 offset=-68 imm=0
#line 67 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=536 dst=r2 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=537 dst=r2 src=r0 offset=0 imm=-4
#line 67 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=538 dst=r3 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=539 dst=r3 src=r0 offset=0 imm=-68
#line 67 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=540 dst=r1 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=542 dst=r4 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=543 dst=r0 src=r0 offset=0 imm=2
#line 70 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 70 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 70 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=544 dst=r6 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=545 dst=r3 src=r6 offset=0 imm=0
#line 70 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=546 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=547 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=548 dst=r3 src=r0 offset=9 imm=-1
#line 71 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 71 "sample/map.c"
        goto label_38;
label_37:
    // EBPF_OP_LDDW pc=549 dst=r1 src=r0 offset=0 imm=1684369010
#line 71 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=551 dst=r10 src=r1 offset=-40 imm=0
#line 71 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=552 dst=r1 src=r0 offset=0 imm=544040300
#line 71 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=554 dst=r10 src=r1 offset=-48 imm=0
#line 71 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=555 dst=r1 src=r0 offset=0 imm=1633972341
#line 71 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=557 dst=r0 src=r0 offset=45 imm=0
#line 71 "sample/map.c"
    goto label_41;
label_38:
    // EBPF_OP_MOV64_REG pc=558 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=559 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=560 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_CALL pc=562 dst=r0 src=r0 offset=0 imm=1
#line 76 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=563 dst=r0 src=r0 offset=21 imm=0
#line 77 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 77 "sample/map.c"
        goto label_40;
        // EBPF_OP_MOV64_IMM pc=564 dst=r1 src=r0 offset=0 imm=76
#line 77 "sample/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=565 dst=r10 src=r1 offset=-32 imm=0
#line 78 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=566 dst=r1 src=r0 offset=0 imm=1684369010
#line 78 "sample/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=568 dst=r10 src=r1 offset=-40 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=569 dst=r1 src=r0 offset=0 imm=544040300
#line 78 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=571 dst=r10 src=r1 offset=-48 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=572 dst=r1 src=r0 offset=0 imm=1802465132
#line 78 "sample/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=574 dst=r10 src=r1 offset=-56 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=575 dst=r1 src=r0 offset=0 imm=1600548962
#line 78 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=577 dst=r10 src=r1 offset=-64 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=578 dst=r1 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=579 dst=r1 src=r0 offset=0 imm=-64
#line 78 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=580 dst=r2 src=r0 offset=0 imm=34
#line 78 "sample/map.c"
    r2 = IMMEDIATE(34);
label_39:
    // EBPF_OP_CALL pc=581 dst=r0 src=r0 offset=0 imm=12
#line 78 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 78 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 78 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 78 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=582 dst=r6 src=r0 offset=0 imm=-1
#line 78 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=584 dst=r0 src=r0 offset=26 imm=0
#line 78 "sample/map.c"
    goto label_42;
label_40:
    // EBPF_OP_MOV64_REG pc=585 dst=r2 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=586 dst=r2 src=r0 offset=0 imm=-4
#line 78 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=587 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_CALL pc=589 dst=r0 src=r0 offset=0 imm=3
#line 82 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=590 dst=r6 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=591 dst=r3 src=r6 offset=0 imm=0
#line 82 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=592 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=593 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=594 dst=r3 src=r0 offset=40 imm=-1
#line 83 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 83 "sample/map.c"
        goto label_43;
        // EBPF_OP_LDDW pc=595 dst=r1 src=r0 offset=0 imm=1684369010
#line 83 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=597 dst=r10 src=r1 offset=-40 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=598 dst=r1 src=r0 offset=0 imm=544040300
#line 84 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=600 dst=r10 src=r1 offset=-48 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=601 dst=r1 src=r0 offset=0 imm=1701602660
#line 84 "sample/map.c"
    r1 = (uint64_t)7304668671210448228;
label_41:
    // EBPF_OP_STXDW pc=603 dst=r10 src=r1 offset=-56 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=604 dst=r1 src=r0 offset=0 imm=1600548962
#line 84 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=606 dst=r10 src=r1 offset=-64 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=607 dst=r1 src=r10 offset=0 imm=0
#line 84 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=608 dst=r1 src=r0 offset=0 imm=-64
#line 84 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=609 dst=r2 src=r0 offset=0 imm=32
#line 84 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=610 dst=r0 src=r0 offset=0 imm=13
#line 84 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 84 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 84 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 84 "sample/map.c"
        return 0;
label_42:
    // EBPF_OP_MOV64_IMM pc=611 dst=r1 src=r0 offset=0 imm=100
#line 84 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=612 dst=r10 src=r1 offset=-24 imm=0
#line 293 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=613 dst=r1 src=r0 offset=0 imm=1852994932
#line 293 "sample/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=615 dst=r10 src=r1 offset=-32 imm=0
#line 293 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=616 dst=r1 src=r0 offset=0 imm=1396787295
#line 293 "sample/map.c"
    r1 = (uint64_t)7309940640182257759;
    // EBPF_OP_STXDW pc=618 dst=r10 src=r1 offset=-40 imm=0
#line 293 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=619 dst=r1 src=r0 offset=0 imm=1885433120
#line 293 "sample/map.c"
    r1 = (uint64_t)6148060143522245920;
    // EBPF_OP_STXDW pc=621 dst=r10 src=r1 offset=-48 imm=0
#line 293 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=622 dst=r1 src=r0 offset=0 imm=1279349317
#line 293 "sample/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=624 dst=r10 src=r1 offset=-56 imm=0
#line 293 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=625 dst=r1 src=r0 offset=0 imm=1953719636
#line 293 "sample/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=627 dst=r10 src=r1 offset=-64 imm=0
#line 293 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=628 dst=r3 src=r6 offset=0 imm=0
#line 293 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=629 dst=r3 src=r0 offset=0 imm=32
#line 293 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=630 dst=r3 src=r0 offset=0 imm=32
#line 293 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=631 dst=r1 src=r10 offset=0 imm=0
#line 293 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=632 dst=r1 src=r0 offset=0 imm=-64
#line 293 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=633 dst=r2 src=r0 offset=0 imm=42
#line 293 "sample/map.c"
    r2 = IMMEDIATE(42);
    // EBPF_OP_JA pc=634 dst=r0 src=r0 offset=-534 imm=0
#line 293 "sample/map.c"
    goto label_8;
label_43:
    // EBPF_OP_MOV64_REG pc=635 dst=r2 src=r10 offset=0 imm=0
#line 293 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=636 dst=r2 src=r0 offset=0 imm=-4
#line 293 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=637 dst=r3 src=r10 offset=0 imm=0
#line 293 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=638 dst=r3 src=r0 offset=0 imm=-68
#line 293 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=639 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=641 dst=r4 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=642 dst=r0 src=r0 offset=0 imm=2
#line 88 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=643 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=644 dst=r3 src=r6 offset=0 imm=0
#line 88 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=645 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=646 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=647 dst=r3 src=r0 offset=1 imm=-1
#line 89 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 89 "sample/map.c"
        goto label_44;
        // EBPF_OP_JA pc=648 dst=r0 src=r0 offset=-100 imm=0
#line 89 "sample/map.c"
    goto label_37;
label_44:
    // EBPF_OP_MOV64_REG pc=649 dst=r2 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=650 dst=r2 src=r0 offset=0 imm=-4
#line 89 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=651 dst=r1 src=r0 offset=0 imm=0
#line 99 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_CALL pc=653 dst=r0 src=r0 offset=0 imm=4
#line 99 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 99 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 99 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 99 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=654 dst=r0 src=r0 offset=23 imm=0
#line 100 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 100 "sample/map.c"
        goto label_45;
        // EBPF_OP_MOV64_IMM pc=655 dst=r1 src=r0 offset=0 imm=0
#line 100 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=656 dst=r10 src=r1 offset=-20 imm=0
#line 101 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=657 dst=r1 src=r0 offset=0 imm=1280070990
#line 101 "sample/map.c"
    r1 = IMMEDIATE(1280070990);
    // EBPF_OP_STXW pc=658 dst=r10 src=r1 offset=-24 imm=0
#line 101 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=659 dst=r1 src=r0 offset=0 imm=1920300133
#line 101 "sample/map.c"
    r1 = (uint64_t)2334102031925867621;
    // EBPF_OP_STXDW pc=661 dst=r10 src=r1 offset=-32 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=662 dst=r1 src=r0 offset=0 imm=1818582885
#line 101 "sample/map.c"
    r1 = (uint64_t)8223693201956233061;
    // EBPF_OP_STXDW pc=664 dst=r10 src=r1 offset=-40 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=665 dst=r1 src=r0 offset=0 imm=1683973230
#line 101 "sample/map.c"
    r1 = (uint64_t)8387229063778886766;
    // EBPF_OP_STXDW pc=667 dst=r10 src=r1 offset=-48 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=668 dst=r1 src=r0 offset=0 imm=1802465132
#line 101 "sample/map.c"
    r1 = (uint64_t)7016450394082471788;
    // EBPF_OP_STXDW pc=670 dst=r10 src=r1 offset=-56 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=671 dst=r1 src=r0 offset=0 imm=1600548962
#line 101 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=673 dst=r10 src=r1 offset=-64 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=674 dst=r1 src=r10 offset=0 imm=0
#line 101 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=675 dst=r1 src=r0 offset=0 imm=-64
#line 101 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=676 dst=r2 src=r0 offset=0 imm=45
#line 101 "sample/map.c"
    r2 = IMMEDIATE(45);
    // EBPF_OP_JA pc=677 dst=r0 src=r0 offset=-97 imm=0
#line 101 "sample/map.c"
    goto label_39;
label_45:
    // EBPF_OP_MOV64_IMM pc=678 dst=r1 src=r0 offset=0 imm=0
#line 101 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=679 dst=r10 src=r1 offset=-4 imm=0
#line 66 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=680 dst=r1 src=r0 offset=0 imm=1
#line 66 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=681 dst=r10 src=r1 offset=-68 imm=0
#line 67 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=682 dst=r2 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=683 dst=r2 src=r0 offset=0 imm=-4
#line 67 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=684 dst=r3 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=685 dst=r3 src=r0 offset=0 imm=-68
#line 67 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=686 dst=r1 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=688 dst=r4 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=689 dst=r0 src=r0 offset=0 imm=2
#line 70 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 70 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 70 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=690 dst=r6 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=691 dst=r3 src=r6 offset=0 imm=0
#line 70 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=692 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=693 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=694 dst=r3 src=r0 offset=9 imm=-1
#line 71 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 71 "sample/map.c"
        goto label_47;
label_46:
    // EBPF_OP_LDDW pc=695 dst=r1 src=r0 offset=0 imm=1684369010
#line 71 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=697 dst=r10 src=r1 offset=-40 imm=0
#line 71 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=698 dst=r1 src=r0 offset=0 imm=544040300
#line 71 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=700 dst=r10 src=r1 offset=-48 imm=0
#line 71 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=701 dst=r1 src=r0 offset=0 imm=1633972341
#line 71 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=703 dst=r0 src=r0 offset=45 imm=0
#line 71 "sample/map.c"
    goto label_50;
label_47:
    // EBPF_OP_MOV64_REG pc=704 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=705 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=706 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_CALL pc=708 dst=r0 src=r0 offset=0 imm=1
#line 76 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=709 dst=r0 src=r0 offset=21 imm=0
#line 77 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 77 "sample/map.c"
        goto label_49;
        // EBPF_OP_MOV64_IMM pc=710 dst=r1 src=r0 offset=0 imm=76
#line 77 "sample/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=711 dst=r10 src=r1 offset=-32 imm=0
#line 78 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=712 dst=r1 src=r0 offset=0 imm=1684369010
#line 78 "sample/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=714 dst=r10 src=r1 offset=-40 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=715 dst=r1 src=r0 offset=0 imm=544040300
#line 78 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=717 dst=r10 src=r1 offset=-48 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=718 dst=r1 src=r0 offset=0 imm=1802465132
#line 78 "sample/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=720 dst=r10 src=r1 offset=-56 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=721 dst=r1 src=r0 offset=0 imm=1600548962
#line 78 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=723 dst=r10 src=r1 offset=-64 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=724 dst=r1 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=725 dst=r1 src=r0 offset=0 imm=-64
#line 78 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=726 dst=r2 src=r0 offset=0 imm=34
#line 78 "sample/map.c"
    r2 = IMMEDIATE(34);
label_48:
    // EBPF_OP_CALL pc=727 dst=r0 src=r0 offset=0 imm=12
#line 78 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 78 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 78 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 78 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=728 dst=r6 src=r0 offset=0 imm=-1
#line 78 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=730 dst=r0 src=r0 offset=26 imm=0
#line 78 "sample/map.c"
    goto label_51;
label_49:
    // EBPF_OP_MOV64_REG pc=731 dst=r2 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=732 dst=r2 src=r0 offset=0 imm=-4
#line 78 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=733 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_CALL pc=735 dst=r0 src=r0 offset=0 imm=3
#line 82 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=736 dst=r6 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=737 dst=r3 src=r6 offset=0 imm=0
#line 82 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=738 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=739 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=740 dst=r3 src=r0 offset=43 imm=-1
#line 83 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 83 "sample/map.c"
        goto label_52;
        // EBPF_OP_LDDW pc=741 dst=r1 src=r0 offset=0 imm=1684369010
#line 83 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=743 dst=r10 src=r1 offset=-40 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=744 dst=r1 src=r0 offset=0 imm=544040300
#line 84 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=746 dst=r10 src=r1 offset=-48 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=747 dst=r1 src=r0 offset=0 imm=1701602660
#line 84 "sample/map.c"
    r1 = (uint64_t)7304668671210448228;
label_50:
    // EBPF_OP_STXDW pc=749 dst=r10 src=r1 offset=-56 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=750 dst=r1 src=r0 offset=0 imm=1600548962
#line 84 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=752 dst=r10 src=r1 offset=-64 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=753 dst=r1 src=r10 offset=0 imm=0
#line 84 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=754 dst=r1 src=r0 offset=0 imm=-64
#line 84 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=755 dst=r2 src=r0 offset=0 imm=32
#line 84 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=756 dst=r0 src=r0 offset=0 imm=13
#line 84 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 84 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 84 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 84 "sample/map.c"
        return 0;
label_51:
    // EBPF_OP_MOV64_IMM pc=757 dst=r1 src=r0 offset=0 imm=0
#line 84 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=758 dst=r10 src=r1 offset=-16 imm=0
#line 294 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=759 dst=r1 src=r0 offset=0 imm=1701737077
#line 294 "sample/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=761 dst=r10 src=r1 offset=-24 imm=0
#line 294 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=762 dst=r1 src=r0 offset=0 imm=1213415752
#line 294 "sample/map.c"
    r1 = (uint64_t)8387235364025352520;
    // EBPF_OP_STXDW pc=764 dst=r10 src=r1 offset=-32 imm=0
#line 294 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=765 dst=r1 src=r0 offset=0 imm=1380274271
#line 294 "sample/map.c"
    r1 = (uint64_t)6869485056696864863;
    // EBPF_OP_STXDW pc=767 dst=r10 src=r1 offset=-40 imm=0
#line 294 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=768 dst=r1 src=r0 offset=0 imm=1885433120
#line 294 "sample/map.c"
    r1 = (uint64_t)6148060143522245920;
    // EBPF_OP_STXDW pc=770 dst=r10 src=r1 offset=-48 imm=0
#line 294 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=771 dst=r1 src=r0 offset=0 imm=1279349317
#line 294 "sample/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=773 dst=r10 src=r1 offset=-56 imm=0
#line 294 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=774 dst=r1 src=r0 offset=0 imm=1953719636
#line 294 "sample/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=776 dst=r10 src=r1 offset=-64 imm=0
#line 294 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=777 dst=r3 src=r6 offset=0 imm=0
#line 294 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=778 dst=r3 src=r0 offset=0 imm=32
#line 294 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=779 dst=r3 src=r0 offset=0 imm=32
#line 294 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=780 dst=r1 src=r10 offset=0 imm=0
#line 294 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=781 dst=r1 src=r0 offset=0 imm=-64
#line 294 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=782 dst=r2 src=r0 offset=0 imm=49
#line 294 "sample/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=783 dst=r0 src=r0 offset=-683 imm=0
#line 294 "sample/map.c"
    goto label_8;
label_52:
    // EBPF_OP_MOV64_REG pc=784 dst=r2 src=r10 offset=0 imm=0
#line 294 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=785 dst=r2 src=r0 offset=0 imm=-4
#line 294 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=786 dst=r3 src=r10 offset=0 imm=0
#line 294 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=787 dst=r3 src=r0 offset=0 imm=-68
#line 294 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=788 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=790 dst=r4 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=791 dst=r0 src=r0 offset=0 imm=2
#line 88 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=792 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=793 dst=r3 src=r6 offset=0 imm=0
#line 88 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=794 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=795 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=796 dst=r3 src=r0 offset=1 imm=-1
#line 89 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 89 "sample/map.c"
        goto label_53;
        // EBPF_OP_JA pc=797 dst=r0 src=r0 offset=-103 imm=0
#line 89 "sample/map.c"
    goto label_46;
label_53:
    // EBPF_OP_MOV64_REG pc=798 dst=r2 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=799 dst=r2 src=r0 offset=0 imm=-4
#line 89 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=800 dst=r1 src=r0 offset=0 imm=0
#line 99 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_CALL pc=802 dst=r0 src=r0 offset=0 imm=4
#line 99 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 99 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 99 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 99 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=803 dst=r0 src=r0 offset=23 imm=0
#line 100 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 100 "sample/map.c"
        goto label_54;
        // EBPF_OP_MOV64_IMM pc=804 dst=r1 src=r0 offset=0 imm=0
#line 100 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=805 dst=r10 src=r1 offset=-20 imm=0
#line 101 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=806 dst=r1 src=r0 offset=0 imm=1280070990
#line 101 "sample/map.c"
    r1 = IMMEDIATE(1280070990);
    // EBPF_OP_STXW pc=807 dst=r10 src=r1 offset=-24 imm=0
#line 101 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=808 dst=r1 src=r0 offset=0 imm=1920300133
#line 101 "sample/map.c"
    r1 = (uint64_t)2334102031925867621;
    // EBPF_OP_STXDW pc=810 dst=r10 src=r1 offset=-32 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=811 dst=r1 src=r0 offset=0 imm=1818582885
#line 101 "sample/map.c"
    r1 = (uint64_t)8223693201956233061;
    // EBPF_OP_STXDW pc=813 dst=r10 src=r1 offset=-40 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=814 dst=r1 src=r0 offset=0 imm=1683973230
#line 101 "sample/map.c"
    r1 = (uint64_t)8387229063778886766;
    // EBPF_OP_STXDW pc=816 dst=r10 src=r1 offset=-48 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=817 dst=r1 src=r0 offset=0 imm=1802465132
#line 101 "sample/map.c"
    r1 = (uint64_t)7016450394082471788;
    // EBPF_OP_STXDW pc=819 dst=r10 src=r1 offset=-56 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=820 dst=r1 src=r0 offset=0 imm=1600548962
#line 101 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=822 dst=r10 src=r1 offset=-64 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=823 dst=r1 src=r10 offset=0 imm=0
#line 101 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=824 dst=r1 src=r0 offset=0 imm=-64
#line 101 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=825 dst=r2 src=r0 offset=0 imm=45
#line 101 "sample/map.c"
    r2 = IMMEDIATE(45);
    // EBPF_OP_JA pc=826 dst=r0 src=r0 offset=-100 imm=0
#line 101 "sample/map.c"
    goto label_48;
label_54:
    // EBPF_OP_MOV64_IMM pc=827 dst=r1 src=r0 offset=0 imm=0
#line 101 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=828 dst=r10 src=r1 offset=-4 imm=0
#line 110 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=829 dst=r7 src=r0 offset=0 imm=1
#line 110 "sample/map.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=830 dst=r10 src=r7 offset=-68 imm=0
#line 111 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=831 dst=r2 src=r10 offset=0 imm=0
#line 111 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=832 dst=r2 src=r0 offset=0 imm=-4
#line 111 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=833 dst=r3 src=r10 offset=0 imm=0
#line 111 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=834 dst=r3 src=r0 offset=0 imm=-68
#line 111 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=835 dst=r1 src=r0 offset=0 imm=0
#line 125 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=837 dst=r4 src=r0 offset=0 imm=0
#line 125 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=838 dst=r0 src=r0 offset=0 imm=2
#line 125 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 125 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 125 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 125 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=839 dst=r6 src=r0 offset=0 imm=0
#line 125 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=840 dst=r3 src=r6 offset=0 imm=0
#line 125 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=841 dst=r3 src=r0 offset=0 imm=32
#line 125 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=842 dst=r3 src=r0 offset=0 imm=32
#line 125 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=843 dst=r3 src=r0 offset=1 imm=-1
#line 126 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 126 "sample/map.c"
        goto label_55;
        // EBPF_OP_JA pc=844 dst=r0 src=r0 offset=159 imm=0
#line 126 "sample/map.c"
    goto label_65;
label_55:
    // EBPF_OP_STXW pc=845 dst=r10 src=r7 offset=-4 imm=0
#line 130 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=846 dst=r2 src=r10 offset=0 imm=0
#line 130 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=847 dst=r2 src=r0 offset=0 imm=-4
#line 130 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=848 dst=r3 src=r10 offset=0 imm=0
#line 130 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=849 dst=r3 src=r0 offset=0 imm=-68
#line 130 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=850 dst=r1 src=r0 offset=0 imm=0
#line 131 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=852 dst=r4 src=r0 offset=0 imm=0
#line 131 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=853 dst=r0 src=r0 offset=0 imm=2
#line 131 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 131 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 131 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 131 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=854 dst=r6 src=r0 offset=0 imm=0
#line 131 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=855 dst=r3 src=r6 offset=0 imm=0
#line 131 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=856 dst=r3 src=r0 offset=0 imm=32
#line 131 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=857 dst=r3 src=r0 offset=0 imm=32
#line 131 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=858 dst=r3 src=r0 offset=1 imm=-1
#line 132 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 132 "sample/map.c"
        goto label_56;
        // EBPF_OP_JA pc=859 dst=r0 src=r0 offset=144 imm=0
#line 132 "sample/map.c"
    goto label_65;
label_56:
    // EBPF_OP_MOV64_IMM pc=860 dst=r1 src=r0 offset=0 imm=2
#line 132 "sample/map.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=861 dst=r10 src=r1 offset=-4 imm=0
#line 136 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=862 dst=r2 src=r10 offset=0 imm=0
#line 136 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=863 dst=r2 src=r0 offset=0 imm=-4
#line 136 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=864 dst=r3 src=r10 offset=0 imm=0
#line 136 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=865 dst=r3 src=r0 offset=0 imm=-68
#line 136 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=866 dst=r1 src=r0 offset=0 imm=0
#line 137 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=868 dst=r4 src=r0 offset=0 imm=0
#line 137 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=869 dst=r0 src=r0 offset=0 imm=2
#line 137 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 137 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 137 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 137 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=870 dst=r6 src=r0 offset=0 imm=0
#line 137 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=871 dst=r3 src=r6 offset=0 imm=0
#line 137 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=872 dst=r3 src=r0 offset=0 imm=32
#line 137 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=873 dst=r3 src=r0 offset=0 imm=32
#line 137 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=874 dst=r3 src=r0 offset=1 imm=-1
#line 138 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 138 "sample/map.c"
        goto label_57;
        // EBPF_OP_JA pc=875 dst=r0 src=r0 offset=128 imm=0
#line 138 "sample/map.c"
    goto label_65;
label_57:
    // EBPF_OP_MOV64_IMM pc=876 dst=r1 src=r0 offset=0 imm=3
#line 138 "sample/map.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=877 dst=r10 src=r1 offset=-4 imm=0
#line 142 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=878 dst=r2 src=r10 offset=0 imm=0
#line 142 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=879 dst=r2 src=r0 offset=0 imm=-4
#line 142 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=880 dst=r3 src=r10 offset=0 imm=0
#line 142 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=881 dst=r3 src=r0 offset=0 imm=-68
#line 142 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=882 dst=r1 src=r0 offset=0 imm=0
#line 143 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=884 dst=r4 src=r0 offset=0 imm=0
#line 143 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=885 dst=r0 src=r0 offset=0 imm=2
#line 143 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 143 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 143 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 143 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=886 dst=r6 src=r0 offset=0 imm=0
#line 143 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=887 dst=r3 src=r6 offset=0 imm=0
#line 143 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=888 dst=r3 src=r0 offset=0 imm=32
#line 143 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=889 dst=r3 src=r0 offset=0 imm=32
#line 143 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=890 dst=r3 src=r0 offset=1 imm=-1
#line 144 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 144 "sample/map.c"
        goto label_58;
        // EBPF_OP_JA pc=891 dst=r0 src=r0 offset=112 imm=0
#line 144 "sample/map.c"
    goto label_65;
label_58:
    // EBPF_OP_MOV64_IMM pc=892 dst=r1 src=r0 offset=0 imm=4
#line 144 "sample/map.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=893 dst=r10 src=r1 offset=-4 imm=0
#line 148 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=894 dst=r2 src=r10 offset=0 imm=0
#line 148 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=895 dst=r2 src=r0 offset=0 imm=-4
#line 148 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=896 dst=r3 src=r10 offset=0 imm=0
#line 148 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=897 dst=r3 src=r0 offset=0 imm=-68
#line 148 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=898 dst=r1 src=r0 offset=0 imm=0
#line 149 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=900 dst=r4 src=r0 offset=0 imm=0
#line 149 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=901 dst=r0 src=r0 offset=0 imm=2
#line 149 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 149 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 149 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 149 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=902 dst=r6 src=r0 offset=0 imm=0
#line 149 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=903 dst=r3 src=r6 offset=0 imm=0
#line 149 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=904 dst=r3 src=r0 offset=0 imm=32
#line 149 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=905 dst=r3 src=r0 offset=0 imm=32
#line 149 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=906 dst=r3 src=r0 offset=1 imm=-1
#line 150 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 150 "sample/map.c"
        goto label_59;
        // EBPF_OP_JA pc=907 dst=r0 src=r0 offset=96 imm=0
#line 150 "sample/map.c"
    goto label_65;
label_59:
    // EBPF_OP_MOV64_IMM pc=908 dst=r1 src=r0 offset=0 imm=5
#line 150 "sample/map.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=909 dst=r10 src=r1 offset=-4 imm=0
#line 154 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=910 dst=r2 src=r10 offset=0 imm=0
#line 154 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=911 dst=r2 src=r0 offset=0 imm=-4
#line 154 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=912 dst=r3 src=r10 offset=0 imm=0
#line 154 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=913 dst=r3 src=r0 offset=0 imm=-68
#line 154 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=914 dst=r1 src=r0 offset=0 imm=0
#line 155 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=916 dst=r4 src=r0 offset=0 imm=0
#line 155 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=917 dst=r0 src=r0 offset=0 imm=2
#line 155 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 155 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 155 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 155 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=918 dst=r6 src=r0 offset=0 imm=0
#line 155 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=919 dst=r3 src=r6 offset=0 imm=0
#line 155 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=920 dst=r3 src=r0 offset=0 imm=32
#line 155 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=921 dst=r3 src=r0 offset=0 imm=32
#line 155 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=922 dst=r3 src=r0 offset=1 imm=-1
#line 156 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 156 "sample/map.c"
        goto label_60;
        // EBPF_OP_JA pc=923 dst=r0 src=r0 offset=80 imm=0
#line 156 "sample/map.c"
    goto label_65;
label_60:
    // EBPF_OP_MOV64_IMM pc=924 dst=r1 src=r0 offset=0 imm=6
#line 156 "sample/map.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=925 dst=r10 src=r1 offset=-4 imm=0
#line 160 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=926 dst=r2 src=r10 offset=0 imm=0
#line 160 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=927 dst=r2 src=r0 offset=0 imm=-4
#line 160 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=928 dst=r3 src=r10 offset=0 imm=0
#line 160 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=929 dst=r3 src=r0 offset=0 imm=-68
#line 160 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=930 dst=r1 src=r0 offset=0 imm=0
#line 161 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=932 dst=r4 src=r0 offset=0 imm=0
#line 161 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=933 dst=r0 src=r0 offset=0 imm=2
#line 161 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 161 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 161 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 161 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=934 dst=r6 src=r0 offset=0 imm=0
#line 161 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=935 dst=r3 src=r6 offset=0 imm=0
#line 161 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=936 dst=r3 src=r0 offset=0 imm=32
#line 161 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=937 dst=r3 src=r0 offset=0 imm=32
#line 161 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=938 dst=r3 src=r0 offset=1 imm=-1
#line 162 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 162 "sample/map.c"
        goto label_61;
        // EBPF_OP_JA pc=939 dst=r0 src=r0 offset=64 imm=0
#line 162 "sample/map.c"
    goto label_65;
label_61:
    // EBPF_OP_MOV64_IMM pc=940 dst=r1 src=r0 offset=0 imm=7
#line 162 "sample/map.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=941 dst=r10 src=r1 offset=-4 imm=0
#line 166 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=942 dst=r2 src=r10 offset=0 imm=0
#line 166 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=943 dst=r2 src=r0 offset=0 imm=-4
#line 166 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=944 dst=r3 src=r10 offset=0 imm=0
#line 166 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=945 dst=r3 src=r0 offset=0 imm=-68
#line 166 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=946 dst=r1 src=r0 offset=0 imm=0
#line 167 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=948 dst=r4 src=r0 offset=0 imm=0
#line 167 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=949 dst=r0 src=r0 offset=0 imm=2
#line 167 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 167 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 167 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 167 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=950 dst=r6 src=r0 offset=0 imm=0
#line 167 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=951 dst=r3 src=r6 offset=0 imm=0
#line 167 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=952 dst=r3 src=r0 offset=0 imm=32
#line 167 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=953 dst=r3 src=r0 offset=0 imm=32
#line 167 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=954 dst=r3 src=r0 offset=1 imm=-1
#line 168 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 168 "sample/map.c"
        goto label_62;
        // EBPF_OP_JA pc=955 dst=r0 src=r0 offset=48 imm=0
#line 168 "sample/map.c"
    goto label_65;
label_62:
    // EBPF_OP_MOV64_IMM pc=956 dst=r1 src=r0 offset=0 imm=8
#line 168 "sample/map.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=957 dst=r10 src=r1 offset=-4 imm=0
#line 172 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=958 dst=r2 src=r10 offset=0 imm=0
#line 172 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=959 dst=r2 src=r0 offset=0 imm=-4
#line 172 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=960 dst=r3 src=r10 offset=0 imm=0
#line 172 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=961 dst=r3 src=r0 offset=0 imm=-68
#line 172 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=962 dst=r1 src=r0 offset=0 imm=0
#line 173 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=964 dst=r4 src=r0 offset=0 imm=0
#line 173 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=965 dst=r0 src=r0 offset=0 imm=2
#line 173 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 173 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 173 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 173 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=966 dst=r6 src=r0 offset=0 imm=0
#line 173 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=967 dst=r3 src=r6 offset=0 imm=0
#line 173 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=968 dst=r3 src=r0 offset=0 imm=32
#line 173 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=969 dst=r3 src=r0 offset=0 imm=32
#line 173 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=970 dst=r3 src=r0 offset=1 imm=-1
#line 174 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 174 "sample/map.c"
        goto label_63;
        // EBPF_OP_JA pc=971 dst=r0 src=r0 offset=32 imm=0
#line 174 "sample/map.c"
    goto label_65;
label_63:
    // EBPF_OP_MOV64_IMM pc=972 dst=r1 src=r0 offset=0 imm=9
#line 174 "sample/map.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=973 dst=r10 src=r1 offset=-4 imm=0
#line 178 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=974 dst=r2 src=r10 offset=0 imm=0
#line 178 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=975 dst=r2 src=r0 offset=0 imm=-4
#line 178 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=976 dst=r3 src=r10 offset=0 imm=0
#line 178 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=977 dst=r3 src=r0 offset=0 imm=-68
#line 178 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=978 dst=r1 src=r0 offset=0 imm=0
#line 179 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=980 dst=r4 src=r0 offset=0 imm=0
#line 179 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=981 dst=r0 src=r0 offset=0 imm=2
#line 179 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 179 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 179 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 179 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=982 dst=r6 src=r0 offset=0 imm=0
#line 179 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=983 dst=r3 src=r6 offset=0 imm=0
#line 179 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=984 dst=r3 src=r0 offset=0 imm=32
#line 179 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=985 dst=r3 src=r0 offset=0 imm=32
#line 179 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=986 dst=r3 src=r0 offset=1 imm=-1
#line 180 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 180 "sample/map.c"
        goto label_64;
        // EBPF_OP_JA pc=987 dst=r0 src=r0 offset=16 imm=0
#line 180 "sample/map.c"
    goto label_65;
label_64:
    // EBPF_OP_MOV64_IMM pc=988 dst=r1 src=r0 offset=0 imm=10
#line 180 "sample/map.c"
    r1 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=989 dst=r10 src=r1 offset=-4 imm=0
#line 184 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=990 dst=r2 src=r10 offset=0 imm=0
#line 184 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=991 dst=r2 src=r0 offset=0 imm=-4
#line 184 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=992 dst=r3 src=r10 offset=0 imm=0
#line 184 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=993 dst=r3 src=r0 offset=0 imm=-68
#line 184 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_MOV64_IMM pc=994 dst=r7 src=r0 offset=0 imm=0
#line 184 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=995 dst=r1 src=r0 offset=0 imm=0
#line 185 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=997 dst=r4 src=r0 offset=0 imm=0
#line 185 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=998 dst=r0 src=r0 offset=0 imm=2
#line 185 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 185 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 185 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 185 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=999 dst=r6 src=r0 offset=0 imm=0
#line 185 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1000 dst=r3 src=r6 offset=0 imm=0
#line 185 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1001 dst=r3 src=r0 offset=0 imm=32
#line 185 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1002 dst=r3 src=r0 offset=0 imm=32
#line 185 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1003 dst=r3 src=r0 offset=32 imm=-1
#line 186 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 186 "sample/map.c"
        goto label_66;
label_65:
    // EBPF_OP_LDDW pc=1004 dst=r1 src=r0 offset=0 imm=1684369010
#line 186 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=1006 dst=r10 src=r1 offset=-40 imm=0
#line 186 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1007 dst=r1 src=r0 offset=0 imm=544040300
#line 186 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=1009 dst=r10 src=r1 offset=-48 imm=0
#line 186 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1010 dst=r1 src=r0 offset=0 imm=1633972341
#line 186 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_STXDW pc=1012 dst=r10 src=r1 offset=-56 imm=0
#line 186 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1013 dst=r1 src=r0 offset=0 imm=1600548962
#line 186 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1015 dst=r10 src=r1 offset=-64 imm=0
#line 186 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1016 dst=r1 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1017 dst=r1 src=r0 offset=0 imm=-64
#line 186 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1018 dst=r2 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=1019 dst=r0 src=r0 offset=0 imm=13
#line 186 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_IMM pc=1020 dst=r1 src=r0 offset=0 imm=100
#line 186 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=1021 dst=r10 src=r1 offset=-28 imm=0
#line 296 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1022 dst=r1 src=r0 offset=0 imm=622879845
#line 296 "sample/map.c"
    r1 = IMMEDIATE(622879845);
    // EBPF_OP_STXW pc=1023 dst=r10 src=r1 offset=-32 imm=0
#line 296 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1024 dst=r1 src=r0 offset=0 imm=1701978184
#line 296 "sample/map.c"
    r1 = (uint64_t)7958552634295722056;
    // EBPF_OP_STXDW pc=1026 dst=r10 src=r1 offset=-40 imm=0
#line 296 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1027 dst=r1 src=r0 offset=0 imm=1431456800
#line 296 "sample/map.c"
    r1 = (uint64_t)5999155752924761120;
    // EBPF_OP_STXDW pc=1029 dst=r10 src=r1 offset=-48 imm=0
#line 296 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1030 dst=r1 src=r0 offset=0 imm=1919903264
#line 296 "sample/map.c"
    r1 = (uint64_t)8097873591115146784;
    // EBPF_OP_STXDW pc=1032 dst=r10 src=r1 offset=-56 imm=0
#line 296 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1033 dst=r1 src=r0 offset=0 imm=1953719636
#line 296 "sample/map.c"
    r1 = (uint64_t)6148060143590532436;
    // EBPF_OP_JA pc=1035 dst=r0 src=r0 offset=-942 imm=0
#line 296 "sample/map.c"
    goto label_7;
label_66:
    // EBPF_OP_STXW pc=1036 dst=r10 src=r7 offset=-4 imm=0
#line 110 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=1037 dst=r7 src=r0 offset=0 imm=1
#line 110 "sample/map.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=1038 dst=r10 src=r7 offset=-68 imm=0
#line 111 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1039 dst=r2 src=r10 offset=0 imm=0
#line 111 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1040 dst=r2 src=r0 offset=0 imm=-4
#line 111 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1041 dst=r3 src=r10 offset=0 imm=0
#line 111 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1042 dst=r3 src=r0 offset=0 imm=-68
#line 111 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=1043 dst=r1 src=r0 offset=0 imm=0
#line 125 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=1045 dst=r4 src=r0 offset=0 imm=0
#line 125 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1046 dst=r0 src=r0 offset=0 imm=2
#line 125 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 125 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 125 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 125 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1047 dst=r6 src=r0 offset=0 imm=0
#line 125 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1048 dst=r3 src=r6 offset=0 imm=0
#line 125 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1049 dst=r3 src=r0 offset=0 imm=32
#line 125 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1050 dst=r3 src=r0 offset=0 imm=32
#line 125 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1051 dst=r3 src=r0 offset=1 imm=-1
#line 126 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 126 "sample/map.c"
        goto label_67;
        // EBPF_OP_JA pc=1052 dst=r0 src=r0 offset=159 imm=0
#line 126 "sample/map.c"
    goto label_77;
label_67:
    // EBPF_OP_STXW pc=1053 dst=r10 src=r7 offset=-4 imm=0
#line 130 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1054 dst=r2 src=r10 offset=0 imm=0
#line 130 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1055 dst=r2 src=r0 offset=0 imm=-4
#line 130 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1056 dst=r3 src=r10 offset=0 imm=0
#line 130 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1057 dst=r3 src=r0 offset=0 imm=-68
#line 130 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=1058 dst=r1 src=r0 offset=0 imm=0
#line 131 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=1060 dst=r4 src=r0 offset=0 imm=0
#line 131 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1061 dst=r0 src=r0 offset=0 imm=2
#line 131 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 131 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 131 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 131 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1062 dst=r6 src=r0 offset=0 imm=0
#line 131 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1063 dst=r3 src=r6 offset=0 imm=0
#line 131 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1064 dst=r3 src=r0 offset=0 imm=32
#line 131 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1065 dst=r3 src=r0 offset=0 imm=32
#line 131 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1066 dst=r3 src=r0 offset=1 imm=-1
#line 132 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 132 "sample/map.c"
        goto label_68;
        // EBPF_OP_JA pc=1067 dst=r0 src=r0 offset=144 imm=0
#line 132 "sample/map.c"
    goto label_77;
label_68:
    // EBPF_OP_MOV64_IMM pc=1068 dst=r1 src=r0 offset=0 imm=2
#line 132 "sample/map.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=1069 dst=r10 src=r1 offset=-4 imm=0
#line 136 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1070 dst=r2 src=r10 offset=0 imm=0
#line 136 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1071 dst=r2 src=r0 offset=0 imm=-4
#line 136 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1072 dst=r3 src=r10 offset=0 imm=0
#line 136 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1073 dst=r3 src=r0 offset=0 imm=-68
#line 136 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=1074 dst=r1 src=r0 offset=0 imm=0
#line 137 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=1076 dst=r4 src=r0 offset=0 imm=0
#line 137 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1077 dst=r0 src=r0 offset=0 imm=2
#line 137 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 137 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 137 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 137 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1078 dst=r6 src=r0 offset=0 imm=0
#line 137 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1079 dst=r3 src=r6 offset=0 imm=0
#line 137 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1080 dst=r3 src=r0 offset=0 imm=32
#line 137 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1081 dst=r3 src=r0 offset=0 imm=32
#line 137 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1082 dst=r3 src=r0 offset=1 imm=-1
#line 138 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 138 "sample/map.c"
        goto label_69;
        // EBPF_OP_JA pc=1083 dst=r0 src=r0 offset=128 imm=0
#line 138 "sample/map.c"
    goto label_77;
label_69:
    // EBPF_OP_MOV64_IMM pc=1084 dst=r1 src=r0 offset=0 imm=3
#line 138 "sample/map.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=1085 dst=r10 src=r1 offset=-4 imm=0
#line 142 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1086 dst=r2 src=r10 offset=0 imm=0
#line 142 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1087 dst=r2 src=r0 offset=0 imm=-4
#line 142 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1088 dst=r3 src=r10 offset=0 imm=0
#line 142 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1089 dst=r3 src=r0 offset=0 imm=-68
#line 142 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=1090 dst=r1 src=r0 offset=0 imm=0
#line 143 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=1092 dst=r4 src=r0 offset=0 imm=0
#line 143 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1093 dst=r0 src=r0 offset=0 imm=2
#line 143 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 143 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 143 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 143 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1094 dst=r6 src=r0 offset=0 imm=0
#line 143 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1095 dst=r3 src=r6 offset=0 imm=0
#line 143 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1096 dst=r3 src=r0 offset=0 imm=32
#line 143 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1097 dst=r3 src=r0 offset=0 imm=32
#line 143 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1098 dst=r3 src=r0 offset=1 imm=-1
#line 144 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 144 "sample/map.c"
        goto label_70;
        // EBPF_OP_JA pc=1099 dst=r0 src=r0 offset=112 imm=0
#line 144 "sample/map.c"
    goto label_77;
label_70:
    // EBPF_OP_MOV64_IMM pc=1100 dst=r1 src=r0 offset=0 imm=4
#line 144 "sample/map.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=1101 dst=r10 src=r1 offset=-4 imm=0
#line 148 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1102 dst=r2 src=r10 offset=0 imm=0
#line 148 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1103 dst=r2 src=r0 offset=0 imm=-4
#line 148 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1104 dst=r3 src=r10 offset=0 imm=0
#line 148 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1105 dst=r3 src=r0 offset=0 imm=-68
#line 148 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=1106 dst=r1 src=r0 offset=0 imm=0
#line 149 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=1108 dst=r4 src=r0 offset=0 imm=0
#line 149 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1109 dst=r0 src=r0 offset=0 imm=2
#line 149 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 149 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 149 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 149 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1110 dst=r6 src=r0 offset=0 imm=0
#line 149 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1111 dst=r3 src=r6 offset=0 imm=0
#line 149 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1112 dst=r3 src=r0 offset=0 imm=32
#line 149 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1113 dst=r3 src=r0 offset=0 imm=32
#line 149 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1114 dst=r3 src=r0 offset=1 imm=-1
#line 150 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 150 "sample/map.c"
        goto label_71;
        // EBPF_OP_JA pc=1115 dst=r0 src=r0 offset=96 imm=0
#line 150 "sample/map.c"
    goto label_77;
label_71:
    // EBPF_OP_MOV64_IMM pc=1116 dst=r1 src=r0 offset=0 imm=5
#line 150 "sample/map.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=1117 dst=r10 src=r1 offset=-4 imm=0
#line 154 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1118 dst=r2 src=r10 offset=0 imm=0
#line 154 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1119 dst=r2 src=r0 offset=0 imm=-4
#line 154 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1120 dst=r3 src=r10 offset=0 imm=0
#line 154 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1121 dst=r3 src=r0 offset=0 imm=-68
#line 154 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=1122 dst=r1 src=r0 offset=0 imm=0
#line 155 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=1124 dst=r4 src=r0 offset=0 imm=0
#line 155 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1125 dst=r0 src=r0 offset=0 imm=2
#line 155 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 155 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 155 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 155 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1126 dst=r6 src=r0 offset=0 imm=0
#line 155 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1127 dst=r3 src=r6 offset=0 imm=0
#line 155 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1128 dst=r3 src=r0 offset=0 imm=32
#line 155 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1129 dst=r3 src=r0 offset=0 imm=32
#line 155 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1130 dst=r3 src=r0 offset=1 imm=-1
#line 156 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 156 "sample/map.c"
        goto label_72;
        // EBPF_OP_JA pc=1131 dst=r0 src=r0 offset=80 imm=0
#line 156 "sample/map.c"
    goto label_77;
label_72:
    // EBPF_OP_MOV64_IMM pc=1132 dst=r1 src=r0 offset=0 imm=6
#line 156 "sample/map.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=1133 dst=r10 src=r1 offset=-4 imm=0
#line 160 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1134 dst=r2 src=r10 offset=0 imm=0
#line 160 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1135 dst=r2 src=r0 offset=0 imm=-4
#line 160 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1136 dst=r3 src=r10 offset=0 imm=0
#line 160 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1137 dst=r3 src=r0 offset=0 imm=-68
#line 160 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=1138 dst=r1 src=r0 offset=0 imm=0
#line 161 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=1140 dst=r4 src=r0 offset=0 imm=0
#line 161 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1141 dst=r0 src=r0 offset=0 imm=2
#line 161 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 161 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 161 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 161 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1142 dst=r6 src=r0 offset=0 imm=0
#line 161 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1143 dst=r3 src=r6 offset=0 imm=0
#line 161 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1144 dst=r3 src=r0 offset=0 imm=32
#line 161 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1145 dst=r3 src=r0 offset=0 imm=32
#line 161 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1146 dst=r3 src=r0 offset=1 imm=-1
#line 162 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 162 "sample/map.c"
        goto label_73;
        // EBPF_OP_JA pc=1147 dst=r0 src=r0 offset=64 imm=0
#line 162 "sample/map.c"
    goto label_77;
label_73:
    // EBPF_OP_MOV64_IMM pc=1148 dst=r1 src=r0 offset=0 imm=7
#line 162 "sample/map.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=1149 dst=r10 src=r1 offset=-4 imm=0
#line 166 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1150 dst=r2 src=r10 offset=0 imm=0
#line 166 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1151 dst=r2 src=r0 offset=0 imm=-4
#line 166 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1152 dst=r3 src=r10 offset=0 imm=0
#line 166 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1153 dst=r3 src=r0 offset=0 imm=-68
#line 166 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=1154 dst=r1 src=r0 offset=0 imm=0
#line 167 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=1156 dst=r4 src=r0 offset=0 imm=0
#line 167 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1157 dst=r0 src=r0 offset=0 imm=2
#line 167 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 167 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 167 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 167 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1158 dst=r6 src=r0 offset=0 imm=0
#line 167 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1159 dst=r3 src=r6 offset=0 imm=0
#line 167 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1160 dst=r3 src=r0 offset=0 imm=32
#line 167 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1161 dst=r3 src=r0 offset=0 imm=32
#line 167 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1162 dst=r3 src=r0 offset=1 imm=-1
#line 168 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 168 "sample/map.c"
        goto label_74;
        // EBPF_OP_JA pc=1163 dst=r0 src=r0 offset=48 imm=0
#line 168 "sample/map.c"
    goto label_77;
label_74:
    // EBPF_OP_MOV64_IMM pc=1164 dst=r1 src=r0 offset=0 imm=8
#line 168 "sample/map.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=1165 dst=r10 src=r1 offset=-4 imm=0
#line 172 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1166 dst=r2 src=r10 offset=0 imm=0
#line 172 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1167 dst=r2 src=r0 offset=0 imm=-4
#line 172 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1168 dst=r3 src=r10 offset=0 imm=0
#line 172 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1169 dst=r3 src=r0 offset=0 imm=-68
#line 172 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=1170 dst=r1 src=r0 offset=0 imm=0
#line 173 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=1172 dst=r4 src=r0 offset=0 imm=0
#line 173 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1173 dst=r0 src=r0 offset=0 imm=2
#line 173 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 173 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 173 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 173 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1174 dst=r6 src=r0 offset=0 imm=0
#line 173 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1175 dst=r3 src=r6 offset=0 imm=0
#line 173 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1176 dst=r3 src=r0 offset=0 imm=32
#line 173 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1177 dst=r3 src=r0 offset=0 imm=32
#line 173 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1178 dst=r3 src=r0 offset=1 imm=-1
#line 174 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 174 "sample/map.c"
        goto label_75;
        // EBPF_OP_JA pc=1179 dst=r0 src=r0 offset=32 imm=0
#line 174 "sample/map.c"
    goto label_77;
label_75:
    // EBPF_OP_MOV64_IMM pc=1180 dst=r1 src=r0 offset=0 imm=9
#line 174 "sample/map.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=1181 dst=r10 src=r1 offset=-4 imm=0
#line 178 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1182 dst=r2 src=r10 offset=0 imm=0
#line 178 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1183 dst=r2 src=r0 offset=0 imm=-4
#line 178 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1184 dst=r3 src=r10 offset=0 imm=0
#line 178 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1185 dst=r3 src=r0 offset=0 imm=-68
#line 178 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=1186 dst=r1 src=r0 offset=0 imm=0
#line 179 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=1188 dst=r4 src=r0 offset=0 imm=0
#line 179 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1189 dst=r0 src=r0 offset=0 imm=2
#line 179 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 179 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 179 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 179 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1190 dst=r6 src=r0 offset=0 imm=0
#line 179 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1191 dst=r3 src=r6 offset=0 imm=0
#line 179 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1192 dst=r3 src=r0 offset=0 imm=32
#line 179 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1193 dst=r3 src=r0 offset=0 imm=32
#line 179 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1194 dst=r3 src=r0 offset=1 imm=-1
#line 180 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 180 "sample/map.c"
        goto label_76;
        // EBPF_OP_JA pc=1195 dst=r0 src=r0 offset=16 imm=0
#line 180 "sample/map.c"
    goto label_77;
label_76:
    // EBPF_OP_MOV64_IMM pc=1196 dst=r1 src=r0 offset=0 imm=10
#line 180 "sample/map.c"
    r1 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=1197 dst=r10 src=r1 offset=-4 imm=0
#line 184 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1198 dst=r2 src=r10 offset=0 imm=0
#line 184 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1199 dst=r2 src=r0 offset=0 imm=-4
#line 184 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1200 dst=r3 src=r10 offset=0 imm=0
#line 184 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1201 dst=r3 src=r0 offset=0 imm=-68
#line 184 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_MOV64_IMM pc=1202 dst=r7 src=r0 offset=0 imm=0
#line 184 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=1203 dst=r1 src=r0 offset=0 imm=0
#line 185 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=1205 dst=r4 src=r0 offset=0 imm=0
#line 185 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1206 dst=r0 src=r0 offset=0 imm=2
#line 185 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 185 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 185 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 185 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1207 dst=r6 src=r0 offset=0 imm=0
#line 185 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1208 dst=r3 src=r6 offset=0 imm=0
#line 185 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1209 dst=r3 src=r0 offset=0 imm=32
#line 185 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1210 dst=r3 src=r0 offset=0 imm=32
#line 185 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1211 dst=r3 src=r0 offset=35 imm=-1
#line 186 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 186 "sample/map.c"
        goto label_78;
label_77:
    // EBPF_OP_LDDW pc=1212 dst=r1 src=r0 offset=0 imm=1684369010
#line 186 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=1214 dst=r10 src=r1 offset=-40 imm=0
#line 186 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1215 dst=r1 src=r0 offset=0 imm=544040300
#line 186 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=1217 dst=r10 src=r1 offset=-48 imm=0
#line 186 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1218 dst=r1 src=r0 offset=0 imm=1633972341
#line 186 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_STXDW pc=1220 dst=r10 src=r1 offset=-56 imm=0
#line 186 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1221 dst=r1 src=r0 offset=0 imm=1600548962
#line 186 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1223 dst=r10 src=r1 offset=-64 imm=0
#line 186 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1224 dst=r1 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1225 dst=r1 src=r0 offset=0 imm=-64
#line 186 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1226 dst=r2 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=1227 dst=r0 src=r0 offset=0 imm=13
#line 186 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_IMM pc=1228 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1229 dst=r10 src=r1 offset=-20 imm=0
#line 297 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=1230 dst=r1 src=r0 offset=0 imm=1680154724
#line 297 "sample/map.c"
    r1 = IMMEDIATE(1680154724);
    // EBPF_OP_STXW pc=1231 dst=r10 src=r1 offset=-24 imm=0
#line 297 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1232 dst=r1 src=r0 offset=0 imm=1952805408
#line 297 "sample/map.c"
    r1 = (uint64_t)7308905094058439200;
    // EBPF_OP_STXDW pc=1234 dst=r10 src=r1 offset=-32 imm=0
#line 297 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1235 dst=r1 src=r0 offset=0 imm=1599426627
#line 297 "sample/map.c"
    r1 = (uint64_t)5211580972890673219;
    // EBPF_OP_STXDW pc=1237 dst=r10 src=r1 offset=-40 imm=0
#line 297 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1238 dst=r1 src=r0 offset=0 imm=1431456800
#line 297 "sample/map.c"
    r1 = (uint64_t)5928232854886698016;
    // EBPF_OP_STXDW pc=1240 dst=r10 src=r1 offset=-48 imm=0
#line 297 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1241 dst=r1 src=r0 offset=0 imm=1919903264
#line 297 "sample/map.c"
    r1 = (uint64_t)8097873591115146784;
    // EBPF_OP_STXDW pc=1243 dst=r10 src=r1 offset=-56 imm=0
#line 297 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1244 dst=r1 src=r0 offset=0 imm=1953719636
#line 297 "sample/map.c"
    r1 = (uint64_t)6148060143590532436;
    // EBPF_OP_JA pc=1246 dst=r0 src=r0 offset=-1003 imm=0
#line 297 "sample/map.c"
    goto label_19;
label_78:
    // EBPF_OP_STXW pc=1247 dst=r10 src=r7 offset=-4 imm=0
#line 236 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1248 dst=r2 src=r10 offset=0 imm=0
#line 236 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1249 dst=r2 src=r0 offset=0 imm=-4
#line 236 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1250 dst=r1 src=r0 offset=0 imm=0
#line 236 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1252 dst=r0 src=r0 offset=0 imm=18
#line 236 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 236 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 236 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 236 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1253 dst=r6 src=r0 offset=0 imm=0
#line 236 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1254 dst=r4 src=r6 offset=0 imm=0
#line 236 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1255 dst=r4 src=r0 offset=0 imm=32
#line 236 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1256 dst=r1 src=r4 offset=0 imm=0
#line 236 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1257 dst=r1 src=r0 offset=0 imm=32
#line 236 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=1258 dst=r2 src=r0 offset=0 imm=-7
#line 236 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1260 dst=r1 src=r2 offset=27 imm=0
#line 236 "sample/map.c"
    if (r1 == r2)
#line 236 "sample/map.c"
        goto label_81;
label_79:
    // EBPF_OP_MOV64_IMM pc=1261 dst=r1 src=r0 offset=0 imm=100
#line 236 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=1262 dst=r10 src=r1 offset=-16 imm=0
#line 236 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=1263 dst=r1 src=r0 offset=0 imm=1852994932
#line 236 "sample/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=1265 dst=r10 src=r1 offset=-24 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1266 dst=r1 src=r0 offset=0 imm=622883948
#line 236 "sample/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=1268 dst=r10 src=r1 offset=-32 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1269 dst=r1 src=r0 offset=0 imm=543649385
#line 236 "sample/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=1271 dst=r10 src=r1 offset=-40 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1272 dst=r1 src=r0 offset=0 imm=2019893357
#line 236 "sample/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=1274 dst=r10 src=r1 offset=-48 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1275 dst=r1 src=r0 offset=0 imm=1801807216
#line 236 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1277 dst=r10 src=r1 offset=-56 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1278 dst=r1 src=r0 offset=0 imm=1600548962
#line 236 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1280 dst=r10 src=r1 offset=-64 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1281 dst=r4 src=r0 offset=0 imm=32
#line 236 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1282 dst=r1 src=r10 offset=0 imm=0
#line 236 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1283 dst=r1 src=r0 offset=0 imm=-64
#line 236 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1284 dst=r2 src=r0 offset=0 imm=50
#line 236 "sample/map.c"
    r2 = IMMEDIATE(50);
label_80:
    // EBPF_OP_MOV64_IMM pc=1285 dst=r3 src=r0 offset=0 imm=-7
#line 236 "sample/map.c"
    r3 = IMMEDIATE(-7);
    // EBPF_OP_CALL pc=1286 dst=r0 src=r0 offset=0 imm=14
#line 236 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 236 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 236 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 236 "sample/map.c"
        return 0;
        // EBPF_OP_JA pc=1287 dst=r0 src=r0 offset=26 imm=0
#line 236 "sample/map.c"
    goto label_85;
label_81:
    // EBPF_OP_LDXW pc=1288 dst=r3 src=r10 offset=-4 imm=0
#line 236 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1289 dst=r3 src=r0 offset=90 imm=0
#line 236 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 236 "sample/map.c"
        goto label_90;
label_82:
    // EBPF_OP_LDDW pc=1290 dst=r1 src=r0 offset=0 imm=1852404835
#line 236 "sample/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=1292 dst=r10 src=r1 offset=-32 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1293 dst=r1 src=r0 offset=0 imm=543434016
#line 236 "sample/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=1295 dst=r10 src=r1 offset=-40 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1296 dst=r1 src=r0 offset=0 imm=1701978221
#line 236 "sample/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=1298 dst=r10 src=r1 offset=-48 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1299 dst=r1 src=r0 offset=0 imm=1801807216
#line 236 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1301 dst=r10 src=r1 offset=-56 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1302 dst=r1 src=r0 offset=0 imm=1600548962
#line 236 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1304 dst=r10 src=r1 offset=-64 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=1305 dst=r1 src=r0 offset=0 imm=0
#line 236 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1306 dst=r10 src=r1 offset=-24 imm=0
#line 236 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint8_t)r1;
    // EBPF_OP_MOV64_REG pc=1307 dst=r1 src=r10 offset=0 imm=0
#line 236 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1308 dst=r1 src=r0 offset=0 imm=-64
#line 236 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1309 dst=r2 src=r0 offset=0 imm=41
#line 236 "sample/map.c"
    r2 = IMMEDIATE(41);
label_83:
    // EBPF_OP_MOV64_IMM pc=1310 dst=r4 src=r0 offset=0 imm=0
#line 236 "sample/map.c"
    r4 = IMMEDIATE(0);
label_84:
    // EBPF_OP_CALL pc=1311 dst=r0 src=r0 offset=0 imm=14
#line 236 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 236 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 236 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 236 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=1312 dst=r6 src=r0 offset=0 imm=-1
#line 236 "sample/map.c"
    r6 = (uint64_t)4294967295;
label_85:
    // EBPF_OP_MOV64_REG pc=1314 dst=r3 src=r6 offset=0 imm=0
#line 299 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1315 dst=r3 src=r0 offset=0 imm=32
#line 299 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1316 dst=r3 src=r0 offset=0 imm=32
#line 299 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1317 dst=r3 src=r0 offset=1 imm=-1
#line 299 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 299 "sample/map.c"
        goto label_86;
        // EBPF_OP_JA pc=1318 dst=r0 src=r0 offset=42 imm=0
#line 299 "sample/map.c"
    goto label_89;
label_86:
    // EBPF_OP_MOV64_IMM pc=1319 dst=r1 src=r0 offset=0 imm=0
#line 299 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1320 dst=r10 src=r1 offset=-4 imm=0
#line 236 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1321 dst=r2 src=r10 offset=0 imm=0
#line 236 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1322 dst=r2 src=r0 offset=0 imm=-4
#line 236 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1323 dst=r1 src=r0 offset=0 imm=0
#line 236 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1325 dst=r0 src=r0 offset=0 imm=18
#line 236 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 236 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 236 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 236 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1326 dst=r7 src=r0 offset=0 imm=0
#line 236 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1327 dst=r4 src=r7 offset=0 imm=0
#line 236 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=1328 dst=r4 src=r0 offset=0 imm=32
#line 236 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1329 dst=r1 src=r4 offset=0 imm=0
#line 236 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1330 dst=r1 src=r0 offset=0 imm=32
#line 236 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=1331 dst=r2 src=r0 offset=0 imm=-7
#line 236 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1333 dst=r1 src=r2 offset=865 imm=0
#line 236 "sample/map.c"
    if (r1 == r2)
#line 236 "sample/map.c"
        goto label_137;
label_87:
    // EBPF_OP_MOV64_IMM pc=1334 dst=r1 src=r0 offset=0 imm=100
#line 236 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=1335 dst=r10 src=r1 offset=-16 imm=0
#line 236 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=1336 dst=r1 src=r0 offset=0 imm=1852994932
#line 236 "sample/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=1338 dst=r10 src=r1 offset=-24 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1339 dst=r1 src=r0 offset=0 imm=622883948
#line 236 "sample/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=1341 dst=r10 src=r1 offset=-32 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1342 dst=r1 src=r0 offset=0 imm=543649385
#line 236 "sample/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=1344 dst=r10 src=r1 offset=-40 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1345 dst=r1 src=r0 offset=0 imm=2019893357
#line 236 "sample/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=1347 dst=r10 src=r1 offset=-48 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1348 dst=r1 src=r0 offset=0 imm=1801807216
#line 236 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1350 dst=r10 src=r1 offset=-56 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1351 dst=r1 src=r0 offset=0 imm=1600548962
#line 236 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1353 dst=r10 src=r1 offset=-64 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1354 dst=r4 src=r0 offset=0 imm=32
#line 236 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1355 dst=r1 src=r10 offset=0 imm=0
#line 236 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1356 dst=r1 src=r0 offset=0 imm=-64
#line 236 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1357 dst=r2 src=r0 offset=0 imm=50
#line 236 "sample/map.c"
    r2 = IMMEDIATE(50);
label_88:
    // EBPF_OP_MOV64_IMM pc=1358 dst=r3 src=r0 offset=0 imm=-7
#line 236 "sample/map.c"
    r3 = IMMEDIATE(-7);
    // EBPF_OP_CALL pc=1359 dst=r0 src=r0 offset=0 imm=14
#line 236 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 236 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 236 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 236 "sample/map.c"
        return 0;
        // EBPF_OP_JA pc=1360 dst=r0 src=r0 offset=864 imm=0
#line 236 "sample/map.c"
    goto label_141;
label_89:
    // EBPF_OP_LDDW pc=1361 dst=r1 src=r0 offset=0 imm=1684369010
#line 236 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=1363 dst=r10 src=r1 offset=-32 imm=0
#line 299 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1364 dst=r1 src=r0 offset=0 imm=541414725
#line 299 "sample/map.c"
    r1 = (uint64_t)8463501140578096453;
    // EBPF_OP_STXDW pc=1366 dst=r10 src=r1 offset=-40 imm=0
#line 299 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1367 dst=r1 src=r0 offset=0 imm=1634541682
#line 299 "sample/map.c"
    r1 = (uint64_t)6147730633380405362;
    // EBPF_OP_STXDW pc=1369 dst=r10 src=r1 offset=-48 imm=0
#line 299 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1370 dst=r1 src=r0 offset=0 imm=1330667336
#line 299 "sample/map.c"
    r1 = (uint64_t)8027138915134627656;
    // EBPF_OP_STXDW pc=1372 dst=r10 src=r1 offset=-56 imm=0
#line 299 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1373 dst=r1 src=r0 offset=0 imm=1953719636
#line 299 "sample/map.c"
    r1 = (uint64_t)6004793778491319636;
    // EBPF_OP_STXDW pc=1375 dst=r10 src=r1 offset=-64 imm=0
#line 299 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1376 dst=r1 src=r10 offset=0 imm=0
#line 299 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1377 dst=r1 src=r0 offset=0 imm=-64
#line 299 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1378 dst=r2 src=r0 offset=0 imm=40
#line 299 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_JA pc=1379 dst=r0 src=r0 offset=-1279 imm=0
#line 299 "sample/map.c"
    goto label_8;
label_90:
    // EBPF_OP_MOV64_IMM pc=1380 dst=r7 src=r0 offset=0 imm=0
#line 299 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1381 dst=r10 src=r7 offset=-4 imm=0
#line 237 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1382 dst=r2 src=r10 offset=0 imm=0
#line 237 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1383 dst=r2 src=r0 offset=0 imm=-4
#line 237 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1384 dst=r1 src=r0 offset=0 imm=0
#line 237 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1386 dst=r0 src=r0 offset=0 imm=17
#line 237 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 237 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 237 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 237 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1387 dst=r6 src=r0 offset=0 imm=0
#line 237 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1388 dst=r4 src=r6 offset=0 imm=0
#line 237 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1389 dst=r4 src=r0 offset=0 imm=32
#line 237 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1390 dst=r1 src=r4 offset=0 imm=0
#line 237 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1391 dst=r1 src=r0 offset=0 imm=32
#line 237 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=1392 dst=r2 src=r0 offset=0 imm=-7
#line 237 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1394 dst=r1 src=r2 offset=24 imm=0
#line 237 "sample/map.c"
    if (r1 == r2)
#line 237 "sample/map.c"
        goto label_92;
label_91:
    // EBPF_OP_STXB pc=1395 dst=r10 src=r7 offset=-16 imm=0
#line 237 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint8_t)r7;
    // EBPF_OP_LDDW pc=1396 dst=r1 src=r0 offset=0 imm=1701737077
#line 237 "sample/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=1398 dst=r10 src=r1 offset=-24 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1399 dst=r1 src=r0 offset=0 imm=1680154740
#line 237 "sample/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=1401 dst=r10 src=r1 offset=-32 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1402 dst=r1 src=r0 offset=0 imm=1914726254
#line 237 "sample/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=1404 dst=r10 src=r1 offset=-40 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1405 dst=r1 src=r0 offset=0 imm=1886938400
#line 237 "sample/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=1407 dst=r10 src=r1 offset=-48 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1408 dst=r1 src=r0 offset=0 imm=1601204080
#line 237 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1410 dst=r10 src=r1 offset=-56 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1411 dst=r1 src=r0 offset=0 imm=1600548962
#line 237 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1413 dst=r10 src=r1 offset=-64 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1414 dst=r4 src=r0 offset=0 imm=32
#line 237 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1415 dst=r1 src=r10 offset=0 imm=0
#line 237 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1416 dst=r1 src=r0 offset=0 imm=-64
#line 237 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1417 dst=r2 src=r0 offset=0 imm=49
#line 237 "sample/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=1418 dst=r0 src=r0 offset=-134 imm=0
#line 237 "sample/map.c"
    goto label_80;
label_92:
    // EBPF_OP_LDXW pc=1419 dst=r3 src=r10 offset=-4 imm=0
#line 237 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1420 dst=r3 src=r0 offset=19 imm=0
#line 237 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 237 "sample/map.c"
        goto label_94;
label_93:
    // EBPF_OP_LDDW pc=1421 dst=r1 src=r0 offset=0 imm=1735289204
#line 237 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1423 dst=r10 src=r1 offset=-32 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1424 dst=r1 src=r0 offset=0 imm=1696621605
#line 237 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1426 dst=r10 src=r1 offset=-40 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1427 dst=r1 src=r0 offset=0 imm=1952805408
#line 237 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1429 dst=r10 src=r1 offset=-48 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1430 dst=r1 src=r0 offset=0 imm=1601204080
#line 237 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1432 dst=r10 src=r1 offset=-56 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1433 dst=r1 src=r0 offset=0 imm=1600548962
#line 237 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1435 dst=r10 src=r1 offset=-64 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1436 dst=r1 src=r10 offset=0 imm=0
#line 237 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1437 dst=r1 src=r0 offset=0 imm=-64
#line 237 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1438 dst=r2 src=r0 offset=0 imm=40
#line 237 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_JA pc=1439 dst=r0 src=r0 offset=-130 imm=0
#line 237 "sample/map.c"
    goto label_83;
label_94:
    // EBPF_OP_MOV64_IMM pc=1440 dst=r7 src=r0 offset=0 imm=0
#line 237 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1441 dst=r10 src=r7 offset=-4 imm=0
#line 245 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1442 dst=r2 src=r10 offset=0 imm=0
#line 245 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1443 dst=r2 src=r0 offset=0 imm=-4
#line 245 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1444 dst=r1 src=r0 offset=0 imm=0
#line 245 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1446 dst=r3 src=r0 offset=0 imm=0
#line 245 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1447 dst=r0 src=r0 offset=0 imm=16
#line 245 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 245 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 245 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 245 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1448 dst=r6 src=r0 offset=0 imm=0
#line 245 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1449 dst=r5 src=r6 offset=0 imm=0
#line 245 "sample/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1450 dst=r5 src=r0 offset=0 imm=32
#line 245 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1451 dst=r1 src=r5 offset=0 imm=0
#line 245 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1452 dst=r1 src=r0 offset=0 imm=32
#line 245 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1453 dst=r1 src=r0 offset=31 imm=0
#line 245 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 245 "sample/map.c"
        goto label_98;
label_95:
    // EBPF_OP_MOV64_IMM pc=1454 dst=r1 src=r0 offset=0 imm=25637
#line 245 "sample/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1455 dst=r10 src=r1 offset=-12 imm=0
#line 245 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1456 dst=r1 src=r0 offset=0 imm=543450478
#line 245 "sample/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1457 dst=r10 src=r1 offset=-16 imm=0
#line 245 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1458 dst=r1 src=r0 offset=0 imm=1914725413
#line 245 "sample/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1460 dst=r10 src=r1 offset=-24 imm=0
#line 245 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1461 dst=r1 src=r0 offset=0 imm=1667592312
#line 245 "sample/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1463 dst=r10 src=r1 offset=-32 imm=0
#line 245 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1464 dst=r1 src=r0 offset=0 imm=543649385
#line 245 "sample/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1466 dst=r10 src=r1 offset=-40 imm=0
#line 245 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1467 dst=r1 src=r0 offset=0 imm=1852383341
#line 245 "sample/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1469 dst=r10 src=r1 offset=-48 imm=0
#line 245 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1470 dst=r1 src=r0 offset=0 imm=1752397168
#line 245 "sample/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1472 dst=r10 src=r1 offset=-56 imm=0
#line 245 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1473 dst=r1 src=r0 offset=0 imm=1600548962
#line 245 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1475 dst=r10 src=r1 offset=-64 imm=0
#line 245 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_STXB pc=1476 dst=r10 src=r7 offset=-10 imm=0
#line 245 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-10)) = (uint8_t)r7;
label_96:
    // EBPF_OP_LDXW pc=1477 dst=r3 src=r10 offset=-4 imm=0
#line 245 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ARSH64_IMM pc=1478 dst=r5 src=r0 offset=0 imm=32
#line 245 "sample/map.c"
    r5 = (int64_t)r5 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1479 dst=r1 src=r10 offset=0 imm=0
#line 245 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1480 dst=r1 src=r0 offset=0 imm=-64
#line 245 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1481 dst=r2 src=r0 offset=0 imm=55
#line 245 "sample/map.c"
    r2 = IMMEDIATE(55);
    // EBPF_OP_MOV64_IMM pc=1482 dst=r4 src=r0 offset=0 imm=0
#line 245 "sample/map.c"
    r4 = IMMEDIATE(0);
label_97:
    // EBPF_OP_CALL pc=1483 dst=r0 src=r0 offset=0 imm=15
#line 245 "sample/map.c"
    r0 = test_maps_helpers[10].address
#line 245 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 245 "sample/map.c"
    if ((test_maps_helpers[10].tail_call) && (r0 == 0))
#line 245 "sample/map.c"
        return 0;
        // EBPF_OP_JA pc=1484 dst=r0 src=r0 offset=-171 imm=0
#line 245 "sample/map.c"
    goto label_85;
label_98:
    // EBPF_OP_MOV64_IMM pc=1485 dst=r1 src=r0 offset=0 imm=1
#line 245 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=1486 dst=r10 src=r1 offset=-4 imm=0
#line 246 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1487 dst=r2 src=r10 offset=0 imm=0
#line 246 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1488 dst=r2 src=r0 offset=0 imm=-4
#line 246 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=1489 dst=r7 src=r0 offset=0 imm=0
#line 246 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=1490 dst=r1 src=r0 offset=0 imm=0
#line 246 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1492 dst=r3 src=r0 offset=0 imm=0
#line 246 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1493 dst=r0 src=r0 offset=0 imm=16
#line 246 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 246 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 246 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 246 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1494 dst=r6 src=r0 offset=0 imm=0
#line 246 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1495 dst=r5 src=r6 offset=0 imm=0
#line 246 "sample/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1496 dst=r5 src=r0 offset=0 imm=32
#line 246 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1497 dst=r1 src=r5 offset=0 imm=0
#line 246 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1498 dst=r1 src=r0 offset=0 imm=32
#line 246 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1499 dst=r1 src=r0 offset=1 imm=0
#line 246 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 246 "sample/map.c"
        goto label_99;
        // EBPF_OP_JA pc=1500 dst=r0 src=r0 offset=-47 imm=0
#line 246 "sample/map.c"
    goto label_95;
label_99:
    // EBPF_OP_MOV64_IMM pc=1501 dst=r1 src=r0 offset=0 imm=2
#line 246 "sample/map.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=1502 dst=r10 src=r1 offset=-4 imm=0
#line 247 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1503 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1504 dst=r2 src=r0 offset=0 imm=-4
#line 247 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=1505 dst=r7 src=r0 offset=0 imm=0
#line 247 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=1506 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1508 dst=r3 src=r0 offset=0 imm=0
#line 247 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1509 dst=r0 src=r0 offset=0 imm=16
#line 247 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 247 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 247 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 247 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1510 dst=r6 src=r0 offset=0 imm=0
#line 247 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1511 dst=r5 src=r6 offset=0 imm=0
#line 247 "sample/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1512 dst=r5 src=r0 offset=0 imm=32
#line 247 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1513 dst=r1 src=r5 offset=0 imm=0
#line 247 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1514 dst=r1 src=r0 offset=0 imm=32
#line 247 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1515 dst=r1 src=r0 offset=1 imm=0
#line 247 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 247 "sample/map.c"
        goto label_100;
        // EBPF_OP_JA pc=1516 dst=r0 src=r0 offset=-63 imm=0
#line 247 "sample/map.c"
    goto label_95;
label_100:
    // EBPF_OP_MOV64_IMM pc=1517 dst=r1 src=r0 offset=0 imm=3
#line 247 "sample/map.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=1518 dst=r10 src=r1 offset=-4 imm=0
#line 248 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1519 dst=r2 src=r10 offset=0 imm=0
#line 248 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1520 dst=r2 src=r0 offset=0 imm=-4
#line 248 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=1521 dst=r7 src=r0 offset=0 imm=0
#line 248 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=1522 dst=r1 src=r0 offset=0 imm=0
#line 248 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1524 dst=r3 src=r0 offset=0 imm=0
#line 248 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1525 dst=r0 src=r0 offset=0 imm=16
#line 248 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 248 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 248 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 248 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1526 dst=r6 src=r0 offset=0 imm=0
#line 248 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1527 dst=r5 src=r6 offset=0 imm=0
#line 248 "sample/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1528 dst=r5 src=r0 offset=0 imm=32
#line 248 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1529 dst=r1 src=r5 offset=0 imm=0
#line 248 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1530 dst=r1 src=r0 offset=0 imm=32
#line 248 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1531 dst=r1 src=r0 offset=1 imm=0
#line 248 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 248 "sample/map.c"
        goto label_101;
        // EBPF_OP_JA pc=1532 dst=r0 src=r0 offset=-79 imm=0
#line 248 "sample/map.c"
    goto label_95;
label_101:
    // EBPF_OP_MOV64_IMM pc=1533 dst=r1 src=r0 offset=0 imm=4
#line 248 "sample/map.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=1534 dst=r10 src=r1 offset=-4 imm=0
#line 249 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1535 dst=r2 src=r10 offset=0 imm=0
#line 249 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1536 dst=r2 src=r0 offset=0 imm=-4
#line 249 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=1537 dst=r7 src=r0 offset=0 imm=0
#line 249 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=1538 dst=r1 src=r0 offset=0 imm=0
#line 249 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1540 dst=r3 src=r0 offset=0 imm=0
#line 249 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1541 dst=r0 src=r0 offset=0 imm=16
#line 249 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 249 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 249 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 249 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1542 dst=r6 src=r0 offset=0 imm=0
#line 249 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1543 dst=r5 src=r6 offset=0 imm=0
#line 249 "sample/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1544 dst=r5 src=r0 offset=0 imm=32
#line 249 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1545 dst=r1 src=r5 offset=0 imm=0
#line 249 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1546 dst=r1 src=r0 offset=0 imm=32
#line 249 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1547 dst=r1 src=r0 offset=1 imm=0
#line 249 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 249 "sample/map.c"
        goto label_102;
        // EBPF_OP_JA pc=1548 dst=r0 src=r0 offset=-95 imm=0
#line 249 "sample/map.c"
    goto label_95;
label_102:
    // EBPF_OP_MOV64_IMM pc=1549 dst=r1 src=r0 offset=0 imm=5
#line 249 "sample/map.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=1550 dst=r10 src=r1 offset=-4 imm=0
#line 250 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1551 dst=r2 src=r10 offset=0 imm=0
#line 250 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1552 dst=r2 src=r0 offset=0 imm=-4
#line 250 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=1553 dst=r7 src=r0 offset=0 imm=0
#line 250 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=1554 dst=r1 src=r0 offset=0 imm=0
#line 250 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1556 dst=r3 src=r0 offset=0 imm=0
#line 250 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1557 dst=r0 src=r0 offset=0 imm=16
#line 250 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 250 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 250 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 250 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1558 dst=r6 src=r0 offset=0 imm=0
#line 250 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1559 dst=r5 src=r6 offset=0 imm=0
#line 250 "sample/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1560 dst=r5 src=r0 offset=0 imm=32
#line 250 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1561 dst=r1 src=r5 offset=0 imm=0
#line 250 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1562 dst=r1 src=r0 offset=0 imm=32
#line 250 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1563 dst=r1 src=r0 offset=1 imm=0
#line 250 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 250 "sample/map.c"
        goto label_103;
        // EBPF_OP_JA pc=1564 dst=r0 src=r0 offset=-111 imm=0
#line 250 "sample/map.c"
    goto label_95;
label_103:
    // EBPF_OP_MOV64_IMM pc=1565 dst=r1 src=r0 offset=0 imm=6
#line 250 "sample/map.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=1566 dst=r10 src=r1 offset=-4 imm=0
#line 251 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1567 dst=r2 src=r10 offset=0 imm=0
#line 251 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1568 dst=r2 src=r0 offset=0 imm=-4
#line 251 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=1569 dst=r7 src=r0 offset=0 imm=0
#line 251 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=1570 dst=r1 src=r0 offset=0 imm=0
#line 251 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1572 dst=r3 src=r0 offset=0 imm=0
#line 251 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1573 dst=r0 src=r0 offset=0 imm=16
#line 251 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 251 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 251 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 251 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1574 dst=r6 src=r0 offset=0 imm=0
#line 251 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1575 dst=r5 src=r6 offset=0 imm=0
#line 251 "sample/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1576 dst=r5 src=r0 offset=0 imm=32
#line 251 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1577 dst=r1 src=r5 offset=0 imm=0
#line 251 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1578 dst=r1 src=r0 offset=0 imm=32
#line 251 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1579 dst=r1 src=r0 offset=1 imm=0
#line 251 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 251 "sample/map.c"
        goto label_104;
        // EBPF_OP_JA pc=1580 dst=r0 src=r0 offset=-127 imm=0
#line 251 "sample/map.c"
    goto label_95;
label_104:
    // EBPF_OP_MOV64_IMM pc=1581 dst=r1 src=r0 offset=0 imm=7
#line 251 "sample/map.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=1582 dst=r10 src=r1 offset=-4 imm=0
#line 252 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1583 dst=r2 src=r10 offset=0 imm=0
#line 252 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1584 dst=r2 src=r0 offset=0 imm=-4
#line 252 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=1585 dst=r7 src=r0 offset=0 imm=0
#line 252 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=1586 dst=r1 src=r0 offset=0 imm=0
#line 252 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1588 dst=r3 src=r0 offset=0 imm=0
#line 252 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1589 dst=r0 src=r0 offset=0 imm=16
#line 252 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 252 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 252 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 252 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1590 dst=r6 src=r0 offset=0 imm=0
#line 252 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1591 dst=r5 src=r6 offset=0 imm=0
#line 252 "sample/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1592 dst=r5 src=r0 offset=0 imm=32
#line 252 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1593 dst=r1 src=r5 offset=0 imm=0
#line 252 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1594 dst=r1 src=r0 offset=0 imm=32
#line 252 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1595 dst=r1 src=r0 offset=1 imm=0
#line 252 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 252 "sample/map.c"
        goto label_105;
        // EBPF_OP_JA pc=1596 dst=r0 src=r0 offset=-143 imm=0
#line 252 "sample/map.c"
    goto label_95;
label_105:
    // EBPF_OP_MOV64_IMM pc=1597 dst=r1 src=r0 offset=0 imm=8
#line 252 "sample/map.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=1598 dst=r10 src=r1 offset=-4 imm=0
#line 253 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1599 dst=r2 src=r10 offset=0 imm=0
#line 253 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1600 dst=r2 src=r0 offset=0 imm=-4
#line 253 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=1601 dst=r7 src=r0 offset=0 imm=0
#line 253 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=1602 dst=r1 src=r0 offset=0 imm=0
#line 253 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1604 dst=r3 src=r0 offset=0 imm=0
#line 253 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1605 dst=r0 src=r0 offset=0 imm=16
#line 253 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 253 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 253 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 253 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1606 dst=r6 src=r0 offset=0 imm=0
#line 253 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1607 dst=r5 src=r6 offset=0 imm=0
#line 253 "sample/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1608 dst=r5 src=r0 offset=0 imm=32
#line 253 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1609 dst=r1 src=r5 offset=0 imm=0
#line 253 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1610 dst=r1 src=r0 offset=0 imm=32
#line 253 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1611 dst=r1 src=r0 offset=1 imm=0
#line 253 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 253 "sample/map.c"
        goto label_106;
        // EBPF_OP_JA pc=1612 dst=r0 src=r0 offset=-159 imm=0
#line 253 "sample/map.c"
    goto label_95;
label_106:
    // EBPF_OP_MOV64_IMM pc=1613 dst=r1 src=r0 offset=0 imm=9
#line 253 "sample/map.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=1614 dst=r10 src=r1 offset=-4 imm=0
#line 254 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1615 dst=r2 src=r10 offset=0 imm=0
#line 254 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1616 dst=r2 src=r0 offset=0 imm=-4
#line 254 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=1617 dst=r7 src=r0 offset=0 imm=0
#line 254 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=1618 dst=r1 src=r0 offset=0 imm=0
#line 254 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1620 dst=r3 src=r0 offset=0 imm=0
#line 254 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1621 dst=r0 src=r0 offset=0 imm=16
#line 254 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 254 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 254 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 254 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1622 dst=r6 src=r0 offset=0 imm=0
#line 254 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1623 dst=r5 src=r6 offset=0 imm=0
#line 254 "sample/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1624 dst=r5 src=r0 offset=0 imm=32
#line 254 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1625 dst=r1 src=r5 offset=0 imm=0
#line 254 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1626 dst=r1 src=r0 offset=0 imm=32
#line 254 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1627 dst=r1 src=r0 offset=1 imm=0
#line 254 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 254 "sample/map.c"
        goto label_107;
        // EBPF_OP_JA pc=1628 dst=r0 src=r0 offset=-175 imm=0
#line 254 "sample/map.c"
    goto label_95;
label_107:
    // EBPF_OP_MOV64_IMM pc=1629 dst=r7 src=r0 offset=0 imm=10
#line 254 "sample/map.c"
    r7 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=1630 dst=r10 src=r7 offset=-4 imm=0
#line 257 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1631 dst=r2 src=r10 offset=0 imm=0
#line 257 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1632 dst=r2 src=r0 offset=0 imm=-4
#line 257 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=1633 dst=r8 src=r0 offset=0 imm=0
#line 257 "sample/map.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=1634 dst=r1 src=r0 offset=0 imm=0
#line 257 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1636 dst=r3 src=r0 offset=0 imm=0
#line 257 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1637 dst=r0 src=r0 offset=0 imm=16
#line 257 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 257 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 257 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 257 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1638 dst=r6 src=r0 offset=0 imm=0
#line 257 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1639 dst=r5 src=r6 offset=0 imm=0
#line 257 "sample/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1640 dst=r5 src=r0 offset=0 imm=32
#line 257 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1641 dst=r1 src=r5 offset=0 imm=0
#line 257 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1642 dst=r1 src=r0 offset=0 imm=32
#line 257 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=1643 dst=r2 src=r0 offset=0 imm=-29
#line 257 "sample/map.c"
    r2 = (uint64_t)4294967267;
    // EBPF_OP_JEQ_REG pc=1645 dst=r1 src=r2 offset=30 imm=0
#line 257 "sample/map.c"
    if (r1 == r2)
#line 257 "sample/map.c"
        goto label_108;
        // EBPF_OP_STXB pc=1646 dst=r10 src=r8 offset=-10 imm=0
#line 257 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-10)) = (uint8_t)r8;
    // EBPF_OP_MOV64_IMM pc=1647 dst=r1 src=r0 offset=0 imm=25637
#line 257 "sample/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1648 dst=r10 src=r1 offset=-12 imm=0
#line 257 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1649 dst=r1 src=r0 offset=0 imm=543450478
#line 257 "sample/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1650 dst=r10 src=r1 offset=-16 imm=0
#line 257 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1651 dst=r1 src=r0 offset=0 imm=1914725413
#line 257 "sample/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1653 dst=r10 src=r1 offset=-24 imm=0
#line 257 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1654 dst=r1 src=r0 offset=0 imm=1667592312
#line 257 "sample/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1656 dst=r10 src=r1 offset=-32 imm=0
#line 257 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1657 dst=r1 src=r0 offset=0 imm=543649385
#line 257 "sample/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1659 dst=r10 src=r1 offset=-40 imm=0
#line 257 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1660 dst=r1 src=r0 offset=0 imm=1852383341
#line 257 "sample/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1662 dst=r10 src=r1 offset=-48 imm=0
#line 257 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1663 dst=r1 src=r0 offset=0 imm=1752397168
#line 257 "sample/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1665 dst=r10 src=r1 offset=-56 imm=0
#line 257 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1666 dst=r1 src=r0 offset=0 imm=1600548962
#line 257 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1668 dst=r10 src=r1 offset=-64 imm=0
#line 257 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=1669 dst=r3 src=r10 offset=-4 imm=0
#line 257 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ARSH64_IMM pc=1670 dst=r5 src=r0 offset=0 imm=32
#line 257 "sample/map.c"
    r5 = (int64_t)r5 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1671 dst=r1 src=r10 offset=0 imm=0
#line 257 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1672 dst=r1 src=r0 offset=0 imm=-64
#line 257 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1673 dst=r2 src=r0 offset=0 imm=55
#line 257 "sample/map.c"
    r2 = IMMEDIATE(55);
    // EBPF_OP_MOV64_IMM pc=1674 dst=r4 src=r0 offset=0 imm=-29
#line 257 "sample/map.c"
    r4 = IMMEDIATE(-29);
    // EBPF_OP_JA pc=1675 dst=r0 src=r0 offset=-193 imm=0
#line 257 "sample/map.c"
    goto label_97;
label_108:
    // EBPF_OP_STXW pc=1676 dst=r10 src=r7 offset=-4 imm=0
#line 258 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1677 dst=r2 src=r10 offset=0 imm=0
#line 258 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1678 dst=r2 src=r0 offset=0 imm=-4
#line 258 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1679 dst=r1 src=r0 offset=0 imm=0
#line 258 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1681 dst=r3 src=r0 offset=0 imm=2
#line 258 "sample/map.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_CALL pc=1682 dst=r0 src=r0 offset=0 imm=16
#line 258 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 258 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 258 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 258 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1683 dst=r6 src=r0 offset=0 imm=0
#line 258 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1684 dst=r5 src=r6 offset=0 imm=0
#line 258 "sample/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1685 dst=r5 src=r0 offset=0 imm=32
#line 258 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1686 dst=r1 src=r5 offset=0 imm=0
#line 258 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1687 dst=r1 src=r0 offset=0 imm=32
#line 258 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1688 dst=r1 src=r0 offset=25 imm=0
#line 258 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 258 "sample/map.c"
        goto label_109;
        // EBPF_OP_MOV64_IMM pc=1689 dst=r1 src=r0 offset=0 imm=25637
#line 258 "sample/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1690 dst=r10 src=r1 offset=-12 imm=0
#line 258 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1691 dst=r1 src=r0 offset=0 imm=543450478
#line 258 "sample/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1692 dst=r10 src=r1 offset=-16 imm=0
#line 258 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1693 dst=r1 src=r0 offset=0 imm=1914725413
#line 258 "sample/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1695 dst=r10 src=r1 offset=-24 imm=0
#line 258 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1696 dst=r1 src=r0 offset=0 imm=1667592312
#line 258 "sample/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1698 dst=r10 src=r1 offset=-32 imm=0
#line 258 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1699 dst=r1 src=r0 offset=0 imm=543649385
#line 258 "sample/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1701 dst=r10 src=r1 offset=-40 imm=0
#line 258 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1702 dst=r1 src=r0 offset=0 imm=1852383341
#line 258 "sample/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1704 dst=r10 src=r1 offset=-48 imm=0
#line 258 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1705 dst=r1 src=r0 offset=0 imm=1752397168
#line 258 "sample/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1707 dst=r10 src=r1 offset=-56 imm=0
#line 258 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1708 dst=r1 src=r0 offset=0 imm=1600548962
#line 258 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1710 dst=r10 src=r1 offset=-64 imm=0
#line 258 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=1711 dst=r1 src=r0 offset=0 imm=0
#line 258 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1712 dst=r10 src=r1 offset=-10 imm=0
#line 258 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-10)) = (uint8_t)r1;
    // EBPF_OP_JA pc=1713 dst=r0 src=r0 offset=-237 imm=0
#line 258 "sample/map.c"
    goto label_96;
label_109:
    // EBPF_OP_MOV64_IMM pc=1714 dst=r1 src=r0 offset=0 imm=0
#line 258 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1715 dst=r10 src=r1 offset=-4 imm=0
#line 260 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1716 dst=r2 src=r10 offset=0 imm=0
#line 260 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1717 dst=r2 src=r0 offset=0 imm=-4
#line 260 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1718 dst=r1 src=r0 offset=0 imm=0
#line 260 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1720 dst=r0 src=r0 offset=0 imm=18
#line 260 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 260 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 260 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 260 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1721 dst=r6 src=r0 offset=0 imm=0
#line 260 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1722 dst=r4 src=r6 offset=0 imm=0
#line 260 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1723 dst=r4 src=r0 offset=0 imm=32
#line 260 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1724 dst=r1 src=r4 offset=0 imm=0
#line 260 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1725 dst=r1 src=r0 offset=0 imm=32
#line 260 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1726 dst=r1 src=r0 offset=27 imm=0
#line 260 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 260 "sample/map.c"
        goto label_111;
        // EBPF_OP_MOV64_IMM pc=1727 dst=r1 src=r0 offset=0 imm=100
#line 260 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=1728 dst=r10 src=r1 offset=-16 imm=0
#line 260 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=1729 dst=r1 src=r0 offset=0 imm=1852994932
#line 260 "sample/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=1731 dst=r10 src=r1 offset=-24 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1732 dst=r1 src=r0 offset=0 imm=622883948
#line 260 "sample/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=1734 dst=r10 src=r1 offset=-32 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1735 dst=r1 src=r0 offset=0 imm=543649385
#line 260 "sample/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=1737 dst=r10 src=r1 offset=-40 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1738 dst=r1 src=r0 offset=0 imm=2019893357
#line 260 "sample/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=1740 dst=r10 src=r1 offset=-48 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1741 dst=r1 src=r0 offset=0 imm=1801807216
#line 260 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1743 dst=r10 src=r1 offset=-56 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1744 dst=r1 src=r0 offset=0 imm=1600548962
#line 260 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1746 dst=r10 src=r1 offset=-64 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1747 dst=r4 src=r0 offset=0 imm=32
#line 260 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1748 dst=r1 src=r10 offset=0 imm=0
#line 260 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1749 dst=r1 src=r0 offset=0 imm=-64
#line 260 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1750 dst=r2 src=r0 offset=0 imm=50
#line 260 "sample/map.c"
    r2 = IMMEDIATE(50);
label_110:
    // EBPF_OP_MOV64_IMM pc=1751 dst=r3 src=r0 offset=0 imm=0
#line 260 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1752 dst=r0 src=r0 offset=0 imm=14
#line 260 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 260 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 260 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 260 "sample/map.c"
        return 0;
        // EBPF_OP_JA pc=1753 dst=r0 src=r0 offset=-440 imm=0
#line 260 "sample/map.c"
    goto label_85;
label_111:
    // EBPF_OP_LDXW pc=1754 dst=r3 src=r10 offset=-4 imm=0
#line 260 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1755 dst=r3 src=r0 offset=22 imm=1
#line 260 "sample/map.c"
    if (r3 == IMMEDIATE(1))
#line 260 "sample/map.c"
        goto label_112;
        // EBPF_OP_MOV64_IMM pc=1756 dst=r1 src=r0 offset=0 imm=0
#line 260 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1757 dst=r10 src=r1 offset=-24 imm=0
#line 260 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=1758 dst=r1 src=r0 offset=0 imm=1852404835
#line 260 "sample/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=1760 dst=r10 src=r1 offset=-32 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1761 dst=r1 src=r0 offset=0 imm=543434016
#line 260 "sample/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=1763 dst=r10 src=r1 offset=-40 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1764 dst=r1 src=r0 offset=0 imm=1701978221
#line 260 "sample/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=1766 dst=r10 src=r1 offset=-48 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1767 dst=r1 src=r0 offset=0 imm=1801807216
#line 260 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1769 dst=r10 src=r1 offset=-56 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1770 dst=r1 src=r0 offset=0 imm=1600548962
#line 260 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1772 dst=r10 src=r1 offset=-64 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1773 dst=r1 src=r10 offset=0 imm=0
#line 260 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1774 dst=r1 src=r0 offset=0 imm=-64
#line 260 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1775 dst=r2 src=r0 offset=0 imm=41
#line 260 "sample/map.c"
    r2 = IMMEDIATE(41);
    // EBPF_OP_MOV64_IMM pc=1776 dst=r4 src=r0 offset=0 imm=1
#line 260 "sample/map.c"
    r4 = IMMEDIATE(1);
    // EBPF_OP_JA pc=1777 dst=r0 src=r0 offset=-467 imm=0
#line 260 "sample/map.c"
    goto label_84;
label_112:
    // EBPF_OP_MOV64_IMM pc=1778 dst=r7 src=r0 offset=0 imm=0
#line 260 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1779 dst=r10 src=r7 offset=-4 imm=0
#line 268 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1780 dst=r2 src=r10 offset=0 imm=0
#line 268 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1781 dst=r2 src=r0 offset=0 imm=-4
#line 268 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1782 dst=r1 src=r0 offset=0 imm=0
#line 268 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1784 dst=r0 src=r0 offset=0 imm=17
#line 268 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 268 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 268 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 268 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1785 dst=r6 src=r0 offset=0 imm=0
#line 268 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1786 dst=r4 src=r6 offset=0 imm=0
#line 268 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1787 dst=r4 src=r0 offset=0 imm=32
#line 268 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1788 dst=r1 src=r4 offset=0 imm=0
#line 268 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1789 dst=r1 src=r0 offset=0 imm=32
#line 268 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1790 dst=r1 src=r0 offset=24 imm=0
#line 268 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 268 "sample/map.c"
        goto label_114;
label_113:
    // EBPF_OP_LDDW pc=1791 dst=r1 src=r0 offset=0 imm=1701737077
#line 268 "sample/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=1793 dst=r10 src=r1 offset=-24 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1794 dst=r1 src=r0 offset=0 imm=1680154740
#line 268 "sample/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=1796 dst=r10 src=r1 offset=-32 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1797 dst=r1 src=r0 offset=0 imm=1914726254
#line 268 "sample/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=1799 dst=r10 src=r1 offset=-40 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1800 dst=r1 src=r0 offset=0 imm=1886938400
#line 268 "sample/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=1802 dst=r10 src=r1 offset=-48 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1803 dst=r1 src=r0 offset=0 imm=1601204080
#line 268 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1805 dst=r10 src=r1 offset=-56 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1806 dst=r1 src=r0 offset=0 imm=1600548962
#line 268 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1808 dst=r10 src=r1 offset=-64 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_STXB pc=1809 dst=r10 src=r7 offset=-16 imm=0
#line 268 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint8_t)r7;
    // EBPF_OP_ARSH64_IMM pc=1810 dst=r4 src=r0 offset=0 imm=32
#line 268 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1811 dst=r1 src=r10 offset=0 imm=0
#line 268 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1812 dst=r1 src=r0 offset=0 imm=-64
#line 268 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1813 dst=r2 src=r0 offset=0 imm=49
#line 268 "sample/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=1814 dst=r0 src=r0 offset=-64 imm=0
#line 268 "sample/map.c"
    goto label_110;
label_114:
    // EBPF_OP_LDXW pc=1815 dst=r3 src=r10 offset=-4 imm=0
#line 268 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1816 dst=r3 src=r0 offset=20 imm=1
#line 268 "sample/map.c"
    if (r3 == IMMEDIATE(1))
#line 268 "sample/map.c"
        goto label_115;
        // EBPF_OP_LDDW pc=1817 dst=r1 src=r0 offset=0 imm=1735289204
#line 268 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1819 dst=r10 src=r1 offset=-32 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1820 dst=r1 src=r0 offset=0 imm=1696621605
#line 268 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1822 dst=r10 src=r1 offset=-40 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1823 dst=r1 src=r0 offset=0 imm=1952805408
#line 268 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1825 dst=r10 src=r1 offset=-48 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1826 dst=r1 src=r0 offset=0 imm=1601204080
#line 268 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1828 dst=r10 src=r1 offset=-56 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1829 dst=r1 src=r0 offset=0 imm=1600548962
#line 268 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1831 dst=r10 src=r1 offset=-64 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1832 dst=r1 src=r10 offset=0 imm=0
#line 268 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1833 dst=r1 src=r0 offset=0 imm=-64
#line 268 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1834 dst=r2 src=r0 offset=0 imm=40
#line 268 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=1835 dst=r4 src=r0 offset=0 imm=1
#line 268 "sample/map.c"
    r4 = IMMEDIATE(1);
    // EBPF_OP_JA pc=1836 dst=r0 src=r0 offset=-526 imm=0
#line 268 "sample/map.c"
    goto label_84;
label_115:
    // EBPF_OP_MOV64_IMM pc=1837 dst=r7 src=r0 offset=0 imm=0
#line 268 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1838 dst=r10 src=r7 offset=-4 imm=0
#line 269 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1839 dst=r2 src=r10 offset=0 imm=0
#line 269 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1840 dst=r2 src=r0 offset=0 imm=-4
#line 269 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1841 dst=r1 src=r0 offset=0 imm=0
#line 269 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1843 dst=r0 src=r0 offset=0 imm=17
#line 269 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 269 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 269 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 269 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1844 dst=r6 src=r0 offset=0 imm=0
#line 269 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1845 dst=r4 src=r6 offset=0 imm=0
#line 269 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1846 dst=r4 src=r0 offset=0 imm=32
#line 269 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1847 dst=r1 src=r4 offset=0 imm=0
#line 269 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1848 dst=r1 src=r0 offset=0 imm=32
#line 269 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1849 dst=r1 src=r0 offset=1 imm=0
#line 269 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 269 "sample/map.c"
        goto label_116;
        // EBPF_OP_JA pc=1850 dst=r0 src=r0 offset=-60 imm=0
#line 269 "sample/map.c"
    goto label_113;
label_116:
    // EBPF_OP_LDXW pc=1851 dst=r3 src=r10 offset=-4 imm=0
#line 269 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1852 dst=r3 src=r0 offset=20 imm=2
#line 269 "sample/map.c"
    if (r3 == IMMEDIATE(2))
#line 269 "sample/map.c"
        goto label_117;
        // EBPF_OP_LDDW pc=1853 dst=r1 src=r0 offset=0 imm=1735289204
#line 269 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1855 dst=r10 src=r1 offset=-32 imm=0
#line 269 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1856 dst=r1 src=r0 offset=0 imm=1696621605
#line 269 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1858 dst=r10 src=r1 offset=-40 imm=0
#line 269 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1859 dst=r1 src=r0 offset=0 imm=1952805408
#line 269 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1861 dst=r10 src=r1 offset=-48 imm=0
#line 269 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1862 dst=r1 src=r0 offset=0 imm=1601204080
#line 269 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1864 dst=r10 src=r1 offset=-56 imm=0
#line 269 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1865 dst=r1 src=r0 offset=0 imm=1600548962
#line 269 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1867 dst=r10 src=r1 offset=-64 imm=0
#line 269 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1868 dst=r1 src=r10 offset=0 imm=0
#line 269 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1869 dst=r1 src=r0 offset=0 imm=-64
#line 269 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1870 dst=r2 src=r0 offset=0 imm=40
#line 269 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=1871 dst=r4 src=r0 offset=0 imm=2
#line 269 "sample/map.c"
    r4 = IMMEDIATE(2);
    // EBPF_OP_JA pc=1872 dst=r0 src=r0 offset=-562 imm=0
#line 269 "sample/map.c"
    goto label_84;
label_117:
    // EBPF_OP_MOV64_IMM pc=1873 dst=r7 src=r0 offset=0 imm=0
#line 269 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1874 dst=r10 src=r7 offset=-4 imm=0
#line 270 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1875 dst=r2 src=r10 offset=0 imm=0
#line 270 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1876 dst=r2 src=r0 offset=0 imm=-4
#line 270 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1877 dst=r1 src=r0 offset=0 imm=0
#line 270 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1879 dst=r0 src=r0 offset=0 imm=17
#line 270 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 270 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 270 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 270 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1880 dst=r6 src=r0 offset=0 imm=0
#line 270 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1881 dst=r4 src=r6 offset=0 imm=0
#line 270 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1882 dst=r4 src=r0 offset=0 imm=32
#line 270 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1883 dst=r1 src=r4 offset=0 imm=0
#line 270 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1884 dst=r1 src=r0 offset=0 imm=32
#line 270 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1885 dst=r1 src=r0 offset=1 imm=0
#line 270 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 270 "sample/map.c"
        goto label_118;
        // EBPF_OP_JA pc=1886 dst=r0 src=r0 offset=-96 imm=0
#line 270 "sample/map.c"
    goto label_113;
label_118:
    // EBPF_OP_LDXW pc=1887 dst=r3 src=r10 offset=-4 imm=0
#line 270 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1888 dst=r3 src=r0 offset=20 imm=3
#line 270 "sample/map.c"
    if (r3 == IMMEDIATE(3))
#line 270 "sample/map.c"
        goto label_119;
        // EBPF_OP_LDDW pc=1889 dst=r1 src=r0 offset=0 imm=1735289204
#line 270 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1891 dst=r10 src=r1 offset=-32 imm=0
#line 270 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1892 dst=r1 src=r0 offset=0 imm=1696621605
#line 270 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1894 dst=r10 src=r1 offset=-40 imm=0
#line 270 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1895 dst=r1 src=r0 offset=0 imm=1952805408
#line 270 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1897 dst=r10 src=r1 offset=-48 imm=0
#line 270 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1898 dst=r1 src=r0 offset=0 imm=1601204080
#line 270 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1900 dst=r10 src=r1 offset=-56 imm=0
#line 270 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1901 dst=r1 src=r0 offset=0 imm=1600548962
#line 270 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1903 dst=r10 src=r1 offset=-64 imm=0
#line 270 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1904 dst=r1 src=r10 offset=0 imm=0
#line 270 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1905 dst=r1 src=r0 offset=0 imm=-64
#line 270 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1906 dst=r2 src=r0 offset=0 imm=40
#line 270 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=1907 dst=r4 src=r0 offset=0 imm=3
#line 270 "sample/map.c"
    r4 = IMMEDIATE(3);
    // EBPF_OP_JA pc=1908 dst=r0 src=r0 offset=-598 imm=0
#line 270 "sample/map.c"
    goto label_84;
label_119:
    // EBPF_OP_MOV64_IMM pc=1909 dst=r7 src=r0 offset=0 imm=0
#line 270 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1910 dst=r10 src=r7 offset=-4 imm=0
#line 271 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1911 dst=r2 src=r10 offset=0 imm=0
#line 271 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1912 dst=r2 src=r0 offset=0 imm=-4
#line 271 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1913 dst=r1 src=r0 offset=0 imm=0
#line 271 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1915 dst=r0 src=r0 offset=0 imm=17
#line 271 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 271 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 271 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 271 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1916 dst=r6 src=r0 offset=0 imm=0
#line 271 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1917 dst=r4 src=r6 offset=0 imm=0
#line 271 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1918 dst=r4 src=r0 offset=0 imm=32
#line 271 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1919 dst=r1 src=r4 offset=0 imm=0
#line 271 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1920 dst=r1 src=r0 offset=0 imm=32
#line 271 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1921 dst=r1 src=r0 offset=1 imm=0
#line 271 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 271 "sample/map.c"
        goto label_120;
        // EBPF_OP_JA pc=1922 dst=r0 src=r0 offset=-132 imm=0
#line 271 "sample/map.c"
    goto label_113;
label_120:
    // EBPF_OP_LDXW pc=1923 dst=r3 src=r10 offset=-4 imm=0
#line 271 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1924 dst=r3 src=r0 offset=20 imm=4
#line 271 "sample/map.c"
    if (r3 == IMMEDIATE(4))
#line 271 "sample/map.c"
        goto label_121;
        // EBPF_OP_LDDW pc=1925 dst=r1 src=r0 offset=0 imm=1735289204
#line 271 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1927 dst=r10 src=r1 offset=-32 imm=0
#line 271 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1928 dst=r1 src=r0 offset=0 imm=1696621605
#line 271 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1930 dst=r10 src=r1 offset=-40 imm=0
#line 271 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1931 dst=r1 src=r0 offset=0 imm=1952805408
#line 271 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1933 dst=r10 src=r1 offset=-48 imm=0
#line 271 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1934 dst=r1 src=r0 offset=0 imm=1601204080
#line 271 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1936 dst=r10 src=r1 offset=-56 imm=0
#line 271 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1937 dst=r1 src=r0 offset=0 imm=1600548962
#line 271 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1939 dst=r10 src=r1 offset=-64 imm=0
#line 271 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1940 dst=r1 src=r10 offset=0 imm=0
#line 271 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1941 dst=r1 src=r0 offset=0 imm=-64
#line 271 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1942 dst=r2 src=r0 offset=0 imm=40
#line 271 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=1943 dst=r4 src=r0 offset=0 imm=4
#line 271 "sample/map.c"
    r4 = IMMEDIATE(4);
    // EBPF_OP_JA pc=1944 dst=r0 src=r0 offset=-634 imm=0
#line 271 "sample/map.c"
    goto label_84;
label_121:
    // EBPF_OP_MOV64_IMM pc=1945 dst=r7 src=r0 offset=0 imm=0
#line 271 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1946 dst=r10 src=r7 offset=-4 imm=0
#line 272 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1947 dst=r2 src=r10 offset=0 imm=0
#line 272 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1948 dst=r2 src=r0 offset=0 imm=-4
#line 272 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1949 dst=r1 src=r0 offset=0 imm=0
#line 272 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1951 dst=r0 src=r0 offset=0 imm=17
#line 272 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 272 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 272 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 272 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1952 dst=r6 src=r0 offset=0 imm=0
#line 272 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1953 dst=r4 src=r6 offset=0 imm=0
#line 272 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1954 dst=r4 src=r0 offset=0 imm=32
#line 272 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1955 dst=r1 src=r4 offset=0 imm=0
#line 272 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1956 dst=r1 src=r0 offset=0 imm=32
#line 272 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1957 dst=r1 src=r0 offset=1 imm=0
#line 272 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 272 "sample/map.c"
        goto label_122;
        // EBPF_OP_JA pc=1958 dst=r0 src=r0 offset=-168 imm=0
#line 272 "sample/map.c"
    goto label_113;
label_122:
    // EBPF_OP_LDXW pc=1959 dst=r3 src=r10 offset=-4 imm=0
#line 272 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1960 dst=r3 src=r0 offset=20 imm=5
#line 272 "sample/map.c"
    if (r3 == IMMEDIATE(5))
#line 272 "sample/map.c"
        goto label_123;
        // EBPF_OP_LDDW pc=1961 dst=r1 src=r0 offset=0 imm=1735289204
#line 272 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1963 dst=r10 src=r1 offset=-32 imm=0
#line 272 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1964 dst=r1 src=r0 offset=0 imm=1696621605
#line 272 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1966 dst=r10 src=r1 offset=-40 imm=0
#line 272 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1967 dst=r1 src=r0 offset=0 imm=1952805408
#line 272 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1969 dst=r10 src=r1 offset=-48 imm=0
#line 272 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1970 dst=r1 src=r0 offset=0 imm=1601204080
#line 272 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1972 dst=r10 src=r1 offset=-56 imm=0
#line 272 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1973 dst=r1 src=r0 offset=0 imm=1600548962
#line 272 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1975 dst=r10 src=r1 offset=-64 imm=0
#line 272 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1976 dst=r1 src=r10 offset=0 imm=0
#line 272 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1977 dst=r1 src=r0 offset=0 imm=-64
#line 272 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1978 dst=r2 src=r0 offset=0 imm=40
#line 272 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=1979 dst=r4 src=r0 offset=0 imm=5
#line 272 "sample/map.c"
    r4 = IMMEDIATE(5);
    // EBPF_OP_JA pc=1980 dst=r0 src=r0 offset=-670 imm=0
#line 272 "sample/map.c"
    goto label_84;
label_123:
    // EBPF_OP_MOV64_IMM pc=1981 dst=r7 src=r0 offset=0 imm=0
#line 272 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1982 dst=r10 src=r7 offset=-4 imm=0
#line 273 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1983 dst=r2 src=r10 offset=0 imm=0
#line 273 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1984 dst=r2 src=r0 offset=0 imm=-4
#line 273 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1985 dst=r1 src=r0 offset=0 imm=0
#line 273 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1987 dst=r0 src=r0 offset=0 imm=17
#line 273 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 273 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 273 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 273 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1988 dst=r6 src=r0 offset=0 imm=0
#line 273 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1989 dst=r4 src=r6 offset=0 imm=0
#line 273 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1990 dst=r4 src=r0 offset=0 imm=32
#line 273 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1991 dst=r1 src=r4 offset=0 imm=0
#line 273 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1992 dst=r1 src=r0 offset=0 imm=32
#line 273 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1993 dst=r1 src=r0 offset=1 imm=0
#line 273 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 273 "sample/map.c"
        goto label_124;
        // EBPF_OP_JA pc=1994 dst=r0 src=r0 offset=-204 imm=0
#line 273 "sample/map.c"
    goto label_113;
label_124:
    // EBPF_OP_LDXW pc=1995 dst=r3 src=r10 offset=-4 imm=0
#line 273 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1996 dst=r3 src=r0 offset=20 imm=6
#line 273 "sample/map.c"
    if (r3 == IMMEDIATE(6))
#line 273 "sample/map.c"
        goto label_125;
        // EBPF_OP_LDDW pc=1997 dst=r1 src=r0 offset=0 imm=1735289204
#line 273 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1999 dst=r10 src=r1 offset=-32 imm=0
#line 273 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2000 dst=r1 src=r0 offset=0 imm=1696621605
#line 273 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2002 dst=r10 src=r1 offset=-40 imm=0
#line 273 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2003 dst=r1 src=r0 offset=0 imm=1952805408
#line 273 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2005 dst=r10 src=r1 offset=-48 imm=0
#line 273 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2006 dst=r1 src=r0 offset=0 imm=1601204080
#line 273 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2008 dst=r10 src=r1 offset=-56 imm=0
#line 273 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2009 dst=r1 src=r0 offset=0 imm=1600548962
#line 273 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2011 dst=r10 src=r1 offset=-64 imm=0
#line 273 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2012 dst=r1 src=r10 offset=0 imm=0
#line 273 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2013 dst=r1 src=r0 offset=0 imm=-64
#line 273 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2014 dst=r2 src=r0 offset=0 imm=40
#line 273 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2015 dst=r4 src=r0 offset=0 imm=6
#line 273 "sample/map.c"
    r4 = IMMEDIATE(6);
    // EBPF_OP_JA pc=2016 dst=r0 src=r0 offset=-706 imm=0
#line 273 "sample/map.c"
    goto label_84;
label_125:
    // EBPF_OP_MOV64_IMM pc=2017 dst=r7 src=r0 offset=0 imm=0
#line 273 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2018 dst=r10 src=r7 offset=-4 imm=0
#line 274 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=2019 dst=r2 src=r10 offset=0 imm=0
#line 274 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2020 dst=r2 src=r0 offset=0 imm=-4
#line 274 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2021 dst=r1 src=r0 offset=0 imm=0
#line 274 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=2023 dst=r0 src=r0 offset=0 imm=17
#line 274 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 274 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 274 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 274 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2024 dst=r6 src=r0 offset=0 imm=0
#line 274 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=2025 dst=r4 src=r6 offset=0 imm=0
#line 274 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=2026 dst=r4 src=r0 offset=0 imm=32
#line 274 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2027 dst=r1 src=r4 offset=0 imm=0
#line 274 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2028 dst=r1 src=r0 offset=0 imm=32
#line 274 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2029 dst=r1 src=r0 offset=1 imm=0
#line 274 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 274 "sample/map.c"
        goto label_126;
        // EBPF_OP_JA pc=2030 dst=r0 src=r0 offset=-240 imm=0
#line 274 "sample/map.c"
    goto label_113;
label_126:
    // EBPF_OP_LDXW pc=2031 dst=r3 src=r10 offset=-4 imm=0
#line 274 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2032 dst=r3 src=r0 offset=20 imm=7
#line 274 "sample/map.c"
    if (r3 == IMMEDIATE(7))
#line 274 "sample/map.c"
        goto label_127;
        // EBPF_OP_LDDW pc=2033 dst=r1 src=r0 offset=0 imm=1735289204
#line 274 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2035 dst=r10 src=r1 offset=-32 imm=0
#line 274 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2036 dst=r1 src=r0 offset=0 imm=1696621605
#line 274 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2038 dst=r10 src=r1 offset=-40 imm=0
#line 274 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2039 dst=r1 src=r0 offset=0 imm=1952805408
#line 274 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2041 dst=r10 src=r1 offset=-48 imm=0
#line 274 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2042 dst=r1 src=r0 offset=0 imm=1601204080
#line 274 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2044 dst=r10 src=r1 offset=-56 imm=0
#line 274 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2045 dst=r1 src=r0 offset=0 imm=1600548962
#line 274 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2047 dst=r10 src=r1 offset=-64 imm=0
#line 274 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2048 dst=r1 src=r10 offset=0 imm=0
#line 274 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2049 dst=r1 src=r0 offset=0 imm=-64
#line 274 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2050 dst=r2 src=r0 offset=0 imm=40
#line 274 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2051 dst=r4 src=r0 offset=0 imm=7
#line 274 "sample/map.c"
    r4 = IMMEDIATE(7);
    // EBPF_OP_JA pc=2052 dst=r0 src=r0 offset=-742 imm=0
#line 274 "sample/map.c"
    goto label_84;
label_127:
    // EBPF_OP_MOV64_IMM pc=2053 dst=r7 src=r0 offset=0 imm=0
#line 274 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2054 dst=r10 src=r7 offset=-4 imm=0
#line 275 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=2055 dst=r2 src=r10 offset=0 imm=0
#line 275 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2056 dst=r2 src=r0 offset=0 imm=-4
#line 275 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2057 dst=r1 src=r0 offset=0 imm=0
#line 275 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=2059 dst=r0 src=r0 offset=0 imm=17
#line 275 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 275 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 275 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 275 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2060 dst=r6 src=r0 offset=0 imm=0
#line 275 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=2061 dst=r4 src=r6 offset=0 imm=0
#line 275 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=2062 dst=r4 src=r0 offset=0 imm=32
#line 275 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2063 dst=r1 src=r4 offset=0 imm=0
#line 275 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2064 dst=r1 src=r0 offset=0 imm=32
#line 275 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2065 dst=r1 src=r0 offset=1 imm=0
#line 275 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 275 "sample/map.c"
        goto label_128;
        // EBPF_OP_JA pc=2066 dst=r0 src=r0 offset=-276 imm=0
#line 275 "sample/map.c"
    goto label_113;
label_128:
    // EBPF_OP_LDXW pc=2067 dst=r3 src=r10 offset=-4 imm=0
#line 275 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2068 dst=r3 src=r0 offset=20 imm=8
#line 275 "sample/map.c"
    if (r3 == IMMEDIATE(8))
#line 275 "sample/map.c"
        goto label_129;
        // EBPF_OP_LDDW pc=2069 dst=r1 src=r0 offset=0 imm=1735289204
#line 275 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2071 dst=r10 src=r1 offset=-32 imm=0
#line 275 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2072 dst=r1 src=r0 offset=0 imm=1696621605
#line 275 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2074 dst=r10 src=r1 offset=-40 imm=0
#line 275 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2075 dst=r1 src=r0 offset=0 imm=1952805408
#line 275 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2077 dst=r10 src=r1 offset=-48 imm=0
#line 275 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2078 dst=r1 src=r0 offset=0 imm=1601204080
#line 275 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2080 dst=r10 src=r1 offset=-56 imm=0
#line 275 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2081 dst=r1 src=r0 offset=0 imm=1600548962
#line 275 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2083 dst=r10 src=r1 offset=-64 imm=0
#line 275 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2084 dst=r1 src=r10 offset=0 imm=0
#line 275 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2085 dst=r1 src=r0 offset=0 imm=-64
#line 275 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2086 dst=r2 src=r0 offset=0 imm=40
#line 275 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2087 dst=r4 src=r0 offset=0 imm=8
#line 275 "sample/map.c"
    r4 = IMMEDIATE(8);
    // EBPF_OP_JA pc=2088 dst=r0 src=r0 offset=-778 imm=0
#line 275 "sample/map.c"
    goto label_84;
label_129:
    // EBPF_OP_MOV64_IMM pc=2089 dst=r7 src=r0 offset=0 imm=0
#line 275 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2090 dst=r10 src=r7 offset=-4 imm=0
#line 276 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=2091 dst=r2 src=r10 offset=0 imm=0
#line 276 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2092 dst=r2 src=r0 offset=0 imm=-4
#line 276 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2093 dst=r1 src=r0 offset=0 imm=0
#line 276 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=2095 dst=r0 src=r0 offset=0 imm=17
#line 276 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 276 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 276 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 276 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2096 dst=r6 src=r0 offset=0 imm=0
#line 276 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=2097 dst=r4 src=r6 offset=0 imm=0
#line 276 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=2098 dst=r4 src=r0 offset=0 imm=32
#line 276 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2099 dst=r1 src=r4 offset=0 imm=0
#line 276 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2100 dst=r1 src=r0 offset=0 imm=32
#line 276 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2101 dst=r1 src=r0 offset=1 imm=0
#line 276 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 276 "sample/map.c"
        goto label_130;
        // EBPF_OP_JA pc=2102 dst=r0 src=r0 offset=-312 imm=0
#line 276 "sample/map.c"
    goto label_113;
label_130:
    // EBPF_OP_LDXW pc=2103 dst=r3 src=r10 offset=-4 imm=0
#line 276 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2104 dst=r3 src=r0 offset=20 imm=9
#line 276 "sample/map.c"
    if (r3 == IMMEDIATE(9))
#line 276 "sample/map.c"
        goto label_131;
        // EBPF_OP_LDDW pc=2105 dst=r1 src=r0 offset=0 imm=1735289204
#line 276 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2107 dst=r10 src=r1 offset=-32 imm=0
#line 276 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2108 dst=r1 src=r0 offset=0 imm=1696621605
#line 276 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2110 dst=r10 src=r1 offset=-40 imm=0
#line 276 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2111 dst=r1 src=r0 offset=0 imm=1952805408
#line 276 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2113 dst=r10 src=r1 offset=-48 imm=0
#line 276 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2114 dst=r1 src=r0 offset=0 imm=1601204080
#line 276 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2116 dst=r10 src=r1 offset=-56 imm=0
#line 276 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2117 dst=r1 src=r0 offset=0 imm=1600548962
#line 276 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2119 dst=r10 src=r1 offset=-64 imm=0
#line 276 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2120 dst=r1 src=r10 offset=0 imm=0
#line 276 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2121 dst=r1 src=r0 offset=0 imm=-64
#line 276 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2122 dst=r2 src=r0 offset=0 imm=40
#line 276 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2123 dst=r4 src=r0 offset=0 imm=9
#line 276 "sample/map.c"
    r4 = IMMEDIATE(9);
    // EBPF_OP_JA pc=2124 dst=r0 src=r0 offset=-814 imm=0
#line 276 "sample/map.c"
    goto label_84;
label_131:
    // EBPF_OP_MOV64_IMM pc=2125 dst=r7 src=r0 offset=0 imm=0
#line 276 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2126 dst=r10 src=r7 offset=-4 imm=0
#line 277 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=2127 dst=r2 src=r10 offset=0 imm=0
#line 277 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2128 dst=r2 src=r0 offset=0 imm=-4
#line 277 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2129 dst=r1 src=r0 offset=0 imm=0
#line 277 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=2131 dst=r0 src=r0 offset=0 imm=17
#line 277 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 277 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 277 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 277 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2132 dst=r6 src=r0 offset=0 imm=0
#line 277 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=2133 dst=r4 src=r6 offset=0 imm=0
#line 277 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=2134 dst=r4 src=r0 offset=0 imm=32
#line 277 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2135 dst=r1 src=r4 offset=0 imm=0
#line 277 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2136 dst=r1 src=r0 offset=0 imm=32
#line 277 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2137 dst=r1 src=r0 offset=1 imm=0
#line 277 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 277 "sample/map.c"
        goto label_132;
        // EBPF_OP_JA pc=2138 dst=r0 src=r0 offset=-348 imm=0
#line 277 "sample/map.c"
    goto label_113;
label_132:
    // EBPF_OP_LDXW pc=2139 dst=r3 src=r10 offset=-4 imm=0
#line 277 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2140 dst=r3 src=r0 offset=20 imm=10
#line 277 "sample/map.c"
    if (r3 == IMMEDIATE(10))
#line 277 "sample/map.c"
        goto label_133;
        // EBPF_OP_LDDW pc=2141 dst=r1 src=r0 offset=0 imm=1735289204
#line 277 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2143 dst=r10 src=r1 offset=-32 imm=0
#line 277 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2144 dst=r1 src=r0 offset=0 imm=1696621605
#line 277 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2146 dst=r10 src=r1 offset=-40 imm=0
#line 277 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2147 dst=r1 src=r0 offset=0 imm=1952805408
#line 277 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2149 dst=r10 src=r1 offset=-48 imm=0
#line 277 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2150 dst=r1 src=r0 offset=0 imm=1601204080
#line 277 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2152 dst=r10 src=r1 offset=-56 imm=0
#line 277 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2153 dst=r1 src=r0 offset=0 imm=1600548962
#line 277 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2155 dst=r10 src=r1 offset=-64 imm=0
#line 277 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2156 dst=r1 src=r10 offset=0 imm=0
#line 277 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2157 dst=r1 src=r0 offset=0 imm=-64
#line 277 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2158 dst=r2 src=r0 offset=0 imm=40
#line 277 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2159 dst=r4 src=r0 offset=0 imm=10
#line 277 "sample/map.c"
    r4 = IMMEDIATE(10);
    // EBPF_OP_JA pc=2160 dst=r0 src=r0 offset=-850 imm=0
#line 277 "sample/map.c"
    goto label_84;
label_133:
    // EBPF_OP_MOV64_IMM pc=2161 dst=r1 src=r0 offset=0 imm=0
#line 277 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2162 dst=r10 src=r1 offset=-4 imm=0
#line 280 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2163 dst=r2 src=r10 offset=0 imm=0
#line 280 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2164 dst=r2 src=r0 offset=0 imm=-4
#line 280 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2165 dst=r1 src=r0 offset=0 imm=0
#line 280 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=2167 dst=r0 src=r0 offset=0 imm=18
#line 280 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 280 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 280 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 280 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2168 dst=r6 src=r0 offset=0 imm=0
#line 280 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=2169 dst=r4 src=r6 offset=0 imm=0
#line 280 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=2170 dst=r4 src=r0 offset=0 imm=32
#line 280 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2171 dst=r1 src=r4 offset=0 imm=0
#line 280 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2172 dst=r1 src=r0 offset=0 imm=32
#line 280 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=2173 dst=r2 src=r0 offset=0 imm=-7
#line 280 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=2175 dst=r1 src=r2 offset=1 imm=0
#line 280 "sample/map.c"
    if (r1 == r2)
#line 280 "sample/map.c"
        goto label_134;
        // EBPF_OP_JA pc=2176 dst=r0 src=r0 offset=-916 imm=0
#line 280 "sample/map.c"
    goto label_79;
label_134:
    // EBPF_OP_LDXW pc=2177 dst=r3 src=r10 offset=-4 imm=0
#line 280 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2178 dst=r3 src=r0 offset=1 imm=0
#line 280 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 280 "sample/map.c"
        goto label_135;
        // EBPF_OP_JA pc=2179 dst=r0 src=r0 offset=-890 imm=0
#line 280 "sample/map.c"
    goto label_82;
label_135:
    // EBPF_OP_MOV64_IMM pc=2180 dst=r7 src=r0 offset=0 imm=0
#line 280 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2181 dst=r10 src=r7 offset=-4 imm=0
#line 281 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=2182 dst=r2 src=r10 offset=0 imm=0
#line 281 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2183 dst=r2 src=r0 offset=0 imm=-4
#line 281 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2184 dst=r1 src=r0 offset=0 imm=0
#line 281 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=2186 dst=r0 src=r0 offset=0 imm=17
#line 281 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 281 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 281 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 281 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2187 dst=r6 src=r0 offset=0 imm=0
#line 281 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=2188 dst=r4 src=r6 offset=0 imm=0
#line 281 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=2189 dst=r4 src=r0 offset=0 imm=32
#line 281 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2190 dst=r1 src=r4 offset=0 imm=0
#line 281 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2191 dst=r1 src=r0 offset=0 imm=32
#line 281 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=2192 dst=r2 src=r0 offset=0 imm=-7
#line 281 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=2194 dst=r1 src=r2 offset=1 imm=0
#line 281 "sample/map.c"
    if (r1 == r2)
#line 281 "sample/map.c"
        goto label_136;
        // EBPF_OP_JA pc=2195 dst=r0 src=r0 offset=-801 imm=0
#line 281 "sample/map.c"
    goto label_91;
label_136:
    // EBPF_OP_LDXW pc=2196 dst=r3 src=r10 offset=-4 imm=0
#line 281 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2197 dst=r3 src=r0 offset=-879 imm=0
#line 281 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 281 "sample/map.c"
        goto label_86;
        // EBPF_OP_JA pc=2198 dst=r0 src=r0 offset=-778 imm=0
#line 281 "sample/map.c"
    goto label_93;
label_137:
    // EBPF_OP_LDXW pc=2199 dst=r3 src=r10 offset=-4 imm=0
#line 236 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2200 dst=r3 src=r0 offset=50 imm=0
#line 236 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 236 "sample/map.c"
        goto label_142;
label_138:
    // EBPF_OP_LDDW pc=2201 dst=r1 src=r0 offset=0 imm=1852404835
#line 236 "sample/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=2203 dst=r10 src=r1 offset=-32 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2204 dst=r1 src=r0 offset=0 imm=543434016
#line 236 "sample/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=2206 dst=r10 src=r1 offset=-40 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2207 dst=r1 src=r0 offset=0 imm=1701978221
#line 236 "sample/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=2209 dst=r10 src=r1 offset=-48 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2210 dst=r1 src=r0 offset=0 imm=1801807216
#line 236 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=2212 dst=r10 src=r1 offset=-56 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2213 dst=r1 src=r0 offset=0 imm=1600548962
#line 236 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2215 dst=r10 src=r1 offset=-64 imm=0
#line 236 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=2216 dst=r1 src=r0 offset=0 imm=0
#line 236 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=2217 dst=r10 src=r1 offset=-24 imm=0
#line 236 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint8_t)r1;
    // EBPF_OP_MOV64_REG pc=2218 dst=r1 src=r10 offset=0 imm=0
#line 236 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2219 dst=r1 src=r0 offset=0 imm=-64
#line 236 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2220 dst=r2 src=r0 offset=0 imm=41
#line 236 "sample/map.c"
    r2 = IMMEDIATE(41);
label_139:
    // EBPF_OP_MOV64_IMM pc=2221 dst=r4 src=r0 offset=0 imm=0
#line 236 "sample/map.c"
    r4 = IMMEDIATE(0);
label_140:
    // EBPF_OP_CALL pc=2222 dst=r0 src=r0 offset=0 imm=14
#line 236 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 236 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 236 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 236 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=2223 dst=r7 src=r0 offset=0 imm=-1
#line 236 "sample/map.c"
    r7 = (uint64_t)4294967295;
label_141:
    // EBPF_OP_MOV64_IMM pc=2225 dst=r6 src=r0 offset=0 imm=0
#line 236 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_MOV64_REG pc=2226 dst=r3 src=r7 offset=0 imm=0
#line 300 "sample/map.c"
    r3 = r7;
    // EBPF_OP_LSH64_IMM pc=2227 dst=r3 src=r0 offset=0 imm=32
#line 300 "sample/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=2228 dst=r3 src=r0 offset=0 imm=32
#line 300 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=2229 dst=r3 src=r0 offset=-2128 imm=-1
#line 300 "sample/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1))
#line 300 "sample/map.c"
        goto label_9;
        // EBPF_OP_LDDW pc=2230 dst=r1 src=r0 offset=0 imm=1684369010
#line 300 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=2232 dst=r10 src=r1 offset=-32 imm=0
#line 300 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2233 dst=r1 src=r0 offset=0 imm=541803329
#line 300 "sample/map.c"
    r1 = (uint64_t)8463501140578485057;
    // EBPF_OP_STXDW pc=2235 dst=r10 src=r1 offset=-40 imm=0
#line 300 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2236 dst=r1 src=r0 offset=0 imm=1634541682
#line 300 "sample/map.c"
    r1 = (uint64_t)6076235989295898738;
    // EBPF_OP_STXDW pc=2238 dst=r10 src=r1 offset=-48 imm=0
#line 300 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2239 dst=r1 src=r0 offset=0 imm=1330667336
#line 300 "sample/map.c"
    r1 = (uint64_t)8027138915134627656;
    // EBPF_OP_STXDW pc=2241 dst=r10 src=r1 offset=-56 imm=0
#line 300 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2242 dst=r1 src=r0 offset=0 imm=1953719636
#line 300 "sample/map.c"
    r1 = (uint64_t)6004793778491319636;
    // EBPF_OP_STXDW pc=2244 dst=r10 src=r1 offset=-64 imm=0
#line 300 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2245 dst=r1 src=r10 offset=0 imm=0
#line 300 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2246 dst=r1 src=r0 offset=0 imm=-64
#line 300 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2247 dst=r2 src=r0 offset=0 imm=40
#line 300 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_CALL pc=2248 dst=r0 src=r0 offset=0 imm=13
#line 300 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 300 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 300 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 300 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2249 dst=r6 src=r7 offset=0 imm=0
#line 300 "sample/map.c"
    r6 = r7;
    // EBPF_OP_JA pc=2250 dst=r0 src=r0 offset=-2149 imm=0
#line 300 "sample/map.c"
    goto label_9;
label_142:
    // EBPF_OP_MOV64_IMM pc=2251 dst=r6 src=r0 offset=0 imm=0
#line 300 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2252 dst=r10 src=r6 offset=-4 imm=0
#line 237 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2253 dst=r2 src=r10 offset=0 imm=0
#line 237 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2254 dst=r2 src=r0 offset=0 imm=-4
#line 237 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2255 dst=r1 src=r0 offset=0 imm=0
#line 237 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2257 dst=r0 src=r0 offset=0 imm=17
#line 237 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 237 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 237 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 237 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2258 dst=r7 src=r0 offset=0 imm=0
#line 237 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2259 dst=r4 src=r7 offset=0 imm=0
#line 237 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2260 dst=r4 src=r0 offset=0 imm=32
#line 237 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2261 dst=r1 src=r4 offset=0 imm=0
#line 237 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2262 dst=r1 src=r0 offset=0 imm=32
#line 237 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=2263 dst=r2 src=r0 offset=0 imm=-7
#line 237 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=2265 dst=r1 src=r2 offset=24 imm=0
#line 237 "sample/map.c"
    if (r1 == r2)
#line 237 "sample/map.c"
        goto label_144;
label_143:
    // EBPF_OP_STXB pc=2266 dst=r10 src=r6 offset=-16 imm=0
#line 237 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint8_t)r6;
    // EBPF_OP_LDDW pc=2267 dst=r1 src=r0 offset=0 imm=1701737077
#line 237 "sample/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=2269 dst=r10 src=r1 offset=-24 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2270 dst=r1 src=r0 offset=0 imm=1680154740
#line 237 "sample/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=2272 dst=r10 src=r1 offset=-32 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2273 dst=r1 src=r0 offset=0 imm=1914726254
#line 237 "sample/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=2275 dst=r10 src=r1 offset=-40 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2276 dst=r1 src=r0 offset=0 imm=1886938400
#line 237 "sample/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=2278 dst=r10 src=r1 offset=-48 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2279 dst=r1 src=r0 offset=0 imm=1601204080
#line 237 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2281 dst=r10 src=r1 offset=-56 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2282 dst=r1 src=r0 offset=0 imm=1600548962
#line 237 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2284 dst=r10 src=r1 offset=-64 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=2285 dst=r4 src=r0 offset=0 imm=32
#line 237 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2286 dst=r1 src=r10 offset=0 imm=0
#line 237 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2287 dst=r1 src=r0 offset=0 imm=-64
#line 237 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2288 dst=r2 src=r0 offset=0 imm=49
#line 237 "sample/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=2289 dst=r0 src=r0 offset=-932 imm=0
#line 237 "sample/map.c"
    goto label_88;
label_144:
    // EBPF_OP_LDXW pc=2290 dst=r3 src=r10 offset=-4 imm=0
#line 237 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2291 dst=r3 src=r0 offset=19 imm=0
#line 237 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 237 "sample/map.c"
        goto label_146;
label_145:
    // EBPF_OP_LDDW pc=2292 dst=r1 src=r0 offset=0 imm=1735289204
#line 237 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2294 dst=r10 src=r1 offset=-32 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2295 dst=r1 src=r0 offset=0 imm=1696621605
#line 237 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2297 dst=r10 src=r1 offset=-40 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2298 dst=r1 src=r0 offset=0 imm=1952805408
#line 237 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2300 dst=r10 src=r1 offset=-48 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2301 dst=r1 src=r0 offset=0 imm=1601204080
#line 237 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2303 dst=r10 src=r1 offset=-56 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2304 dst=r1 src=r0 offset=0 imm=1600548962
#line 237 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2306 dst=r10 src=r1 offset=-64 imm=0
#line 237 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2307 dst=r1 src=r10 offset=0 imm=0
#line 237 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2308 dst=r1 src=r0 offset=0 imm=-64
#line 237 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2309 dst=r2 src=r0 offset=0 imm=40
#line 237 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_JA pc=2310 dst=r0 src=r0 offset=-90 imm=0
#line 237 "sample/map.c"
    goto label_139;
label_146:
    // EBPF_OP_MOV64_IMM pc=2311 dst=r6 src=r0 offset=0 imm=0
#line 237 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2312 dst=r10 src=r6 offset=-4 imm=0
#line 245 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2313 dst=r2 src=r10 offset=0 imm=0
#line 245 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2314 dst=r2 src=r0 offset=0 imm=-4
#line 245 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2315 dst=r1 src=r0 offset=0 imm=0
#line 245 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=2317 dst=r3 src=r0 offset=0 imm=0
#line 245 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2318 dst=r0 src=r0 offset=0 imm=16
#line 245 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 245 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 245 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 245 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2319 dst=r7 src=r0 offset=0 imm=0
#line 245 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2320 dst=r5 src=r7 offset=0 imm=0
#line 245 "sample/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2321 dst=r5 src=r0 offset=0 imm=32
#line 245 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2322 dst=r1 src=r5 offset=0 imm=0
#line 245 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2323 dst=r1 src=r0 offset=0 imm=32
#line 245 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2324 dst=r1 src=r0 offset=31 imm=0
#line 245 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 245 "sample/map.c"
        goto label_150;
label_147:
    // EBPF_OP_MOV64_IMM pc=2325 dst=r1 src=r0 offset=0 imm=25637
#line 245 "sample/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=2326 dst=r10 src=r1 offset=-12 imm=0
#line 245 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=2327 dst=r1 src=r0 offset=0 imm=543450478
#line 245 "sample/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=2328 dst=r10 src=r1 offset=-16 imm=0
#line 245 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=2329 dst=r1 src=r0 offset=0 imm=1914725413
#line 245 "sample/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=2331 dst=r10 src=r1 offset=-24 imm=0
#line 245 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2332 dst=r1 src=r0 offset=0 imm=1667592312
#line 245 "sample/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=2334 dst=r10 src=r1 offset=-32 imm=0
#line 245 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2335 dst=r1 src=r0 offset=0 imm=543649385
#line 245 "sample/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=2337 dst=r10 src=r1 offset=-40 imm=0
#line 245 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2338 dst=r1 src=r0 offset=0 imm=1852383341
#line 245 "sample/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=2340 dst=r10 src=r1 offset=-48 imm=0
#line 245 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2341 dst=r1 src=r0 offset=0 imm=1752397168
#line 245 "sample/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=2343 dst=r10 src=r1 offset=-56 imm=0
#line 245 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2344 dst=r1 src=r0 offset=0 imm=1600548962
#line 245 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2346 dst=r10 src=r1 offset=-64 imm=0
#line 245 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_STXB pc=2347 dst=r10 src=r6 offset=-10 imm=0
#line 245 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-10)) = (uint8_t)r6;
label_148:
    // EBPF_OP_LDXW pc=2348 dst=r3 src=r10 offset=-4 imm=0
#line 245 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ARSH64_IMM pc=2349 dst=r5 src=r0 offset=0 imm=32
#line 245 "sample/map.c"
    r5 = (int64_t)r5 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2350 dst=r1 src=r10 offset=0 imm=0
#line 245 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2351 dst=r1 src=r0 offset=0 imm=-64
#line 245 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2352 dst=r2 src=r0 offset=0 imm=55
#line 245 "sample/map.c"
    r2 = IMMEDIATE(55);
    // EBPF_OP_MOV64_IMM pc=2353 dst=r4 src=r0 offset=0 imm=0
#line 245 "sample/map.c"
    r4 = IMMEDIATE(0);
label_149:
    // EBPF_OP_CALL pc=2354 dst=r0 src=r0 offset=0 imm=15
#line 245 "sample/map.c"
    r0 = test_maps_helpers[10].address
#line 245 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 245 "sample/map.c"
    if ((test_maps_helpers[10].tail_call) && (r0 == 0))
#line 245 "sample/map.c"
        return 0;
        // EBPF_OP_JA pc=2355 dst=r0 src=r0 offset=-131 imm=0
#line 245 "sample/map.c"
    goto label_141;
label_150:
    // EBPF_OP_MOV64_IMM pc=2356 dst=r1 src=r0 offset=0 imm=1
#line 245 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=2357 dst=r10 src=r1 offset=-4 imm=0
#line 246 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2358 dst=r2 src=r10 offset=0 imm=0
#line 246 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2359 dst=r2 src=r0 offset=0 imm=-4
#line 246 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=2360 dst=r6 src=r0 offset=0 imm=0
#line 246 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=2361 dst=r1 src=r0 offset=0 imm=0
#line 246 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=2363 dst=r3 src=r0 offset=0 imm=0
#line 246 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2364 dst=r0 src=r0 offset=0 imm=16
#line 246 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 246 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 246 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 246 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2365 dst=r7 src=r0 offset=0 imm=0
#line 246 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2366 dst=r5 src=r7 offset=0 imm=0
#line 246 "sample/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2367 dst=r5 src=r0 offset=0 imm=32
#line 246 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2368 dst=r1 src=r5 offset=0 imm=0
#line 246 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2369 dst=r1 src=r0 offset=0 imm=32
#line 246 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2370 dst=r1 src=r0 offset=1 imm=0
#line 246 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 246 "sample/map.c"
        goto label_151;
        // EBPF_OP_JA pc=2371 dst=r0 src=r0 offset=-47 imm=0
#line 246 "sample/map.c"
    goto label_147;
label_151:
    // EBPF_OP_MOV64_IMM pc=2372 dst=r1 src=r0 offset=0 imm=2
#line 246 "sample/map.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=2373 dst=r10 src=r1 offset=-4 imm=0
#line 247 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2374 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2375 dst=r2 src=r0 offset=0 imm=-4
#line 247 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=2376 dst=r6 src=r0 offset=0 imm=0
#line 247 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=2377 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=2379 dst=r3 src=r0 offset=0 imm=0
#line 247 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2380 dst=r0 src=r0 offset=0 imm=16
#line 247 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 247 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 247 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 247 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2381 dst=r7 src=r0 offset=0 imm=0
#line 247 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2382 dst=r5 src=r7 offset=0 imm=0
#line 247 "sample/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2383 dst=r5 src=r0 offset=0 imm=32
#line 247 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2384 dst=r1 src=r5 offset=0 imm=0
#line 247 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2385 dst=r1 src=r0 offset=0 imm=32
#line 247 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2386 dst=r1 src=r0 offset=1 imm=0
#line 247 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 247 "sample/map.c"
        goto label_152;
        // EBPF_OP_JA pc=2387 dst=r0 src=r0 offset=-63 imm=0
#line 247 "sample/map.c"
    goto label_147;
label_152:
    // EBPF_OP_MOV64_IMM pc=2388 dst=r1 src=r0 offset=0 imm=3
#line 247 "sample/map.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=2389 dst=r10 src=r1 offset=-4 imm=0
#line 248 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2390 dst=r2 src=r10 offset=0 imm=0
#line 248 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2391 dst=r2 src=r0 offset=0 imm=-4
#line 248 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=2392 dst=r6 src=r0 offset=0 imm=0
#line 248 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=2393 dst=r1 src=r0 offset=0 imm=0
#line 248 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=2395 dst=r3 src=r0 offset=0 imm=0
#line 248 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2396 dst=r0 src=r0 offset=0 imm=16
#line 248 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 248 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 248 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 248 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2397 dst=r7 src=r0 offset=0 imm=0
#line 248 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2398 dst=r5 src=r7 offset=0 imm=0
#line 248 "sample/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2399 dst=r5 src=r0 offset=0 imm=32
#line 248 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2400 dst=r1 src=r5 offset=0 imm=0
#line 248 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2401 dst=r1 src=r0 offset=0 imm=32
#line 248 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2402 dst=r1 src=r0 offset=1 imm=0
#line 248 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 248 "sample/map.c"
        goto label_153;
        // EBPF_OP_JA pc=2403 dst=r0 src=r0 offset=-79 imm=0
#line 248 "sample/map.c"
    goto label_147;
label_153:
    // EBPF_OP_MOV64_IMM pc=2404 dst=r1 src=r0 offset=0 imm=4
#line 248 "sample/map.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=2405 dst=r10 src=r1 offset=-4 imm=0
#line 249 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2406 dst=r2 src=r10 offset=0 imm=0
#line 249 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2407 dst=r2 src=r0 offset=0 imm=-4
#line 249 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=2408 dst=r6 src=r0 offset=0 imm=0
#line 249 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=2409 dst=r1 src=r0 offset=0 imm=0
#line 249 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=2411 dst=r3 src=r0 offset=0 imm=0
#line 249 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2412 dst=r0 src=r0 offset=0 imm=16
#line 249 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 249 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 249 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 249 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2413 dst=r7 src=r0 offset=0 imm=0
#line 249 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2414 dst=r5 src=r7 offset=0 imm=0
#line 249 "sample/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2415 dst=r5 src=r0 offset=0 imm=32
#line 249 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2416 dst=r1 src=r5 offset=0 imm=0
#line 249 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2417 dst=r1 src=r0 offset=0 imm=32
#line 249 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2418 dst=r1 src=r0 offset=1 imm=0
#line 249 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 249 "sample/map.c"
        goto label_154;
        // EBPF_OP_JA pc=2419 dst=r0 src=r0 offset=-95 imm=0
#line 249 "sample/map.c"
    goto label_147;
label_154:
    // EBPF_OP_MOV64_IMM pc=2420 dst=r1 src=r0 offset=0 imm=5
#line 249 "sample/map.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=2421 dst=r10 src=r1 offset=-4 imm=0
#line 250 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2422 dst=r2 src=r10 offset=0 imm=0
#line 250 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2423 dst=r2 src=r0 offset=0 imm=-4
#line 250 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=2424 dst=r6 src=r0 offset=0 imm=0
#line 250 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=2425 dst=r1 src=r0 offset=0 imm=0
#line 250 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=2427 dst=r3 src=r0 offset=0 imm=0
#line 250 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2428 dst=r0 src=r0 offset=0 imm=16
#line 250 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 250 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 250 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 250 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2429 dst=r7 src=r0 offset=0 imm=0
#line 250 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2430 dst=r5 src=r7 offset=0 imm=0
#line 250 "sample/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2431 dst=r5 src=r0 offset=0 imm=32
#line 250 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2432 dst=r1 src=r5 offset=0 imm=0
#line 250 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2433 dst=r1 src=r0 offset=0 imm=32
#line 250 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2434 dst=r1 src=r0 offset=1 imm=0
#line 250 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 250 "sample/map.c"
        goto label_155;
        // EBPF_OP_JA pc=2435 dst=r0 src=r0 offset=-111 imm=0
#line 250 "sample/map.c"
    goto label_147;
label_155:
    // EBPF_OP_MOV64_IMM pc=2436 dst=r1 src=r0 offset=0 imm=6
#line 250 "sample/map.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=2437 dst=r10 src=r1 offset=-4 imm=0
#line 251 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2438 dst=r2 src=r10 offset=0 imm=0
#line 251 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2439 dst=r2 src=r0 offset=0 imm=-4
#line 251 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=2440 dst=r6 src=r0 offset=0 imm=0
#line 251 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=2441 dst=r1 src=r0 offset=0 imm=0
#line 251 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=2443 dst=r3 src=r0 offset=0 imm=0
#line 251 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2444 dst=r0 src=r0 offset=0 imm=16
#line 251 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 251 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 251 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 251 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2445 dst=r7 src=r0 offset=0 imm=0
#line 251 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2446 dst=r5 src=r7 offset=0 imm=0
#line 251 "sample/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2447 dst=r5 src=r0 offset=0 imm=32
#line 251 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2448 dst=r1 src=r5 offset=0 imm=0
#line 251 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2449 dst=r1 src=r0 offset=0 imm=32
#line 251 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2450 dst=r1 src=r0 offset=1 imm=0
#line 251 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 251 "sample/map.c"
        goto label_156;
        // EBPF_OP_JA pc=2451 dst=r0 src=r0 offset=-127 imm=0
#line 251 "sample/map.c"
    goto label_147;
label_156:
    // EBPF_OP_MOV64_IMM pc=2452 dst=r1 src=r0 offset=0 imm=7
#line 251 "sample/map.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=2453 dst=r10 src=r1 offset=-4 imm=0
#line 252 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2454 dst=r2 src=r10 offset=0 imm=0
#line 252 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2455 dst=r2 src=r0 offset=0 imm=-4
#line 252 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=2456 dst=r6 src=r0 offset=0 imm=0
#line 252 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=2457 dst=r1 src=r0 offset=0 imm=0
#line 252 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=2459 dst=r3 src=r0 offset=0 imm=0
#line 252 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2460 dst=r0 src=r0 offset=0 imm=16
#line 252 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 252 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 252 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 252 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2461 dst=r7 src=r0 offset=0 imm=0
#line 252 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2462 dst=r5 src=r7 offset=0 imm=0
#line 252 "sample/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2463 dst=r5 src=r0 offset=0 imm=32
#line 252 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2464 dst=r1 src=r5 offset=0 imm=0
#line 252 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2465 dst=r1 src=r0 offset=0 imm=32
#line 252 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2466 dst=r1 src=r0 offset=1 imm=0
#line 252 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 252 "sample/map.c"
        goto label_157;
        // EBPF_OP_JA pc=2467 dst=r0 src=r0 offset=-143 imm=0
#line 252 "sample/map.c"
    goto label_147;
label_157:
    // EBPF_OP_MOV64_IMM pc=2468 dst=r1 src=r0 offset=0 imm=8
#line 252 "sample/map.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=2469 dst=r10 src=r1 offset=-4 imm=0
#line 253 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2470 dst=r2 src=r10 offset=0 imm=0
#line 253 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2471 dst=r2 src=r0 offset=0 imm=-4
#line 253 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=2472 dst=r6 src=r0 offset=0 imm=0
#line 253 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=2473 dst=r1 src=r0 offset=0 imm=0
#line 253 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=2475 dst=r3 src=r0 offset=0 imm=0
#line 253 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2476 dst=r0 src=r0 offset=0 imm=16
#line 253 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 253 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 253 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 253 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2477 dst=r7 src=r0 offset=0 imm=0
#line 253 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2478 dst=r5 src=r7 offset=0 imm=0
#line 253 "sample/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2479 dst=r5 src=r0 offset=0 imm=32
#line 253 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2480 dst=r1 src=r5 offset=0 imm=0
#line 253 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2481 dst=r1 src=r0 offset=0 imm=32
#line 253 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2482 dst=r1 src=r0 offset=1 imm=0
#line 253 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 253 "sample/map.c"
        goto label_158;
        // EBPF_OP_JA pc=2483 dst=r0 src=r0 offset=-159 imm=0
#line 253 "sample/map.c"
    goto label_147;
label_158:
    // EBPF_OP_MOV64_IMM pc=2484 dst=r1 src=r0 offset=0 imm=9
#line 253 "sample/map.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=2485 dst=r10 src=r1 offset=-4 imm=0
#line 254 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2486 dst=r2 src=r10 offset=0 imm=0
#line 254 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2487 dst=r2 src=r0 offset=0 imm=-4
#line 254 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=2488 dst=r6 src=r0 offset=0 imm=0
#line 254 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=2489 dst=r1 src=r0 offset=0 imm=0
#line 254 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=2491 dst=r3 src=r0 offset=0 imm=0
#line 254 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2492 dst=r0 src=r0 offset=0 imm=16
#line 254 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 254 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 254 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 254 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2493 dst=r7 src=r0 offset=0 imm=0
#line 254 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2494 dst=r5 src=r7 offset=0 imm=0
#line 254 "sample/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2495 dst=r5 src=r0 offset=0 imm=32
#line 254 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2496 dst=r1 src=r5 offset=0 imm=0
#line 254 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2497 dst=r1 src=r0 offset=0 imm=32
#line 254 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2498 dst=r1 src=r0 offset=1 imm=0
#line 254 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 254 "sample/map.c"
        goto label_159;
        // EBPF_OP_JA pc=2499 dst=r0 src=r0 offset=-175 imm=0
#line 254 "sample/map.c"
    goto label_147;
label_159:
    // EBPF_OP_MOV64_IMM pc=2500 dst=r6 src=r0 offset=0 imm=10
#line 254 "sample/map.c"
    r6 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=2501 dst=r10 src=r6 offset=-4 imm=0
#line 257 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2502 dst=r2 src=r10 offset=0 imm=0
#line 257 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2503 dst=r2 src=r0 offset=0 imm=-4
#line 257 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=2504 dst=r8 src=r0 offset=0 imm=0
#line 257 "sample/map.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=2505 dst=r1 src=r0 offset=0 imm=0
#line 257 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=2507 dst=r3 src=r0 offset=0 imm=0
#line 257 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2508 dst=r0 src=r0 offset=0 imm=16
#line 257 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 257 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 257 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 257 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2509 dst=r7 src=r0 offset=0 imm=0
#line 257 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2510 dst=r5 src=r7 offset=0 imm=0
#line 257 "sample/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2511 dst=r5 src=r0 offset=0 imm=32
#line 257 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2512 dst=r1 src=r5 offset=0 imm=0
#line 257 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2513 dst=r1 src=r0 offset=0 imm=32
#line 257 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=2514 dst=r2 src=r0 offset=0 imm=-29
#line 257 "sample/map.c"
    r2 = (uint64_t)4294967267;
    // EBPF_OP_JEQ_REG pc=2516 dst=r1 src=r2 offset=30 imm=0
#line 257 "sample/map.c"
    if (r1 == r2)
#line 257 "sample/map.c"
        goto label_160;
        // EBPF_OP_STXB pc=2517 dst=r10 src=r8 offset=-10 imm=0
#line 257 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-10)) = (uint8_t)r8;
    // EBPF_OP_MOV64_IMM pc=2518 dst=r1 src=r0 offset=0 imm=25637
#line 257 "sample/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=2519 dst=r10 src=r1 offset=-12 imm=0
#line 257 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=2520 dst=r1 src=r0 offset=0 imm=543450478
#line 257 "sample/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=2521 dst=r10 src=r1 offset=-16 imm=0
#line 257 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=2522 dst=r1 src=r0 offset=0 imm=1914725413
#line 257 "sample/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=2524 dst=r10 src=r1 offset=-24 imm=0
#line 257 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2525 dst=r1 src=r0 offset=0 imm=1667592312
#line 257 "sample/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=2527 dst=r10 src=r1 offset=-32 imm=0
#line 257 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2528 dst=r1 src=r0 offset=0 imm=543649385
#line 257 "sample/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=2530 dst=r10 src=r1 offset=-40 imm=0
#line 257 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2531 dst=r1 src=r0 offset=0 imm=1852383341
#line 257 "sample/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=2533 dst=r10 src=r1 offset=-48 imm=0
#line 257 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2534 dst=r1 src=r0 offset=0 imm=1752397168
#line 257 "sample/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=2536 dst=r10 src=r1 offset=-56 imm=0
#line 257 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2537 dst=r1 src=r0 offset=0 imm=1600548962
#line 257 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2539 dst=r10 src=r1 offset=-64 imm=0
#line 257 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=2540 dst=r3 src=r10 offset=-4 imm=0
#line 257 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ARSH64_IMM pc=2541 dst=r5 src=r0 offset=0 imm=32
#line 257 "sample/map.c"
    r5 = (int64_t)r5 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2542 dst=r1 src=r10 offset=0 imm=0
#line 257 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2543 dst=r1 src=r0 offset=0 imm=-64
#line 257 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2544 dst=r2 src=r0 offset=0 imm=55
#line 257 "sample/map.c"
    r2 = IMMEDIATE(55);
    // EBPF_OP_MOV64_IMM pc=2545 dst=r4 src=r0 offset=0 imm=-29
#line 257 "sample/map.c"
    r4 = IMMEDIATE(-29);
    // EBPF_OP_JA pc=2546 dst=r0 src=r0 offset=-193 imm=0
#line 257 "sample/map.c"
    goto label_149;
label_160:
    // EBPF_OP_STXW pc=2547 dst=r10 src=r6 offset=-4 imm=0
#line 258 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2548 dst=r2 src=r10 offset=0 imm=0
#line 258 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2549 dst=r2 src=r0 offset=0 imm=-4
#line 258 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2550 dst=r1 src=r0 offset=0 imm=0
#line 258 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=2552 dst=r3 src=r0 offset=0 imm=2
#line 258 "sample/map.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_CALL pc=2553 dst=r0 src=r0 offset=0 imm=16
#line 258 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 258 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 258 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 258 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2554 dst=r7 src=r0 offset=0 imm=0
#line 258 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2555 dst=r5 src=r7 offset=0 imm=0
#line 258 "sample/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2556 dst=r5 src=r0 offset=0 imm=32
#line 258 "sample/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2557 dst=r1 src=r5 offset=0 imm=0
#line 258 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2558 dst=r1 src=r0 offset=0 imm=32
#line 258 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2559 dst=r1 src=r0 offset=25 imm=0
#line 258 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 258 "sample/map.c"
        goto label_161;
        // EBPF_OP_MOV64_IMM pc=2560 dst=r1 src=r0 offset=0 imm=25637
#line 258 "sample/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=2561 dst=r10 src=r1 offset=-12 imm=0
#line 258 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=2562 dst=r1 src=r0 offset=0 imm=543450478
#line 258 "sample/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=2563 dst=r10 src=r1 offset=-16 imm=0
#line 258 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=2564 dst=r1 src=r0 offset=0 imm=1914725413
#line 258 "sample/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=2566 dst=r10 src=r1 offset=-24 imm=0
#line 258 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2567 dst=r1 src=r0 offset=0 imm=1667592312
#line 258 "sample/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=2569 dst=r10 src=r1 offset=-32 imm=0
#line 258 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2570 dst=r1 src=r0 offset=0 imm=543649385
#line 258 "sample/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=2572 dst=r10 src=r1 offset=-40 imm=0
#line 258 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2573 dst=r1 src=r0 offset=0 imm=1852383341
#line 258 "sample/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=2575 dst=r10 src=r1 offset=-48 imm=0
#line 258 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2576 dst=r1 src=r0 offset=0 imm=1752397168
#line 258 "sample/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=2578 dst=r10 src=r1 offset=-56 imm=0
#line 258 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2579 dst=r1 src=r0 offset=0 imm=1600548962
#line 258 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2581 dst=r10 src=r1 offset=-64 imm=0
#line 258 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=2582 dst=r1 src=r0 offset=0 imm=0
#line 258 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=2583 dst=r10 src=r1 offset=-10 imm=0
#line 258 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-10)) = (uint8_t)r1;
    // EBPF_OP_JA pc=2584 dst=r0 src=r0 offset=-237 imm=0
#line 258 "sample/map.c"
    goto label_148;
label_161:
    // EBPF_OP_MOV64_IMM pc=2585 dst=r1 src=r0 offset=0 imm=0
#line 258 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2586 dst=r10 src=r1 offset=-4 imm=0
#line 260 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2587 dst=r2 src=r10 offset=0 imm=0
#line 260 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2588 dst=r2 src=r0 offset=0 imm=-4
#line 260 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2589 dst=r1 src=r0 offset=0 imm=0
#line 260 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2591 dst=r0 src=r0 offset=0 imm=18
#line 260 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 260 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 260 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 260 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2592 dst=r7 src=r0 offset=0 imm=0
#line 260 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2593 dst=r4 src=r7 offset=0 imm=0
#line 260 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2594 dst=r4 src=r0 offset=0 imm=32
#line 260 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2595 dst=r1 src=r4 offset=0 imm=0
#line 260 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2596 dst=r1 src=r0 offset=0 imm=32
#line 260 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2597 dst=r1 src=r0 offset=27 imm=0
#line 260 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 260 "sample/map.c"
        goto label_163;
        // EBPF_OP_MOV64_IMM pc=2598 dst=r1 src=r0 offset=0 imm=100
#line 260 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=2599 dst=r10 src=r1 offset=-16 imm=0
#line 260 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=2600 dst=r1 src=r0 offset=0 imm=1852994932
#line 260 "sample/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=2602 dst=r10 src=r1 offset=-24 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2603 dst=r1 src=r0 offset=0 imm=622883948
#line 260 "sample/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=2605 dst=r10 src=r1 offset=-32 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2606 dst=r1 src=r0 offset=0 imm=543649385
#line 260 "sample/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=2608 dst=r10 src=r1 offset=-40 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2609 dst=r1 src=r0 offset=0 imm=2019893357
#line 260 "sample/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=2611 dst=r10 src=r1 offset=-48 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2612 dst=r1 src=r0 offset=0 imm=1801807216
#line 260 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=2614 dst=r10 src=r1 offset=-56 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2615 dst=r1 src=r0 offset=0 imm=1600548962
#line 260 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2617 dst=r10 src=r1 offset=-64 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=2618 dst=r4 src=r0 offset=0 imm=32
#line 260 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2619 dst=r1 src=r10 offset=0 imm=0
#line 260 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2620 dst=r1 src=r0 offset=0 imm=-64
#line 260 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2621 dst=r2 src=r0 offset=0 imm=50
#line 260 "sample/map.c"
    r2 = IMMEDIATE(50);
label_162:
    // EBPF_OP_MOV64_IMM pc=2622 dst=r3 src=r0 offset=0 imm=0
#line 260 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2623 dst=r0 src=r0 offset=0 imm=14
#line 260 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 260 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 260 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 260 "sample/map.c"
        return 0;
        // EBPF_OP_JA pc=2624 dst=r0 src=r0 offset=-400 imm=0
#line 260 "sample/map.c"
    goto label_141;
label_163:
    // EBPF_OP_LDXW pc=2625 dst=r3 src=r10 offset=-4 imm=0
#line 260 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2626 dst=r3 src=r0 offset=22 imm=10
#line 260 "sample/map.c"
    if (r3 == IMMEDIATE(10))
#line 260 "sample/map.c"
        goto label_164;
        // EBPF_OP_MOV64_IMM pc=2627 dst=r1 src=r0 offset=0 imm=0
#line 260 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=2628 dst=r10 src=r1 offset=-24 imm=0
#line 260 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=2629 dst=r1 src=r0 offset=0 imm=1852404835
#line 260 "sample/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=2631 dst=r10 src=r1 offset=-32 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2632 dst=r1 src=r0 offset=0 imm=543434016
#line 260 "sample/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=2634 dst=r10 src=r1 offset=-40 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2635 dst=r1 src=r0 offset=0 imm=1701978221
#line 260 "sample/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=2637 dst=r10 src=r1 offset=-48 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2638 dst=r1 src=r0 offset=0 imm=1801807216
#line 260 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=2640 dst=r10 src=r1 offset=-56 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2641 dst=r1 src=r0 offset=0 imm=1600548962
#line 260 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2643 dst=r10 src=r1 offset=-64 imm=0
#line 260 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2644 dst=r1 src=r10 offset=0 imm=0
#line 260 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2645 dst=r1 src=r0 offset=0 imm=-64
#line 260 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2646 dst=r2 src=r0 offset=0 imm=41
#line 260 "sample/map.c"
    r2 = IMMEDIATE(41);
    // EBPF_OP_MOV64_IMM pc=2647 dst=r4 src=r0 offset=0 imm=10
#line 260 "sample/map.c"
    r4 = IMMEDIATE(10);
    // EBPF_OP_JA pc=2648 dst=r0 src=r0 offset=-427 imm=0
#line 260 "sample/map.c"
    goto label_140;
label_164:
    // EBPF_OP_MOV64_IMM pc=2649 dst=r6 src=r0 offset=0 imm=0
#line 260 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2650 dst=r10 src=r6 offset=-4 imm=0
#line 268 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2651 dst=r2 src=r10 offset=0 imm=0
#line 268 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2652 dst=r2 src=r0 offset=0 imm=-4
#line 268 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2653 dst=r1 src=r0 offset=0 imm=0
#line 268 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2655 dst=r0 src=r0 offset=0 imm=17
#line 268 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 268 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 268 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 268 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2656 dst=r7 src=r0 offset=0 imm=0
#line 268 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2657 dst=r4 src=r7 offset=0 imm=0
#line 268 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2658 dst=r4 src=r0 offset=0 imm=32
#line 268 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2659 dst=r1 src=r4 offset=0 imm=0
#line 268 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2660 dst=r1 src=r0 offset=0 imm=32
#line 268 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2661 dst=r1 src=r0 offset=24 imm=0
#line 268 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 268 "sample/map.c"
        goto label_166;
label_165:
    // EBPF_OP_LDDW pc=2662 dst=r1 src=r0 offset=0 imm=1701737077
#line 268 "sample/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=2664 dst=r10 src=r1 offset=-24 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2665 dst=r1 src=r0 offset=0 imm=1680154740
#line 268 "sample/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=2667 dst=r10 src=r1 offset=-32 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2668 dst=r1 src=r0 offset=0 imm=1914726254
#line 268 "sample/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=2670 dst=r10 src=r1 offset=-40 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2671 dst=r1 src=r0 offset=0 imm=1886938400
#line 268 "sample/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=2673 dst=r10 src=r1 offset=-48 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2674 dst=r1 src=r0 offset=0 imm=1601204080
#line 268 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2676 dst=r10 src=r1 offset=-56 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2677 dst=r1 src=r0 offset=0 imm=1600548962
#line 268 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2679 dst=r10 src=r1 offset=-64 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_STXB pc=2680 dst=r10 src=r6 offset=-16 imm=0
#line 268 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint8_t)r6;
    // EBPF_OP_ARSH64_IMM pc=2681 dst=r4 src=r0 offset=0 imm=32
#line 268 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2682 dst=r1 src=r10 offset=0 imm=0
#line 268 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2683 dst=r1 src=r0 offset=0 imm=-64
#line 268 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2684 dst=r2 src=r0 offset=0 imm=49
#line 268 "sample/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=2685 dst=r0 src=r0 offset=-64 imm=0
#line 268 "sample/map.c"
    goto label_162;
label_166:
    // EBPF_OP_LDXW pc=2686 dst=r3 src=r10 offset=-4 imm=0
#line 268 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2687 dst=r3 src=r0 offset=20 imm=10
#line 268 "sample/map.c"
    if (r3 == IMMEDIATE(10))
#line 268 "sample/map.c"
        goto label_167;
        // EBPF_OP_LDDW pc=2688 dst=r1 src=r0 offset=0 imm=1735289204
#line 268 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2690 dst=r10 src=r1 offset=-32 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2691 dst=r1 src=r0 offset=0 imm=1696621605
#line 268 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2693 dst=r10 src=r1 offset=-40 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2694 dst=r1 src=r0 offset=0 imm=1952805408
#line 268 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2696 dst=r10 src=r1 offset=-48 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2697 dst=r1 src=r0 offset=0 imm=1601204080
#line 268 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2699 dst=r10 src=r1 offset=-56 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2700 dst=r1 src=r0 offset=0 imm=1600548962
#line 268 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2702 dst=r10 src=r1 offset=-64 imm=0
#line 268 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2703 dst=r1 src=r10 offset=0 imm=0
#line 268 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2704 dst=r1 src=r0 offset=0 imm=-64
#line 268 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2705 dst=r2 src=r0 offset=0 imm=40
#line 268 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2706 dst=r4 src=r0 offset=0 imm=10
#line 268 "sample/map.c"
    r4 = IMMEDIATE(10);
    // EBPF_OP_JA pc=2707 dst=r0 src=r0 offset=-486 imm=0
#line 268 "sample/map.c"
    goto label_140;
label_167:
    // EBPF_OP_MOV64_IMM pc=2708 dst=r6 src=r0 offset=0 imm=0
#line 268 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2709 dst=r10 src=r6 offset=-4 imm=0
#line 269 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2710 dst=r2 src=r10 offset=0 imm=0
#line 269 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2711 dst=r2 src=r0 offset=0 imm=-4
#line 269 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2712 dst=r1 src=r0 offset=0 imm=0
#line 269 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2714 dst=r0 src=r0 offset=0 imm=17
#line 269 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 269 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 269 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 269 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2715 dst=r7 src=r0 offset=0 imm=0
#line 269 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2716 dst=r4 src=r7 offset=0 imm=0
#line 269 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2717 dst=r4 src=r0 offset=0 imm=32
#line 269 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2718 dst=r1 src=r4 offset=0 imm=0
#line 269 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2719 dst=r1 src=r0 offset=0 imm=32
#line 269 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2720 dst=r1 src=r0 offset=1 imm=0
#line 269 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 269 "sample/map.c"
        goto label_168;
        // EBPF_OP_JA pc=2721 dst=r0 src=r0 offset=-60 imm=0
#line 269 "sample/map.c"
    goto label_165;
label_168:
    // EBPF_OP_LDXW pc=2722 dst=r3 src=r10 offset=-4 imm=0
#line 269 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2723 dst=r3 src=r0 offset=20 imm=9
#line 269 "sample/map.c"
    if (r3 == IMMEDIATE(9))
#line 269 "sample/map.c"
        goto label_169;
        // EBPF_OP_LDDW pc=2724 dst=r1 src=r0 offset=0 imm=1735289204
#line 269 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2726 dst=r10 src=r1 offset=-32 imm=0
#line 269 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2727 dst=r1 src=r0 offset=0 imm=1696621605
#line 269 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2729 dst=r10 src=r1 offset=-40 imm=0
#line 269 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2730 dst=r1 src=r0 offset=0 imm=1952805408
#line 269 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2732 dst=r10 src=r1 offset=-48 imm=0
#line 269 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2733 dst=r1 src=r0 offset=0 imm=1601204080
#line 269 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2735 dst=r10 src=r1 offset=-56 imm=0
#line 269 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2736 dst=r1 src=r0 offset=0 imm=1600548962
#line 269 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2738 dst=r10 src=r1 offset=-64 imm=0
#line 269 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2739 dst=r1 src=r10 offset=0 imm=0
#line 269 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2740 dst=r1 src=r0 offset=0 imm=-64
#line 269 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2741 dst=r2 src=r0 offset=0 imm=40
#line 269 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2742 dst=r4 src=r0 offset=0 imm=9
#line 269 "sample/map.c"
    r4 = IMMEDIATE(9);
    // EBPF_OP_JA pc=2743 dst=r0 src=r0 offset=-522 imm=0
#line 269 "sample/map.c"
    goto label_140;
label_169:
    // EBPF_OP_MOV64_IMM pc=2744 dst=r6 src=r0 offset=0 imm=0
#line 269 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2745 dst=r10 src=r6 offset=-4 imm=0
#line 270 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2746 dst=r2 src=r10 offset=0 imm=0
#line 270 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2747 dst=r2 src=r0 offset=0 imm=-4
#line 270 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2748 dst=r1 src=r0 offset=0 imm=0
#line 270 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2750 dst=r0 src=r0 offset=0 imm=17
#line 270 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 270 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 270 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 270 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2751 dst=r7 src=r0 offset=0 imm=0
#line 270 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2752 dst=r4 src=r7 offset=0 imm=0
#line 270 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2753 dst=r4 src=r0 offset=0 imm=32
#line 270 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2754 dst=r1 src=r4 offset=0 imm=0
#line 270 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2755 dst=r1 src=r0 offset=0 imm=32
#line 270 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2756 dst=r1 src=r0 offset=1 imm=0
#line 270 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 270 "sample/map.c"
        goto label_170;
        // EBPF_OP_JA pc=2757 dst=r0 src=r0 offset=-96 imm=0
#line 270 "sample/map.c"
    goto label_165;
label_170:
    // EBPF_OP_LDXW pc=2758 dst=r3 src=r10 offset=-4 imm=0
#line 270 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2759 dst=r3 src=r0 offset=20 imm=8
#line 270 "sample/map.c"
    if (r3 == IMMEDIATE(8))
#line 270 "sample/map.c"
        goto label_171;
        // EBPF_OP_LDDW pc=2760 dst=r1 src=r0 offset=0 imm=1735289204
#line 270 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2762 dst=r10 src=r1 offset=-32 imm=0
#line 270 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2763 dst=r1 src=r0 offset=0 imm=1696621605
#line 270 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2765 dst=r10 src=r1 offset=-40 imm=0
#line 270 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2766 dst=r1 src=r0 offset=0 imm=1952805408
#line 270 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2768 dst=r10 src=r1 offset=-48 imm=0
#line 270 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2769 dst=r1 src=r0 offset=0 imm=1601204080
#line 270 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2771 dst=r10 src=r1 offset=-56 imm=0
#line 270 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2772 dst=r1 src=r0 offset=0 imm=1600548962
#line 270 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2774 dst=r10 src=r1 offset=-64 imm=0
#line 270 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2775 dst=r1 src=r10 offset=0 imm=0
#line 270 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2776 dst=r1 src=r0 offset=0 imm=-64
#line 270 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2777 dst=r2 src=r0 offset=0 imm=40
#line 270 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2778 dst=r4 src=r0 offset=0 imm=8
#line 270 "sample/map.c"
    r4 = IMMEDIATE(8);
    // EBPF_OP_JA pc=2779 dst=r0 src=r0 offset=-558 imm=0
#line 270 "sample/map.c"
    goto label_140;
label_171:
    // EBPF_OP_MOV64_IMM pc=2780 dst=r6 src=r0 offset=0 imm=0
#line 270 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2781 dst=r10 src=r6 offset=-4 imm=0
#line 271 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2782 dst=r2 src=r10 offset=0 imm=0
#line 271 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2783 dst=r2 src=r0 offset=0 imm=-4
#line 271 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2784 dst=r1 src=r0 offset=0 imm=0
#line 271 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2786 dst=r0 src=r0 offset=0 imm=17
#line 271 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 271 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 271 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 271 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2787 dst=r7 src=r0 offset=0 imm=0
#line 271 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2788 dst=r4 src=r7 offset=0 imm=0
#line 271 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2789 dst=r4 src=r0 offset=0 imm=32
#line 271 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2790 dst=r1 src=r4 offset=0 imm=0
#line 271 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2791 dst=r1 src=r0 offset=0 imm=32
#line 271 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2792 dst=r1 src=r0 offset=1 imm=0
#line 271 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 271 "sample/map.c"
        goto label_172;
        // EBPF_OP_JA pc=2793 dst=r0 src=r0 offset=-132 imm=0
#line 271 "sample/map.c"
    goto label_165;
label_172:
    // EBPF_OP_LDXW pc=2794 dst=r3 src=r10 offset=-4 imm=0
#line 271 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2795 dst=r3 src=r0 offset=20 imm=7
#line 271 "sample/map.c"
    if (r3 == IMMEDIATE(7))
#line 271 "sample/map.c"
        goto label_173;
        // EBPF_OP_LDDW pc=2796 dst=r1 src=r0 offset=0 imm=1735289204
#line 271 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2798 dst=r10 src=r1 offset=-32 imm=0
#line 271 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2799 dst=r1 src=r0 offset=0 imm=1696621605
#line 271 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2801 dst=r10 src=r1 offset=-40 imm=0
#line 271 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2802 dst=r1 src=r0 offset=0 imm=1952805408
#line 271 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2804 dst=r10 src=r1 offset=-48 imm=0
#line 271 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2805 dst=r1 src=r0 offset=0 imm=1601204080
#line 271 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2807 dst=r10 src=r1 offset=-56 imm=0
#line 271 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2808 dst=r1 src=r0 offset=0 imm=1600548962
#line 271 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2810 dst=r10 src=r1 offset=-64 imm=0
#line 271 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2811 dst=r1 src=r10 offset=0 imm=0
#line 271 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2812 dst=r1 src=r0 offset=0 imm=-64
#line 271 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2813 dst=r2 src=r0 offset=0 imm=40
#line 271 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2814 dst=r4 src=r0 offset=0 imm=7
#line 271 "sample/map.c"
    r4 = IMMEDIATE(7);
    // EBPF_OP_JA pc=2815 dst=r0 src=r0 offset=-594 imm=0
#line 271 "sample/map.c"
    goto label_140;
label_173:
    // EBPF_OP_MOV64_IMM pc=2816 dst=r6 src=r0 offset=0 imm=0
#line 271 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2817 dst=r10 src=r6 offset=-4 imm=0
#line 272 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2818 dst=r2 src=r10 offset=0 imm=0
#line 272 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2819 dst=r2 src=r0 offset=0 imm=-4
#line 272 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2820 dst=r1 src=r0 offset=0 imm=0
#line 272 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2822 dst=r0 src=r0 offset=0 imm=17
#line 272 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 272 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 272 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 272 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2823 dst=r7 src=r0 offset=0 imm=0
#line 272 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2824 dst=r4 src=r7 offset=0 imm=0
#line 272 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2825 dst=r4 src=r0 offset=0 imm=32
#line 272 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2826 dst=r1 src=r4 offset=0 imm=0
#line 272 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2827 dst=r1 src=r0 offset=0 imm=32
#line 272 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2828 dst=r1 src=r0 offset=1 imm=0
#line 272 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 272 "sample/map.c"
        goto label_174;
        // EBPF_OP_JA pc=2829 dst=r0 src=r0 offset=-168 imm=0
#line 272 "sample/map.c"
    goto label_165;
label_174:
    // EBPF_OP_LDXW pc=2830 dst=r3 src=r10 offset=-4 imm=0
#line 272 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2831 dst=r3 src=r0 offset=20 imm=6
#line 272 "sample/map.c"
    if (r3 == IMMEDIATE(6))
#line 272 "sample/map.c"
        goto label_175;
        // EBPF_OP_LDDW pc=2832 dst=r1 src=r0 offset=0 imm=1735289204
#line 272 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2834 dst=r10 src=r1 offset=-32 imm=0
#line 272 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2835 dst=r1 src=r0 offset=0 imm=1696621605
#line 272 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2837 dst=r10 src=r1 offset=-40 imm=0
#line 272 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2838 dst=r1 src=r0 offset=0 imm=1952805408
#line 272 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2840 dst=r10 src=r1 offset=-48 imm=0
#line 272 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2841 dst=r1 src=r0 offset=0 imm=1601204080
#line 272 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2843 dst=r10 src=r1 offset=-56 imm=0
#line 272 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2844 dst=r1 src=r0 offset=0 imm=1600548962
#line 272 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2846 dst=r10 src=r1 offset=-64 imm=0
#line 272 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2847 dst=r1 src=r10 offset=0 imm=0
#line 272 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2848 dst=r1 src=r0 offset=0 imm=-64
#line 272 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2849 dst=r2 src=r0 offset=0 imm=40
#line 272 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2850 dst=r4 src=r0 offset=0 imm=6
#line 272 "sample/map.c"
    r4 = IMMEDIATE(6);
    // EBPF_OP_JA pc=2851 dst=r0 src=r0 offset=-630 imm=0
#line 272 "sample/map.c"
    goto label_140;
label_175:
    // EBPF_OP_MOV64_IMM pc=2852 dst=r6 src=r0 offset=0 imm=0
#line 272 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2853 dst=r10 src=r6 offset=-4 imm=0
#line 273 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2854 dst=r2 src=r10 offset=0 imm=0
#line 273 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2855 dst=r2 src=r0 offset=0 imm=-4
#line 273 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2856 dst=r1 src=r0 offset=0 imm=0
#line 273 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2858 dst=r0 src=r0 offset=0 imm=17
#line 273 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 273 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 273 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 273 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2859 dst=r7 src=r0 offset=0 imm=0
#line 273 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2860 dst=r4 src=r7 offset=0 imm=0
#line 273 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2861 dst=r4 src=r0 offset=0 imm=32
#line 273 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2862 dst=r1 src=r4 offset=0 imm=0
#line 273 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2863 dst=r1 src=r0 offset=0 imm=32
#line 273 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2864 dst=r1 src=r0 offset=1 imm=0
#line 273 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 273 "sample/map.c"
        goto label_176;
        // EBPF_OP_JA pc=2865 dst=r0 src=r0 offset=-204 imm=0
#line 273 "sample/map.c"
    goto label_165;
label_176:
    // EBPF_OP_LDXW pc=2866 dst=r3 src=r10 offset=-4 imm=0
#line 273 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2867 dst=r3 src=r0 offset=20 imm=5
#line 273 "sample/map.c"
    if (r3 == IMMEDIATE(5))
#line 273 "sample/map.c"
        goto label_177;
        // EBPF_OP_LDDW pc=2868 dst=r1 src=r0 offset=0 imm=1735289204
#line 273 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2870 dst=r10 src=r1 offset=-32 imm=0
#line 273 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2871 dst=r1 src=r0 offset=0 imm=1696621605
#line 273 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2873 dst=r10 src=r1 offset=-40 imm=0
#line 273 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2874 dst=r1 src=r0 offset=0 imm=1952805408
#line 273 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2876 dst=r10 src=r1 offset=-48 imm=0
#line 273 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2877 dst=r1 src=r0 offset=0 imm=1601204080
#line 273 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2879 dst=r10 src=r1 offset=-56 imm=0
#line 273 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2880 dst=r1 src=r0 offset=0 imm=1600548962
#line 273 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2882 dst=r10 src=r1 offset=-64 imm=0
#line 273 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2883 dst=r1 src=r10 offset=0 imm=0
#line 273 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2884 dst=r1 src=r0 offset=0 imm=-64
#line 273 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2885 dst=r2 src=r0 offset=0 imm=40
#line 273 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2886 dst=r4 src=r0 offset=0 imm=5
#line 273 "sample/map.c"
    r4 = IMMEDIATE(5);
    // EBPF_OP_JA pc=2887 dst=r0 src=r0 offset=-666 imm=0
#line 273 "sample/map.c"
    goto label_140;
label_177:
    // EBPF_OP_MOV64_IMM pc=2888 dst=r6 src=r0 offset=0 imm=0
#line 273 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2889 dst=r10 src=r6 offset=-4 imm=0
#line 274 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2890 dst=r2 src=r10 offset=0 imm=0
#line 274 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2891 dst=r2 src=r0 offset=0 imm=-4
#line 274 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2892 dst=r1 src=r0 offset=0 imm=0
#line 274 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2894 dst=r0 src=r0 offset=0 imm=17
#line 274 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 274 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 274 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 274 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2895 dst=r7 src=r0 offset=0 imm=0
#line 274 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2896 dst=r4 src=r7 offset=0 imm=0
#line 274 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2897 dst=r4 src=r0 offset=0 imm=32
#line 274 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2898 dst=r1 src=r4 offset=0 imm=0
#line 274 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2899 dst=r1 src=r0 offset=0 imm=32
#line 274 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2900 dst=r1 src=r0 offset=1 imm=0
#line 274 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 274 "sample/map.c"
        goto label_178;
        // EBPF_OP_JA pc=2901 dst=r0 src=r0 offset=-240 imm=0
#line 274 "sample/map.c"
    goto label_165;
label_178:
    // EBPF_OP_LDXW pc=2902 dst=r3 src=r10 offset=-4 imm=0
#line 274 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2903 dst=r3 src=r0 offset=20 imm=4
#line 274 "sample/map.c"
    if (r3 == IMMEDIATE(4))
#line 274 "sample/map.c"
        goto label_179;
        // EBPF_OP_LDDW pc=2904 dst=r1 src=r0 offset=0 imm=1735289204
#line 274 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2906 dst=r10 src=r1 offset=-32 imm=0
#line 274 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2907 dst=r1 src=r0 offset=0 imm=1696621605
#line 274 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2909 dst=r10 src=r1 offset=-40 imm=0
#line 274 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2910 dst=r1 src=r0 offset=0 imm=1952805408
#line 274 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2912 dst=r10 src=r1 offset=-48 imm=0
#line 274 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2913 dst=r1 src=r0 offset=0 imm=1601204080
#line 274 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2915 dst=r10 src=r1 offset=-56 imm=0
#line 274 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2916 dst=r1 src=r0 offset=0 imm=1600548962
#line 274 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2918 dst=r10 src=r1 offset=-64 imm=0
#line 274 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2919 dst=r1 src=r10 offset=0 imm=0
#line 274 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2920 dst=r1 src=r0 offset=0 imm=-64
#line 274 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2921 dst=r2 src=r0 offset=0 imm=40
#line 274 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2922 dst=r4 src=r0 offset=0 imm=4
#line 274 "sample/map.c"
    r4 = IMMEDIATE(4);
    // EBPF_OP_JA pc=2923 dst=r0 src=r0 offset=-702 imm=0
#line 274 "sample/map.c"
    goto label_140;
label_179:
    // EBPF_OP_MOV64_IMM pc=2924 dst=r6 src=r0 offset=0 imm=0
#line 274 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2925 dst=r10 src=r6 offset=-4 imm=0
#line 275 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2926 dst=r2 src=r10 offset=0 imm=0
#line 275 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2927 dst=r2 src=r0 offset=0 imm=-4
#line 275 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2928 dst=r1 src=r0 offset=0 imm=0
#line 275 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2930 dst=r0 src=r0 offset=0 imm=17
#line 275 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 275 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 275 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 275 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2931 dst=r7 src=r0 offset=0 imm=0
#line 275 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2932 dst=r4 src=r7 offset=0 imm=0
#line 275 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2933 dst=r4 src=r0 offset=0 imm=32
#line 275 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2934 dst=r1 src=r4 offset=0 imm=0
#line 275 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2935 dst=r1 src=r0 offset=0 imm=32
#line 275 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2936 dst=r1 src=r0 offset=1 imm=0
#line 275 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 275 "sample/map.c"
        goto label_180;
        // EBPF_OP_JA pc=2937 dst=r0 src=r0 offset=-276 imm=0
#line 275 "sample/map.c"
    goto label_165;
label_180:
    // EBPF_OP_LDXW pc=2938 dst=r3 src=r10 offset=-4 imm=0
#line 275 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2939 dst=r3 src=r0 offset=20 imm=3
#line 275 "sample/map.c"
    if (r3 == IMMEDIATE(3))
#line 275 "sample/map.c"
        goto label_181;
        // EBPF_OP_LDDW pc=2940 dst=r1 src=r0 offset=0 imm=1735289204
#line 275 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2942 dst=r10 src=r1 offset=-32 imm=0
#line 275 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2943 dst=r1 src=r0 offset=0 imm=1696621605
#line 275 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2945 dst=r10 src=r1 offset=-40 imm=0
#line 275 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2946 dst=r1 src=r0 offset=0 imm=1952805408
#line 275 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2948 dst=r10 src=r1 offset=-48 imm=0
#line 275 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2949 dst=r1 src=r0 offset=0 imm=1601204080
#line 275 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2951 dst=r10 src=r1 offset=-56 imm=0
#line 275 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2952 dst=r1 src=r0 offset=0 imm=1600548962
#line 275 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2954 dst=r10 src=r1 offset=-64 imm=0
#line 275 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2955 dst=r1 src=r10 offset=0 imm=0
#line 275 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2956 dst=r1 src=r0 offset=0 imm=-64
#line 275 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2957 dst=r2 src=r0 offset=0 imm=40
#line 275 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2958 dst=r4 src=r0 offset=0 imm=3
#line 275 "sample/map.c"
    r4 = IMMEDIATE(3);
    // EBPF_OP_JA pc=2959 dst=r0 src=r0 offset=-738 imm=0
#line 275 "sample/map.c"
    goto label_140;
label_181:
    // EBPF_OP_MOV64_IMM pc=2960 dst=r6 src=r0 offset=0 imm=0
#line 275 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2961 dst=r10 src=r6 offset=-4 imm=0
#line 276 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2962 dst=r2 src=r10 offset=0 imm=0
#line 276 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2963 dst=r2 src=r0 offset=0 imm=-4
#line 276 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2964 dst=r1 src=r0 offset=0 imm=0
#line 276 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2966 dst=r0 src=r0 offset=0 imm=17
#line 276 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 276 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 276 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 276 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2967 dst=r7 src=r0 offset=0 imm=0
#line 276 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2968 dst=r4 src=r7 offset=0 imm=0
#line 276 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2969 dst=r4 src=r0 offset=0 imm=32
#line 276 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2970 dst=r1 src=r4 offset=0 imm=0
#line 276 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2971 dst=r1 src=r0 offset=0 imm=32
#line 276 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2972 dst=r1 src=r0 offset=1 imm=0
#line 276 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 276 "sample/map.c"
        goto label_182;
        // EBPF_OP_JA pc=2973 dst=r0 src=r0 offset=-312 imm=0
#line 276 "sample/map.c"
    goto label_165;
label_182:
    // EBPF_OP_LDXW pc=2974 dst=r3 src=r10 offset=-4 imm=0
#line 276 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2975 dst=r3 src=r0 offset=20 imm=2
#line 276 "sample/map.c"
    if (r3 == IMMEDIATE(2))
#line 276 "sample/map.c"
        goto label_183;
        // EBPF_OP_LDDW pc=2976 dst=r1 src=r0 offset=0 imm=1735289204
#line 276 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2978 dst=r10 src=r1 offset=-32 imm=0
#line 276 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2979 dst=r1 src=r0 offset=0 imm=1696621605
#line 276 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2981 dst=r10 src=r1 offset=-40 imm=0
#line 276 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2982 dst=r1 src=r0 offset=0 imm=1952805408
#line 276 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2984 dst=r10 src=r1 offset=-48 imm=0
#line 276 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2985 dst=r1 src=r0 offset=0 imm=1601204080
#line 276 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2987 dst=r10 src=r1 offset=-56 imm=0
#line 276 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2988 dst=r1 src=r0 offset=0 imm=1600548962
#line 276 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2990 dst=r10 src=r1 offset=-64 imm=0
#line 276 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2991 dst=r1 src=r10 offset=0 imm=0
#line 276 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2992 dst=r1 src=r0 offset=0 imm=-64
#line 276 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2993 dst=r2 src=r0 offset=0 imm=40
#line 276 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2994 dst=r4 src=r0 offset=0 imm=2
#line 276 "sample/map.c"
    r4 = IMMEDIATE(2);
    // EBPF_OP_JA pc=2995 dst=r0 src=r0 offset=-774 imm=0
#line 276 "sample/map.c"
    goto label_140;
label_183:
    // EBPF_OP_MOV64_IMM pc=2996 dst=r6 src=r0 offset=0 imm=0
#line 276 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2997 dst=r10 src=r6 offset=-4 imm=0
#line 277 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2998 dst=r2 src=r10 offset=0 imm=0
#line 277 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2999 dst=r2 src=r0 offset=0 imm=-4
#line 277 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=3000 dst=r1 src=r0 offset=0 imm=0
#line 277 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=3002 dst=r0 src=r0 offset=0 imm=17
#line 277 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 277 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 277 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 277 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=3003 dst=r7 src=r0 offset=0 imm=0
#line 277 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=3004 dst=r4 src=r7 offset=0 imm=0
#line 277 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=3005 dst=r4 src=r0 offset=0 imm=32
#line 277 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=3006 dst=r1 src=r4 offset=0 imm=0
#line 277 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=3007 dst=r1 src=r0 offset=0 imm=32
#line 277 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=3008 dst=r1 src=r0 offset=1 imm=0
#line 277 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 277 "sample/map.c"
        goto label_184;
        // EBPF_OP_JA pc=3009 dst=r0 src=r0 offset=-348 imm=0
#line 277 "sample/map.c"
    goto label_165;
label_184:
    // EBPF_OP_LDXW pc=3010 dst=r3 src=r10 offset=-4 imm=0
#line 277 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=3011 dst=r3 src=r0 offset=20 imm=1
#line 277 "sample/map.c"
    if (r3 == IMMEDIATE(1))
#line 277 "sample/map.c"
        goto label_185;
        // EBPF_OP_LDDW pc=3012 dst=r1 src=r0 offset=0 imm=1735289204
#line 277 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=3014 dst=r10 src=r1 offset=-32 imm=0
#line 277 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=3015 dst=r1 src=r0 offset=0 imm=1696621605
#line 277 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=3017 dst=r10 src=r1 offset=-40 imm=0
#line 277 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=3018 dst=r1 src=r0 offset=0 imm=1952805408
#line 277 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=3020 dst=r10 src=r1 offset=-48 imm=0
#line 277 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=3021 dst=r1 src=r0 offset=0 imm=1601204080
#line 277 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=3023 dst=r10 src=r1 offset=-56 imm=0
#line 277 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=3024 dst=r1 src=r0 offset=0 imm=1600548962
#line 277 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=3026 dst=r10 src=r1 offset=-64 imm=0
#line 277 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=3027 dst=r1 src=r10 offset=0 imm=0
#line 277 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=3028 dst=r1 src=r0 offset=0 imm=-64
#line 277 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=3029 dst=r2 src=r0 offset=0 imm=40
#line 277 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=3030 dst=r4 src=r0 offset=0 imm=1
#line 277 "sample/map.c"
    r4 = IMMEDIATE(1);
    // EBPF_OP_JA pc=3031 dst=r0 src=r0 offset=-810 imm=0
#line 277 "sample/map.c"
    goto label_140;
label_185:
    // EBPF_OP_MOV64_IMM pc=3032 dst=r1 src=r0 offset=0 imm=0
#line 277 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=3033 dst=r10 src=r1 offset=-4 imm=0
#line 280 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3034 dst=r2 src=r10 offset=0 imm=0
#line 280 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=3035 dst=r2 src=r0 offset=0 imm=-4
#line 280 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=3036 dst=r1 src=r0 offset=0 imm=0
#line 280 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=3038 dst=r0 src=r0 offset=0 imm=18
#line 280 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 280 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 280 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 280 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=3039 dst=r7 src=r0 offset=0 imm=0
#line 280 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=3040 dst=r4 src=r7 offset=0 imm=0
#line 280 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=3041 dst=r4 src=r0 offset=0 imm=32
#line 280 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=3042 dst=r1 src=r4 offset=0 imm=0
#line 280 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=3043 dst=r1 src=r0 offset=0 imm=32
#line 280 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=3044 dst=r2 src=r0 offset=0 imm=-7
#line 280 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=3046 dst=r1 src=r2 offset=1 imm=0
#line 280 "sample/map.c"
    if (r1 == r2)
#line 280 "sample/map.c"
        goto label_186;
        // EBPF_OP_JA pc=3047 dst=r0 src=r0 offset=-1714 imm=0
#line 280 "sample/map.c"
    goto label_87;
label_186:
    // EBPF_OP_LDXW pc=3048 dst=r3 src=r10 offset=-4 imm=0
#line 280 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=3049 dst=r3 src=r0 offset=1 imm=0
#line 280 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 280 "sample/map.c"
        goto label_187;
        // EBPF_OP_JA pc=3050 dst=r0 src=r0 offset=-850 imm=0
#line 280 "sample/map.c"
    goto label_138;
label_187:
    // EBPF_OP_MOV64_IMM pc=3051 dst=r6 src=r0 offset=0 imm=0
#line 280 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=3052 dst=r10 src=r6 offset=-4 imm=0
#line 281 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=3053 dst=r2 src=r10 offset=0 imm=0
#line 281 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=3054 dst=r2 src=r0 offset=0 imm=-4
#line 281 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=3055 dst=r1 src=r0 offset=0 imm=0
#line 281 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=3057 dst=r0 src=r0 offset=0 imm=17
#line 281 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 281 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 281 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 281 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=3058 dst=r7 src=r0 offset=0 imm=0
#line 281 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=3059 dst=r4 src=r7 offset=0 imm=0
#line 281 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=3060 dst=r4 src=r0 offset=0 imm=32
#line 281 "sample/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=3061 dst=r1 src=r4 offset=0 imm=0
#line 281 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=3062 dst=r1 src=r0 offset=0 imm=32
#line 281 "sample/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=3063 dst=r2 src=r0 offset=0 imm=-7
#line 281 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=3065 dst=r1 src=r2 offset=1 imm=0
#line 281 "sample/map.c"
    if (r1 == r2)
#line 281 "sample/map.c"
        goto label_188;
        // EBPF_OP_JA pc=3066 dst=r0 src=r0 offset=-801 imm=0
#line 281 "sample/map.c"
    goto label_143;
label_188:
    // EBPF_OP_LDXW pc=3067 dst=r3 src=r10 offset=-4 imm=0
#line 281 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=3068 dst=r3 src=r0 offset=1 imm=0
#line 281 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 281 "sample/map.c"
        goto label_189;
        // EBPF_OP_JA pc=3069 dst=r0 src=r0 offset=-778 imm=0
#line 281 "sample/map.c"
    goto label_145;
label_189:
    // EBPF_OP_MOV64_IMM pc=3070 dst=r6 src=r0 offset=0 imm=0
#line 281 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_JA pc=3071 dst=r0 src=r0 offset=-2970 imm=0
#line 281 "sample/map.c"
    goto label_9;
#line 281 "sample/map.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        test_maps,
        "xdp_prog",
        "xdp_prog",
        "test_maps",
        test_maps_maps,
        8,
        test_maps_helpers,
        11,
        3072,
        &test_maps_program_type_guid,
        &test_maps_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 1;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = 0;
    version->minor = 9;
    version->revision = 0;
}

metadata_table_t map_metadata_table = {sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
