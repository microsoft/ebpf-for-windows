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
    {NULL, 3, "helper_id_3"},
    {NULL, 4, "helper_id_4"},
    {NULL, 18, "helper_id_18"},
    {NULL, 17, "helper_id_17"},
    {NULL, 16, "helper_id_16"},
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
#line 195 "sample/map.c"
{
#line 195 "sample/map.c"
    // Prologue
#line 195 "sample/map.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 195 "sample/map.c"
    register uint64_t r0 = 0;
#line 195 "sample/map.c"
    register uint64_t r1 = 0;
#line 195 "sample/map.c"
    register uint64_t r2 = 0;
#line 195 "sample/map.c"
    register uint64_t r3 = 0;
#line 195 "sample/map.c"
    register uint64_t r4 = 0;
#line 195 "sample/map.c"
    register uint64_t r5 = 0;
#line 195 "sample/map.c"
    register uint64_t r6 = 0;
#line 195 "sample/map.c"
    register uint64_t r7 = 0;
#line 195 "sample/map.c"
    register uint64_t r8 = 0;
#line 195 "sample/map.c"
    register uint64_t r10 = 0;

#line 195 "sample/map.c"
    r1 = (uintptr_t)context;
#line 195 "sample/map.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r7 src=r0 offset=0 imm=0
#line 195 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r7 offset=-4 imm=0
#line 72 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=2 dst=r1 src=r0 offset=0 imm=1
#line 72 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=3 dst=r10 src=r1 offset=-8 imm=0
#line 73 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=4 dst=r2 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=5 dst=r2 src=r0 offset=0 imm=-4
#line 73 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=6 dst=r3 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r3 src=r0 offset=0 imm=-8
#line 73 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=8 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=10 dst=r4 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=11 dst=r0 src=r0 offset=0 imm=2
#line 76 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=12 dst=r6 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=13 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=14 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=15 dst=r7 src=r6 offset=30 imm=0
#line 77 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 77 "sample/map.c"
        goto label_1;
        // EBPF_OP_MOV64_REG pc=16 dst=r2 src=r10 offset=0 imm=0
#line 77 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=17 dst=r2 src=r0 offset=0 imm=-4
#line 77 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=20 dst=r0 src=r0 offset=0 imm=1
#line 82 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=21 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=23 dst=r0 src=r0 offset=22 imm=0
#line 83 "sample/map.c"
    if (r0 == IMMEDIATE(0))
#line 83 "sample/map.c"
        goto label_1;
        // EBPF_OP_MOV64_REG pc=24 dst=r2 src=r10 offset=0 imm=0
#line 83 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=25 dst=r2 src=r0 offset=0 imm=-4
#line 83 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=26 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=28 dst=r0 src=r0 offset=0 imm=3
#line 88 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=29 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=30 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=31 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=32 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=33 dst=r1 src=r6 offset=12 imm=0
#line 89 "sample/map.c"
    if ((int64_t)r1 > (int64_t)r6)
#line 89 "sample/map.c"
        goto label_1;
        // EBPF_OP_MOV64_REG pc=34 dst=r2 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=35 dst=r2 src=r0 offset=0 imm=-4
#line 89 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=36 dst=r3 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=37 dst=r3 src=r0 offset=0 imm=-8
#line 89 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=38 dst=r1 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=40 dst=r4 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=41 dst=r0 src=r0 offset=0 imm=2
#line 94 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 94 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 94 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 94 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=42 dst=r6 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=43 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=44 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=45 dst=r6 src=r0 offset=2 imm=-1
#line 95 "sample/map.c"
    if ((int64_t)r6 > IMMEDIATE(-1))
#line 95 "sample/map.c"
        goto label_2;
label_1:
    // EBPF_OP_MOV64_REG pc=46 dst=r0 src=r6 offset=0 imm=0
#line 211 "sample/map.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=47 dst=r0 src=r0 offset=0 imm=0
#line 211 "sample/map.c"
    return r0;
label_2:
    // EBPF_OP_MOV64_REG pc=48 dst=r2 src=r10 offset=0 imm=0
#line 211 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=49 dst=r2 src=r0 offset=0 imm=-4
#line 211 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=50 dst=r1 src=r0 offset=0 imm=0
#line 105 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=52 dst=r0 src=r0 offset=0 imm=4
#line 105 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 105 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 105 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 105 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=53 dst=r6 src=r0 offset=0 imm=-1
#line 105 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=55 dst=r0 src=r0 offset=-10 imm=0
#line 198 "sample/map.c"
    if (r0 == IMMEDIATE(0))
#line 198 "sample/map.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=56 dst=r7 src=r0 offset=0 imm=0
#line 198 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=57 dst=r10 src=r7 offset=-4 imm=0
#line 72 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=58 dst=r1 src=r0 offset=0 imm=1
#line 72 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=59 dst=r10 src=r1 offset=-8 imm=0
#line 73 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=60 dst=r2 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=61 dst=r2 src=r0 offset=0 imm=-4
#line 73 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=62 dst=r3 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=63 dst=r3 src=r0 offset=0 imm=-8
#line 73 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=64 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_MOV64_IMM pc=66 dst=r4 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=67 dst=r0 src=r0 offset=0 imm=2
#line 76 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=68 dst=r6 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=69 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=70 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=71 dst=r7 src=r6 offset=30 imm=0
#line 77 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 77 "sample/map.c"
        goto label_3;
        // EBPF_OP_MOV64_REG pc=72 dst=r2 src=r10 offset=0 imm=0
#line 77 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=73 dst=r2 src=r0 offset=0 imm=-4
#line 77 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=74 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=76 dst=r0 src=r0 offset=0 imm=1
#line 82 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=77 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=79 dst=r0 src=r0 offset=22 imm=0
#line 83 "sample/map.c"
    if (r0 == IMMEDIATE(0))
#line 83 "sample/map.c"
        goto label_3;
        // EBPF_OP_MOV64_REG pc=80 dst=r2 src=r10 offset=0 imm=0
#line 83 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=81 dst=r2 src=r0 offset=0 imm=-4
#line 83 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=82 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=84 dst=r0 src=r0 offset=0 imm=3
#line 88 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=85 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=86 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=87 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=88 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=89 dst=r1 src=r6 offset=12 imm=0
#line 89 "sample/map.c"
    if ((int64_t)r1 > (int64_t)r6)
#line 89 "sample/map.c"
        goto label_3;
        // EBPF_OP_MOV64_REG pc=90 dst=r2 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=91 dst=r2 src=r0 offset=0 imm=-4
#line 89 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=92 dst=r3 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=93 dst=r3 src=r0 offset=0 imm=-8
#line 89 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=94 dst=r1 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_MOV64_IMM pc=96 dst=r4 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=97 dst=r0 src=r0 offset=0 imm=2
#line 94 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 94 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 94 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 94 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=98 dst=r6 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=99 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=100 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=101 dst=r6 src=r0 offset=1 imm=-1
#line 95 "sample/map.c"
    if ((int64_t)r6 > IMMEDIATE(-1))
#line 95 "sample/map.c"
        goto label_4;
label_3:
    // EBPF_OP_JA pc=102 dst=r0 src=r0 offset=-57 imm=0
#line 95 "sample/map.c"
    goto label_1;
label_4:
    // EBPF_OP_MOV64_REG pc=103 dst=r2 src=r10 offset=0 imm=0
#line 95 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=104 dst=r2 src=r0 offset=0 imm=-4
#line 95 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=105 dst=r1 src=r0 offset=0 imm=0
#line 105 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=107 dst=r0 src=r0 offset=0 imm=4
#line 105 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 105 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 105 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 105 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=108 dst=r6 src=r0 offset=0 imm=-1
#line 105 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=110 dst=r0 src=r0 offset=-65 imm=0
#line 199 "sample/map.c"
    if (r0 == IMMEDIATE(0))
#line 199 "sample/map.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=111 dst=r7 src=r0 offset=0 imm=0
#line 199 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=112 dst=r10 src=r7 offset=-4 imm=0
#line 72 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=113 dst=r1 src=r0 offset=0 imm=1
#line 72 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=114 dst=r10 src=r1 offset=-8 imm=0
#line 73 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=115 dst=r2 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=116 dst=r2 src=r0 offset=0 imm=-4
#line 73 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=117 dst=r3 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=118 dst=r3 src=r0 offset=0 imm=-8
#line 73 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=119 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_MOV64_IMM pc=121 dst=r4 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=122 dst=r0 src=r0 offset=0 imm=2
#line 76 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=123 dst=r6 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=124 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=125 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=126 dst=r7 src=r6 offset=31 imm=0
#line 77 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 77 "sample/map.c"
        goto label_5;
        // EBPF_OP_MOV64_REG pc=127 dst=r2 src=r10 offset=0 imm=0
#line 77 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=128 dst=r2 src=r0 offset=0 imm=-4
#line 77 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=129 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_CALL pc=131 dst=r0 src=r0 offset=0 imm=1
#line 82 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=132 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=134 dst=r0 src=r0 offset=23 imm=0
#line 83 "sample/map.c"
    if (r0 == IMMEDIATE(0))
#line 83 "sample/map.c"
        goto label_5;
        // EBPF_OP_MOV64_REG pc=135 dst=r2 src=r10 offset=0 imm=0
#line 83 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=136 dst=r2 src=r0 offset=0 imm=-4
#line 83 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=137 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_CALL pc=139 dst=r0 src=r0 offset=0 imm=3
#line 88 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=140 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=141 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=142 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=143 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=144 dst=r1 src=r6 offset=13 imm=0
#line 89 "sample/map.c"
    if ((int64_t)r1 > (int64_t)r6)
#line 89 "sample/map.c"
        goto label_5;
        // EBPF_OP_MOV64_REG pc=145 dst=r2 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=146 dst=r2 src=r0 offset=0 imm=-4
#line 89 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=147 dst=r3 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=148 dst=r3 src=r0 offset=0 imm=-8
#line 89 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=149 dst=r7 src=r0 offset=0 imm=0
#line 89 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=150 dst=r1 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_MOV64_IMM pc=152 dst=r4 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=153 dst=r0 src=r0 offset=0 imm=2
#line 94 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 94 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 94 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 94 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=154 dst=r6 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=155 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=156 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=157 dst=r6 src=r0 offset=1 imm=-1
#line 95 "sample/map.c"
    if ((int64_t)r6 > IMMEDIATE(-1))
#line 95 "sample/map.c"
        goto label_6;
label_5:
    // EBPF_OP_JA pc=158 dst=r0 src=r0 offset=-113 imm=0
#line 95 "sample/map.c"
    goto label_1;
label_6:
    // EBPF_OP_STXW pc=159 dst=r10 src=r7 offset=-4 imm=0
#line 72 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=160 dst=r1 src=r0 offset=0 imm=1
#line 72 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=161 dst=r10 src=r1 offset=-8 imm=0
#line 73 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=162 dst=r2 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=163 dst=r2 src=r0 offset=0 imm=-4
#line 73 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=164 dst=r3 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=165 dst=r3 src=r0 offset=0 imm=-8
#line 73 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=166 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_MOV64_IMM pc=168 dst=r4 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=169 dst=r0 src=r0 offset=0 imm=2
#line 76 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=170 dst=r6 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=171 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=172 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=173 dst=r7 src=r6 offset=31 imm=0
#line 77 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 77 "sample/map.c"
        goto label_7;
        // EBPF_OP_MOV64_REG pc=174 dst=r2 src=r10 offset=0 imm=0
#line 77 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=175 dst=r2 src=r0 offset=0 imm=-4
#line 77 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=176 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_CALL pc=178 dst=r0 src=r0 offset=0 imm=1
#line 82 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=179 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=181 dst=r0 src=r0 offset=23 imm=0
#line 83 "sample/map.c"
    if (r0 == IMMEDIATE(0))
#line 83 "sample/map.c"
        goto label_7;
        // EBPF_OP_MOV64_REG pc=182 dst=r2 src=r10 offset=0 imm=0
#line 83 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=183 dst=r2 src=r0 offset=0 imm=-4
#line 83 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=184 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_CALL pc=186 dst=r0 src=r0 offset=0 imm=3
#line 88 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=187 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=188 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=189 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=190 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=191 dst=r1 src=r6 offset=13 imm=0
#line 89 "sample/map.c"
    if ((int64_t)r1 > (int64_t)r6)
#line 89 "sample/map.c"
        goto label_7;
        // EBPF_OP_MOV64_REG pc=192 dst=r2 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=193 dst=r2 src=r0 offset=0 imm=-4
#line 89 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=194 dst=r3 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=195 dst=r3 src=r0 offset=0 imm=-8
#line 89 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=196 dst=r7 src=r0 offset=0 imm=0
#line 89 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=197 dst=r1 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_MOV64_IMM pc=199 dst=r4 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=200 dst=r0 src=r0 offset=0 imm=2
#line 94 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 94 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 94 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 94 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=201 dst=r6 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=202 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=203 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=204 dst=r6 src=r0 offset=1 imm=-1
#line 95 "sample/map.c"
    if ((int64_t)r6 > IMMEDIATE(-1))
#line 95 "sample/map.c"
        goto label_8;
label_7:
    // EBPF_OP_JA pc=205 dst=r0 src=r0 offset=-160 imm=0
#line 95 "sample/map.c"
    goto label_1;
label_8:
    // EBPF_OP_STXW pc=206 dst=r10 src=r7 offset=-4 imm=0
#line 72 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=207 dst=r1 src=r0 offset=0 imm=1
#line 72 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=208 dst=r10 src=r1 offset=-8 imm=0
#line 73 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=209 dst=r2 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=210 dst=r2 src=r0 offset=0 imm=-4
#line 73 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=211 dst=r3 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=212 dst=r3 src=r0 offset=0 imm=-8
#line 73 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=213 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=215 dst=r4 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=216 dst=r0 src=r0 offset=0 imm=2
#line 76 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=217 dst=r6 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=218 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=219 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=220 dst=r7 src=r6 offset=30 imm=0
#line 77 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 77 "sample/map.c"
        goto label_9;
        // EBPF_OP_MOV64_REG pc=221 dst=r2 src=r10 offset=0 imm=0
#line 77 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=222 dst=r2 src=r0 offset=0 imm=-4
#line 77 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=223 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_CALL pc=225 dst=r0 src=r0 offset=0 imm=1
#line 82 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=226 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=228 dst=r0 src=r0 offset=22 imm=0
#line 83 "sample/map.c"
    if (r0 == IMMEDIATE(0))
#line 83 "sample/map.c"
        goto label_9;
        // EBPF_OP_MOV64_REG pc=229 dst=r2 src=r10 offset=0 imm=0
#line 83 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=230 dst=r2 src=r0 offset=0 imm=-4
#line 83 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=231 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_CALL pc=233 dst=r0 src=r0 offset=0 imm=3
#line 88 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=234 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=235 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=236 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=237 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=238 dst=r1 src=r6 offset=12 imm=0
#line 89 "sample/map.c"
    if ((int64_t)r1 > (int64_t)r6)
#line 89 "sample/map.c"
        goto label_9;
        // EBPF_OP_MOV64_REG pc=239 dst=r2 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=240 dst=r2 src=r0 offset=0 imm=-4
#line 89 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=241 dst=r3 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=242 dst=r3 src=r0 offset=0 imm=-8
#line 89 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=243 dst=r1 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=245 dst=r4 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=246 dst=r0 src=r0 offset=0 imm=2
#line 94 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 94 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 94 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 94 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=247 dst=r6 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=248 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=249 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=250 dst=r6 src=r0 offset=1 imm=-1
#line 95 "sample/map.c"
    if ((int64_t)r6 > IMMEDIATE(-1))
#line 95 "sample/map.c"
        goto label_10;
label_9:
    // EBPF_OP_JA pc=251 dst=r0 src=r0 offset=-206 imm=0
#line 95 "sample/map.c"
    goto label_1;
label_10:
    // EBPF_OP_MOV64_REG pc=252 dst=r2 src=r10 offset=0 imm=0
#line 95 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=253 dst=r2 src=r0 offset=0 imm=-4
#line 95 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=254 dst=r1 src=r0 offset=0 imm=0
#line 105 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_CALL pc=256 dst=r0 src=r0 offset=0 imm=4
#line 105 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 105 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 105 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 105 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=257 dst=r6 src=r0 offset=0 imm=-1
#line 105 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=259 dst=r0 src=r0 offset=-214 imm=0
#line 202 "sample/map.c"
    if (r0 == IMMEDIATE(0))
#line 202 "sample/map.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=260 dst=r7 src=r0 offset=0 imm=0
#line 202 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=261 dst=r10 src=r7 offset=-4 imm=0
#line 72 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=262 dst=r1 src=r0 offset=0 imm=1
#line 72 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=263 dst=r10 src=r1 offset=-8 imm=0
#line 73 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=264 dst=r2 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=265 dst=r2 src=r0 offset=0 imm=-4
#line 73 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=266 dst=r3 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=267 dst=r3 src=r0 offset=0 imm=-8
#line 73 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=268 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=270 dst=r4 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=271 dst=r0 src=r0 offset=0 imm=2
#line 76 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=272 dst=r6 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=273 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=274 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=275 dst=r7 src=r6 offset=30 imm=0
#line 77 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 77 "sample/map.c"
        goto label_11;
        // EBPF_OP_MOV64_REG pc=276 dst=r2 src=r10 offset=0 imm=0
#line 77 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=277 dst=r2 src=r0 offset=0 imm=-4
#line 77 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=278 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_CALL pc=280 dst=r0 src=r0 offset=0 imm=1
#line 82 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=281 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=283 dst=r0 src=r0 offset=22 imm=0
#line 83 "sample/map.c"
    if (r0 == IMMEDIATE(0))
#line 83 "sample/map.c"
        goto label_11;
        // EBPF_OP_MOV64_REG pc=284 dst=r2 src=r10 offset=0 imm=0
#line 83 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=285 dst=r2 src=r0 offset=0 imm=-4
#line 83 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=286 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_CALL pc=288 dst=r0 src=r0 offset=0 imm=3
#line 88 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=289 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=290 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=291 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=292 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=293 dst=r1 src=r6 offset=12 imm=0
#line 89 "sample/map.c"
    if ((int64_t)r1 > (int64_t)r6)
#line 89 "sample/map.c"
        goto label_11;
        // EBPF_OP_MOV64_REG pc=294 dst=r2 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=295 dst=r2 src=r0 offset=0 imm=-4
#line 89 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=296 dst=r3 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=297 dst=r3 src=r0 offset=0 imm=-8
#line 89 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=298 dst=r1 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=300 dst=r4 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=301 dst=r0 src=r0 offset=0 imm=2
#line 94 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 94 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 94 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 94 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=302 dst=r6 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=303 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=304 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=305 dst=r6 src=r0 offset=1 imm=-1
#line 95 "sample/map.c"
    if ((int64_t)r6 > IMMEDIATE(-1))
#line 95 "sample/map.c"
        goto label_12;
label_11:
    // EBPF_OP_JA pc=306 dst=r0 src=r0 offset=-261 imm=0
#line 95 "sample/map.c"
    goto label_1;
label_12:
    // EBPF_OP_MOV64_REG pc=307 dst=r2 src=r10 offset=0 imm=0
#line 95 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=308 dst=r2 src=r0 offset=0 imm=-4
#line 95 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=309 dst=r1 src=r0 offset=0 imm=0
#line 105 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_CALL pc=311 dst=r0 src=r0 offset=0 imm=4
#line 105 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 105 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 105 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 105 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=312 dst=r6 src=r0 offset=0 imm=-1
#line 105 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=314 dst=r0 src=r0 offset=-269 imm=0
#line 203 "sample/map.c"
    if (r0 == IMMEDIATE(0))
#line 203 "sample/map.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=315 dst=r1 src=r0 offset=0 imm=0
#line 203 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=316 dst=r10 src=r1 offset=-4 imm=0
#line 203 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=317 dst=r1 src=r0 offset=0 imm=1
#line 203 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=318 dst=r10 src=r1 offset=-8 imm=0
#line 117 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=319 dst=r7 src=r0 offset=0 imm=11
#line 117 "sample/map.c"
    r7 = IMMEDIATE(11);
    // EBPF_OP_JA pc=320 dst=r0 src=r0 offset=12 imm=0
#line 117 "sample/map.c"
    goto label_14;
label_13:
    // EBPF_OP_LDXW pc=321 dst=r1 src=r10 offset=-4 imm=0
#line 121 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ADD64_IMM pc=322 dst=r1 src=r0 offset=0 imm=1
#line 121 "sample/map.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=323 dst=r10 src=r1 offset=-4 imm=0
#line 121 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_LSH64_IMM pc=324 dst=r1 src=r0 offset=0 imm=32
#line 121 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=325 dst=r1 src=r0 offset=0 imm=32
#line 121 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JGT_REG pc=326 dst=r7 src=r1 offset=6 imm=0
#line 121 "sample/map.c"
    if (r7 > r1)
#line 121 "sample/map.c"
        goto label_14;
        // EBPF_OP_MOV64_IMM pc=327 dst=r1 src=r0 offset=0 imm=0
#line 121 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=328 dst=r10 src=r1 offset=-4 imm=0
#line 121 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=329 dst=r1 src=r0 offset=0 imm=1
#line 121 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=330 dst=r10 src=r1 offset=-8 imm=0
#line 117 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=331 dst=r7 src=r0 offset=0 imm=11
#line 117 "sample/map.c"
    r7 = IMMEDIATE(11);
    // EBPF_OP_JA pc=332 dst=r0 src=r0 offset=36 imm=0
#line 117 "sample/map.c"
    goto label_16;
label_14:
    // EBPF_OP_MOV64_REG pc=333 dst=r2 src=r10 offset=0 imm=0
#line 117 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=334 dst=r2 src=r0 offset=0 imm=-4
#line 117 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=335 dst=r3 src=r10 offset=0 imm=0
#line 117 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=336 dst=r3 src=r0 offset=0 imm=-8
#line 117 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=337 dst=r1 src=r0 offset=0 imm=0
#line 122 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=339 dst=r4 src=r0 offset=0 imm=0
#line 122 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=340 dst=r0 src=r0 offset=0 imm=2
#line 122 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 122 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 122 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 122 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=341 dst=r6 src=r0 offset=0 imm=0
#line 122 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=342 dst=r1 src=r6 offset=0 imm=0
#line 122 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=343 dst=r1 src=r0 offset=0 imm=32
#line 122 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=344 dst=r1 src=r0 offset=0 imm=32
#line 122 "sample/map.c"
    r1 = (int64_t)r1 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=345 dst=r1 src=r0 offset=-25 imm=-1
#line 123 "sample/map.c"
    if ((int64_t)r1 > IMMEDIATE(-1))
#line 123 "sample/map.c"
        goto label_13;
        // EBPF_OP_JA pc=346 dst=r0 src=r0 offset=-301 imm=0
#line 123 "sample/map.c"
    goto label_1;
label_15:
    // EBPF_OP_LDXW pc=347 dst=r1 src=r10 offset=-4 imm=0
#line 121 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ADD64_IMM pc=348 dst=r1 src=r0 offset=0 imm=1
#line 121 "sample/map.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=349 dst=r10 src=r1 offset=-4 imm=0
#line 121 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_LSH64_IMM pc=350 dst=r1 src=r0 offset=0 imm=32
#line 121 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=351 dst=r1 src=r0 offset=0 imm=32
#line 121 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JGT_REG pc=352 dst=r7 src=r1 offset=16 imm=0
#line 121 "sample/map.c"
    if (r7 > r1)
#line 121 "sample/map.c"
        goto label_16;
        // EBPF_OP_MOV64_IMM pc=353 dst=r1 src=r0 offset=0 imm=0
#line 121 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=354 dst=r10 src=r1 offset=-4 imm=0
#line 173 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=355 dst=r2 src=r10 offset=0 imm=0
#line 173 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=356 dst=r2 src=r0 offset=0 imm=-4
#line 173 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=357 dst=r1 src=r0 offset=0 imm=0
#line 173 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=359 dst=r0 src=r0 offset=0 imm=18
#line 173 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 173 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 173 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 173 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=360 dst=r1 src=r0 offset=0 imm=0
#line 173 "sample/map.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=361 dst=r1 src=r0 offset=0 imm=32
#line 173 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=362 dst=r1 src=r0 offset=0 imm=32
#line 173 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=363 dst=r6 src=r0 offset=0 imm=-1
#line 173 "sample/map.c"
    r6 = IMMEDIATE(-1);
    // EBPF_OP_LDDW pc=364 dst=r2 src=r0 offset=0 imm=-7
#line 173 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=366 dst=r1 src=r2 offset=16 imm=0
#line 173 "sample/map.c"
    if (r1 == r2)
#line 173 "sample/map.c"
        goto label_17;
        // EBPF_OP_MOV64_REG pc=367 dst=r6 src=r0 offset=0 imm=0
#line 173 "sample/map.c"
    r6 = r0;
    // EBPF_OP_JA pc=368 dst=r0 src=r0 offset=14 imm=0
#line 173 "sample/map.c"
    goto label_17;
label_16:
    // EBPF_OP_MOV64_REG pc=369 dst=r2 src=r10 offset=0 imm=0
#line 173 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=370 dst=r2 src=r0 offset=0 imm=-4
#line 173 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=371 dst=r3 src=r10 offset=0 imm=0
#line 173 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=372 dst=r3 src=r0 offset=0 imm=-8
#line 173 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=373 dst=r1 src=r0 offset=0 imm=0
#line 122 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=375 dst=r4 src=r0 offset=0 imm=0
#line 122 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=376 dst=r0 src=r0 offset=0 imm=2
#line 122 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 122 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 122 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 122 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=377 dst=r6 src=r0 offset=0 imm=0
#line 122 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=378 dst=r1 src=r6 offset=0 imm=0
#line 122 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=379 dst=r1 src=r0 offset=0 imm=32
#line 122 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=380 dst=r1 src=r0 offset=0 imm=32
#line 122 "sample/map.c"
    r1 = (int64_t)r1 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=381 dst=r1 src=r0 offset=-35 imm=-1
#line 123 "sample/map.c"
    if ((int64_t)r1 > IMMEDIATE(-1))
#line 123 "sample/map.c"
        goto label_15;
        // EBPF_OP_JA pc=382 dst=r0 src=r0 offset=-337 imm=0
#line 123 "sample/map.c"
    goto label_1;
label_17:
    // EBPF_OP_JNE_REG pc=383 dst=r1 src=r2 offset=170 imm=0
#line 123 "sample/map.c"
    if (r1 != r2)
#line 123 "sample/map.c"
        goto label_21;
        // EBPF_OP_LDXW pc=384 dst=r1 src=r10 offset=-4 imm=0
#line 123 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=385 dst=r1 src=r0 offset=168 imm=0
#line 123 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 123 "sample/map.c"
        goto label_21;
        // EBPF_OP_MOV64_IMM pc=386 dst=r1 src=r0 offset=0 imm=0
#line 123 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=387 dst=r10 src=r1 offset=-4 imm=0
#line 174 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=388 dst=r2 src=r10 offset=0 imm=0
#line 174 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=389 dst=r2 src=r0 offset=0 imm=-4
#line 174 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=390 dst=r1 src=r0 offset=0 imm=0
#line 174 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=392 dst=r0 src=r0 offset=0 imm=17
#line 174 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 174 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 174 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 174 "sample/map.c"
        return 0;
        // EBPF_OP_LDXW pc=393 dst=r1 src=r10 offset=-4 imm=0
#line 174 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=394 dst=r7 src=r6 offset=0 imm=0
#line 174 "sample/map.c"
    r7 = r6;
    // EBPF_OP_JEQ_IMM pc=395 dst=r1 src=r0 offset=1 imm=0
#line 174 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 174 "sample/map.c"
        goto label_18;
        // EBPF_OP_MOV64_IMM pc=396 dst=r7 src=r0 offset=0 imm=-1
#line 174 "sample/map.c"
    r7 = IMMEDIATE(-1);
label_18:
    // EBPF_OP_MOV64_REG pc=397 dst=r2 src=r0 offset=0 imm=0
#line 174 "sample/map.c"
    r2 = r0;
    // EBPF_OP_LSH64_IMM pc=398 dst=r2 src=r0 offset=0 imm=32
#line 174 "sample/map.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=399 dst=r2 src=r0 offset=0 imm=32
#line 174 "sample/map.c"
    r2 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=400 dst=r3 src=r0 offset=0 imm=-7
#line 174 "sample/map.c"
    r3 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=402 dst=r2 src=r3 offset=1 imm=0
#line 174 "sample/map.c"
    if (r2 == r3)
#line 174 "sample/map.c"
        goto label_19;
        // EBPF_OP_MOV64_REG pc=403 dst=r7 src=r0 offset=0 imm=0
#line 174 "sample/map.c"
    r7 = r0;
label_19:
    // EBPF_OP_MOV64_REG pc=404 dst=r6 src=r7 offset=0 imm=0
#line 174 "sample/map.c"
    r6 = r7;
    // EBPF_OP_JNE_REG pc=405 dst=r2 src=r3 offset=148 imm=0
#line 174 "sample/map.c"
    if (r2 != r3)
#line 174 "sample/map.c"
        goto label_21;
        // EBPF_OP_MOV64_REG pc=406 dst=r6 src=r7 offset=0 imm=0
#line 174 "sample/map.c"
    r6 = r7;
    // EBPF_OP_JNE_IMM pc=407 dst=r1 src=r0 offset=146 imm=0
#line 174 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 174 "sample/map.c"
        goto label_21;
        // EBPF_OP_MOV64_IMM pc=408 dst=r1 src=r0 offset=0 imm=0
#line 174 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=409 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=410 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=411 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=412 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=414 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=415 dst=r0 src=r0 offset=0 imm=16
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=416 dst=r6 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=417 dst=r1 src=r6 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=418 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=419 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=420 dst=r1 src=r0 offset=133 imm=0
#line 177 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_21;
        // EBPF_OP_MOV64_IMM pc=421 dst=r1 src=r0 offset=0 imm=1
#line 177 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=422 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=423 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=424 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=425 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=427 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=428 dst=r0 src=r0 offset=0 imm=16
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=429 dst=r6 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=430 dst=r1 src=r6 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=431 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=432 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=433 dst=r1 src=r0 offset=1 imm=0
#line 177 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_20;
        // EBPF_OP_JA pc=434 dst=r0 src=r0 offset=119 imm=0
#line 177 "sample/map.c"
    goto label_21;
label_20:
    // EBPF_OP_MOV64_IMM pc=435 dst=r1 src=r0 offset=0 imm=2
#line 177 "sample/map.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=436 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=437 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=438 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=439 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=441 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=442 dst=r0 src=r0 offset=0 imm=16
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=443 dst=r6 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=444 dst=r1 src=r6 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=445 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=446 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=447 dst=r1 src=r0 offset=106 imm=0
#line 177 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_21;
        // EBPF_OP_MOV64_IMM pc=448 dst=r1 src=r0 offset=0 imm=3
#line 177 "sample/map.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=449 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=450 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=451 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=452 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=454 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=455 dst=r0 src=r0 offset=0 imm=16
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=456 dst=r6 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=457 dst=r1 src=r6 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=458 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=459 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=460 dst=r1 src=r0 offset=93 imm=0
#line 177 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_21;
        // EBPF_OP_MOV64_IMM pc=461 dst=r1 src=r0 offset=0 imm=4
#line 177 "sample/map.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=462 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=463 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=464 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=465 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=467 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=468 dst=r0 src=r0 offset=0 imm=16
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=469 dst=r6 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=470 dst=r1 src=r6 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=471 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=472 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=473 dst=r1 src=r0 offset=80 imm=0
#line 177 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_21;
        // EBPF_OP_MOV64_IMM pc=474 dst=r1 src=r0 offset=0 imm=5
#line 177 "sample/map.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=475 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=476 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=477 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=478 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=480 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=481 dst=r0 src=r0 offset=0 imm=16
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=482 dst=r6 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=483 dst=r1 src=r6 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=484 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=485 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=486 dst=r1 src=r0 offset=67 imm=0
#line 177 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_21;
        // EBPF_OP_MOV64_IMM pc=487 dst=r1 src=r0 offset=0 imm=6
#line 177 "sample/map.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=488 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=489 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=490 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=491 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=493 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=494 dst=r0 src=r0 offset=0 imm=16
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=495 dst=r6 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=496 dst=r1 src=r6 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=497 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=498 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=499 dst=r1 src=r0 offset=54 imm=0
#line 177 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_21;
        // EBPF_OP_MOV64_IMM pc=500 dst=r1 src=r0 offset=0 imm=7
#line 177 "sample/map.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=501 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=502 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=503 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=504 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=506 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=507 dst=r0 src=r0 offset=0 imm=16
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=508 dst=r6 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=509 dst=r1 src=r6 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=510 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=511 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=512 dst=r1 src=r0 offset=41 imm=0
#line 177 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_21;
        // EBPF_OP_MOV64_IMM pc=513 dst=r1 src=r0 offset=0 imm=8
#line 177 "sample/map.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=514 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=515 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=516 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=517 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=519 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=520 dst=r0 src=r0 offset=0 imm=16
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=521 dst=r6 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=522 dst=r1 src=r6 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=523 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=524 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=525 dst=r1 src=r0 offset=28 imm=0
#line 177 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_21;
        // EBPF_OP_MOV64_IMM pc=526 dst=r1 src=r0 offset=0 imm=9
#line 177 "sample/map.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=527 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=528 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=529 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=530 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=532 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=533 dst=r0 src=r0 offset=0 imm=16
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=534 dst=r6 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=535 dst=r1 src=r6 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=536 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=537 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=538 dst=r1 src=r0 offset=15 imm=0
#line 177 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_21;
        // EBPF_OP_MOV64_IMM pc=539 dst=r8 src=r0 offset=0 imm=10
#line 177 "sample/map.c"
    r8 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=540 dst=r10 src=r8 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r8;
    // EBPF_OP_MOV64_REG pc=541 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=542 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=543 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=545 dst=r3 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=546 dst=r0 src=r0 offset=0 imm=16
#line 180 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=547 dst=r6 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=548 dst=r1 src=r6 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=549 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=550 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=551 dst=r2 src=r0 offset=0 imm=-29
#line 180 "sample/map.c"
    r2 = (uint64_t)4294967267;
    // EBPF_OP_JEQ_REG pc=553 dst=r1 src=r2 offset=198 imm=0
#line 180 "sample/map.c"
    if (r1 == r2)
#line 180 "sample/map.c"
        goto label_29;
label_21:
    // EBPF_OP_MOV64_REG pc=554 dst=r1 src=r6 offset=0 imm=0
#line 208 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=555 dst=r1 src=r0 offset=0 imm=32
#line 208 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=556 dst=r1 src=r0 offset=0 imm=32
#line 208 "sample/map.c"
    r1 = (int64_t)r1 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=557 dst=r2 src=r0 offset=0 imm=0
#line 208 "sample/map.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=558 dst=r2 src=r1 offset=-513 imm=0
#line 208 "sample/map.c"
    if ((int64_t)r2 > (int64_t)r1)
#line 208 "sample/map.c"
        goto label_1;
label_22:
    // EBPF_OP_MOV64_IMM pc=559 dst=r1 src=r0 offset=0 imm=0
#line 208 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=560 dst=r10 src=r1 offset=-4 imm=0
#line 173 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=561 dst=r2 src=r10 offset=0 imm=0
#line 173 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=562 dst=r2 src=r0 offset=0 imm=-4
#line 173 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=563 dst=r1 src=r0 offset=0 imm=0
#line 173 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=565 dst=r0 src=r0 offset=0 imm=18
#line 173 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 173 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 173 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 173 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=566 dst=r1 src=r0 offset=0 imm=0
#line 173 "sample/map.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=567 dst=r1 src=r0 offset=0 imm=32
#line 173 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=568 dst=r1 src=r0 offset=0 imm=32
#line 173 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=569 dst=r7 src=r0 offset=0 imm=-1
#line 173 "sample/map.c"
    r7 = IMMEDIATE(-1);
    // EBPF_OP_LDDW pc=570 dst=r2 src=r0 offset=0 imm=-7
#line 173 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=572 dst=r1 src=r2 offset=1 imm=0
#line 173 "sample/map.c"
    if (r1 == r2)
#line 173 "sample/map.c"
        goto label_23;
        // EBPF_OP_MOV64_REG pc=573 dst=r7 src=r0 offset=0 imm=0
#line 173 "sample/map.c"
    r7 = r0;
label_23:
    // EBPF_OP_JNE_REG pc=574 dst=r1 src=r2 offset=170 imm=0
#line 173 "sample/map.c"
    if (r1 != r2)
#line 173 "sample/map.c"
        goto label_27;
        // EBPF_OP_LDXW pc=575 dst=r1 src=r10 offset=-4 imm=0
#line 173 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=576 dst=r1 src=r0 offset=168 imm=0
#line 173 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 173 "sample/map.c"
        goto label_27;
        // EBPF_OP_MOV64_IMM pc=577 dst=r1 src=r0 offset=0 imm=0
#line 173 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=578 dst=r10 src=r1 offset=-4 imm=0
#line 174 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=579 dst=r2 src=r10 offset=0 imm=0
#line 174 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=580 dst=r2 src=r0 offset=0 imm=-4
#line 174 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=581 dst=r1 src=r0 offset=0 imm=0
#line 174 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=583 dst=r0 src=r0 offset=0 imm=17
#line 174 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 174 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 174 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 174 "sample/map.c"
        return 0;
        // EBPF_OP_LDXW pc=584 dst=r1 src=r10 offset=-4 imm=0
#line 174 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=585 dst=r6 src=r7 offset=0 imm=0
#line 174 "sample/map.c"
    r6 = r7;
    // EBPF_OP_JEQ_IMM pc=586 dst=r1 src=r0 offset=1 imm=0
#line 174 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 174 "sample/map.c"
        goto label_24;
        // EBPF_OP_MOV64_IMM pc=587 dst=r6 src=r0 offset=0 imm=-1
#line 174 "sample/map.c"
    r6 = IMMEDIATE(-1);
label_24:
    // EBPF_OP_MOV64_REG pc=588 dst=r2 src=r0 offset=0 imm=0
#line 174 "sample/map.c"
    r2 = r0;
    // EBPF_OP_LSH64_IMM pc=589 dst=r2 src=r0 offset=0 imm=32
#line 174 "sample/map.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=590 dst=r2 src=r0 offset=0 imm=32
#line 174 "sample/map.c"
    r2 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=591 dst=r3 src=r0 offset=0 imm=-7
#line 174 "sample/map.c"
    r3 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=593 dst=r2 src=r3 offset=1 imm=0
#line 174 "sample/map.c"
    if (r2 == r3)
#line 174 "sample/map.c"
        goto label_25;
        // EBPF_OP_MOV64_REG pc=594 dst=r6 src=r0 offset=0 imm=0
#line 174 "sample/map.c"
    r6 = r0;
label_25:
    // EBPF_OP_MOV64_REG pc=595 dst=r7 src=r6 offset=0 imm=0
#line 174 "sample/map.c"
    r7 = r6;
    // EBPF_OP_JNE_REG pc=596 dst=r2 src=r3 offset=148 imm=0
#line 174 "sample/map.c"
    if (r2 != r3)
#line 174 "sample/map.c"
        goto label_27;
        // EBPF_OP_MOV64_REG pc=597 dst=r7 src=r6 offset=0 imm=0
#line 174 "sample/map.c"
    r7 = r6;
    // EBPF_OP_JNE_IMM pc=598 dst=r1 src=r0 offset=146 imm=0
#line 174 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 174 "sample/map.c"
        goto label_27;
        // EBPF_OP_MOV64_IMM pc=599 dst=r1 src=r0 offset=0 imm=0
#line 174 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=600 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=601 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=602 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=603 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=605 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=606 dst=r0 src=r0 offset=0 imm=16
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=607 dst=r7 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=608 dst=r1 src=r7 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=609 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=610 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=611 dst=r1 src=r0 offset=133 imm=0
#line 177 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_27;
        // EBPF_OP_MOV64_IMM pc=612 dst=r1 src=r0 offset=0 imm=1
#line 177 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=613 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=614 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=615 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=616 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=618 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=619 dst=r0 src=r0 offset=0 imm=16
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=620 dst=r7 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=621 dst=r1 src=r7 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=622 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=623 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=624 dst=r1 src=r0 offset=1 imm=0
#line 177 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_26;
        // EBPF_OP_JA pc=625 dst=r0 src=r0 offset=119 imm=0
#line 177 "sample/map.c"
    goto label_27;
label_26:
    // EBPF_OP_MOV64_IMM pc=626 dst=r1 src=r0 offset=0 imm=2
#line 177 "sample/map.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=627 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=628 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=629 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=630 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=632 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=633 dst=r0 src=r0 offset=0 imm=16
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=634 dst=r7 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=635 dst=r1 src=r7 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=636 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=637 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=638 dst=r1 src=r0 offset=106 imm=0
#line 177 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_27;
        // EBPF_OP_MOV64_IMM pc=639 dst=r1 src=r0 offset=0 imm=3
#line 177 "sample/map.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=640 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=641 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=642 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=643 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=645 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=646 dst=r0 src=r0 offset=0 imm=16
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=647 dst=r7 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=648 dst=r1 src=r7 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=649 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=650 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=651 dst=r1 src=r0 offset=93 imm=0
#line 177 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_27;
        // EBPF_OP_MOV64_IMM pc=652 dst=r1 src=r0 offset=0 imm=4
#line 177 "sample/map.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=653 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=654 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=655 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=656 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=658 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=659 dst=r0 src=r0 offset=0 imm=16
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=660 dst=r7 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=661 dst=r1 src=r7 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=662 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=663 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=664 dst=r1 src=r0 offset=80 imm=0
#line 177 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_27;
        // EBPF_OP_MOV64_IMM pc=665 dst=r1 src=r0 offset=0 imm=5
#line 177 "sample/map.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=666 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=667 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=668 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=669 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=671 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=672 dst=r0 src=r0 offset=0 imm=16
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=673 dst=r7 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=674 dst=r1 src=r7 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=675 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=676 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=677 dst=r1 src=r0 offset=67 imm=0
#line 177 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_27;
        // EBPF_OP_MOV64_IMM pc=678 dst=r1 src=r0 offset=0 imm=6
#line 177 "sample/map.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=679 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=680 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=681 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=682 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=684 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=685 dst=r0 src=r0 offset=0 imm=16
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=686 dst=r7 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=687 dst=r1 src=r7 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=688 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=689 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=690 dst=r1 src=r0 offset=54 imm=0
#line 177 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_27;
        // EBPF_OP_MOV64_IMM pc=691 dst=r1 src=r0 offset=0 imm=7
#line 177 "sample/map.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=692 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=693 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=694 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=695 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=697 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=698 dst=r0 src=r0 offset=0 imm=16
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=699 dst=r7 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=700 dst=r1 src=r7 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=701 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=702 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=703 dst=r1 src=r0 offset=41 imm=0
#line 177 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_27;
        // EBPF_OP_MOV64_IMM pc=704 dst=r1 src=r0 offset=0 imm=8
#line 177 "sample/map.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=705 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=706 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=707 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=708 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=710 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=711 dst=r0 src=r0 offset=0 imm=16
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=712 dst=r7 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=713 dst=r1 src=r7 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=714 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=715 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=716 dst=r1 src=r0 offset=28 imm=0
#line 177 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_27;
        // EBPF_OP_MOV64_IMM pc=717 dst=r1 src=r0 offset=0 imm=9
#line 177 "sample/map.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=718 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=719 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=720 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=721 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=723 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=724 dst=r0 src=r0 offset=0 imm=16
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=725 dst=r7 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=726 dst=r1 src=r7 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=727 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=728 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=729 dst=r1 src=r0 offset=15 imm=0
#line 177 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_27;
        // EBPF_OP_MOV64_IMM pc=730 dst=r8 src=r0 offset=0 imm=10
#line 177 "sample/map.c"
    r8 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=731 dst=r10 src=r8 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r8;
    // EBPF_OP_MOV64_REG pc=732 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=733 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=734 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=736 dst=r3 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=737 dst=r0 src=r0 offset=0 imm=16
#line 180 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=738 dst=r7 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=739 dst=r1 src=r7 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=740 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=741 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=742 dst=r2 src=r0 offset=0 imm=-29
#line 180 "sample/map.c"
    r2 = (uint64_t)4294967267;
    // EBPF_OP_JEQ_REG pc=744 dst=r1 src=r2 offset=34 imm=0
#line 180 "sample/map.c"
    if (r1 == r2)
#line 180 "sample/map.c"
        goto label_31;
label_27:
    // EBPF_OP_MOV64_IMM pc=745 dst=r6 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_MOV64_REG pc=746 dst=r1 src=r7 offset=0 imm=0
#line 209 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=747 dst=r1 src=r0 offset=0 imm=32
#line 209 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=748 dst=r1 src=r0 offset=0 imm=32
#line 209 "sample/map.c"
    r1 = (int64_t)r1 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=749 dst=r1 src=r0 offset=-704 imm=-1
#line 209 "sample/map.c"
    if ((int64_t)r1 > IMMEDIATE(-1))
#line 209 "sample/map.c"
        goto label_1;
label_28:
    // EBPF_OP_MOV64_REG pc=750 dst=r6 src=r7 offset=0 imm=0
#line 209 "sample/map.c"
    r6 = r7;
    // EBPF_OP_JA pc=751 dst=r0 src=r0 offset=-706 imm=0
#line 209 "sample/map.c"
    goto label_1;
label_29:
    // EBPF_OP_STXW pc=752 dst=r10 src=r8 offset=-4 imm=0
#line 181 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r8;
    // EBPF_OP_MOV64_REG pc=753 dst=r2 src=r10 offset=0 imm=0
#line 181 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=754 dst=r2 src=r0 offset=0 imm=-4
#line 181 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=755 dst=r1 src=r0 offset=0 imm=0
#line 181 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=757 dst=r3 src=r0 offset=0 imm=2
#line 181 "sample/map.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_CALL pc=758 dst=r0 src=r0 offset=0 imm=16
#line 181 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 181 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 181 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 181 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=759 dst=r6 src=r0 offset=0 imm=0
#line 181 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=760 dst=r1 src=r6 offset=0 imm=0
#line 181 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=761 dst=r1 src=r0 offset=0 imm=32
#line 181 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=762 dst=r1 src=r0 offset=0 imm=32
#line 181 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=763 dst=r1 src=r0 offset=1 imm=0
#line 181 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 181 "sample/map.c"
        goto label_30;
        // EBPF_OP_MOV64_REG pc=764 dst=r7 src=r6 offset=0 imm=0
#line 181 "sample/map.c"
    r7 = r6;
label_30:
    // EBPF_OP_JNE_IMM pc=765 dst=r1 src=r0 offset=-212 imm=0
#line 181 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 181 "sample/map.c"
        goto label_21;
        // EBPF_OP_MOV64_IMM pc=766 dst=r1 src=r0 offset=0 imm=0
#line 181 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=767 dst=r10 src=r1 offset=-4 imm=0
#line 183 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=768 dst=r2 src=r10 offset=0 imm=0
#line 183 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=769 dst=r2 src=r0 offset=0 imm=-4
#line 183 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=770 dst=r1 src=r0 offset=0 imm=0
#line 183 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=772 dst=r0 src=r0 offset=0 imm=18
#line 183 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 183 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 183 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 183 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=773 dst=r6 src=r0 offset=0 imm=0
#line 183 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=774 dst=r1 src=r6 offset=0 imm=0
#line 183 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=775 dst=r1 src=r0 offset=0 imm=32
#line 183 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=776 dst=r1 src=r0 offset=0 imm=32
#line 183 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=777 dst=r1 src=r0 offset=28 imm=0
#line 183 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 183 "sample/map.c"
        goto label_33;
        // EBPF_OP_JA pc=778 dst=r0 src=r0 offset=-225 imm=0
#line 183 "sample/map.c"
    goto label_21;
label_31:
    // EBPF_OP_STXW pc=779 dst=r10 src=r8 offset=-4 imm=0
#line 181 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r8;
    // EBPF_OP_MOV64_REG pc=780 dst=r2 src=r10 offset=0 imm=0
#line 181 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=781 dst=r2 src=r0 offset=0 imm=-4
#line 181 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=782 dst=r1 src=r0 offset=0 imm=0
#line 181 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=784 dst=r3 src=r0 offset=0 imm=2
#line 181 "sample/map.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_CALL pc=785 dst=r0 src=r0 offset=0 imm=16
#line 181 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 181 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 181 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 181 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=786 dst=r7 src=r0 offset=0 imm=0
#line 181 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=787 dst=r1 src=r7 offset=0 imm=0
#line 181 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=788 dst=r1 src=r0 offset=0 imm=32
#line 181 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=789 dst=r1 src=r0 offset=0 imm=32
#line 181 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=790 dst=r1 src=r0 offset=1 imm=0
#line 181 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 181 "sample/map.c"
        goto label_32;
        // EBPF_OP_MOV64_REG pc=791 dst=r6 src=r7 offset=0 imm=0
#line 181 "sample/map.c"
    r6 = r7;
label_32:
    // EBPF_OP_JNE_IMM pc=792 dst=r1 src=r0 offset=-48 imm=0
#line 181 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 181 "sample/map.c"
        goto label_27;
        // EBPF_OP_MOV64_IMM pc=793 dst=r1 src=r0 offset=0 imm=0
#line 181 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=794 dst=r10 src=r1 offset=-4 imm=0
#line 183 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=795 dst=r2 src=r10 offset=0 imm=0
#line 183 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=796 dst=r2 src=r0 offset=0 imm=-4
#line 183 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=797 dst=r1 src=r0 offset=0 imm=0
#line 183 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=799 dst=r0 src=r0 offset=0 imm=18
#line 183 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 183 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 183 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 183 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=800 dst=r7 src=r0 offset=0 imm=0
#line 183 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=801 dst=r1 src=r7 offset=0 imm=0
#line 183 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=802 dst=r1 src=r0 offset=0 imm=32
#line 183 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=803 dst=r1 src=r0 offset=0 imm=32
#line 183 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=804 dst=r1 src=r0 offset=36 imm=0
#line 183 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 183 "sample/map.c"
        goto label_37;
        // EBPF_OP_JA pc=805 dst=r0 src=r0 offset=-61 imm=0
#line 183 "sample/map.c"
    goto label_27;
label_33:
    // EBPF_OP_LDXW pc=806 dst=r1 src=r10 offset=-4 imm=0
#line 183 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=807 dst=r6 src=r0 offset=0 imm=-1
#line 183 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=809 dst=r1 src=r0 offset=-764 imm=1
#line 183 "sample/map.c"
    if (r1 != IMMEDIATE(1))
#line 183 "sample/map.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=810 dst=r1 src=r0 offset=0 imm=0
#line 183 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=811 dst=r10 src=r1 offset=-4 imm=0
#line 186 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=812 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=813 dst=r2 src=r0 offset=0 imm=-4
#line 186 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=814 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=816 dst=r0 src=r0 offset=0 imm=17
#line 186 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=817 dst=r6 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=818 dst=r1 src=r6 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=819 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=820 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=821 dst=r1 src=r0 offset=1 imm=0
#line 186 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 186 "sample/map.c"
        goto label_34;
        // EBPF_OP_JA pc=822 dst=r0 src=r0 offset=17 imm=0
#line 186 "sample/map.c"
    goto label_36;
label_34:
    // EBPF_OP_LDXW pc=823 dst=r1 src=r10 offset=-4 imm=0
#line 186 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=824 dst=r6 src=r0 offset=0 imm=-1
#line 186 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=826 dst=r1 src=r0 offset=1 imm=1
#line 186 "sample/map.c"
    if (r1 == IMMEDIATE(1))
#line 186 "sample/map.c"
        goto label_35;
        // EBPF_OP_JA pc=827 dst=r0 src=r0 offset=-782 imm=0
#line 186 "sample/map.c"
    goto label_1;
label_35:
    // EBPF_OP_MOV64_IMM pc=828 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=829 dst=r10 src=r1 offset=-4 imm=0
#line 186 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=830 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=831 dst=r2 src=r0 offset=0 imm=-4
#line 186 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=832 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=834 dst=r0 src=r0 offset=0 imm=17
#line 186 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=835 dst=r6 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=836 dst=r1 src=r6 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=837 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=838 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=839 dst=r1 src=r0 offset=36 imm=0
#line 186 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 186 "sample/map.c"
        goto label_41;
label_36:
    // EBPF_OP_JA pc=840 dst=r0 src=r0 offset=-287 imm=0
#line 186 "sample/map.c"
    goto label_21;
label_37:
    // EBPF_OP_LDXW pc=841 dst=r1 src=r10 offset=-4 imm=0
#line 183 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=842 dst=r7 src=r0 offset=0 imm=-1
#line 183 "sample/map.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=844 dst=r1 src=r0 offset=-95 imm=10
#line 183 "sample/map.c"
    if (r1 != IMMEDIATE(10))
#line 183 "sample/map.c"
        goto label_28;
        // EBPF_OP_MOV64_IMM pc=845 dst=r1 src=r0 offset=0 imm=0
#line 183 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=846 dst=r10 src=r1 offset=-4 imm=0
#line 186 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=847 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=848 dst=r2 src=r0 offset=0 imm=-4
#line 186 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=849 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=851 dst=r0 src=r0 offset=0 imm=17
#line 186 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=852 dst=r7 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=853 dst=r1 src=r7 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=854 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=855 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=856 dst=r1 src=r0 offset=1 imm=0
#line 186 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 186 "sample/map.c"
        goto label_38;
        // EBPF_OP_JA pc=857 dst=r0 src=r0 offset=17 imm=0
#line 186 "sample/map.c"
    goto label_40;
label_38:
    // EBPF_OP_LDXW pc=858 dst=r1 src=r10 offset=-4 imm=0
#line 186 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=859 dst=r7 src=r0 offset=0 imm=-1
#line 186 "sample/map.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=861 dst=r1 src=r0 offset=1 imm=10
#line 186 "sample/map.c"
    if (r1 == IMMEDIATE(10))
#line 186 "sample/map.c"
        goto label_39;
        // EBPF_OP_JA pc=862 dst=r0 src=r0 offset=-113 imm=0
#line 186 "sample/map.c"
    goto label_28;
label_39:
    // EBPF_OP_MOV64_IMM pc=863 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=864 dst=r10 src=r1 offset=-4 imm=0
#line 186 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=865 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=866 dst=r2 src=r0 offset=0 imm=-4
#line 186 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=867 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=869 dst=r0 src=r0 offset=0 imm=17
#line 186 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=870 dst=r7 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=871 dst=r1 src=r7 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=872 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=873 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=874 dst=r1 src=r0 offset=174 imm=0
#line 186 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 186 "sample/map.c"
        goto label_47;
label_40:
    // EBPF_OP_JA pc=875 dst=r0 src=r0 offset=-131 imm=0
#line 186 "sample/map.c"
    goto label_27;
label_41:
    // EBPF_OP_LDXW pc=876 dst=r1 src=r10 offset=-4 imm=0
#line 186 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=877 dst=r6 src=r0 offset=0 imm=-1
#line 186 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=879 dst=r1 src=r0 offset=-834 imm=2
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(2))
#line 186 "sample/map.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=880 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=881 dst=r10 src=r1 offset=-4 imm=0
#line 186 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=882 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=883 dst=r2 src=r0 offset=0 imm=-4
#line 186 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=884 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=886 dst=r0 src=r0 offset=0 imm=17
#line 186 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=887 dst=r6 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=888 dst=r1 src=r6 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=889 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=890 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=891 dst=r1 src=r0 offset=-52 imm=0
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 186 "sample/map.c"
        goto label_36;
        // EBPF_OP_LDXW pc=892 dst=r1 src=r10 offset=-4 imm=0
#line 186 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=893 dst=r6 src=r0 offset=0 imm=-1
#line 186 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=895 dst=r1 src=r0 offset=-850 imm=3
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(3))
#line 186 "sample/map.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=896 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=897 dst=r10 src=r1 offset=-4 imm=0
#line 186 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=898 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=899 dst=r2 src=r0 offset=0 imm=-4
#line 186 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=900 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=902 dst=r0 src=r0 offset=0 imm=17
#line 186 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=903 dst=r6 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=904 dst=r1 src=r6 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=905 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=906 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=907 dst=r1 src=r0 offset=-68 imm=0
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 186 "sample/map.c"
        goto label_36;
        // EBPF_OP_LDXW pc=908 dst=r1 src=r10 offset=-4 imm=0
#line 186 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=909 dst=r6 src=r0 offset=0 imm=-1
#line 186 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=911 dst=r1 src=r0 offset=-866 imm=4
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(4))
#line 186 "sample/map.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=912 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=913 dst=r10 src=r1 offset=-4 imm=0
#line 186 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=914 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=915 dst=r2 src=r0 offset=0 imm=-4
#line 186 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=916 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=918 dst=r0 src=r0 offset=0 imm=17
#line 186 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=919 dst=r6 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=920 dst=r1 src=r6 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=921 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=922 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=923 dst=r1 src=r0 offset=-84 imm=0
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 186 "sample/map.c"
        goto label_36;
        // EBPF_OP_LDXW pc=924 dst=r1 src=r10 offset=-4 imm=0
#line 186 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=925 dst=r6 src=r0 offset=0 imm=-1
#line 186 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=927 dst=r1 src=r0 offset=-882 imm=5
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(5))
#line 186 "sample/map.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=928 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=929 dst=r10 src=r1 offset=-4 imm=0
#line 186 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=930 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=931 dst=r2 src=r0 offset=0 imm=-4
#line 186 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=932 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=934 dst=r0 src=r0 offset=0 imm=17
#line 186 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=935 dst=r6 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=936 dst=r1 src=r6 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=937 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=938 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=939 dst=r1 src=r0 offset=-100 imm=0
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 186 "sample/map.c"
        goto label_36;
        // EBPF_OP_LDXW pc=940 dst=r1 src=r10 offset=-4 imm=0
#line 186 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=941 dst=r6 src=r0 offset=0 imm=-1
#line 186 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=943 dst=r1 src=r0 offset=-898 imm=6
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(6))
#line 186 "sample/map.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=944 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=945 dst=r10 src=r1 offset=-4 imm=0
#line 186 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=946 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=947 dst=r2 src=r0 offset=0 imm=-4
#line 186 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=948 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=950 dst=r0 src=r0 offset=0 imm=17
#line 186 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=951 dst=r6 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=952 dst=r1 src=r6 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=953 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=954 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=955 dst=r1 src=r0 offset=-116 imm=0
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 186 "sample/map.c"
        goto label_36;
        // EBPF_OP_LDXW pc=956 dst=r1 src=r10 offset=-4 imm=0
#line 186 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=957 dst=r6 src=r0 offset=0 imm=-1
#line 186 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=959 dst=r1 src=r0 offset=-914 imm=7
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(7))
#line 186 "sample/map.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=960 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=961 dst=r10 src=r1 offset=-4 imm=0
#line 186 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=962 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=963 dst=r2 src=r0 offset=0 imm=-4
#line 186 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=964 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=966 dst=r0 src=r0 offset=0 imm=17
#line 186 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=967 dst=r6 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=968 dst=r1 src=r6 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=969 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=970 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=971 dst=r1 src=r0 offset=-132 imm=0
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 186 "sample/map.c"
        goto label_36;
        // EBPF_OP_LDXW pc=972 dst=r1 src=r10 offset=-4 imm=0
#line 186 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=973 dst=r6 src=r0 offset=0 imm=-1
#line 186 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=975 dst=r1 src=r0 offset=-930 imm=8
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(8))
#line 186 "sample/map.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=976 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=977 dst=r10 src=r1 offset=-4 imm=0
#line 186 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=978 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=979 dst=r2 src=r0 offset=0 imm=-4
#line 186 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=980 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=982 dst=r0 src=r0 offset=0 imm=17
#line 186 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=983 dst=r6 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=984 dst=r1 src=r6 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=985 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=986 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=987 dst=r1 src=r0 offset=-148 imm=0
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 186 "sample/map.c"
        goto label_36;
        // EBPF_OP_LDXW pc=988 dst=r1 src=r10 offset=-4 imm=0
#line 186 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=989 dst=r6 src=r0 offset=0 imm=-1
#line 186 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=991 dst=r1 src=r0 offset=-946 imm=9
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(9))
#line 186 "sample/map.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=992 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=993 dst=r10 src=r1 offset=-4 imm=0
#line 186 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=994 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=995 dst=r2 src=r0 offset=0 imm=-4
#line 186 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=996 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=998 dst=r0 src=r0 offset=0 imm=17
#line 186 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=999 dst=r6 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1000 dst=r1 src=r6 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1001 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1002 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1003 dst=r1 src=r0 offset=-164 imm=0
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 186 "sample/map.c"
        goto label_36;
        // EBPF_OP_LDXW pc=1004 dst=r1 src=r10 offset=-4 imm=0
#line 186 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=1005 dst=r6 src=r0 offset=0 imm=-1
#line 186 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=1007 dst=r1 src=r0 offset=-962 imm=10
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(10))
#line 186 "sample/map.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=1008 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1009 dst=r10 src=r1 offset=-4 imm=0
#line 189 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1010 dst=r2 src=r10 offset=0 imm=0
#line 189 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1011 dst=r2 src=r0 offset=0 imm=-4
#line 189 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1012 dst=r1 src=r0 offset=0 imm=0
#line 189 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1014 dst=r0 src=r0 offset=0 imm=18
#line 189 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 189 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 189 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 189 "sample/map.c"
        return 0;
        // EBPF_OP_LDXW pc=1015 dst=r1 src=r10 offset=-4 imm=0
#line 189 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=1016 dst=r6 src=r7 offset=0 imm=0
#line 189 "sample/map.c"
    r6 = r7;
    // EBPF_OP_JEQ_IMM pc=1017 dst=r1 src=r0 offset=1 imm=0
#line 189 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 189 "sample/map.c"
        goto label_42;
        // EBPF_OP_MOV64_IMM pc=1018 dst=r6 src=r0 offset=0 imm=-1
#line 189 "sample/map.c"
    r6 = IMMEDIATE(-1);
label_42:
    // EBPF_OP_MOV64_REG pc=1019 dst=r2 src=r0 offset=0 imm=0
#line 189 "sample/map.c"
    r2 = r0;
    // EBPF_OP_LSH64_IMM pc=1020 dst=r2 src=r0 offset=0 imm=32
#line 189 "sample/map.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1021 dst=r2 src=r0 offset=0 imm=32
#line 189 "sample/map.c"
    r2 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1022 dst=r3 src=r0 offset=0 imm=-7
#line 189 "sample/map.c"
    r3 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1024 dst=r2 src=r3 offset=1 imm=0
#line 189 "sample/map.c"
    if (r2 == r3)
#line 189 "sample/map.c"
        goto label_43;
        // EBPF_OP_MOV64_REG pc=1025 dst=r6 src=r0 offset=0 imm=0
#line 189 "sample/map.c"
    r6 = r0;
label_43:
    // EBPF_OP_JNE_REG pc=1026 dst=r2 src=r3 offset=-473 imm=0
#line 189 "sample/map.c"
    if (r2 != r3)
#line 189 "sample/map.c"
        goto label_21;
        // EBPF_OP_JEQ_IMM pc=1027 dst=r1 src=r0 offset=1 imm=0
#line 189 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 189 "sample/map.c"
        goto label_44;
        // EBPF_OP_JA pc=1028 dst=r0 src=r0 offset=-475 imm=0
#line 189 "sample/map.c"
    goto label_21;
label_44:
    // EBPF_OP_MOV64_IMM pc=1029 dst=r1 src=r0 offset=0 imm=0
#line 189 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1030 dst=r10 src=r1 offset=-4 imm=0
#line 190 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1031 dst=r2 src=r10 offset=0 imm=0
#line 190 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1032 dst=r2 src=r0 offset=0 imm=-4
#line 190 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1033 dst=r1 src=r0 offset=0 imm=0
#line 190 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1035 dst=r0 src=r0 offset=0 imm=17
#line 190 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 190 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 190 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 190 "sample/map.c"
        return 0;
        // EBPF_OP_LDXW pc=1036 dst=r1 src=r10 offset=-4 imm=0
#line 190 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1037 dst=r1 src=r0 offset=1 imm=0
#line 190 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 190 "sample/map.c"
        goto label_45;
        // EBPF_OP_MOV64_IMM pc=1038 dst=r6 src=r0 offset=0 imm=-1
#line 190 "sample/map.c"
    r6 = IMMEDIATE(-1);
label_45:
    // EBPF_OP_MOV64_REG pc=1039 dst=r2 src=r0 offset=0 imm=0
#line 190 "sample/map.c"
    r2 = r0;
    // EBPF_OP_LSH64_IMM pc=1040 dst=r2 src=r0 offset=0 imm=32
#line 190 "sample/map.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1041 dst=r2 src=r0 offset=0 imm=32
#line 190 "sample/map.c"
    r2 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1042 dst=r3 src=r0 offset=0 imm=-7
#line 190 "sample/map.c"
    r3 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1044 dst=r2 src=r3 offset=1 imm=0
#line 190 "sample/map.c"
    if (r2 == r3)
#line 190 "sample/map.c"
        goto label_46;
        // EBPF_OP_MOV64_REG pc=1045 dst=r6 src=r0 offset=0 imm=0
#line 190 "sample/map.c"
    r6 = r0;
label_46:
    // EBPF_OP_JNE_REG pc=1046 dst=r2 src=r3 offset=-493 imm=0
#line 190 "sample/map.c"
    if (r2 != r3)
#line 190 "sample/map.c"
        goto label_21;
        // EBPF_OP_JEQ_IMM pc=1047 dst=r1 src=r0 offset=-489 imm=0
#line 190 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 190 "sample/map.c"
        goto label_22;
        // EBPF_OP_JA pc=1048 dst=r0 src=r0 offset=-495 imm=0
#line 190 "sample/map.c"
    goto label_21;
label_47:
    // EBPF_OP_LDXW pc=1049 dst=r1 src=r10 offset=-4 imm=0
#line 186 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=1050 dst=r7 src=r0 offset=0 imm=-1
#line 186 "sample/map.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=1052 dst=r1 src=r0 offset=-303 imm=9
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(9))
#line 186 "sample/map.c"
        goto label_28;
        // EBPF_OP_MOV64_IMM pc=1053 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1054 dst=r10 src=r1 offset=-4 imm=0
#line 186 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1055 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1056 dst=r2 src=r0 offset=0 imm=-4
#line 186 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1057 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1059 dst=r0 src=r0 offset=0 imm=17
#line 186 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1060 dst=r7 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1061 dst=r1 src=r7 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1062 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1063 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1064 dst=r1 src=r0 offset=-190 imm=0
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 186 "sample/map.c"
        goto label_40;
        // EBPF_OP_LDXW pc=1065 dst=r1 src=r10 offset=-4 imm=0
#line 186 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=1066 dst=r7 src=r0 offset=0 imm=-1
#line 186 "sample/map.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=1068 dst=r1 src=r0 offset=-319 imm=8
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(8))
#line 186 "sample/map.c"
        goto label_28;
        // EBPF_OP_MOV64_IMM pc=1069 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1070 dst=r10 src=r1 offset=-4 imm=0
#line 186 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1071 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1072 dst=r2 src=r0 offset=0 imm=-4
#line 186 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1073 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1075 dst=r0 src=r0 offset=0 imm=17
#line 186 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1076 dst=r7 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1077 dst=r1 src=r7 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1078 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1079 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1080 dst=r1 src=r0 offset=-206 imm=0
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 186 "sample/map.c"
        goto label_40;
        // EBPF_OP_LDXW pc=1081 dst=r1 src=r10 offset=-4 imm=0
#line 186 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=1082 dst=r7 src=r0 offset=0 imm=-1
#line 186 "sample/map.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=1084 dst=r1 src=r0 offset=-335 imm=7
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(7))
#line 186 "sample/map.c"
        goto label_28;
        // EBPF_OP_MOV64_IMM pc=1085 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1086 dst=r10 src=r1 offset=-4 imm=0
#line 186 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1087 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1088 dst=r2 src=r0 offset=0 imm=-4
#line 186 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1089 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1091 dst=r0 src=r0 offset=0 imm=17
#line 186 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1092 dst=r7 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1093 dst=r1 src=r7 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1094 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1095 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1096 dst=r1 src=r0 offset=-222 imm=0
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 186 "sample/map.c"
        goto label_40;
        // EBPF_OP_LDXW pc=1097 dst=r1 src=r10 offset=-4 imm=0
#line 186 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=1098 dst=r7 src=r0 offset=0 imm=-1
#line 186 "sample/map.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=1100 dst=r1 src=r0 offset=-351 imm=6
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(6))
#line 186 "sample/map.c"
        goto label_28;
        // EBPF_OP_MOV64_IMM pc=1101 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1102 dst=r10 src=r1 offset=-4 imm=0
#line 186 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1103 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1104 dst=r2 src=r0 offset=0 imm=-4
#line 186 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1105 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1107 dst=r0 src=r0 offset=0 imm=17
#line 186 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1108 dst=r7 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1109 dst=r1 src=r7 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1110 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1111 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1112 dst=r1 src=r0 offset=-238 imm=0
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 186 "sample/map.c"
        goto label_40;
        // EBPF_OP_LDXW pc=1113 dst=r1 src=r10 offset=-4 imm=0
#line 186 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=1114 dst=r7 src=r0 offset=0 imm=-1
#line 186 "sample/map.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=1116 dst=r1 src=r0 offset=-367 imm=5
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(5))
#line 186 "sample/map.c"
        goto label_28;
        // EBPF_OP_MOV64_IMM pc=1117 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1118 dst=r10 src=r1 offset=-4 imm=0
#line 186 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1119 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1120 dst=r2 src=r0 offset=0 imm=-4
#line 186 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1121 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1123 dst=r0 src=r0 offset=0 imm=17
#line 186 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1124 dst=r7 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1125 dst=r1 src=r7 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1126 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1127 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1128 dst=r1 src=r0 offset=-254 imm=0
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 186 "sample/map.c"
        goto label_40;
        // EBPF_OP_LDXW pc=1129 dst=r1 src=r10 offset=-4 imm=0
#line 186 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=1130 dst=r7 src=r0 offset=0 imm=-1
#line 186 "sample/map.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=1132 dst=r1 src=r0 offset=-383 imm=4
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(4))
#line 186 "sample/map.c"
        goto label_28;
        // EBPF_OP_MOV64_IMM pc=1133 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1134 dst=r10 src=r1 offset=-4 imm=0
#line 186 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1135 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1136 dst=r2 src=r0 offset=0 imm=-4
#line 186 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1137 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1139 dst=r0 src=r0 offset=0 imm=17
#line 186 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1140 dst=r7 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1141 dst=r1 src=r7 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1142 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1143 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1144 dst=r1 src=r0 offset=-270 imm=0
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 186 "sample/map.c"
        goto label_40;
        // EBPF_OP_LDXW pc=1145 dst=r1 src=r10 offset=-4 imm=0
#line 186 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=1146 dst=r7 src=r0 offset=0 imm=-1
#line 186 "sample/map.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=1148 dst=r1 src=r0 offset=-399 imm=3
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(3))
#line 186 "sample/map.c"
        goto label_28;
        // EBPF_OP_MOV64_IMM pc=1149 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1150 dst=r10 src=r1 offset=-4 imm=0
#line 186 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1151 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1152 dst=r2 src=r0 offset=0 imm=-4
#line 186 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1153 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1155 dst=r0 src=r0 offset=0 imm=17
#line 186 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1156 dst=r7 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1157 dst=r1 src=r7 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1158 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1159 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1160 dst=r1 src=r0 offset=-286 imm=0
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 186 "sample/map.c"
        goto label_40;
        // EBPF_OP_LDXW pc=1161 dst=r1 src=r10 offset=-4 imm=0
#line 186 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=1162 dst=r7 src=r0 offset=0 imm=-1
#line 186 "sample/map.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=1164 dst=r1 src=r0 offset=-415 imm=2
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(2))
#line 186 "sample/map.c"
        goto label_28;
        // EBPF_OP_MOV64_IMM pc=1165 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1166 dst=r10 src=r1 offset=-4 imm=0
#line 186 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1167 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1168 dst=r2 src=r0 offset=0 imm=-4
#line 186 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1169 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1171 dst=r0 src=r0 offset=0 imm=17
#line 186 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 186 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 186 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1172 dst=r7 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1173 dst=r1 src=r7 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1174 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1175 dst=r1 src=r0 offset=0 imm=32
#line 186 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1176 dst=r1 src=r0 offset=-302 imm=0
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 186 "sample/map.c"
        goto label_40;
        // EBPF_OP_LDXW pc=1177 dst=r1 src=r10 offset=-4 imm=0
#line 186 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=1178 dst=r7 src=r0 offset=0 imm=-1
#line 186 "sample/map.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=1180 dst=r1 src=r0 offset=-431 imm=1
#line 186 "sample/map.c"
    if (r1 != IMMEDIATE(1))
#line 186 "sample/map.c"
        goto label_28;
        // EBPF_OP_MOV64_IMM pc=1181 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1182 dst=r10 src=r1 offset=-4 imm=0
#line 189 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1183 dst=r2 src=r10 offset=0 imm=0
#line 189 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1184 dst=r2 src=r0 offset=0 imm=-4
#line 189 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1185 dst=r1 src=r0 offset=0 imm=0
#line 189 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1187 dst=r0 src=r0 offset=0 imm=18
#line 189 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 189 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 189 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 189 "sample/map.c"
        return 0;
        // EBPF_OP_LDXW pc=1188 dst=r1 src=r10 offset=-4 imm=0
#line 189 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=1189 dst=r7 src=r6 offset=0 imm=0
#line 189 "sample/map.c"
    r7 = r6;
    // EBPF_OP_JEQ_IMM pc=1190 dst=r1 src=r0 offset=1 imm=0
#line 189 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 189 "sample/map.c"
        goto label_48;
        // EBPF_OP_MOV64_IMM pc=1191 dst=r7 src=r0 offset=0 imm=-1
#line 189 "sample/map.c"
    r7 = IMMEDIATE(-1);
label_48:
    // EBPF_OP_MOV64_REG pc=1192 dst=r2 src=r0 offset=0 imm=0
#line 189 "sample/map.c"
    r2 = r0;
    // EBPF_OP_LSH64_IMM pc=1193 dst=r2 src=r0 offset=0 imm=32
#line 189 "sample/map.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1194 dst=r2 src=r0 offset=0 imm=32
#line 189 "sample/map.c"
    r2 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1195 dst=r3 src=r0 offset=0 imm=-7
#line 189 "sample/map.c"
    r3 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1197 dst=r2 src=r3 offset=1 imm=0
#line 189 "sample/map.c"
    if (r2 == r3)
#line 189 "sample/map.c"
        goto label_49;
        // EBPF_OP_MOV64_REG pc=1198 dst=r7 src=r0 offset=0 imm=0
#line 189 "sample/map.c"
    r7 = r0;
label_49:
    // EBPF_OP_JNE_REG pc=1199 dst=r2 src=r3 offset=-455 imm=0
#line 189 "sample/map.c"
    if (r2 != r3)
#line 189 "sample/map.c"
        goto label_27;
        // EBPF_OP_JEQ_IMM pc=1200 dst=r1 src=r0 offset=1 imm=0
#line 189 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 189 "sample/map.c"
        goto label_50;
        // EBPF_OP_JA pc=1201 dst=r0 src=r0 offset=-457 imm=0
#line 189 "sample/map.c"
    goto label_27;
label_50:
    // EBPF_OP_MOV64_IMM pc=1202 dst=r6 src=r0 offset=0 imm=0
#line 189 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1203 dst=r10 src=r6 offset=-4 imm=0
#line 190 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=1204 dst=r2 src=r10 offset=0 imm=0
#line 190 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1205 dst=r2 src=r0 offset=0 imm=-4
#line 190 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1206 dst=r1 src=r0 offset=0 imm=0
#line 190 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1208 dst=r0 src=r0 offset=0 imm=17
#line 190 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 190 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 190 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 190 "sample/map.c"
        return 0;
        // EBPF_OP_LDXW pc=1209 dst=r1 src=r10 offset=-4 imm=0
#line 190 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1210 dst=r1 src=r0 offset=1 imm=0
#line 190 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 190 "sample/map.c"
        goto label_51;
        // EBPF_OP_MOV64_IMM pc=1211 dst=r7 src=r0 offset=0 imm=-1
#line 190 "sample/map.c"
    r7 = IMMEDIATE(-1);
label_51:
    // EBPF_OP_MOV64_REG pc=1212 dst=r2 src=r0 offset=0 imm=0
#line 190 "sample/map.c"
    r2 = r0;
    // EBPF_OP_LSH64_IMM pc=1213 dst=r2 src=r0 offset=0 imm=32
#line 190 "sample/map.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1214 dst=r2 src=r0 offset=0 imm=32
#line 190 "sample/map.c"
    r2 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1215 dst=r3 src=r0 offset=0 imm=-7
#line 190 "sample/map.c"
    r3 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1217 dst=r2 src=r3 offset=1 imm=0
#line 190 "sample/map.c"
    if (r2 == r3)
#line 190 "sample/map.c"
        goto label_52;
        // EBPF_OP_MOV64_REG pc=1218 dst=r7 src=r0 offset=0 imm=0
#line 190 "sample/map.c"
    r7 = r0;
label_52:
    // EBPF_OP_JNE_REG pc=1219 dst=r2 src=r3 offset=-475 imm=0
#line 190 "sample/map.c"
    if (r2 != r3)
#line 190 "sample/map.c"
        goto label_27;
        // EBPF_OP_JEQ_IMM pc=1220 dst=r1 src=r0 offset=-1175 imm=0
#line 190 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 190 "sample/map.c"
        goto label_1;
        // EBPF_OP_JA pc=1221 dst=r0 src=r0 offset=-477 imm=0
#line 190 "sample/map.c"
    goto label_27;
#line 190 "sample/map.c"
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
        7,
        1222,
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
    version->minor = 5;
    version->revision = 0;
}

metadata_table_t map_metadata_table = {_get_programs, _get_maps, _get_hash, _get_version};
