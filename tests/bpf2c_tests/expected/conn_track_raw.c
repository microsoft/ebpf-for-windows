// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from conn_track.o

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
         BPF_MAP_TYPE_LRU_HASH, // Type of map.
         44,                    // Size in bytes of a map key.
         8,                     // Size in bytes of a map value.
         1024,                  // Maximum number of entries allowed in the map.
         0,                     // Inner map index.
         PIN_NONE,              // Pinning type for the map.
         0,                     // Identifier for a map template.
         0,                     // The id of the inner map template.
     },
     "connection_map"},
    {NULL,
     {
         BPF_MAP_TYPE_RINGBUF, // Type of map.
         0,                    // Size in bytes of a map key.
         0,                    // Size in bytes of a map value.
         262144,               // Maximum number of entries allowed in the map.
         0,                    // Inner map index.
         PIN_NONE,             // Pinning type for the map.
         0,                    // Identifier for a map template.
         0,                    // The id of the inner map template.
     },
     "history_map"},
};

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 2;
}

static helper_function_entry_t connection_tracker_helpers[] = {
    {NULL, 7, "helper_id_7"},
    {NULL, 13, "helper_id_13"},
    {NULL, 4, "helper_id_4"},
    {NULL, 14, "helper_id_14"},
    {NULL, 2, "helper_id_2"},
    {NULL, 11, "helper_id_11"},
};

static GUID connection_tracker_program_type_guid = {
    0x43fb224d, 0x68f8, 0x46d6, {0xaa, 0x3f, 0xc8, 0x56, 0x51, 0x8c, 0xbb, 0x32}};
static GUID connection_tracker_attach_type_guid = {
    0x837d02cd, 0x3251, 0x4632, {0x8d, 0x94, 0x60, 0xd3, 0xb4, 0x57, 0x69, 0xf2}};
static uint16_t connection_tracker_maps[] = {
    0,
    1,
};

static uint64_t
connection_tracker(void* context)
{
#line 91 "sample/conn_track.c"
    // Prologue
#line 91 "sample/conn_track.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 91 "sample/conn_track.c"
    register uint64_t r0 = 0;
#line 91 "sample/conn_track.c"
    register uint64_t r1 = 0;
#line 91 "sample/conn_track.c"
    register uint64_t r2 = 0;
#line 91 "sample/conn_track.c"
    register uint64_t r3 = 0;
#line 91 "sample/conn_track.c"
    register uint64_t r4 = 0;
#line 91 "sample/conn_track.c"
    register uint64_t r5 = 0;
#line 91 "sample/conn_track.c"
    register uint64_t r6 = 0;
#line 91 "sample/conn_track.c"
    register uint64_t r7 = 0;
#line 91 "sample/conn_track.c"
    register uint64_t r8 = 0;
#line 91 "sample/conn_track.c"
    register uint64_t r10 = 0;

#line 91 "sample/conn_track.c"
    r1 = (uintptr_t)context;
#line 91 "sample/conn_track.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r7 src=r0 offset=0 imm=1
#line 91 "sample/conn_track.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=1 dst=r2 src=r1 offset=0 imm=0
#line 95 "sample/conn_track.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_MOV64_IMM pc=2 dst=r3 src=r0 offset=0 imm=2
#line 95 "sample/conn_track.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_MOV64_IMM pc=3 dst=r6 src=r0 offset=0 imm=1
#line 95 "sample/conn_track.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_JGT_REG pc=4 dst=r3 src=r2 offset=2 imm=0
#line 95 "sample/conn_track.c"
    if (r3 > r2)
#line 95 "sample/conn_track.c"
        goto label_1;
        // EBPF_OP_JNE_IMM pc=5 dst=r2 src=r0 offset=239 imm=2
#line 95 "sample/conn_track.c"
    if (r2 != IMMEDIATE(2))
#line 95 "sample/conn_track.c"
        goto label_10;
        // EBPF_OP_MOV64_IMM pc=6 dst=r6 src=r0 offset=0 imm=0
#line 95 "sample/conn_track.c"
    r6 = IMMEDIATE(0);
label_1:
    // EBPF_OP_LDXW pc=7 dst=r8 src=r1 offset=4 imm=0
#line 109 "sample/conn_track.c"
    r8 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(4));
    // EBPF_OP_MOV64_IMM pc=8 dst=r2 src=r0 offset=0 imm=0
#line 109 "sample/conn_track.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=9 dst=r10 src=r2 offset=-8 imm=0
#line 72 "sample/conn_track.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r2;
    // EBPF_OP_STXDW pc=10 dst=r10 src=r2 offset=-16 imm=0
#line 72 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=11 dst=r10 src=r2 offset=-24 imm=0
#line 72 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=12 dst=r10 src=r2 offset=-32 imm=0
#line 72 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r2 offset=-40 imm=0
#line 72 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r2 offset=-48 imm=0
#line 72 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r2;
    // EBPF_OP_JEQ_IMM pc=15 dst=r8 src=r0 offset=1 imm=2
#line 109 "sample/conn_track.c"
    if (r8 == IMMEDIATE(2))
#line 109 "sample/conn_track.c"
        goto label_2;
        // EBPF_OP_MOV64_IMM pc=16 dst=r7 src=r0 offset=0 imm=0
#line 109 "sample/conn_track.c"
    r7 = IMMEDIATE(0);
label_2:
    // EBPF_OP_JNE_IMM pc=17 dst=r8 src=r0 offset=6 imm=2
#line 51 "sample/conn_track.c"
    if (r8 != IMMEDIATE(2))
#line 51 "sample/conn_track.c"
        goto label_3;
        // EBPF_OP_LDXW pc=18 dst=r2 src=r1 offset=8 imm=0
#line 52 "sample/conn_track.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(8));
    // EBPF_OP_STXW pc=19 dst=r10 src=r2 offset=-48 imm=0
#line 52 "sample/conn_track.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=20 dst=r4 src=r1 offset=24 imm=0
#line 53 "sample/conn_track.c"
    r4 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_LDXW pc=21 dst=r2 src=r1 offset=28 imm=0
#line 54 "sample/conn_track.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(28));
    // EBPF_OP_STXW pc=22 dst=r10 src=r2 offset=-28 imm=0
#line 54 "sample/conn_track.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint32_t)r2;
    // EBPF_OP_JA pc=23 dst=r0 src=r0 offset=91 imm=0
#line 54 "sample/conn_track.c"
    goto label_4;
label_3:
    // EBPF_OP_LDXB pc=24 dst=r3 src=r1 offset=17 imm=0
#line 60 "sample/conn_track.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(17));
    // EBPF_OP_LSH64_IMM pc=25 dst=r3 src=r0 offset=0 imm=8
#line 60 "sample/conn_track.c"
    r3 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=26 dst=r2 src=r1 offset=16 imm=0
#line 60 "sample/conn_track.c"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(16));
    // EBPF_OP_OR64_REG pc=27 dst=r3 src=r2 offset=0 imm=0
#line 60 "sample/conn_track.c"
    r3 |= r2;
    // EBPF_OP_LDXB pc=28 dst=r2 src=r1 offset=19 imm=0
#line 60 "sample/conn_track.c"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(19));
    // EBPF_OP_LSH64_IMM pc=29 dst=r2 src=r0 offset=0 imm=8
#line 60 "sample/conn_track.c"
    r2 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=30 dst=r4 src=r1 offset=18 imm=0
#line 60 "sample/conn_track.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(18));
    // EBPF_OP_OR64_REG pc=31 dst=r2 src=r4 offset=0 imm=0
#line 60 "sample/conn_track.c"
    r2 |= r4;
    // EBPF_OP_LSH64_IMM pc=32 dst=r2 src=r0 offset=0 imm=16
#line 60 "sample/conn_track.c"
    r2 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=33 dst=r2 src=r3 offset=0 imm=0
#line 60 "sample/conn_track.c"
    r2 |= r3;
    // EBPF_OP_LDXB pc=34 dst=r4 src=r1 offset=21 imm=0
#line 60 "sample/conn_track.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(21));
    // EBPF_OP_LSH64_IMM pc=35 dst=r4 src=r0 offset=0 imm=8
#line 60 "sample/conn_track.c"
    r4 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=36 dst=r3 src=r1 offset=20 imm=0
#line 60 "sample/conn_track.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(20));
    // EBPF_OP_OR64_REG pc=37 dst=r4 src=r3 offset=0 imm=0
#line 60 "sample/conn_track.c"
    r4 |= r3;
    // EBPF_OP_LDXB pc=38 dst=r3 src=r1 offset=23 imm=0
#line 60 "sample/conn_track.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(23));
    // EBPF_OP_LSH64_IMM pc=39 dst=r3 src=r0 offset=0 imm=8
#line 60 "sample/conn_track.c"
    r3 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=40 dst=r5 src=r1 offset=22 imm=0
#line 60 "sample/conn_track.c"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(22));
    // EBPF_OP_OR64_REG pc=41 dst=r3 src=r5 offset=0 imm=0
#line 60 "sample/conn_track.c"
    r3 |= r5;
    // EBPF_OP_LSH64_IMM pc=42 dst=r3 src=r0 offset=0 imm=16
#line 60 "sample/conn_track.c"
    r3 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=43 dst=r3 src=r4 offset=0 imm=0
#line 60 "sample/conn_track.c"
    r3 |= r4;
    // EBPF_OP_LSH64_IMM pc=44 dst=r3 src=r0 offset=0 imm=32
#line 60 "sample/conn_track.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_OR64_REG pc=45 dst=r3 src=r2 offset=0 imm=0
#line 60 "sample/conn_track.c"
    r3 |= r2;
    // EBPF_OP_LDXB pc=46 dst=r4 src=r1 offset=9 imm=0
#line 60 "sample/conn_track.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(9));
    // EBPF_OP_LSH64_IMM pc=47 dst=r4 src=r0 offset=0 imm=8
#line 60 "sample/conn_track.c"
    r4 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=48 dst=r2 src=r1 offset=8 imm=0
#line 60 "sample/conn_track.c"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(8));
    // EBPF_OP_OR64_REG pc=49 dst=r4 src=r2 offset=0 imm=0
#line 60 "sample/conn_track.c"
    r4 |= r2;
    // EBPF_OP_LDXB pc=50 dst=r2 src=r1 offset=11 imm=0
#line 60 "sample/conn_track.c"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(11));
    // EBPF_OP_LSH64_IMM pc=51 dst=r2 src=r0 offset=0 imm=8
#line 60 "sample/conn_track.c"
    r2 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=52 dst=r5 src=r1 offset=10 imm=0
#line 60 "sample/conn_track.c"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(10));
    // EBPF_OP_OR64_REG pc=53 dst=r2 src=r5 offset=0 imm=0
#line 60 "sample/conn_track.c"
    r2 |= r5;
    // EBPF_OP_STXDW pc=54 dst=r10 src=r3 offset=-40 imm=0
#line 60 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r3;
    // EBPF_OP_LSH64_IMM pc=55 dst=r2 src=r0 offset=0 imm=16
#line 60 "sample/conn_track.c"
    r2 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=56 dst=r2 src=r4 offset=0 imm=0
#line 60 "sample/conn_track.c"
    r2 |= r4;
    // EBPF_OP_LDXB pc=57 dst=r3 src=r1 offset=13 imm=0
#line 60 "sample/conn_track.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(13));
    // EBPF_OP_LSH64_IMM pc=58 dst=r3 src=r0 offset=0 imm=8
#line 60 "sample/conn_track.c"
    r3 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=59 dst=r4 src=r1 offset=12 imm=0
#line 60 "sample/conn_track.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(12));
    // EBPF_OP_OR64_REG pc=60 dst=r3 src=r4 offset=0 imm=0
#line 60 "sample/conn_track.c"
    r3 |= r4;
    // EBPF_OP_LDXB pc=61 dst=r4 src=r1 offset=15 imm=0
#line 60 "sample/conn_track.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(15));
    // EBPF_OP_LSH64_IMM pc=62 dst=r4 src=r0 offset=0 imm=8
#line 60 "sample/conn_track.c"
    r4 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=63 dst=r5 src=r1 offset=14 imm=0
#line 60 "sample/conn_track.c"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(14));
    // EBPF_OP_OR64_REG pc=64 dst=r4 src=r5 offset=0 imm=0
#line 60 "sample/conn_track.c"
    r4 |= r5;
    // EBPF_OP_LSH64_IMM pc=65 dst=r4 src=r0 offset=0 imm=16
#line 60 "sample/conn_track.c"
    r4 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=66 dst=r4 src=r3 offset=0 imm=0
#line 60 "sample/conn_track.c"
    r4 |= r3;
    // EBPF_OP_LSH64_IMM pc=67 dst=r4 src=r0 offset=0 imm=32
#line 60 "sample/conn_track.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_OR64_REG pc=68 dst=r4 src=r2 offset=0 imm=0
#line 60 "sample/conn_track.c"
    r4 |= r2;
    // EBPF_OP_STXDW pc=69 dst=r10 src=r4 offset=-48 imm=0
#line 60 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r4;
    // EBPF_OP_LDXB pc=70 dst=r4 src=r1 offset=33 imm=0
#line 63 "sample/conn_track.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(33));
    // EBPF_OP_LSH64_IMM pc=71 dst=r4 src=r0 offset=0 imm=8
#line 63 "sample/conn_track.c"
    r4 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=72 dst=r2 src=r1 offset=32 imm=0
#line 63 "sample/conn_track.c"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(32));
    // EBPF_OP_OR64_REG pc=73 dst=r4 src=r2 offset=0 imm=0
#line 63 "sample/conn_track.c"
    r4 |= r2;
    // EBPF_OP_LDXB pc=74 dst=r2 src=r1 offset=35 imm=0
#line 63 "sample/conn_track.c"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(35));
    // EBPF_OP_LSH64_IMM pc=75 dst=r2 src=r0 offset=0 imm=8
#line 63 "sample/conn_track.c"
    r2 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=76 dst=r3 src=r1 offset=34 imm=0
#line 63 "sample/conn_track.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(34));
    // EBPF_OP_OR64_REG pc=77 dst=r2 src=r3 offset=0 imm=0
#line 63 "sample/conn_track.c"
    r2 |= r3;
    // EBPF_OP_LDXB pc=78 dst=r5 src=r1 offset=37 imm=0
#line 63 "sample/conn_track.c"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(37));
    // EBPF_OP_LSH64_IMM pc=79 dst=r5 src=r0 offset=0 imm=8
#line 63 "sample/conn_track.c"
    r5 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=80 dst=r3 src=r1 offset=36 imm=0
#line 63 "sample/conn_track.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(36));
    // EBPF_OP_OR64_REG pc=81 dst=r5 src=r3 offset=0 imm=0
#line 63 "sample/conn_track.c"
    r5 |= r3;
    // EBPF_OP_LDXB pc=82 dst=r3 src=r1 offset=39 imm=0
#line 63 "sample/conn_track.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(39));
    // EBPF_OP_LSH64_IMM pc=83 dst=r3 src=r0 offset=0 imm=8
#line 63 "sample/conn_track.c"
    r3 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=84 dst=r0 src=r1 offset=38 imm=0
#line 63 "sample/conn_track.c"
    r0 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(38));
    // EBPF_OP_OR64_REG pc=85 dst=r3 src=r0 offset=0 imm=0
#line 63 "sample/conn_track.c"
    r3 |= r0;
    // EBPF_OP_LSH64_IMM pc=86 dst=r3 src=r0 offset=0 imm=16
#line 63 "sample/conn_track.c"
    r3 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=87 dst=r3 src=r5 offset=0 imm=0
#line 63 "sample/conn_track.c"
    r3 |= r5;
    // EBPF_OP_LSH64_IMM pc=88 dst=r2 src=r0 offset=0 imm=16
#line 63 "sample/conn_track.c"
    r2 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=89 dst=r2 src=r4 offset=0 imm=0
#line 63 "sample/conn_track.c"
    r2 |= r4;
    // EBPF_OP_LDXB pc=90 dst=r4 src=r1 offset=29 imm=0
#line 63 "sample/conn_track.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(29));
    // EBPF_OP_LSH64_IMM pc=91 dst=r4 src=r0 offset=0 imm=8
#line 63 "sample/conn_track.c"
    r4 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=92 dst=r5 src=r1 offset=28 imm=0
#line 63 "sample/conn_track.c"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(28));
    // EBPF_OP_OR64_REG pc=93 dst=r4 src=r5 offset=0 imm=0
#line 63 "sample/conn_track.c"
    r4 |= r5;
    // EBPF_OP_LDXB pc=94 dst=r5 src=r1 offset=31 imm=0
#line 63 "sample/conn_track.c"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(31));
    // EBPF_OP_LSH64_IMM pc=95 dst=r5 src=r0 offset=0 imm=8
#line 63 "sample/conn_track.c"
    r5 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=96 dst=r0 src=r1 offset=30 imm=0
#line 63 "sample/conn_track.c"
    r0 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(30));
    // EBPF_OP_OR64_REG pc=97 dst=r5 src=r0 offset=0 imm=0
#line 63 "sample/conn_track.c"
    r5 |= r0;
    // EBPF_OP_LSH64_IMM pc=98 dst=r5 src=r0 offset=0 imm=16
#line 63 "sample/conn_track.c"
    r5 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=99 dst=r5 src=r4 offset=0 imm=0
#line 63 "sample/conn_track.c"
    r5 |= r4;
    // EBPF_OP_LDXW pc=100 dst=r4 src=r1 offset=24 imm=0
#line 61 "sample/conn_track.c"
    r4 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_STXW pc=101 dst=r10 src=r5 offset=-28 imm=0
#line 63 "sample/conn_track.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint32_t)r5;
    // EBPF_OP_STXW pc=102 dst=r10 src=r2 offset=-24 imm=0
#line 63 "sample/conn_track.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=103 dst=r10 src=r3 offset=-20 imm=0
#line 63 "sample/conn_track.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint32_t)r3;
    // EBPF_OP_LDXB pc=104 dst=r2 src=r1 offset=41 imm=0
#line 63 "sample/conn_track.c"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(41));
    // EBPF_OP_LSH64_IMM pc=105 dst=r2 src=r0 offset=0 imm=8
#line 63 "sample/conn_track.c"
    r2 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=106 dst=r3 src=r1 offset=40 imm=0
#line 63 "sample/conn_track.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_OR64_REG pc=107 dst=r2 src=r3 offset=0 imm=0
#line 63 "sample/conn_track.c"
    r2 |= r3;
    // EBPF_OP_LDXB pc=108 dst=r3 src=r1 offset=42 imm=0
#line 63 "sample/conn_track.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(42));
    // EBPF_OP_LDXB pc=109 dst=r5 src=r1 offset=43 imm=0
#line 63 "sample/conn_track.c"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(43));
    // EBPF_OP_LSH64_IMM pc=110 dst=r5 src=r0 offset=0 imm=8
#line 63 "sample/conn_track.c"
    r5 <<= IMMEDIATE(8);
    // EBPF_OP_OR64_REG pc=111 dst=r5 src=r3 offset=0 imm=0
#line 63 "sample/conn_track.c"
    r5 |= r3;
    // EBPF_OP_LSH64_IMM pc=112 dst=r5 src=r0 offset=0 imm=16
#line 63 "sample/conn_track.c"
    r5 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=113 dst=r5 src=r2 offset=0 imm=0
#line 63 "sample/conn_track.c"
    r5 |= r2;
    // EBPF_OP_STXW pc=114 dst=r10 src=r5 offset=-16 imm=0
#line 63 "sample/conn_track.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r5;
label_4:
    // EBPF_OP_STXH pc=115 dst=r10 src=r4 offset=-32 imm=0
#line 53 "sample/conn_track.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r4;
    // EBPF_OP_LDXW pc=116 dst=r2 src=r1 offset=44 imm=0
#line 53 "sample/conn_track.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_LDXB pc=117 dst=r1 src=r1 offset=48 imm=0
#line 53 "sample/conn_track.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(48));
    // EBPF_OP_STXW pc=118 dst=r10 src=r1 offset=-8 imm=0
#line 56 "sample/conn_track.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_STXH pc=119 dst=r10 src=r2 offset=-12 imm=0
#line 55 "sample/conn_track.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r2;
    // EBPF_OP_CALL pc=120 dst=r0 src=r0 offset=0 imm=7
#line 74 "sample/conn_track.c"
    r0 = connection_tracker_helpers[0].address
#line 74 "sample/conn_track.c"
         (r1, r2, r3, r4, r5);
#line 74 "sample/conn_track.c"
    if ((connection_tracker_helpers[0].tail_call) && (r0 == 0))
#line 74 "sample/conn_track.c"
        return 0;
        // EBPF_OP_STXDW pc=121 dst=r10 src=r0 offset=-56 imm=0
#line 74 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r0;
    // EBPF_OP_JEQ_IMM pc=122 dst=r6 src=r0 offset=19 imm=0
#line 76 "sample/conn_track.c"
    if (r6 == IMMEDIATE(0))
#line 76 "sample/conn_track.c"
        goto label_5;
        // EBPF_OP_JNE_IMM pc=123 dst=r8 src=r0 offset=44 imm=2
#line 32 "sample/conn_track.c"
    if (r8 != IMMEDIATE(2))
#line 32 "sample/conn_track.c"
        goto label_6;
        // EBPF_OP_MOV64_IMM pc=124 dst=r1 src=r0 offset=0 imm=100
#line 32 "sample/conn_track.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=125 dst=r10 src=r1 offset=-96 imm=0
#line 34 "sample/conn_track.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=126 dst=r1 src=r0 offset=0 imm=1953702008
#line 34 "sample/conn_track.c"
    r1 = (uint64_t)7310593858020253816;
    // EBPF_OP_STXDW pc=128 dst=r10 src=r1 offset=-104 imm=0
#line 34 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=129 dst=r1 src=r0 offset=0 imm=544108393
#line 34 "sample/conn_track.c"
    r1 = (uint64_t)2675260723209072489;
    // EBPF_OP_STXDW pc=131 dst=r10 src=r1 offset=-112 imm=0
#line 34 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=132 dst=r1 src=r0 offset=0 imm=1852731203
#line 34 "sample/conn_track.c"
    r1 = (uint64_t)8386658456067534659;
    // EBPF_OP_STXDW pc=134 dst=r10 src=r1 offset=-120 imm=0
#line 34 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=135 dst=r3 src=r10 offset=-28 imm=0
#line 34 "sample/conn_track.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-28));
    // EBPF_OP_BE pc=136 dst=r3 src=r0 offset=0 imm=32
#line 34 "sample/conn_track.c"
    r3 = htobe32((uint32_t)r3);
#line 34 "sample/conn_track.c"
    r3 &= UINT32_MAX;
    // EBPF_OP_MOV64_REG pc=137 dst=r1 src=r10 offset=0 imm=0
#line 34 "sample/conn_track.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=138 dst=r1 src=r0 offset=0 imm=-120
#line 34 "sample/conn_track.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV64_IMM pc=139 dst=r2 src=r0 offset=0 imm=26
#line 34 "sample/conn_track.c"
    r2 = IMMEDIATE(26);
    // EBPF_OP_CALL pc=140 dst=r0 src=r0 offset=0 imm=13
#line 34 "sample/conn_track.c"
    r0 = connection_tracker_helpers[1].address
#line 34 "sample/conn_track.c"
         (r1, r2, r3, r4, r5);
#line 34 "sample/conn_track.c"
    if ((connection_tracker_helpers[1].tail_call) && (r0 == 0))
#line 34 "sample/conn_track.c"
        return 0;
        // EBPF_OP_JA pc=141 dst=r0 src=r0 offset=48 imm=0
#line 34 "sample/conn_track.c"
    goto label_7;
label_5:
    // EBPF_OP_MOV64_REG pc=142 dst=r2 src=r10 offset=0 imm=0
#line 34 "sample/conn_track.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=143 dst=r2 src=r0 offset=0 imm=-48
#line 80 "sample/conn_track.c"
    r2 += IMMEDIATE(-48);
    // EBPF_OP_LDDW pc=144 dst=r1 src=r0 offset=0 imm=0
#line 80 "sample/conn_track.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=146 dst=r0 src=r0 offset=0 imm=4
#line 80 "sample/conn_track.c"
    r0 = connection_tracker_helpers[2].address
#line 80 "sample/conn_track.c"
         (r1, r2, r3, r4, r5);
#line 80 "sample/conn_track.c"
    if ((connection_tracker_helpers[2].tail_call) && (r0 == 0))
#line 80 "sample/conn_track.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=147 dst=r6 src=r0 offset=0 imm=0
#line 80 "sample/conn_track.c"
    r6 = r0;
    // EBPF_OP_JEQ_IMM pc=148 dst=r6 src=r0 offset=96 imm=0
#line 81 "sample/conn_track.c"
    if (r6 == IMMEDIATE(0))
#line 81 "sample/conn_track.c"
        goto label_10;
        // EBPF_OP_JNE_IMM pc=149 dst=r8 src=r0 offset=49 imm=2
#line 32 "sample/conn_track.c"
    if (r8 != IMMEDIATE(2))
#line 32 "sample/conn_track.c"
        goto label_8;
        // EBPF_OP_MOV64_IMM pc=150 dst=r1 src=r0 offset=0 imm=100
#line 32 "sample/conn_track.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=151 dst=r10 src=r1 offset=-96 imm=0
#line 36 "sample/conn_track.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=152 dst=r1 src=r0 offset=0 imm=1953702008
#line 36 "sample/conn_track.c"
    r1 = (uint64_t)7309465819219697784;
    // EBPF_OP_STXDW pc=154 dst=r10 src=r1 offset=-104 imm=0
#line 36 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=155 dst=r1 src=r0 offset=0 imm=544108393
#line 36 "sample/conn_track.c"
    r1 = (uint64_t)2675260723209072489;
    // EBPF_OP_STXDW pc=157 dst=r10 src=r1 offset=-112 imm=0
#line 36 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=158 dst=r1 src=r0 offset=0 imm=1852731203
#line 36 "sample/conn_track.c"
    r1 = (uint64_t)8386658456067534659;
    // EBPF_OP_STXDW pc=160 dst=r10 src=r1 offset=-120 imm=0
#line 36 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=161 dst=r3 src=r10 offset=-28 imm=0
#line 36 "sample/conn_track.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-28));
    // EBPF_OP_BE pc=162 dst=r3 src=r0 offset=0 imm=32
#line 36 "sample/conn_track.c"
    r3 = htobe32((uint32_t)r3);
#line 36 "sample/conn_track.c"
    r3 &= UINT32_MAX;
    // EBPF_OP_MOV64_REG pc=163 dst=r1 src=r10 offset=0 imm=0
#line 36 "sample/conn_track.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=164 dst=r1 src=r0 offset=0 imm=-120
#line 36 "sample/conn_track.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV64_IMM pc=165 dst=r2 src=r0 offset=0 imm=26
#line 36 "sample/conn_track.c"
    r2 = IMMEDIATE(26);
    // EBPF_OP_CALL pc=166 dst=r0 src=r0 offset=0 imm=13
#line 36 "sample/conn_track.c"
    r0 = connection_tracker_helpers[1].address
#line 36 "sample/conn_track.c"
         (r1, r2, r3, r4, r5);
#line 36 "sample/conn_track.c"
    if ((connection_tracker_helpers[1].tail_call) && (r0 == 0))
#line 36 "sample/conn_track.c"
        return 0;
        // EBPF_OP_JA pc=167 dst=r0 src=r0 offset=53 imm=0
#line 36 "sample/conn_track.c"
    goto label_9;
label_6:
    // EBPF_OP_MOV64_IMM pc=168 dst=r1 src=r0 offset=0 imm=0
#line 36 "sample/conn_track.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=169 dst=r10 src=r1 offset=-88 imm=0
#line 41 "sample/conn_track.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=170 dst=r1 src=r0 offset=0 imm=1635021600
#line 41 "sample/conn_track.c"
    r1 = (uint64_t)7234316411050685216;
    // EBPF_OP_STXDW pc=172 dst=r10 src=r1 offset=-96 imm=0
#line 41 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=173 dst=r1 src=r0 offset=0 imm=544762988
#line 41 "sample/conn_track.c"
    r1 = (uint64_t)8677429488750455916;
    // EBPF_OP_STXDW pc=175 dst=r10 src=r1 offset=-104 imm=0
#line 41 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=176 dst=r1 src=r0 offset=0 imm=544108393
#line 41 "sample/conn_track.c"
    r1 = (uint64_t)2675260723209072489;
    // EBPF_OP_STXDW pc=178 dst=r10 src=r1 offset=-112 imm=0
#line 41 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=179 dst=r1 src=r0 offset=0 imm=1852731203
#line 41 "sample/conn_track.c"
    r1 = (uint64_t)8386658456067534659;
    // EBPF_OP_STXDW pc=181 dst=r10 src=r1 offset=-120 imm=0
#line 41 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_LDXDW pc=182 dst=r4 src=r10 offset=-20 imm=0
#line 41 "sample/conn_track.c"
    r4 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-20));
    // EBPF_OP_LDXDW pc=183 dst=r3 src=r10 offset=-28 imm=0
#line 41 "sample/conn_track.c"
    r3 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-28));
    // EBPF_OP_BE pc=184 dst=r3 src=r0 offset=0 imm=64
#line 44 "bpf_endian.h"
    r3 = htobe64((uint64_t)r3);
    // EBPF_OP_BE pc=185 dst=r4 src=r0 offset=0 imm=64
#line 44 "bpf_endian.h"
    r4 = htobe64((uint64_t)r4);
    // EBPF_OP_MOV64_REG pc=186 dst=r1 src=r10 offset=0 imm=0
#line 44 "bpf_endian.h"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=187 dst=r1 src=r0 offset=0 imm=-120
#line 44 "bpf_endian.h"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV64_IMM pc=188 dst=r2 src=r0 offset=0 imm=33
#line 41 "sample/conn_track.c"
    r2 = IMMEDIATE(33);
    // EBPF_OP_CALL pc=189 dst=r0 src=r0 offset=0 imm=14
#line 41 "sample/conn_track.c"
    r0 = connection_tracker_helpers[3].address
#line 41 "sample/conn_track.c"
         (r1, r2, r3, r4, r5);
#line 41 "sample/conn_track.c"
    if ((connection_tracker_helpers[3].tail_call) && (r0 == 0))
#line 41 "sample/conn_track.c"
        return 0;
label_7:
    // EBPF_OP_MOV64_REG pc=190 dst=r2 src=r10 offset=0 imm=0
#line 41 "sample/conn_track.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=191 dst=r2 src=r0 offset=0 imm=-48
#line 41 "sample/conn_track.c"
    r2 += IMMEDIATE(-48);
    // EBPF_OP_MOV64_REG pc=192 dst=r3 src=r10 offset=0 imm=0
#line 41 "sample/conn_track.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=193 dst=r3 src=r0 offset=0 imm=-56
#line 41 "sample/conn_track.c"
    r3 += IMMEDIATE(-56);
    // EBPF_OP_LDDW pc=194 dst=r1 src=r0 offset=0 imm=0
#line 78 "sample/conn_track.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=196 dst=r4 src=r0 offset=0 imm=0
#line 78 "sample/conn_track.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=197 dst=r0 src=r0 offset=0 imm=2
#line 78 "sample/conn_track.c"
    r0 = connection_tracker_helpers[4].address
#line 78 "sample/conn_track.c"
         (r1, r2, r3, r4, r5);
#line 78 "sample/conn_track.c"
    if ((connection_tracker_helpers[4].tail_call) && (r0 == 0))
#line 78 "sample/conn_track.c"
        return 0;
        // EBPF_OP_JA pc=198 dst=r0 src=r0 offset=46 imm=0
#line 78 "sample/conn_track.c"
    goto label_10;
label_8:
    // EBPF_OP_MOV64_IMM pc=199 dst=r1 src=r0 offset=0 imm=0
#line 78 "sample/conn_track.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=200 dst=r10 src=r1 offset=-88 imm=0
#line 43 "sample/conn_track.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=201 dst=r1 src=r0 offset=0 imm=1869902624
#line 43 "sample/conn_track.c"
    r1 = (uint64_t)7234312004649120544;
    // EBPF_OP_STXDW pc=203 dst=r10 src=r1 offset=-96 imm=0
#line 43 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=204 dst=r1 src=r0 offset=0 imm=544762988
#line 43 "sample/conn_track.c"
    r1 = (uint64_t)8677429488750455916;
    // EBPF_OP_STXDW pc=206 dst=r10 src=r1 offset=-104 imm=0
#line 43 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=207 dst=r1 src=r0 offset=0 imm=544108393
#line 43 "sample/conn_track.c"
    r1 = (uint64_t)2675260723209072489;
    // EBPF_OP_STXDW pc=209 dst=r10 src=r1 offset=-112 imm=0
#line 43 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=210 dst=r1 src=r0 offset=0 imm=1852731203
#line 43 "sample/conn_track.c"
    r1 = (uint64_t)8386658456067534659;
    // EBPF_OP_STXDW pc=212 dst=r10 src=r1 offset=-120 imm=0
#line 43 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_LDXDW pc=213 dst=r4 src=r10 offset=-20 imm=0
#line 43 "sample/conn_track.c"
    r4 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-20));
    // EBPF_OP_LDXDW pc=214 dst=r3 src=r10 offset=-28 imm=0
#line 43 "sample/conn_track.c"
    r3 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-28));
    // EBPF_OP_BE pc=215 dst=r3 src=r0 offset=0 imm=64
#line 44 "bpf_endian.h"
    r3 = htobe64((uint64_t)r3);
    // EBPF_OP_BE pc=216 dst=r4 src=r0 offset=0 imm=64
#line 44 "bpf_endian.h"
    r4 = htobe64((uint64_t)r4);
    // EBPF_OP_MOV64_REG pc=217 dst=r1 src=r10 offset=0 imm=0
#line 44 "bpf_endian.h"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=218 dst=r1 src=r0 offset=0 imm=-120
#line 44 "bpf_endian.h"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV64_IMM pc=219 dst=r2 src=r0 offset=0 imm=33
#line 43 "sample/conn_track.c"
    r2 = IMMEDIATE(33);
    // EBPF_OP_CALL pc=220 dst=r0 src=r0 offset=0 imm=14
#line 43 "sample/conn_track.c"
    r0 = connection_tracker_helpers[3].address
#line 43 "sample/conn_track.c"
         (r1, r2, r3, r4, r5);
#line 43 "sample/conn_track.c"
    if ((connection_tracker_helpers[3].tail_call) && (r0 == 0))
#line 43 "sample/conn_track.c"
        return 0;
label_9:
    // EBPF_OP_LDXW pc=221 dst=r1 src=r10 offset=-8 imm=0
#line 83 "sample/conn_track.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8));
    // EBPF_OP_STXW pc=222 dst=r10 src=r1 offset=-80 imm=0
#line 83 "sample/conn_track.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint32_t)r1;
    // EBPF_OP_LDXDW pc=223 dst=r1 src=r10 offset=-16 imm=0
#line 83 "sample/conn_track.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16));
    // EBPF_OP_STXDW pc=224 dst=r10 src=r1 offset=-88 imm=0
#line 83 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDXDW pc=225 dst=r1 src=r10 offset=-24 imm=0
#line 83 "sample/conn_track.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24));
    // EBPF_OP_STXDW pc=226 dst=r10 src=r1 offset=-96 imm=0
#line 83 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDXDW pc=227 dst=r1 src=r10 offset=-32 imm=0
#line 83 "sample/conn_track.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32));
    // EBPF_OP_STXDW pc=228 dst=r10 src=r1 offset=-104 imm=0
#line 83 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDXDW pc=229 dst=r1 src=r10 offset=-40 imm=0
#line 83 "sample/conn_track.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40));
    // EBPF_OP_STXDW pc=230 dst=r10 src=r1 offset=-112 imm=0
#line 83 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDXDW pc=231 dst=r1 src=r10 offset=-48 imm=0
#line 83 "sample/conn_track.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48));
    // EBPF_OP_STXDW pc=232 dst=r10 src=r1 offset=-120 imm=0
#line 83 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_STXB pc=233 dst=r10 src=r7 offset=-76 imm=0
#line 83 "sample/conn_track.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-76)) = (uint8_t)r7;
    // EBPF_OP_LDXDW pc=234 dst=r1 src=r6 offset=0 imm=0
#line 83 "sample/conn_track.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_STXDW pc=235 dst=r10 src=r1 offset=-72 imm=0
#line 83 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDXDW pc=236 dst=r1 src=r10 offset=-56 imm=0
#line 83 "sample/conn_track.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56));
    // EBPF_OP_STXDW pc=237 dst=r10 src=r1 offset=-64 imm=0
#line 83 "sample/conn_track.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=238 dst=r2 src=r10 offset=0 imm=0
#line 83 "sample/conn_track.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=239 dst=r2 src=r0 offset=0 imm=-120
#line 83 "sample/conn_track.c"
    r2 += IMMEDIATE(-120);
    // EBPF_OP_LDDW pc=240 dst=r1 src=r0 offset=0 imm=0
#line 84 "sample/conn_track.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_MOV64_IMM pc=242 dst=r3 src=r0 offset=0 imm=64
#line 84 "sample/conn_track.c"
    r3 = IMMEDIATE(64);
    // EBPF_OP_MOV64_IMM pc=243 dst=r4 src=r0 offset=0 imm=0
#line 84 "sample/conn_track.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=244 dst=r0 src=r0 offset=0 imm=11
#line 84 "sample/conn_track.c"
    r0 = connection_tracker_helpers[5].address
#line 84 "sample/conn_track.c"
         (r1, r2, r3, r4, r5);
#line 84 "sample/conn_track.c"
    if ((connection_tracker_helpers[5].tail_call) && (r0 == 0))
#line 84 "sample/conn_track.c"
        return 0;
label_10:
    // EBPF_OP_MOV64_IMM pc=245 dst=r0 src=r0 offset=0 imm=0
#line 111 "sample/conn_track.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=246 dst=r0 src=r0 offset=0 imm=0
#line 111 "sample/conn_track.c"
    return r0;
#line 111 "sample/conn_track.c"
}
#line __LINE__ __FILE__

static program_entry_t _programs[] = {
    {
        connection_tracker,
        "sockops",
        "connection_tracker",
        connection_tracker_maps,
        2,
        connection_tracker_helpers,
        6,
        247,
        &connection_tracker_program_type_guid,
        &connection_tracker_attach_type_guid,
    },
};

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 1;
}

metadata_table_t conn_track_metadata_table = {_get_programs, _get_maps, _get_hash};
