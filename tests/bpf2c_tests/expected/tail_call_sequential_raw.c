// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from tail_call_sequential.o

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
         BPF_MAP_TYPE_PROG_ARRAY, // Type of map.
         4,                       // Size in bytes of a map key.
         4,                       // Size in bytes of a map value.
         35,                      // Maximum number of entries allowed in the map.
         0,                       // Inner map index.
         PIN_NONE,                // Pinning type for the map.
         19,                      // Identifier for a map template.
         0,                       // The id of the inner map template.
     },
     "map"},
    {NULL,
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         PIN_NONE,           // Pinning type for the map.
         25,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "canary"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 2;
}

static helper_function_entry_t sequential0_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential0_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential0_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential0_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_pr~1")
static uint64_t
sequential0(void* context)
#line 131 "sample/tail_call_sequential.c"
{
#line 131 "sample/tail_call_sequential.c"
    // Prologue
#line 131 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 131 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 131 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 131 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 131 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 131 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 131 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 131 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 131 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 131 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 131 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 131 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 131 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 131 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 131 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 131 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 131 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 131 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 131 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 131 "sample/tail_call_sequential.c"
    r0 = sequential0_helpers[0].address
#line 131 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 131 "sample/tail_call_sequential.c"
    if ((sequential0_helpers[0].tail_call) && (r0 == 0))
#line 131 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 131 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 131 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 131 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 131 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 131 "sample/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 131 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976252001
#line 131 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834439265;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 131 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 131 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 131 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 131 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 131 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 131 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 131 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 131 "sample/tail_call_sequential.c"
    r0 = sequential0_helpers[1].address
#line 131 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 131 "sample/tail_call_sequential.c"
    if ((sequential0_helpers[1].tail_call) && (r0 == 0))
#line 131 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 131 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=0
#line 131 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(0))
#line 131 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=1
#line 131 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 131 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 131 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r0 offset=0 imm=0
#line 131 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=1
#line 131 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(1);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 131 "sample/tail_call_sequential.c"
    r0 = sequential0_helpers[2].address
#line 131 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 131 "sample/tail_call_sequential.c"
    if ((sequential0_helpers[2].tail_call) && (r0 == 0))
#line 131 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 131 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 131 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 131 "sample/tail_call_sequential.c"
    return r0;
#line 131 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential1_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential1_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential1_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential1_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_pr~2")
static uint64_t
sequential1(void* context)
#line 132 "sample/tail_call_sequential.c"
{
#line 132 "sample/tail_call_sequential.c"
    // Prologue
#line 132 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 132 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 132 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 132 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 132 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 132 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 132 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 132 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 132 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 132 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 132 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 132 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 132 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 132 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 132 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 132 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 132 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 132 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 132 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 132 "sample/tail_call_sequential.c"
    r0 = sequential1_helpers[0].address
#line 132 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 132 "sample/tail_call_sequential.c"
    if ((sequential1_helpers[0].tail_call) && (r0 == 0))
#line 132 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 132 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 132 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 132 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 132 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 132 "sample/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 132 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976317537
#line 132 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834504801;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 132 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 132 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 132 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 132 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 132 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 132 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 132 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 132 "sample/tail_call_sequential.c"
    r0 = sequential1_helpers[1].address
#line 132 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 132 "sample/tail_call_sequential.c"
    if ((sequential1_helpers[1].tail_call) && (r0 == 0))
#line 132 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 132 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=1
#line 132 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(1))
#line 132 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=2
#line 132 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 132 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 132 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r0 offset=0 imm=0
#line 132 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=2
#line 132 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 132 "sample/tail_call_sequential.c"
    r0 = sequential1_helpers[2].address
#line 132 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 132 "sample/tail_call_sequential.c"
    if ((sequential1_helpers[2].tail_call) && (r0 == 0))
#line 132 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 132 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 132 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 132 "sample/tail_call_sequential.c"
    return r0;
#line 132 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential10_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential10_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential10_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential10_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~11")
static uint64_t
sequential10(void* context)
#line 141 "sample/tail_call_sequential.c"
{
#line 141 "sample/tail_call_sequential.c"
    // Prologue
#line 141 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 141 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 141 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 141 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 141 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 141 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 141 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 141 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 141 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 141 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 141 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 141 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 141 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 141 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 141 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 141 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 141 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 141 "sample/tail_call_sequential.c"
    r0 = sequential10_helpers[0].address
#line 141 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/tail_call_sequential.c"
    if ((sequential10_helpers[0].tail_call) && (r0 == 0))
#line 141 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 141 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 141 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 141 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 141 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 141 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 141 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 141 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=808545377
#line 141 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479786081377;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 141 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 141 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 141 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 141 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 141 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 141 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 141 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 141 "sample/tail_call_sequential.c"
    r0 = sequential10_helpers[1].address
#line 141 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/tail_call_sequential.c"
    if ((sequential10_helpers[1].tail_call) && (r0 == 0))
#line 141 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 141 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=10
#line 141 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(10))
#line 141 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=11
#line 141 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(11);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 141 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 141 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 141 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=11
#line 141 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(11);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 141 "sample/tail_call_sequential.c"
    r0 = sequential10_helpers[2].address
#line 141 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 141 "sample/tail_call_sequential.c"
    if ((sequential10_helpers[2].tail_call) && (r0 == 0))
#line 141 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 141 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 141 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 141 "sample/tail_call_sequential.c"
    return r0;
#line 141 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential11_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential11_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential11_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential11_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~12")
static uint64_t
sequential11(void* context)
#line 142 "sample/tail_call_sequential.c"
{
#line 142 "sample/tail_call_sequential.c"
    // Prologue
#line 142 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 142 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 142 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 142 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 142 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 142 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 142 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 142 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 142 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 142 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 142 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 142 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 142 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 142 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 142 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 142 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 142 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 142 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 142 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 142 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 142 "sample/tail_call_sequential.c"
    r0 = sequential11_helpers[0].address
#line 142 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 142 "sample/tail_call_sequential.c"
    if ((sequential11_helpers[0].tail_call) && (r0 == 0))
#line 142 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 142 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 142 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 142 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 142 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 142 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 142 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 142 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=825322593
#line 142 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479802858593;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 142 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 142 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 142 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 142 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 142 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 142 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 142 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 142 "sample/tail_call_sequential.c"
    r0 = sequential11_helpers[1].address
#line 142 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 142 "sample/tail_call_sequential.c"
    if ((sequential11_helpers[1].tail_call) && (r0 == 0))
#line 142 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 142 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=11
#line 142 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(11))
#line 142 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=12
#line 142 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(12);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 142 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 142 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 142 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=12
#line 142 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(12);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 142 "sample/tail_call_sequential.c"
    r0 = sequential11_helpers[2].address
#line 142 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 142 "sample/tail_call_sequential.c"
    if ((sequential11_helpers[2].tail_call) && (r0 == 0))
#line 142 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 142 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 142 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 142 "sample/tail_call_sequential.c"
    return r0;
#line 142 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential12_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential12_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential12_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential12_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~13")
static uint64_t
sequential12(void* context)
#line 143 "sample/tail_call_sequential.c"
{
#line 143 "sample/tail_call_sequential.c"
    // Prologue
#line 143 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 143 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 143 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 143 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 143 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 143 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 143 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 143 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 143 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 143 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 143 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 143 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 143 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 143 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 143 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 143 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 143 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 143 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 143 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 143 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 143 "sample/tail_call_sequential.c"
    r0 = sequential12_helpers[0].address
#line 143 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 143 "sample/tail_call_sequential.c"
    if ((sequential12_helpers[0].tail_call) && (r0 == 0))
#line 143 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 143 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 143 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 143 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 143 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 143 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 143 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 143 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=842099809
#line 143 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479819635809;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 143 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 143 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 143 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 143 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 143 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 143 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 143 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 143 "sample/tail_call_sequential.c"
    r0 = sequential12_helpers[1].address
#line 143 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 143 "sample/tail_call_sequential.c"
    if ((sequential12_helpers[1].tail_call) && (r0 == 0))
#line 143 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 143 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=12
#line 143 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(12))
#line 143 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=13
#line 143 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(13);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 143 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 143 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 143 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=13
#line 143 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(13);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 143 "sample/tail_call_sequential.c"
    r0 = sequential12_helpers[2].address
#line 143 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 143 "sample/tail_call_sequential.c"
    if ((sequential12_helpers[2].tail_call) && (r0 == 0))
#line 143 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 143 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 143 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 143 "sample/tail_call_sequential.c"
    return r0;
#line 143 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential13_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential13_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential13_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential13_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~14")
static uint64_t
sequential13(void* context)
#line 144 "sample/tail_call_sequential.c"
{
#line 144 "sample/tail_call_sequential.c"
    // Prologue
#line 144 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 144 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 144 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 144 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 144 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 144 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 144 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 144 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 144 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 144 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 144 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 144 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 144 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 144 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 144 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 144 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 144 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 144 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 144 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 144 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 144 "sample/tail_call_sequential.c"
    r0 = sequential13_helpers[0].address
#line 144 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 144 "sample/tail_call_sequential.c"
    if ((sequential13_helpers[0].tail_call) && (r0 == 0))
#line 144 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 144 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 144 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 144 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 144 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 144 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 144 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 144 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=858877025
#line 144 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479836413025;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 144 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 144 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 144 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 144 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 144 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 144 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 144 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 144 "sample/tail_call_sequential.c"
    r0 = sequential13_helpers[1].address
#line 144 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 144 "sample/tail_call_sequential.c"
    if ((sequential13_helpers[1].tail_call) && (r0 == 0))
#line 144 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 144 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=13
#line 144 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(13))
#line 144 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=14
#line 144 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(14);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 144 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 144 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 144 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=14
#line 144 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(14);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 144 "sample/tail_call_sequential.c"
    r0 = sequential13_helpers[2].address
#line 144 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 144 "sample/tail_call_sequential.c"
    if ((sequential13_helpers[2].tail_call) && (r0 == 0))
#line 144 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 144 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 144 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 144 "sample/tail_call_sequential.c"
    return r0;
#line 144 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential14_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential14_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential14_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential14_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~15")
static uint64_t
sequential14(void* context)
#line 145 "sample/tail_call_sequential.c"
{
#line 145 "sample/tail_call_sequential.c"
    // Prologue
#line 145 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 145 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 145 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 145 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 145 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 145 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 145 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 145 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 145 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 145 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 145 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 145 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 145 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 145 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 145 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 145 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 145 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 145 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 145 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 145 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 145 "sample/tail_call_sequential.c"
    r0 = sequential14_helpers[0].address
#line 145 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 145 "sample/tail_call_sequential.c"
    if ((sequential14_helpers[0].tail_call) && (r0 == 0))
#line 145 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 145 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 145 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 145 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 145 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 145 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 145 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 145 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=875654241
#line 145 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479853190241;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 145 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 145 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 145 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 145 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 145 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 145 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 145 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 145 "sample/tail_call_sequential.c"
    r0 = sequential14_helpers[1].address
#line 145 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 145 "sample/tail_call_sequential.c"
    if ((sequential14_helpers[1].tail_call) && (r0 == 0))
#line 145 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 145 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=14
#line 145 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(14))
#line 145 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=15
#line 145 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(15);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 145 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 145 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 145 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=15
#line 145 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(15);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 145 "sample/tail_call_sequential.c"
    r0 = sequential14_helpers[2].address
#line 145 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 145 "sample/tail_call_sequential.c"
    if ((sequential14_helpers[2].tail_call) && (r0 == 0))
#line 145 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 145 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 145 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 145 "sample/tail_call_sequential.c"
    return r0;
#line 145 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential15_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential15_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential15_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential15_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~16")
static uint64_t
sequential15(void* context)
#line 146 "sample/tail_call_sequential.c"
{
#line 146 "sample/tail_call_sequential.c"
    // Prologue
#line 146 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 146 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 146 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 146 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 146 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 146 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 146 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 146 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 146 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 146 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 146 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 146 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 146 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 146 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 146 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 146 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 146 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 146 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 146 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 146 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 146 "sample/tail_call_sequential.c"
    r0 = sequential15_helpers[0].address
#line 146 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 146 "sample/tail_call_sequential.c"
    if ((sequential15_helpers[0].tail_call) && (r0 == 0))
#line 146 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 146 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 146 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 146 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 146 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 146 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 146 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 146 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=892431457
#line 146 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479869967457;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 146 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 146 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 146 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 146 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 146 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 146 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 146 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 146 "sample/tail_call_sequential.c"
    r0 = sequential15_helpers[1].address
#line 146 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 146 "sample/tail_call_sequential.c"
    if ((sequential15_helpers[1].tail_call) && (r0 == 0))
#line 146 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 146 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=15
#line 146 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(15))
#line 146 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=16
#line 146 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(16);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 146 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 146 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 146 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=16
#line 146 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(16);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 146 "sample/tail_call_sequential.c"
    r0 = sequential15_helpers[2].address
#line 146 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 146 "sample/tail_call_sequential.c"
    if ((sequential15_helpers[2].tail_call) && (r0 == 0))
#line 146 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 146 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 146 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 146 "sample/tail_call_sequential.c"
    return r0;
#line 146 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential16_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential16_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential16_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential16_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~17")
static uint64_t
sequential16(void* context)
#line 147 "sample/tail_call_sequential.c"
{
#line 147 "sample/tail_call_sequential.c"
    // Prologue
#line 147 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 147 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 147 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 147 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 147 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 147 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 147 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 147 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 147 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 147 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 147 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 147 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 147 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 147 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 147 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 147 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 147 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 147 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 147 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 147 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 147 "sample/tail_call_sequential.c"
    r0 = sequential16_helpers[0].address
#line 147 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 147 "sample/tail_call_sequential.c"
    if ((sequential16_helpers[0].tail_call) && (r0 == 0))
#line 147 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 147 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 147 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 147 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 147 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 147 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 147 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 147 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=909208673
#line 147 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479886744673;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 147 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 147 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 147 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 147 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 147 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 147 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 147 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 147 "sample/tail_call_sequential.c"
    r0 = sequential16_helpers[1].address
#line 147 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 147 "sample/tail_call_sequential.c"
    if ((sequential16_helpers[1].tail_call) && (r0 == 0))
#line 147 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 147 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=16
#line 147 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(16))
#line 147 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=17
#line 147 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(17);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 147 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 147 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 147 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=17
#line 147 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(17);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 147 "sample/tail_call_sequential.c"
    r0 = sequential16_helpers[2].address
#line 147 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 147 "sample/tail_call_sequential.c"
    if ((sequential16_helpers[2].tail_call) && (r0 == 0))
#line 147 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 147 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 147 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 147 "sample/tail_call_sequential.c"
    return r0;
#line 147 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential17_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential17_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential17_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential17_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~18")
static uint64_t
sequential17(void* context)
#line 148 "sample/tail_call_sequential.c"
{
#line 148 "sample/tail_call_sequential.c"
    // Prologue
#line 148 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 148 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 148 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 148 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 148 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 148 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 148 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 148 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 148 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 148 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 148 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 148 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 148 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 148 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 148 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 148 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 148 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 148 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 148 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 148 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 148 "sample/tail_call_sequential.c"
    r0 = sequential17_helpers[0].address
#line 148 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 148 "sample/tail_call_sequential.c"
    if ((sequential17_helpers[0].tail_call) && (r0 == 0))
#line 148 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 148 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 148 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 148 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 148 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 148 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 148 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 148 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=925985889
#line 148 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479903521889;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 148 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 148 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 148 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 148 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 148 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 148 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 148 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 148 "sample/tail_call_sequential.c"
    r0 = sequential17_helpers[1].address
#line 148 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 148 "sample/tail_call_sequential.c"
    if ((sequential17_helpers[1].tail_call) && (r0 == 0))
#line 148 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 148 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=17
#line 148 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(17))
#line 148 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=18
#line 148 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(18);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 148 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 148 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 148 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=18
#line 148 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(18);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 148 "sample/tail_call_sequential.c"
    r0 = sequential17_helpers[2].address
#line 148 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 148 "sample/tail_call_sequential.c"
    if ((sequential17_helpers[2].tail_call) && (r0 == 0))
#line 148 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 148 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 148 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 148 "sample/tail_call_sequential.c"
    return r0;
#line 148 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential18_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential18_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential18_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential18_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~19")
static uint64_t
sequential18(void* context)
#line 149 "sample/tail_call_sequential.c"
{
#line 149 "sample/tail_call_sequential.c"
    // Prologue
#line 149 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 149 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 149 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 149 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 149 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 149 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 149 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 149 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 149 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 149 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 149 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 149 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 149 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 149 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 149 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 149 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 149 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 149 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 149 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 149 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 149 "sample/tail_call_sequential.c"
    r0 = sequential18_helpers[0].address
#line 149 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 149 "sample/tail_call_sequential.c"
    if ((sequential18_helpers[0].tail_call) && (r0 == 0))
#line 149 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 149 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 149 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 149 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 149 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 149 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 149 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 149 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=942763105
#line 149 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479920299105;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 149 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 149 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 149 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 149 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 149 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 149 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 149 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 149 "sample/tail_call_sequential.c"
    r0 = sequential18_helpers[1].address
#line 149 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 149 "sample/tail_call_sequential.c"
    if ((sequential18_helpers[1].tail_call) && (r0 == 0))
#line 149 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 149 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=18
#line 149 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(18))
#line 149 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=19
#line 149 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(19);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 149 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 149 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 149 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=19
#line 149 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(19);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 149 "sample/tail_call_sequential.c"
    r0 = sequential18_helpers[2].address
#line 149 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 149 "sample/tail_call_sequential.c"
    if ((sequential18_helpers[2].tail_call) && (r0 == 0))
#line 149 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 149 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 149 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 149 "sample/tail_call_sequential.c"
    return r0;
#line 149 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential19_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential19_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential19_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential19_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~20")
static uint64_t
sequential19(void* context)
#line 150 "sample/tail_call_sequential.c"
{
#line 150 "sample/tail_call_sequential.c"
    // Prologue
#line 150 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 150 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 150 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 150 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 150 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 150 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 150 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 150 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 150 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 150 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 150 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 150 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 150 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 150 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 150 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 150 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 150 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 150 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 150 "sample/tail_call_sequential.c"
    r0 = sequential19_helpers[0].address
#line 150 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/tail_call_sequential.c"
    if ((sequential19_helpers[0].tail_call) && (r0 == 0))
#line 150 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 150 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 150 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 150 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 150 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 150 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 150 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 150 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=959540321
#line 150 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479937076321;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 150 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 150 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 150 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 150 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 150 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 150 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 150 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 150 "sample/tail_call_sequential.c"
    r0 = sequential19_helpers[1].address
#line 150 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/tail_call_sequential.c"
    if ((sequential19_helpers[1].tail_call) && (r0 == 0))
#line 150 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 150 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=19
#line 150 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(19))
#line 150 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=20
#line 150 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(20);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 150 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 150 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 150 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=20
#line 150 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(20);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 150 "sample/tail_call_sequential.c"
    r0 = sequential19_helpers[2].address
#line 150 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 150 "sample/tail_call_sequential.c"
    if ((sequential19_helpers[2].tail_call) && (r0 == 0))
#line 150 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 150 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 150 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 150 "sample/tail_call_sequential.c"
    return r0;
#line 150 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential2_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential2_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential2_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential2_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_pr~3")
static uint64_t
sequential2(void* context)
#line 133 "sample/tail_call_sequential.c"
{
#line 133 "sample/tail_call_sequential.c"
    // Prologue
#line 133 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 133 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 133 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 133 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 133 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 133 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 133 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 133 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 133 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 133 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 133 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 133 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 133 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 133 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 133 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 133 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 133 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 133 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 133 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 133 "sample/tail_call_sequential.c"
    r0 = sequential2_helpers[0].address
#line 133 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 133 "sample/tail_call_sequential.c"
    if ((sequential2_helpers[0].tail_call) && (r0 == 0))
#line 133 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 133 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 133 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 133 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 133 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 133 "sample/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 133 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976383073
#line 133 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834570337;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 133 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 133 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 133 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 133 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 133 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 133 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 133 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 133 "sample/tail_call_sequential.c"
    r0 = sequential2_helpers[1].address
#line 133 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 133 "sample/tail_call_sequential.c"
    if ((sequential2_helpers[1].tail_call) && (r0 == 0))
#line 133 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 133 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=2
#line 133 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(2))
#line 133 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=3
#line 133 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 133 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 133 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r0 offset=0 imm=0
#line 133 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=3
#line 133 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(3);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 133 "sample/tail_call_sequential.c"
    r0 = sequential2_helpers[2].address
#line 133 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 133 "sample/tail_call_sequential.c"
    if ((sequential2_helpers[2].tail_call) && (r0 == 0))
#line 133 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 133 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 133 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 133 "sample/tail_call_sequential.c"
    return r0;
#line 133 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential20_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential20_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential20_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential20_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~21")
static uint64_t
sequential20(void* context)
#line 151 "sample/tail_call_sequential.c"
{
#line 151 "sample/tail_call_sequential.c"
    // Prologue
#line 151 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 151 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 151 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 151 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 151 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 151 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 151 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 151 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 151 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 151 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 151 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 151 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 151 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 151 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 151 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 151 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 151 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 151 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 151 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 151 "sample/tail_call_sequential.c"
    r0 = sequential20_helpers[0].address
#line 151 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 151 "sample/tail_call_sequential.c"
    if ((sequential20_helpers[0].tail_call) && (r0 == 0))
#line 151 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 151 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 151 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 151 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 151 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 151 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 151 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 151 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=808610913
#line 151 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479786146913;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 151 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 151 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 151 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 151 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 151 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 151 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 151 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 151 "sample/tail_call_sequential.c"
    r0 = sequential20_helpers[1].address
#line 151 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 151 "sample/tail_call_sequential.c"
    if ((sequential20_helpers[1].tail_call) && (r0 == 0))
#line 151 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 151 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=20
#line 151 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(20))
#line 151 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=21
#line 151 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(21);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 151 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 151 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 151 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=21
#line 151 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(21);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 151 "sample/tail_call_sequential.c"
    r0 = sequential20_helpers[2].address
#line 151 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 151 "sample/tail_call_sequential.c"
    if ((sequential20_helpers[2].tail_call) && (r0 == 0))
#line 151 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 151 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 151 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 151 "sample/tail_call_sequential.c"
    return r0;
#line 151 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential21_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential21_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential21_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential21_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~22")
static uint64_t
sequential21(void* context)
#line 152 "sample/tail_call_sequential.c"
{
#line 152 "sample/tail_call_sequential.c"
    // Prologue
#line 152 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 152 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 152 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 152 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 152 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 152 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 152 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 152 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 152 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 152 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 152 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 152 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 152 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 152 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 152 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 152 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 152 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 152 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 152 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 152 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 152 "sample/tail_call_sequential.c"
    r0 = sequential21_helpers[0].address
#line 152 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 152 "sample/tail_call_sequential.c"
    if ((sequential21_helpers[0].tail_call) && (r0 == 0))
#line 152 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 152 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 152 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 152 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 152 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 152 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 152 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 152 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=825388129
#line 152 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479802924129;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 152 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 152 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 152 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 152 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 152 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 152 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 152 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 152 "sample/tail_call_sequential.c"
    r0 = sequential21_helpers[1].address
#line 152 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 152 "sample/tail_call_sequential.c"
    if ((sequential21_helpers[1].tail_call) && (r0 == 0))
#line 152 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 152 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=21
#line 152 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(21))
#line 152 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=22
#line 152 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(22);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 152 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 152 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 152 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=22
#line 152 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(22);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 152 "sample/tail_call_sequential.c"
    r0 = sequential21_helpers[2].address
#line 152 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 152 "sample/tail_call_sequential.c"
    if ((sequential21_helpers[2].tail_call) && (r0 == 0))
#line 152 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 152 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 152 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 152 "sample/tail_call_sequential.c"
    return r0;
#line 152 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential22_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential22_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential22_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential22_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~23")
static uint64_t
sequential22(void* context)
#line 153 "sample/tail_call_sequential.c"
{
#line 153 "sample/tail_call_sequential.c"
    // Prologue
#line 153 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 153 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 153 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 153 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 153 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 153 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 153 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 153 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 153 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 153 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 153 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 153 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 153 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 153 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 153 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 153 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 153 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 153 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 153 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 153 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 153 "sample/tail_call_sequential.c"
    r0 = sequential22_helpers[0].address
#line 153 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 153 "sample/tail_call_sequential.c"
    if ((sequential22_helpers[0].tail_call) && (r0 == 0))
#line 153 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 153 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 153 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 153 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 153 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 153 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 153 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 153 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=842165345
#line 153 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479819701345;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 153 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 153 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 153 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 153 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 153 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 153 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 153 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 153 "sample/tail_call_sequential.c"
    r0 = sequential22_helpers[1].address
#line 153 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 153 "sample/tail_call_sequential.c"
    if ((sequential22_helpers[1].tail_call) && (r0 == 0))
#line 153 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 153 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=22
#line 153 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(22))
#line 153 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=23
#line 153 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(23);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 153 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 153 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 153 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=23
#line 153 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(23);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 153 "sample/tail_call_sequential.c"
    r0 = sequential22_helpers[2].address
#line 153 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 153 "sample/tail_call_sequential.c"
    if ((sequential22_helpers[2].tail_call) && (r0 == 0))
#line 153 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 153 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 153 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 153 "sample/tail_call_sequential.c"
    return r0;
#line 153 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential23_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential23_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential23_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential23_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~24")
static uint64_t
sequential23(void* context)
#line 154 "sample/tail_call_sequential.c"
{
#line 154 "sample/tail_call_sequential.c"
    // Prologue
#line 154 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 154 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 154 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 154 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 154 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 154 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 154 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 154 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 154 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 154 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 154 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 154 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 154 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 154 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 154 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 154 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 154 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 154 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 154 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 154 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 154 "sample/tail_call_sequential.c"
    r0 = sequential23_helpers[0].address
#line 154 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 154 "sample/tail_call_sequential.c"
    if ((sequential23_helpers[0].tail_call) && (r0 == 0))
#line 154 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 154 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 154 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 154 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 154 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 154 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 154 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 154 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=858942561
#line 154 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479836478561;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 154 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 154 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 154 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 154 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 154 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 154 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 154 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 154 "sample/tail_call_sequential.c"
    r0 = sequential23_helpers[1].address
#line 154 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 154 "sample/tail_call_sequential.c"
    if ((sequential23_helpers[1].tail_call) && (r0 == 0))
#line 154 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 154 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=23
#line 154 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(23))
#line 154 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=24
#line 154 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(24);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 154 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 154 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 154 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=24
#line 154 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 154 "sample/tail_call_sequential.c"
    r0 = sequential23_helpers[2].address
#line 154 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 154 "sample/tail_call_sequential.c"
    if ((sequential23_helpers[2].tail_call) && (r0 == 0))
#line 154 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 154 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 154 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 154 "sample/tail_call_sequential.c"
    return r0;
#line 154 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential24_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential24_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential24_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential24_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~25")
static uint64_t
sequential24(void* context)
#line 155 "sample/tail_call_sequential.c"
{
#line 155 "sample/tail_call_sequential.c"
    // Prologue
#line 155 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 155 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 155 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 155 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 155 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 155 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 155 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 155 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 155 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 155 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 155 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 155 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 155 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 155 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 155 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 155 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 155 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 155 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 155 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 155 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 155 "sample/tail_call_sequential.c"
    r0 = sequential24_helpers[0].address
#line 155 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 155 "sample/tail_call_sequential.c"
    if ((sequential24_helpers[0].tail_call) && (r0 == 0))
#line 155 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 155 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 155 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 155 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 155 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 155 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 155 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 155 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=875719777
#line 155 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479853255777;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 155 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 155 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 155 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 155 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 155 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 155 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r9 src=r0 offset=0 imm=25
#line 155 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(25);
    // EBPF_OP_MOV64_IMM pc=25 dst=r2 src=r0 offset=0 imm=25
#line 155 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=26 dst=r0 src=r0 offset=0 imm=13
#line 155 "sample/tail_call_sequential.c"
    r0 = sequential24_helpers[1].address
#line 155 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 155 "sample/tail_call_sequential.c"
    if ((sequential24_helpers[1].tail_call) && (r0 == 0))
#line 155 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=27 dst=r1 src=r8 offset=0 imm=0
#line 155 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=28 dst=r1 src=r0 offset=7 imm=24
#line 155 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(24))
#line 155 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXW pc=29 dst=r8 src=r9 offset=0 imm=0
#line 155 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 155 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 155 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=25
#line 155 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 155 "sample/tail_call_sequential.c"
    r0 = sequential24_helpers[2].address
#line 155 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 155 "sample/tail_call_sequential.c"
    if ((sequential24_helpers[2].tail_call) && (r0 == 0))
#line 155 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 155 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 155 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 155 "sample/tail_call_sequential.c"
    return r0;
#line 155 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential25_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential25_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential25_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential25_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~26")
static uint64_t
sequential25(void* context)
#line 156 "sample/tail_call_sequential.c"
{
#line 156 "sample/tail_call_sequential.c"
    // Prologue
#line 156 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 156 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 156 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 156 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 156 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 156 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 156 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 156 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 156 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 156 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 156 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 156 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 156 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 156 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 156 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 156 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 156 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 156 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 156 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 156 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 156 "sample/tail_call_sequential.c"
    r0 = sequential25_helpers[0].address
#line 156 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 156 "sample/tail_call_sequential.c"
    if ((sequential25_helpers[0].tail_call) && (r0 == 0))
#line 156 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 156 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 156 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 156 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 156 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 156 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 156 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 156 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=892496993
#line 156 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479870032993;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 156 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 156 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 156 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 156 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 156 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 156 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 156 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 156 "sample/tail_call_sequential.c"
    r0 = sequential25_helpers[1].address
#line 156 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 156 "sample/tail_call_sequential.c"
    if ((sequential25_helpers[1].tail_call) && (r0 == 0))
#line 156 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 156 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=25
#line 156 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(25))
#line 156 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=26
#line 156 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(26);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 156 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 156 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 156 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=26
#line 156 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(26);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 156 "sample/tail_call_sequential.c"
    r0 = sequential25_helpers[2].address
#line 156 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 156 "sample/tail_call_sequential.c"
    if ((sequential25_helpers[2].tail_call) && (r0 == 0))
#line 156 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 156 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 156 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 156 "sample/tail_call_sequential.c"
    return r0;
#line 156 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential26_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential26_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential26_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential26_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~27")
static uint64_t
sequential26(void* context)
#line 157 "sample/tail_call_sequential.c"
{
#line 157 "sample/tail_call_sequential.c"
    // Prologue
#line 157 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 157 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 157 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 157 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 157 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 157 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 157 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 157 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 157 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 157 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 157 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 157 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 157 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 157 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 157 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 157 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 157 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 157 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 157 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 157 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 157 "sample/tail_call_sequential.c"
    r0 = sequential26_helpers[0].address
#line 157 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 157 "sample/tail_call_sequential.c"
    if ((sequential26_helpers[0].tail_call) && (r0 == 0))
#line 157 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 157 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 157 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 157 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 157 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 157 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 157 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 157 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=909274209
#line 157 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479886810209;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 157 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 157 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 157 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 157 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 157 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 157 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 157 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 157 "sample/tail_call_sequential.c"
    r0 = sequential26_helpers[1].address
#line 157 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 157 "sample/tail_call_sequential.c"
    if ((sequential26_helpers[1].tail_call) && (r0 == 0))
#line 157 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 157 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=26
#line 157 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(26))
#line 157 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=27
#line 157 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(27);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 157 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 157 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 157 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=27
#line 157 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(27);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 157 "sample/tail_call_sequential.c"
    r0 = sequential26_helpers[2].address
#line 157 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 157 "sample/tail_call_sequential.c"
    if ((sequential26_helpers[2].tail_call) && (r0 == 0))
#line 157 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 157 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 157 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 157 "sample/tail_call_sequential.c"
    return r0;
#line 157 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential27_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential27_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential27_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential27_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~28")
static uint64_t
sequential27(void* context)
#line 158 "sample/tail_call_sequential.c"
{
#line 158 "sample/tail_call_sequential.c"
    // Prologue
#line 158 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 158 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 158 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 158 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 158 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 158 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 158 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 158 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 158 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 158 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 158 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 158 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 158 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 158 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 158 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 158 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 158 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 158 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 158 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 158 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 158 "sample/tail_call_sequential.c"
    r0 = sequential27_helpers[0].address
#line 158 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 158 "sample/tail_call_sequential.c"
    if ((sequential27_helpers[0].tail_call) && (r0 == 0))
#line 158 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 158 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 158 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 158 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 158 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 158 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 158 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 158 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=926051425
#line 158 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479903587425;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 158 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 158 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 158 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 158 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 158 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 158 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 158 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 158 "sample/tail_call_sequential.c"
    r0 = sequential27_helpers[1].address
#line 158 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 158 "sample/tail_call_sequential.c"
    if ((sequential27_helpers[1].tail_call) && (r0 == 0))
#line 158 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 158 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=27
#line 158 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(27))
#line 158 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=28
#line 158 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(28);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 158 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 158 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 158 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=28
#line 158 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(28);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 158 "sample/tail_call_sequential.c"
    r0 = sequential27_helpers[2].address
#line 158 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 158 "sample/tail_call_sequential.c"
    if ((sequential27_helpers[2].tail_call) && (r0 == 0))
#line 158 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 158 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 158 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 158 "sample/tail_call_sequential.c"
    return r0;
#line 158 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential28_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential28_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential28_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential28_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~29")
static uint64_t
sequential28(void* context)
#line 159 "sample/tail_call_sequential.c"
{
#line 159 "sample/tail_call_sequential.c"
    // Prologue
#line 159 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 159 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 159 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 159 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 159 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 159 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 159 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 159 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 159 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 159 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 159 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 159 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 159 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 159 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 159 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 159 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 159 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 159 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 159 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 159 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 159 "sample/tail_call_sequential.c"
    r0 = sequential28_helpers[0].address
#line 159 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 159 "sample/tail_call_sequential.c"
    if ((sequential28_helpers[0].tail_call) && (r0 == 0))
#line 159 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 159 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 159 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 159 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 159 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 159 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 159 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 159 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=942828641
#line 159 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479920364641;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 159 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 159 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 159 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 159 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 159 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 159 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 159 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 159 "sample/tail_call_sequential.c"
    r0 = sequential28_helpers[1].address
#line 159 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 159 "sample/tail_call_sequential.c"
    if ((sequential28_helpers[1].tail_call) && (r0 == 0))
#line 159 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 159 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=28
#line 159 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(28))
#line 159 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=29
#line 159 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(29);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 159 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 159 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 159 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=29
#line 159 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(29);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 159 "sample/tail_call_sequential.c"
    r0 = sequential28_helpers[2].address
#line 159 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 159 "sample/tail_call_sequential.c"
    if ((sequential28_helpers[2].tail_call) && (r0 == 0))
#line 159 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 159 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 159 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 159 "sample/tail_call_sequential.c"
    return r0;
#line 159 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential29_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential29_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential29_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential29_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~30")
static uint64_t
sequential29(void* context)
#line 160 "sample/tail_call_sequential.c"
{
#line 160 "sample/tail_call_sequential.c"
    // Prologue
#line 160 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 160 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 160 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 160 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 160 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 160 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 160 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 160 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 160 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 160 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 160 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 160 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 160 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 160 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 160 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 160 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 160 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 160 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 160 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 160 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 160 "sample/tail_call_sequential.c"
    r0 = sequential29_helpers[0].address
#line 160 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 160 "sample/tail_call_sequential.c"
    if ((sequential29_helpers[0].tail_call) && (r0 == 0))
#line 160 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 160 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 160 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 160 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 160 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 160 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 160 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 160 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=959605857
#line 160 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479937141857;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 160 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 160 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 160 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 160 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 160 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 160 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 160 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 160 "sample/tail_call_sequential.c"
    r0 = sequential29_helpers[1].address
#line 160 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 160 "sample/tail_call_sequential.c"
    if ((sequential29_helpers[1].tail_call) && (r0 == 0))
#line 160 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 160 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=29
#line 160 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(29))
#line 160 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=30
#line 160 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(30);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 160 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 160 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 160 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=30
#line 160 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(30);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 160 "sample/tail_call_sequential.c"
    r0 = sequential29_helpers[2].address
#line 160 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 160 "sample/tail_call_sequential.c"
    if ((sequential29_helpers[2].tail_call) && (r0 == 0))
#line 160 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 160 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 160 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 160 "sample/tail_call_sequential.c"
    return r0;
#line 160 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential3_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential3_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential3_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential3_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_pr~4")
static uint64_t
sequential3(void* context)
#line 134 "sample/tail_call_sequential.c"
{
#line 134 "sample/tail_call_sequential.c"
    // Prologue
#line 134 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 134 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 134 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 134 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 134 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 134 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 134 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 134 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 134 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 134 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 134 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 134 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 134 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 134 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 134 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 134 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 134 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 134 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 134 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 134 "sample/tail_call_sequential.c"
    r0 = sequential3_helpers[0].address
#line 134 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 134 "sample/tail_call_sequential.c"
    if ((sequential3_helpers[0].tail_call) && (r0 == 0))
#line 134 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 134 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 134 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 134 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 134 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 134 "sample/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 134 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976448609
#line 134 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834635873;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 134 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 134 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 134 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 134 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 134 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 134 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 134 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 134 "sample/tail_call_sequential.c"
    r0 = sequential3_helpers[1].address
#line 134 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 134 "sample/tail_call_sequential.c"
    if ((sequential3_helpers[1].tail_call) && (r0 == 0))
#line 134 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 134 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=3
#line 134 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(3))
#line 134 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=4
#line 134 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 134 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 134 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r0 offset=0 imm=0
#line 134 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=4
#line 134 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 134 "sample/tail_call_sequential.c"
    r0 = sequential3_helpers[2].address
#line 134 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 134 "sample/tail_call_sequential.c"
    if ((sequential3_helpers[2].tail_call) && (r0 == 0))
#line 134 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 134 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 134 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 134 "sample/tail_call_sequential.c"
    return r0;
#line 134 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential30_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential30_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential30_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential30_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~31")
static uint64_t
sequential30(void* context)
#line 161 "sample/tail_call_sequential.c"
{
#line 161 "sample/tail_call_sequential.c"
    // Prologue
#line 161 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 161 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 161 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 161 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 161 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 161 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 161 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 161 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 161 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 161 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 161 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 161 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 161 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 161 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 161 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 161 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 161 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 161 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 161 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 161 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 161 "sample/tail_call_sequential.c"
    r0 = sequential30_helpers[0].address
#line 161 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 161 "sample/tail_call_sequential.c"
    if ((sequential30_helpers[0].tail_call) && (r0 == 0))
#line 161 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 161 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 161 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 161 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 161 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 161 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 161 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 161 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=808676449
#line 161 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479786212449;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 161 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 161 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 161 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 161 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 161 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 161 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 161 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 161 "sample/tail_call_sequential.c"
    r0 = sequential30_helpers[1].address
#line 161 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 161 "sample/tail_call_sequential.c"
    if ((sequential30_helpers[1].tail_call) && (r0 == 0))
#line 161 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 161 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=30
#line 161 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(30))
#line 161 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=31
#line 161 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(31);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 161 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 161 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 161 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=31
#line 161 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(31);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 161 "sample/tail_call_sequential.c"
    r0 = sequential30_helpers[2].address
#line 161 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 161 "sample/tail_call_sequential.c"
    if ((sequential30_helpers[2].tail_call) && (r0 == 0))
#line 161 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 161 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 161 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 161 "sample/tail_call_sequential.c"
    return r0;
#line 161 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential31_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential31_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential31_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential31_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~32")
static uint64_t
sequential31(void* context)
#line 162 "sample/tail_call_sequential.c"
{
#line 162 "sample/tail_call_sequential.c"
    // Prologue
#line 162 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 162 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 162 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 162 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 162 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 162 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 162 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 162 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 162 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 162 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 162 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 162 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 162 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 162 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 162 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 162 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 162 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 162 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 162 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 162 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 162 "sample/tail_call_sequential.c"
    r0 = sequential31_helpers[0].address
#line 162 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 162 "sample/tail_call_sequential.c"
    if ((sequential31_helpers[0].tail_call) && (r0 == 0))
#line 162 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 162 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 162 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 162 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 162 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 162 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 162 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 162 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=825453665
#line 162 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479802989665;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 162 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 162 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 162 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 162 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 162 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 162 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 162 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 162 "sample/tail_call_sequential.c"
    r0 = sequential31_helpers[1].address
#line 162 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 162 "sample/tail_call_sequential.c"
    if ((sequential31_helpers[1].tail_call) && (r0 == 0))
#line 162 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 162 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=31
#line 162 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(31))
#line 162 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=32
#line 162 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(32);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 162 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 162 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 162 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=32
#line 162 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 162 "sample/tail_call_sequential.c"
    r0 = sequential31_helpers[2].address
#line 162 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 162 "sample/tail_call_sequential.c"
    if ((sequential31_helpers[2].tail_call) && (r0 == 0))
#line 162 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 162 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 162 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 162 "sample/tail_call_sequential.c"
    return r0;
#line 162 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential32_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential32_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential32_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential32_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~33")
static uint64_t
sequential32(void* context)
#line 163 "sample/tail_call_sequential.c"
{
#line 163 "sample/tail_call_sequential.c"
    // Prologue
#line 163 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 163 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 163 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 163 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 163 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 163 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 163 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 163 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 163 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 163 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 163 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 163 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 163 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 163 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 163 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 163 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 163 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 163 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 163 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 163 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 163 "sample/tail_call_sequential.c"
    r0 = sequential32_helpers[0].address
#line 163 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 163 "sample/tail_call_sequential.c"
    if ((sequential32_helpers[0].tail_call) && (r0 == 0))
#line 163 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 163 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 163 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 163 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 163 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 163 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 163 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 163 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=842230881
#line 163 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479819766881;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 163 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 163 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 163 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 163 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 163 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 163 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 163 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 163 "sample/tail_call_sequential.c"
    r0 = sequential32_helpers[1].address
#line 163 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 163 "sample/tail_call_sequential.c"
    if ((sequential32_helpers[1].tail_call) && (r0 == 0))
#line 163 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 163 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=32
#line 163 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(32))
#line 163 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=33
#line 163 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(33);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 163 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 163 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 163 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=33
#line 163 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(33);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 163 "sample/tail_call_sequential.c"
    r0 = sequential32_helpers[2].address
#line 163 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 163 "sample/tail_call_sequential.c"
    if ((sequential32_helpers[2].tail_call) && (r0 == 0))
#line 163 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 163 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 163 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 163 "sample/tail_call_sequential.c"
    return r0;
#line 163 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential4_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential4_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential4_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential4_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_pr~5")
static uint64_t
sequential4(void* context)
#line 135 "sample/tail_call_sequential.c"
{
#line 135 "sample/tail_call_sequential.c"
    // Prologue
#line 135 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 135 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 135 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 135 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 135 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 135 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 135 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 135 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 135 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 135 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 135 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 135 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 135 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 135 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 135 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 135 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 135 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 135 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 135 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 135 "sample/tail_call_sequential.c"
    r0 = sequential4_helpers[0].address
#line 135 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 135 "sample/tail_call_sequential.c"
    if ((sequential4_helpers[0].tail_call) && (r0 == 0))
#line 135 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 135 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 135 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 135 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 135 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 135 "sample/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 135 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976514145
#line 135 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834701409;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 135 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 135 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 135 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 135 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 135 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 135 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 135 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 135 "sample/tail_call_sequential.c"
    r0 = sequential4_helpers[1].address
#line 135 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 135 "sample/tail_call_sequential.c"
    if ((sequential4_helpers[1].tail_call) && (r0 == 0))
#line 135 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 135 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=4
#line 135 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(4))
#line 135 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=5
#line 135 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 135 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 135 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r0 offset=0 imm=0
#line 135 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=5
#line 135 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(5);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 135 "sample/tail_call_sequential.c"
    r0 = sequential4_helpers[2].address
#line 135 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 135 "sample/tail_call_sequential.c"
    if ((sequential4_helpers[2].tail_call) && (r0 == 0))
#line 135 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 135 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 135 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 135 "sample/tail_call_sequential.c"
    return r0;
#line 135 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential5_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential5_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential5_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential5_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_pr~6")
static uint64_t
sequential5(void* context)
#line 136 "sample/tail_call_sequential.c"
{
#line 136 "sample/tail_call_sequential.c"
    // Prologue
#line 136 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 136 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 136 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 136 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 136 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 136 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 136 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 136 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 136 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 136 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 136 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 136 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 136 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 136 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 136 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 136 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 136 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 136 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 136 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 136 "sample/tail_call_sequential.c"
    r0 = sequential5_helpers[0].address
#line 136 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 136 "sample/tail_call_sequential.c"
    if ((sequential5_helpers[0].tail_call) && (r0 == 0))
#line 136 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 136 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 136 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 136 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 136 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 136 "sample/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 136 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976579681
#line 136 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834766945;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 136 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 136 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 136 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 136 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 136 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 136 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 136 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 136 "sample/tail_call_sequential.c"
    r0 = sequential5_helpers[1].address
#line 136 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 136 "sample/tail_call_sequential.c"
    if ((sequential5_helpers[1].tail_call) && (r0 == 0))
#line 136 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 136 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=5
#line 136 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(5))
#line 136 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=6
#line 136 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 136 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 136 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r0 offset=0 imm=0
#line 136 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=6
#line 136 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(6);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 136 "sample/tail_call_sequential.c"
    r0 = sequential5_helpers[2].address
#line 136 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 136 "sample/tail_call_sequential.c"
    if ((sequential5_helpers[2].tail_call) && (r0 == 0))
#line 136 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 136 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 136 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 136 "sample/tail_call_sequential.c"
    return r0;
#line 136 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential6_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential6_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential6_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential6_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_pr~7")
static uint64_t
sequential6(void* context)
#line 137 "sample/tail_call_sequential.c"
{
#line 137 "sample/tail_call_sequential.c"
    // Prologue
#line 137 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 137 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 137 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 137 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 137 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 137 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 137 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 137 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 137 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 137 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 137 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 137 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 137 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 137 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 137 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 137 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 137 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 137 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 137 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 137 "sample/tail_call_sequential.c"
    r0 = sequential6_helpers[0].address
#line 137 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 137 "sample/tail_call_sequential.c"
    if ((sequential6_helpers[0].tail_call) && (r0 == 0))
#line 137 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 137 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 137 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 137 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 137 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 137 "sample/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 137 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976645217
#line 137 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834832481;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 137 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 137 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 137 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 137 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 137 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 137 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 137 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 137 "sample/tail_call_sequential.c"
    r0 = sequential6_helpers[1].address
#line 137 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 137 "sample/tail_call_sequential.c"
    if ((sequential6_helpers[1].tail_call) && (r0 == 0))
#line 137 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 137 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=6
#line 137 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(6))
#line 137 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=7
#line 137 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 137 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 137 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r0 offset=0 imm=0
#line 137 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=7
#line 137 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(7);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 137 "sample/tail_call_sequential.c"
    r0 = sequential6_helpers[2].address
#line 137 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 137 "sample/tail_call_sequential.c"
    if ((sequential6_helpers[2].tail_call) && (r0 == 0))
#line 137 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 137 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 137 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 137 "sample/tail_call_sequential.c"
    return r0;
#line 137 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential7_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential7_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential7_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential7_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_pr~8")
static uint64_t
sequential7(void* context)
#line 138 "sample/tail_call_sequential.c"
{
#line 138 "sample/tail_call_sequential.c"
    // Prologue
#line 138 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 138 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 138 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 138 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 138 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 138 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 138 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 138 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 138 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 138 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 138 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 138 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 138 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 138 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 138 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 138 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 138 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 138 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 138 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 138 "sample/tail_call_sequential.c"
    r0 = sequential7_helpers[0].address
#line 138 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 138 "sample/tail_call_sequential.c"
    if ((sequential7_helpers[0].tail_call) && (r0 == 0))
#line 138 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 138 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 138 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 138 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 138 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 138 "sample/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 138 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976710753
#line 138 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834898017;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 138 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 138 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 138 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 138 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 138 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 138 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 138 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 138 "sample/tail_call_sequential.c"
    r0 = sequential7_helpers[1].address
#line 138 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 138 "sample/tail_call_sequential.c"
    if ((sequential7_helpers[1].tail_call) && (r0 == 0))
#line 138 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 138 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=7
#line 138 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(7))
#line 138 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=8
#line 138 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 138 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 138 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r0 offset=0 imm=0
#line 138 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=8
#line 138 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(8);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 138 "sample/tail_call_sequential.c"
    r0 = sequential7_helpers[2].address
#line 138 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 138 "sample/tail_call_sequential.c"
    if ((sequential7_helpers[2].tail_call) && (r0 == 0))
#line 138 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 138 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 138 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 138 "sample/tail_call_sequential.c"
    return r0;
#line 138 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential8_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential8_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential8_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential8_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_pr~9")
static uint64_t
sequential8(void* context)
#line 139 "sample/tail_call_sequential.c"
{
#line 139 "sample/tail_call_sequential.c"
    // Prologue
#line 139 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 139 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 139 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 139 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 139 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 139 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 139 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 139 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 139 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 139 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 139 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 139 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 139 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 139 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 139 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 139 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 139 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 139 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 139 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 139 "sample/tail_call_sequential.c"
    r0 = sequential8_helpers[0].address
#line 139 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 139 "sample/tail_call_sequential.c"
    if ((sequential8_helpers[0].tail_call) && (r0 == 0))
#line 139 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 139 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 139 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 139 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 139 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 139 "sample/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 139 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976776289
#line 139 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834963553;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 139 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 139 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 139 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 139 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 139 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 139 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 139 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 139 "sample/tail_call_sequential.c"
    r0 = sequential8_helpers[1].address
#line 139 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 139 "sample/tail_call_sequential.c"
    if ((sequential8_helpers[1].tail_call) && (r0 == 0))
#line 139 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 139 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=8
#line 139 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(8))
#line 139 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=9
#line 139 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 139 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 139 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r0 offset=0 imm=0
#line 139 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=9
#line 139 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(9);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 139 "sample/tail_call_sequential.c"
    r0 = sequential8_helpers[2].address
#line 139 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 139 "sample/tail_call_sequential.c"
    if ((sequential8_helpers[2].tail_call) && (r0 == 0))
#line 139 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 139 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 139 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 139 "sample/tail_call_sequential.c"
    return r0;
#line 139 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential9_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID sequential9_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID sequential9_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t sequential9_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp_p~10")
static uint64_t
sequential9(void* context)
#line 140 "sample/tail_call_sequential.c"
{
#line 140 "sample/tail_call_sequential.c"
    // Prologue
#line 140 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 140 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 140 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 140 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 140 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 140 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 140 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 140 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 140 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 140 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 140 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 140 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 140 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 140 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 140 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 140 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 140 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 140 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 140 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 140 "sample/tail_call_sequential.c"
    r0 = sequential9_helpers[0].address
#line 140 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 140 "sample/tail_call_sequential.c"
    if ((sequential9_helpers[0].tail_call) && (r0 == 0))
#line 140 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 140 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 140 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 140 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 140 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 140 "sample/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 140 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976841825
#line 140 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7022846986835029089;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 140 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 140 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 140 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 140 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 140 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 140 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 140 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 140 "sample/tail_call_sequential.c"
    r0 = sequential9_helpers[1].address
#line 140 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 140 "sample/tail_call_sequential.c"
    if ((sequential9_helpers[1].tail_call) && (r0 == 0))
#line 140 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 140 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=9
#line 140 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(9))
#line 140 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=10
#line 140 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 140 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 140 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r0 offset=0 imm=0
#line 140 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=10
#line 140 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(10);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 140 "sample/tail_call_sequential.c"
    r0 = sequential9_helpers[2].address
#line 140 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 140 "sample/tail_call_sequential.c"
    if ((sequential9_helpers[2].tail_call) && (r0 == 0))
#line 140 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 140 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 140 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 140 "sample/tail_call_sequential.c"
    return r0;
#line 140 "sample/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        sequential0,
        "xdp_pr~1",
        "xdp_prog0",
        "sequential0",
        sequential0_maps,
        2,
        sequential0_helpers,
        3,
        37,
        &sequential0_program_type_guid,
        &sequential0_attach_type_guid,
    },
    {
        0,
        sequential1,
        "xdp_pr~2",
        "xdp_prog1",
        "sequential1",
        sequential1_maps,
        2,
        sequential1_helpers,
        3,
        37,
        &sequential1_program_type_guid,
        &sequential1_attach_type_guid,
    },
    {
        0,
        sequential10,
        "xdp_p~11",
        "xdp_prog10",
        "sequential10",
        sequential10_maps,
        2,
        sequential10_helpers,
        3,
        38,
        &sequential10_program_type_guid,
        &sequential10_attach_type_guid,
    },
    {
        0,
        sequential11,
        "xdp_p~12",
        "xdp_prog11",
        "sequential11",
        sequential11_maps,
        2,
        sequential11_helpers,
        3,
        38,
        &sequential11_program_type_guid,
        &sequential11_attach_type_guid,
    },
    {
        0,
        sequential12,
        "xdp_p~13",
        "xdp_prog12",
        "sequential12",
        sequential12_maps,
        2,
        sequential12_helpers,
        3,
        38,
        &sequential12_program_type_guid,
        &sequential12_attach_type_guid,
    },
    {
        0,
        sequential13,
        "xdp_p~14",
        "xdp_prog13",
        "sequential13",
        sequential13_maps,
        2,
        sequential13_helpers,
        3,
        38,
        &sequential13_program_type_guid,
        &sequential13_attach_type_guid,
    },
    {
        0,
        sequential14,
        "xdp_p~15",
        "xdp_prog14",
        "sequential14",
        sequential14_maps,
        2,
        sequential14_helpers,
        3,
        38,
        &sequential14_program_type_guid,
        &sequential14_attach_type_guid,
    },
    {
        0,
        sequential15,
        "xdp_p~16",
        "xdp_prog15",
        "sequential15",
        sequential15_maps,
        2,
        sequential15_helpers,
        3,
        38,
        &sequential15_program_type_guid,
        &sequential15_attach_type_guid,
    },
    {
        0,
        sequential16,
        "xdp_p~17",
        "xdp_prog16",
        "sequential16",
        sequential16_maps,
        2,
        sequential16_helpers,
        3,
        38,
        &sequential16_program_type_guid,
        &sequential16_attach_type_guid,
    },
    {
        0,
        sequential17,
        "xdp_p~18",
        "xdp_prog17",
        "sequential17",
        sequential17_maps,
        2,
        sequential17_helpers,
        3,
        38,
        &sequential17_program_type_guid,
        &sequential17_attach_type_guid,
    },
    {
        0,
        sequential18,
        "xdp_p~19",
        "xdp_prog18",
        "sequential18",
        sequential18_maps,
        2,
        sequential18_helpers,
        3,
        38,
        &sequential18_program_type_guid,
        &sequential18_attach_type_guid,
    },
    {
        0,
        sequential19,
        "xdp_p~20",
        "xdp_prog19",
        "sequential19",
        sequential19_maps,
        2,
        sequential19_helpers,
        3,
        38,
        &sequential19_program_type_guid,
        &sequential19_attach_type_guid,
    },
    {
        0,
        sequential2,
        "xdp_pr~3",
        "xdp_prog2",
        "sequential2",
        sequential2_maps,
        2,
        sequential2_helpers,
        3,
        37,
        &sequential2_program_type_guid,
        &sequential2_attach_type_guid,
    },
    {
        0,
        sequential20,
        "xdp_p~21",
        "xdp_prog20",
        "sequential20",
        sequential20_maps,
        2,
        sequential20_helpers,
        3,
        38,
        &sequential20_program_type_guid,
        &sequential20_attach_type_guid,
    },
    {
        0,
        sequential21,
        "xdp_p~22",
        "xdp_prog21",
        "sequential21",
        sequential21_maps,
        2,
        sequential21_helpers,
        3,
        38,
        &sequential21_program_type_guid,
        &sequential21_attach_type_guid,
    },
    {
        0,
        sequential22,
        "xdp_p~23",
        "xdp_prog22",
        "sequential22",
        sequential22_maps,
        2,
        sequential22_helpers,
        3,
        38,
        &sequential22_program_type_guid,
        &sequential22_attach_type_guid,
    },
    {
        0,
        sequential23,
        "xdp_p~24",
        "xdp_prog23",
        "sequential23",
        sequential23_maps,
        2,
        sequential23_helpers,
        3,
        38,
        &sequential23_program_type_guid,
        &sequential23_attach_type_guid,
    },
    {
        0,
        sequential24,
        "xdp_p~25",
        "xdp_prog24",
        "sequential24",
        sequential24_maps,
        2,
        sequential24_helpers,
        3,
        38,
        &sequential24_program_type_guid,
        &sequential24_attach_type_guid,
    },
    {
        0,
        sequential25,
        "xdp_p~26",
        "xdp_prog25",
        "sequential25",
        sequential25_maps,
        2,
        sequential25_helpers,
        3,
        38,
        &sequential25_program_type_guid,
        &sequential25_attach_type_guid,
    },
    {
        0,
        sequential26,
        "xdp_p~27",
        "xdp_prog26",
        "sequential26",
        sequential26_maps,
        2,
        sequential26_helpers,
        3,
        38,
        &sequential26_program_type_guid,
        &sequential26_attach_type_guid,
    },
    {
        0,
        sequential27,
        "xdp_p~28",
        "xdp_prog27",
        "sequential27",
        sequential27_maps,
        2,
        sequential27_helpers,
        3,
        38,
        &sequential27_program_type_guid,
        &sequential27_attach_type_guid,
    },
    {
        0,
        sequential28,
        "xdp_p~29",
        "xdp_prog28",
        "sequential28",
        sequential28_maps,
        2,
        sequential28_helpers,
        3,
        38,
        &sequential28_program_type_guid,
        &sequential28_attach_type_guid,
    },
    {
        0,
        sequential29,
        "xdp_p~30",
        "xdp_prog29",
        "sequential29",
        sequential29_maps,
        2,
        sequential29_helpers,
        3,
        38,
        &sequential29_program_type_guid,
        &sequential29_attach_type_guid,
    },
    {
        0,
        sequential3,
        "xdp_pr~4",
        "xdp_prog3",
        "sequential3",
        sequential3_maps,
        2,
        sequential3_helpers,
        3,
        37,
        &sequential3_program_type_guid,
        &sequential3_attach_type_guid,
    },
    {
        0,
        sequential30,
        "xdp_p~31",
        "xdp_prog30",
        "sequential30",
        sequential30_maps,
        2,
        sequential30_helpers,
        3,
        38,
        &sequential30_program_type_guid,
        &sequential30_attach_type_guid,
    },
    {
        0,
        sequential31,
        "xdp_p~32",
        "xdp_prog31",
        "sequential31",
        sequential31_maps,
        2,
        sequential31_helpers,
        3,
        38,
        &sequential31_program_type_guid,
        &sequential31_attach_type_guid,
    },
    {
        0,
        sequential32,
        "xdp_p~33",
        "xdp_prog32",
        "sequential32",
        sequential32_maps,
        2,
        sequential32_helpers,
        3,
        38,
        &sequential32_program_type_guid,
        &sequential32_attach_type_guid,
    },
    {
        0,
        sequential4,
        "xdp_pr~5",
        "xdp_prog4",
        "sequential4",
        sequential4_maps,
        2,
        sequential4_helpers,
        3,
        37,
        &sequential4_program_type_guid,
        &sequential4_attach_type_guid,
    },
    {
        0,
        sequential5,
        "xdp_pr~6",
        "xdp_prog5",
        "sequential5",
        sequential5_maps,
        2,
        sequential5_helpers,
        3,
        37,
        &sequential5_program_type_guid,
        &sequential5_attach_type_guid,
    },
    {
        0,
        sequential6,
        "xdp_pr~7",
        "xdp_prog6",
        "sequential6",
        sequential6_maps,
        2,
        sequential6_helpers,
        3,
        37,
        &sequential6_program_type_guid,
        &sequential6_attach_type_guid,
    },
    {
        0,
        sequential7,
        "xdp_pr~8",
        "xdp_prog7",
        "sequential7",
        sequential7_maps,
        2,
        sequential7_helpers,
        3,
        37,
        &sequential7_program_type_guid,
        &sequential7_attach_type_guid,
    },
    {
        0,
        sequential8,
        "xdp_pr~9",
        "xdp_prog8",
        "sequential8",
        sequential8_maps,
        2,
        sequential8_helpers,
        3,
        37,
        &sequential8_program_type_guid,
        &sequential8_attach_type_guid,
    },
    {
        0,
        sequential9,
        "xdp_p~10",
        "xdp_prog9",
        "sequential9",
        sequential9_maps,
        2,
        sequential9_helpers,
        3,
        37,
        &sequential9_program_type_guid,
        &sequential9_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 33;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = 0;
    version->minor = 10;
    version->revision = 0;
}

#pragma data_seg(push, "map_initial_values")
static const char* _map_initial_string_table[] = {
    "sequential0",
    "sequential1",
    "sequential2",
    "sequential3",
    "sequential4",
    "sequential5",
    "sequential6",
    "sequential7",
    "sequential8",
    "sequential9",
    "sequential10",
    "sequential11",
    "sequential12",
    "sequential13",
    "sequential14",
    "sequential15",
    "sequential16",
    "sequential17",
    "sequential18",
    "sequential19",
    "sequential20",
    "sequential21",
    "sequential22",
    "sequential23",
    "sequential24",
    "sequential25",
    "sequential26",
    "sequential27",
    "sequential28",
    "sequential29",
    "sequential30",
    "sequential31",
    "sequential32",
};

static map_initial_values_t _map_initial_values_array[] = {
    {
        .name = "map",
        .count = 33,
        .values = _map_initial_string_table,
    },
};
#pragma data_seg(pop)

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = _map_initial_values_array;
    *count = 1;
}

metadata_table_t tail_call_sequential_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};
