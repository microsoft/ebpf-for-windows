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
         33,                      // Maximum number of entries allowed in the map.
         0,                       // Inner map index.
         PIN_NONE,                // Pinning type for the map.
         0,                       // Identifier for a map template.
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
         0,                  // Identifier for a map template.
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
#line 44 "sample/tail_call_sequential.c"
{
#line 44 "sample/tail_call_sequential.c"
    // Prologue
#line 44 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 44 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 44 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 44 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 44 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 44 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 44 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 44 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 44 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 44 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 44 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 44 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 44 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 44 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 44 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 44 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 44 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 44 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 44 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 44 "sample/tail_call_sequential.c"
    r0 = sequential0_helpers[0].address
#line 44 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 44 "sample/tail_call_sequential.c"
    if ((sequential0_helpers[0].tail_call) && (r0 == 0))
#line 44 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 44 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 44 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 44 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 44 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 44 "sample/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 44 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976252001
#line 44 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834439265;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 44 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 44 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 44 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 44 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 44 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 44 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 44 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 44 "sample/tail_call_sequential.c"
    r0 = sequential0_helpers[1].address
#line 44 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 44 "sample/tail_call_sequential.c"
    if ((sequential0_helpers[1].tail_call) && (r0 == 0))
#line 44 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 44 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=0
#line 44 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(0))
#line 44 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=1
#line 44 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 44 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 44 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r0 offset=0 imm=0
#line 44 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=1
#line 44 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(1);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 44 "sample/tail_call_sequential.c"
    r0 = sequential0_helpers[2].address
#line 44 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 44 "sample/tail_call_sequential.c"
    if ((sequential0_helpers[2].tail_call) && (r0 == 0))
#line 44 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 44 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 44 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 44 "sample/tail_call_sequential.c"
    return r0;
#line 44 "sample/tail_call_sequential.c"
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
#line 45 "sample/tail_call_sequential.c"
{
#line 45 "sample/tail_call_sequential.c"
    // Prologue
#line 45 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 45 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 45 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 45 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 45 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 45 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 45 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 45 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 45 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 45 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 45 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 45 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 45 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 45 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 45 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 45 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 45 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 45 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 45 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 45 "sample/tail_call_sequential.c"
    r0 = sequential1_helpers[0].address
#line 45 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 45 "sample/tail_call_sequential.c"
    if ((sequential1_helpers[0].tail_call) && (r0 == 0))
#line 45 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 45 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 45 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 45 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 45 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 45 "sample/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 45 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976317537
#line 45 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834504801;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 45 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 45 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 45 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 45 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 45 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 45 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 45 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 45 "sample/tail_call_sequential.c"
    r0 = sequential1_helpers[1].address
#line 45 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 45 "sample/tail_call_sequential.c"
    if ((sequential1_helpers[1].tail_call) && (r0 == 0))
#line 45 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 45 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=1
#line 45 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(1))
#line 45 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=2
#line 45 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 45 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 45 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r0 offset=0 imm=0
#line 45 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=2
#line 45 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 45 "sample/tail_call_sequential.c"
    r0 = sequential1_helpers[2].address
#line 45 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 45 "sample/tail_call_sequential.c"
    if ((sequential1_helpers[2].tail_call) && (r0 == 0))
#line 45 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 45 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 45 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 45 "sample/tail_call_sequential.c"
    return r0;
#line 45 "sample/tail_call_sequential.c"
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
#line 54 "sample/tail_call_sequential.c"
{
#line 54 "sample/tail_call_sequential.c"
    // Prologue
#line 54 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 54 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 54 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 54 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 54 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 54 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 54 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 54 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 54 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 54 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 54 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 54 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 54 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 54 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 54 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 54 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 54 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 54 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 54 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 54 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 54 "sample/tail_call_sequential.c"
    r0 = sequential10_helpers[0].address
#line 54 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 54 "sample/tail_call_sequential.c"
    if ((sequential10_helpers[0].tail_call) && (r0 == 0))
#line 54 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 54 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 54 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 54 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 54 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 54 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 54 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 54 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=808545377
#line 54 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479786081377;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 54 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 54 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 54 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 54 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 54 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 54 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 54 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 54 "sample/tail_call_sequential.c"
    r0 = sequential10_helpers[1].address
#line 54 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 54 "sample/tail_call_sequential.c"
    if ((sequential10_helpers[1].tail_call) && (r0 == 0))
#line 54 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 54 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=10
#line 54 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(10))
#line 54 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=11
#line 54 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(11);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 54 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 54 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 54 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=11
#line 54 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(11);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 54 "sample/tail_call_sequential.c"
    r0 = sequential10_helpers[2].address
#line 54 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 54 "sample/tail_call_sequential.c"
    if ((sequential10_helpers[2].tail_call) && (r0 == 0))
#line 54 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 54 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 54 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 54 "sample/tail_call_sequential.c"
    return r0;
#line 54 "sample/tail_call_sequential.c"
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
#line 55 "sample/tail_call_sequential.c"
{
#line 55 "sample/tail_call_sequential.c"
    // Prologue
#line 55 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 55 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 55 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 55 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 55 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 55 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 55 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 55 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 55 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 55 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 55 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 55 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 55 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 55 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 55 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 55 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 55 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 55 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 55 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 55 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 55 "sample/tail_call_sequential.c"
    r0 = sequential11_helpers[0].address
#line 55 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 55 "sample/tail_call_sequential.c"
    if ((sequential11_helpers[0].tail_call) && (r0 == 0))
#line 55 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 55 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 55 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 55 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 55 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 55 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 55 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 55 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=825322593
#line 55 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479802858593;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 55 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 55 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 55 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 55 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 55 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 55 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 55 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 55 "sample/tail_call_sequential.c"
    r0 = sequential11_helpers[1].address
#line 55 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 55 "sample/tail_call_sequential.c"
    if ((sequential11_helpers[1].tail_call) && (r0 == 0))
#line 55 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 55 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=11
#line 55 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(11))
#line 55 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=12
#line 55 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(12);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 55 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 55 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 55 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=12
#line 55 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(12);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 55 "sample/tail_call_sequential.c"
    r0 = sequential11_helpers[2].address
#line 55 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 55 "sample/tail_call_sequential.c"
    if ((sequential11_helpers[2].tail_call) && (r0 == 0))
#line 55 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 55 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 55 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 55 "sample/tail_call_sequential.c"
    return r0;
#line 55 "sample/tail_call_sequential.c"
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
#line 56 "sample/tail_call_sequential.c"
{
#line 56 "sample/tail_call_sequential.c"
    // Prologue
#line 56 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 56 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 56 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 56 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 56 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 56 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 56 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 56 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 56 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 56 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 56 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 56 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 56 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 56 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 56 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 56 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 56 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 56 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 56 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 56 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 56 "sample/tail_call_sequential.c"
    r0 = sequential12_helpers[0].address
#line 56 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 56 "sample/tail_call_sequential.c"
    if ((sequential12_helpers[0].tail_call) && (r0 == 0))
#line 56 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 56 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 56 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 56 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 56 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 56 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 56 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 56 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=842099809
#line 56 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479819635809;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 56 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 56 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 56 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 56 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 56 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 56 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 56 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 56 "sample/tail_call_sequential.c"
    r0 = sequential12_helpers[1].address
#line 56 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 56 "sample/tail_call_sequential.c"
    if ((sequential12_helpers[1].tail_call) && (r0 == 0))
#line 56 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 56 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=12
#line 56 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(12))
#line 56 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=13
#line 56 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(13);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 56 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 56 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 56 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=13
#line 56 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(13);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 56 "sample/tail_call_sequential.c"
    r0 = sequential12_helpers[2].address
#line 56 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 56 "sample/tail_call_sequential.c"
    if ((sequential12_helpers[2].tail_call) && (r0 == 0))
#line 56 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 56 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 56 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 56 "sample/tail_call_sequential.c"
    return r0;
#line 56 "sample/tail_call_sequential.c"
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
#line 57 "sample/tail_call_sequential.c"
{
#line 57 "sample/tail_call_sequential.c"
    // Prologue
#line 57 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 57 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 57 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 57 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 57 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 57 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 57 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 57 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 57 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 57 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 57 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 57 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 57 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 57 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 57 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 57 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 57 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 57 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 57 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 57 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 57 "sample/tail_call_sequential.c"
    r0 = sequential13_helpers[0].address
#line 57 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 57 "sample/tail_call_sequential.c"
    if ((sequential13_helpers[0].tail_call) && (r0 == 0))
#line 57 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 57 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 57 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 57 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 57 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 57 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 57 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 57 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=858877025
#line 57 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479836413025;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 57 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 57 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 57 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 57 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 57 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 57 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 57 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 57 "sample/tail_call_sequential.c"
    r0 = sequential13_helpers[1].address
#line 57 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 57 "sample/tail_call_sequential.c"
    if ((sequential13_helpers[1].tail_call) && (r0 == 0))
#line 57 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 57 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=13
#line 57 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(13))
#line 57 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=14
#line 57 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(14);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 57 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 57 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 57 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=14
#line 57 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(14);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 57 "sample/tail_call_sequential.c"
    r0 = sequential13_helpers[2].address
#line 57 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 57 "sample/tail_call_sequential.c"
    if ((sequential13_helpers[2].tail_call) && (r0 == 0))
#line 57 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 57 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 57 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 57 "sample/tail_call_sequential.c"
    return r0;
#line 57 "sample/tail_call_sequential.c"
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
#line 58 "sample/tail_call_sequential.c"
{
#line 58 "sample/tail_call_sequential.c"
    // Prologue
#line 58 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 58 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 58 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 58 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 58 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 58 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 58 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 58 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 58 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 58 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 58 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 58 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 58 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 58 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 58 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 58 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 58 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 58 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 58 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 58 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 58 "sample/tail_call_sequential.c"
    r0 = sequential14_helpers[0].address
#line 58 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 58 "sample/tail_call_sequential.c"
    if ((sequential14_helpers[0].tail_call) && (r0 == 0))
#line 58 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 58 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 58 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 58 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 58 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 58 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 58 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 58 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=875654241
#line 58 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479853190241;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 58 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 58 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 58 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 58 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 58 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 58 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 58 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 58 "sample/tail_call_sequential.c"
    r0 = sequential14_helpers[1].address
#line 58 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 58 "sample/tail_call_sequential.c"
    if ((sequential14_helpers[1].tail_call) && (r0 == 0))
#line 58 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 58 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=14
#line 58 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(14))
#line 58 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=15
#line 58 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(15);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 58 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 58 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 58 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=15
#line 58 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(15);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 58 "sample/tail_call_sequential.c"
    r0 = sequential14_helpers[2].address
#line 58 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 58 "sample/tail_call_sequential.c"
    if ((sequential14_helpers[2].tail_call) && (r0 == 0))
#line 58 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 58 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 58 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 58 "sample/tail_call_sequential.c"
    return r0;
#line 58 "sample/tail_call_sequential.c"
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
#line 59 "sample/tail_call_sequential.c"
{
#line 59 "sample/tail_call_sequential.c"
    // Prologue
#line 59 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 59 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 59 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 59 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 59 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 59 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 59 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 59 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 59 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 59 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 59 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 59 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 59 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 59 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 59 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 59 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 59 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 59 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 59 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 59 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 59 "sample/tail_call_sequential.c"
    r0 = sequential15_helpers[0].address
#line 59 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 59 "sample/tail_call_sequential.c"
    if ((sequential15_helpers[0].tail_call) && (r0 == 0))
#line 59 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 59 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 59 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 59 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 59 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 59 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 59 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 59 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=892431457
#line 59 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479869967457;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 59 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 59 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 59 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 59 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 59 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 59 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 59 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 59 "sample/tail_call_sequential.c"
    r0 = sequential15_helpers[1].address
#line 59 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 59 "sample/tail_call_sequential.c"
    if ((sequential15_helpers[1].tail_call) && (r0 == 0))
#line 59 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 59 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=15
#line 59 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(15))
#line 59 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=16
#line 59 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(16);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 59 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 59 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 59 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=16
#line 59 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(16);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 59 "sample/tail_call_sequential.c"
    r0 = sequential15_helpers[2].address
#line 59 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 59 "sample/tail_call_sequential.c"
    if ((sequential15_helpers[2].tail_call) && (r0 == 0))
#line 59 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 59 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 59 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 59 "sample/tail_call_sequential.c"
    return r0;
#line 59 "sample/tail_call_sequential.c"
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
#line 60 "sample/tail_call_sequential.c"
{
#line 60 "sample/tail_call_sequential.c"
    // Prologue
#line 60 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 60 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 60 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 60 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 60 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 60 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 60 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 60 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 60 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 60 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 60 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 60 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 60 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 60 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 60 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 60 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 60 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 60 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 60 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 60 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 60 "sample/tail_call_sequential.c"
    r0 = sequential16_helpers[0].address
#line 60 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 60 "sample/tail_call_sequential.c"
    if ((sequential16_helpers[0].tail_call) && (r0 == 0))
#line 60 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 60 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 60 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 60 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 60 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 60 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 60 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 60 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=909208673
#line 60 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479886744673;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 60 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 60 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 60 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 60 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 60 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 60 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 60 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 60 "sample/tail_call_sequential.c"
    r0 = sequential16_helpers[1].address
#line 60 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 60 "sample/tail_call_sequential.c"
    if ((sequential16_helpers[1].tail_call) && (r0 == 0))
#line 60 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 60 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=16
#line 60 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(16))
#line 60 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=17
#line 60 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(17);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 60 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 60 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 60 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=17
#line 60 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(17);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 60 "sample/tail_call_sequential.c"
    r0 = sequential16_helpers[2].address
#line 60 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 60 "sample/tail_call_sequential.c"
    if ((sequential16_helpers[2].tail_call) && (r0 == 0))
#line 60 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 60 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 60 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 60 "sample/tail_call_sequential.c"
    return r0;
#line 60 "sample/tail_call_sequential.c"
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
#line 61 "sample/tail_call_sequential.c"
{
#line 61 "sample/tail_call_sequential.c"
    // Prologue
#line 61 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 61 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 61 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 61 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 61 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 61 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 61 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 61 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 61 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 61 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 61 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 61 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 61 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 61 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 61 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 61 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 61 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 61 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 61 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 61 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 61 "sample/tail_call_sequential.c"
    r0 = sequential17_helpers[0].address
#line 61 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 61 "sample/tail_call_sequential.c"
    if ((sequential17_helpers[0].tail_call) && (r0 == 0))
#line 61 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 61 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 61 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 61 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 61 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 61 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 61 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 61 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=925985889
#line 61 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479903521889;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 61 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 61 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 61 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 61 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 61 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 61 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 61 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 61 "sample/tail_call_sequential.c"
    r0 = sequential17_helpers[1].address
#line 61 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 61 "sample/tail_call_sequential.c"
    if ((sequential17_helpers[1].tail_call) && (r0 == 0))
#line 61 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 61 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=17
#line 61 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(17))
#line 61 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=18
#line 61 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(18);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 61 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 61 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 61 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=18
#line 61 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(18);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 61 "sample/tail_call_sequential.c"
    r0 = sequential17_helpers[2].address
#line 61 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 61 "sample/tail_call_sequential.c"
    if ((sequential17_helpers[2].tail_call) && (r0 == 0))
#line 61 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 61 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 61 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 61 "sample/tail_call_sequential.c"
    return r0;
#line 61 "sample/tail_call_sequential.c"
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
#line 62 "sample/tail_call_sequential.c"
{
#line 62 "sample/tail_call_sequential.c"
    // Prologue
#line 62 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 62 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 62 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 62 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 62 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 62 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 62 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 62 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 62 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 62 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 62 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 62 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 62 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 62 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 62 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 62 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 62 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 62 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 62 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 62 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 62 "sample/tail_call_sequential.c"
    r0 = sequential18_helpers[0].address
#line 62 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 62 "sample/tail_call_sequential.c"
    if ((sequential18_helpers[0].tail_call) && (r0 == 0))
#line 62 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 62 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 62 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 62 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 62 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 62 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 62 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 62 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=942763105
#line 62 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479920299105;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 62 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 62 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 62 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 62 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 62 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 62 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 62 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 62 "sample/tail_call_sequential.c"
    r0 = sequential18_helpers[1].address
#line 62 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 62 "sample/tail_call_sequential.c"
    if ((sequential18_helpers[1].tail_call) && (r0 == 0))
#line 62 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 62 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=18
#line 62 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(18))
#line 62 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=19
#line 62 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(19);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 62 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 62 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 62 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=19
#line 62 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(19);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 62 "sample/tail_call_sequential.c"
    r0 = sequential18_helpers[2].address
#line 62 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 62 "sample/tail_call_sequential.c"
    if ((sequential18_helpers[2].tail_call) && (r0 == 0))
#line 62 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 62 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 62 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 62 "sample/tail_call_sequential.c"
    return r0;
#line 62 "sample/tail_call_sequential.c"
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
#line 63 "sample/tail_call_sequential.c"
{
#line 63 "sample/tail_call_sequential.c"
    // Prologue
#line 63 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 63 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 63 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 63 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 63 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 63 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 63 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 63 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 63 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 63 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 63 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 63 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 63 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 63 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 63 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 63 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 63 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 63 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 63 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 63 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 63 "sample/tail_call_sequential.c"
    r0 = sequential19_helpers[0].address
#line 63 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 63 "sample/tail_call_sequential.c"
    if ((sequential19_helpers[0].tail_call) && (r0 == 0))
#line 63 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 63 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 63 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 63 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 63 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 63 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 63 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 63 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=959540321
#line 63 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479937076321;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 63 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 63 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 63 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 63 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 63 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 63 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 63 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 63 "sample/tail_call_sequential.c"
    r0 = sequential19_helpers[1].address
#line 63 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 63 "sample/tail_call_sequential.c"
    if ((sequential19_helpers[1].tail_call) && (r0 == 0))
#line 63 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 63 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=19
#line 63 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(19))
#line 63 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=20
#line 63 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(20);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 63 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 63 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 63 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=20
#line 63 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(20);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 63 "sample/tail_call_sequential.c"
    r0 = sequential19_helpers[2].address
#line 63 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 63 "sample/tail_call_sequential.c"
    if ((sequential19_helpers[2].tail_call) && (r0 == 0))
#line 63 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 63 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 63 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 63 "sample/tail_call_sequential.c"
    return r0;
#line 63 "sample/tail_call_sequential.c"
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
#line 46 "sample/tail_call_sequential.c"
{
#line 46 "sample/tail_call_sequential.c"
    // Prologue
#line 46 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 46 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 46 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 46 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 46 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 46 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 46 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 46 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 46 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 46 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 46 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 46 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 46 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 46 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 46 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 46 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 46 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 46 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 46 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 46 "sample/tail_call_sequential.c"
    r0 = sequential2_helpers[0].address
#line 46 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 46 "sample/tail_call_sequential.c"
    if ((sequential2_helpers[0].tail_call) && (r0 == 0))
#line 46 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 46 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 46 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 46 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 46 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 46 "sample/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 46 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976383073
#line 46 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834570337;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 46 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 46 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 46 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 46 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 46 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 46 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 46 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 46 "sample/tail_call_sequential.c"
    r0 = sequential2_helpers[1].address
#line 46 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 46 "sample/tail_call_sequential.c"
    if ((sequential2_helpers[1].tail_call) && (r0 == 0))
#line 46 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 46 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=2
#line 46 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(2))
#line 46 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=3
#line 46 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 46 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 46 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r0 offset=0 imm=0
#line 46 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=3
#line 46 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(3);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 46 "sample/tail_call_sequential.c"
    r0 = sequential2_helpers[2].address
#line 46 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 46 "sample/tail_call_sequential.c"
    if ((sequential2_helpers[2].tail_call) && (r0 == 0))
#line 46 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 46 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 46 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 46 "sample/tail_call_sequential.c"
    return r0;
#line 46 "sample/tail_call_sequential.c"
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
#line 64 "sample/tail_call_sequential.c"
{
#line 64 "sample/tail_call_sequential.c"
    // Prologue
#line 64 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 64 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 64 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 64 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 64 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 64 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 64 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 64 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 64 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 64 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 64 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 64 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 64 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 64 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 64 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 64 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 64 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 64 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 64 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 64 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 64 "sample/tail_call_sequential.c"
    r0 = sequential20_helpers[0].address
#line 64 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 64 "sample/tail_call_sequential.c"
    if ((sequential20_helpers[0].tail_call) && (r0 == 0))
#line 64 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 64 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 64 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 64 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 64 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 64 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 64 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 64 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=808610913
#line 64 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479786146913;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 64 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 64 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 64 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 64 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 64 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 64 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 64 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 64 "sample/tail_call_sequential.c"
    r0 = sequential20_helpers[1].address
#line 64 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 64 "sample/tail_call_sequential.c"
    if ((sequential20_helpers[1].tail_call) && (r0 == 0))
#line 64 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 64 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=20
#line 64 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(20))
#line 64 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=21
#line 64 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(21);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 64 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 64 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 64 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=21
#line 64 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(21);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 64 "sample/tail_call_sequential.c"
    r0 = sequential20_helpers[2].address
#line 64 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 64 "sample/tail_call_sequential.c"
    if ((sequential20_helpers[2].tail_call) && (r0 == 0))
#line 64 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 64 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 64 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 64 "sample/tail_call_sequential.c"
    return r0;
#line 64 "sample/tail_call_sequential.c"
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
#line 65 "sample/tail_call_sequential.c"
{
#line 65 "sample/tail_call_sequential.c"
    // Prologue
#line 65 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 65 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 65 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 65 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 65 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 65 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 65 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 65 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 65 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 65 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 65 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 65 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 65 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 65 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 65 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 65 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 65 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 65 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 65 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 65 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 65 "sample/tail_call_sequential.c"
    r0 = sequential21_helpers[0].address
#line 65 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 65 "sample/tail_call_sequential.c"
    if ((sequential21_helpers[0].tail_call) && (r0 == 0))
#line 65 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 65 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 65 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 65 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 65 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 65 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 65 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 65 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=825388129
#line 65 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479802924129;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 65 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 65 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 65 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 65 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 65 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 65 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 65 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 65 "sample/tail_call_sequential.c"
    r0 = sequential21_helpers[1].address
#line 65 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 65 "sample/tail_call_sequential.c"
    if ((sequential21_helpers[1].tail_call) && (r0 == 0))
#line 65 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 65 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=21
#line 65 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(21))
#line 65 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=22
#line 65 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(22);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 65 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 65 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 65 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=22
#line 65 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(22);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 65 "sample/tail_call_sequential.c"
    r0 = sequential21_helpers[2].address
#line 65 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 65 "sample/tail_call_sequential.c"
    if ((sequential21_helpers[2].tail_call) && (r0 == 0))
#line 65 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 65 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 65 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 65 "sample/tail_call_sequential.c"
    return r0;
#line 65 "sample/tail_call_sequential.c"
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
#line 66 "sample/tail_call_sequential.c"
{
#line 66 "sample/tail_call_sequential.c"
    // Prologue
#line 66 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 66 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 66 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 66 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 66 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 66 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 66 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 66 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 66 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 66 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 66 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 66 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 66 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 66 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 66 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 66 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 66 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 66 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 66 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 66 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 66 "sample/tail_call_sequential.c"
    r0 = sequential22_helpers[0].address
#line 66 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 66 "sample/tail_call_sequential.c"
    if ((sequential22_helpers[0].tail_call) && (r0 == 0))
#line 66 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 66 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 66 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 66 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 66 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 66 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 66 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 66 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=842165345
#line 66 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479819701345;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 66 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 66 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 66 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 66 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 66 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 66 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 66 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 66 "sample/tail_call_sequential.c"
    r0 = sequential22_helpers[1].address
#line 66 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 66 "sample/tail_call_sequential.c"
    if ((sequential22_helpers[1].tail_call) && (r0 == 0))
#line 66 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 66 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=22
#line 66 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(22))
#line 66 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=23
#line 66 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(23);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 66 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 66 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 66 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=23
#line 66 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(23);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 66 "sample/tail_call_sequential.c"
    r0 = sequential22_helpers[2].address
#line 66 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 66 "sample/tail_call_sequential.c"
    if ((sequential22_helpers[2].tail_call) && (r0 == 0))
#line 66 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 66 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 66 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 66 "sample/tail_call_sequential.c"
    return r0;
#line 66 "sample/tail_call_sequential.c"
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
#line 67 "sample/tail_call_sequential.c"
{
#line 67 "sample/tail_call_sequential.c"
    // Prologue
#line 67 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 67 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 67 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 67 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 67 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 67 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 67 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 67 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 67 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 67 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 67 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 67 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 67 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 67 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 67 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 67 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 67 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 67 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 67 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 67 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 67 "sample/tail_call_sequential.c"
    r0 = sequential23_helpers[0].address
#line 67 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 67 "sample/tail_call_sequential.c"
    if ((sequential23_helpers[0].tail_call) && (r0 == 0))
#line 67 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 67 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 67 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 67 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 67 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 67 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 67 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 67 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=858942561
#line 67 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479836478561;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 67 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 67 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 67 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 67 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 67 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 67 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 67 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 67 "sample/tail_call_sequential.c"
    r0 = sequential23_helpers[1].address
#line 67 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 67 "sample/tail_call_sequential.c"
    if ((sequential23_helpers[1].tail_call) && (r0 == 0))
#line 67 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 67 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=23
#line 67 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(23))
#line 67 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=24
#line 67 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(24);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 67 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 67 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 67 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=24
#line 67 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 67 "sample/tail_call_sequential.c"
    r0 = sequential23_helpers[2].address
#line 67 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 67 "sample/tail_call_sequential.c"
    if ((sequential23_helpers[2].tail_call) && (r0 == 0))
#line 67 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 67 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 67 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 67 "sample/tail_call_sequential.c"
    return r0;
#line 67 "sample/tail_call_sequential.c"
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
#line 68 "sample/tail_call_sequential.c"
{
#line 68 "sample/tail_call_sequential.c"
    // Prologue
#line 68 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 68 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 68 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 68 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 68 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 68 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 68 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 68 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 68 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 68 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 68 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 68 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 68 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 68 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 68 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 68 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 68 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 68 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 68 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 68 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 68 "sample/tail_call_sequential.c"
    r0 = sequential24_helpers[0].address
#line 68 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 68 "sample/tail_call_sequential.c"
    if ((sequential24_helpers[0].tail_call) && (r0 == 0))
#line 68 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 68 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 68 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 68 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 68 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 68 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 68 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 68 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=875719777
#line 68 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479853255777;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 68 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 68 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 68 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 68 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 68 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 68 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r9 src=r0 offset=0 imm=25
#line 68 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(25);
    // EBPF_OP_MOV64_IMM pc=25 dst=r2 src=r0 offset=0 imm=25
#line 68 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=26 dst=r0 src=r0 offset=0 imm=13
#line 68 "sample/tail_call_sequential.c"
    r0 = sequential24_helpers[1].address
#line 68 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 68 "sample/tail_call_sequential.c"
    if ((sequential24_helpers[1].tail_call) && (r0 == 0))
#line 68 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=27 dst=r1 src=r8 offset=0 imm=0
#line 68 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=28 dst=r1 src=r0 offset=7 imm=24
#line 68 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(24))
#line 68 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXW pc=29 dst=r8 src=r9 offset=0 imm=0
#line 68 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 68 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 68 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=25
#line 68 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 68 "sample/tail_call_sequential.c"
    r0 = sequential24_helpers[2].address
#line 68 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 68 "sample/tail_call_sequential.c"
    if ((sequential24_helpers[2].tail_call) && (r0 == 0))
#line 68 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 68 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 68 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 68 "sample/tail_call_sequential.c"
    return r0;
#line 68 "sample/tail_call_sequential.c"
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
#line 69 "sample/tail_call_sequential.c"
{
#line 69 "sample/tail_call_sequential.c"
    // Prologue
#line 69 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 69 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 69 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 69 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 69 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 69 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 69 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 69 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 69 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 69 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 69 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 69 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 69 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 69 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 69 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 69 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 69 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 69 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 69 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 69 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 69 "sample/tail_call_sequential.c"
    r0 = sequential25_helpers[0].address
#line 69 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 69 "sample/tail_call_sequential.c"
    if ((sequential25_helpers[0].tail_call) && (r0 == 0))
#line 69 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 69 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 69 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 69 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 69 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 69 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 69 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 69 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=892496993
#line 69 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479870032993;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 69 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 69 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 69 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 69 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 69 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 69 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 69 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 69 "sample/tail_call_sequential.c"
    r0 = sequential25_helpers[1].address
#line 69 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 69 "sample/tail_call_sequential.c"
    if ((sequential25_helpers[1].tail_call) && (r0 == 0))
#line 69 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 69 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=25
#line 69 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(25))
#line 69 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=26
#line 69 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(26);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 69 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 69 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 69 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=26
#line 69 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(26);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 69 "sample/tail_call_sequential.c"
    r0 = sequential25_helpers[2].address
#line 69 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 69 "sample/tail_call_sequential.c"
    if ((sequential25_helpers[2].tail_call) && (r0 == 0))
#line 69 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 69 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 69 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 69 "sample/tail_call_sequential.c"
    return r0;
#line 69 "sample/tail_call_sequential.c"
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
#line 70 "sample/tail_call_sequential.c"
{
#line 70 "sample/tail_call_sequential.c"
    // Prologue
#line 70 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 70 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 70 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 70 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 70 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 70 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 70 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 70 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 70 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 70 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 70 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 70 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 70 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 70 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 70 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 70 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 70 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 70 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 70 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 70 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 70 "sample/tail_call_sequential.c"
    r0 = sequential26_helpers[0].address
#line 70 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/tail_call_sequential.c"
    if ((sequential26_helpers[0].tail_call) && (r0 == 0))
#line 70 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 70 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 70 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 70 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 70 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 70 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 70 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 70 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=909274209
#line 70 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479886810209;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 70 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 70 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 70 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 70 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 70 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 70 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 70 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 70 "sample/tail_call_sequential.c"
    r0 = sequential26_helpers[1].address
#line 70 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/tail_call_sequential.c"
    if ((sequential26_helpers[1].tail_call) && (r0 == 0))
#line 70 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 70 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=26
#line 70 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(26))
#line 70 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=27
#line 70 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(27);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 70 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 70 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 70 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=27
#line 70 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(27);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 70 "sample/tail_call_sequential.c"
    r0 = sequential26_helpers[2].address
#line 70 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/tail_call_sequential.c"
    if ((sequential26_helpers[2].tail_call) && (r0 == 0))
#line 70 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 70 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 70 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 70 "sample/tail_call_sequential.c"
    return r0;
#line 70 "sample/tail_call_sequential.c"
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
#line 71 "sample/tail_call_sequential.c"
{
#line 71 "sample/tail_call_sequential.c"
    // Prologue
#line 71 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 71 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 71 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 71 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 71 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 71 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 71 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 71 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 71 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 71 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 71 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 71 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 71 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 71 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 71 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 71 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 71 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 71 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 71 "sample/tail_call_sequential.c"
    r0 = sequential27_helpers[0].address
#line 71 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 71 "sample/tail_call_sequential.c"
    if ((sequential27_helpers[0].tail_call) && (r0 == 0))
#line 71 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 71 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 71 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 71 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 71 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 71 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 71 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 71 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=926051425
#line 71 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479903587425;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 71 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 71 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 71 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 71 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 71 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 71 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 71 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 71 "sample/tail_call_sequential.c"
    r0 = sequential27_helpers[1].address
#line 71 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 71 "sample/tail_call_sequential.c"
    if ((sequential27_helpers[1].tail_call) && (r0 == 0))
#line 71 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 71 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=27
#line 71 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(27))
#line 71 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=28
#line 71 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(28);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 71 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 71 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 71 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=28
#line 71 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(28);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 71 "sample/tail_call_sequential.c"
    r0 = sequential27_helpers[2].address
#line 71 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 71 "sample/tail_call_sequential.c"
    if ((sequential27_helpers[2].tail_call) && (r0 == 0))
#line 71 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 71 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 71 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 71 "sample/tail_call_sequential.c"
    return r0;
#line 71 "sample/tail_call_sequential.c"
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
#line 72 "sample/tail_call_sequential.c"
{
#line 72 "sample/tail_call_sequential.c"
    // Prologue
#line 72 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 72 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 72 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 72 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 72 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 72 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 72 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 72 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 72 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 72 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 72 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 72 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 72 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 72 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 72 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 72 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 72 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 72 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 72 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 72 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 72 "sample/tail_call_sequential.c"
    r0 = sequential28_helpers[0].address
#line 72 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 72 "sample/tail_call_sequential.c"
    if ((sequential28_helpers[0].tail_call) && (r0 == 0))
#line 72 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 72 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 72 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 72 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 72 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 72 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 72 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 72 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=942828641
#line 72 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479920364641;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 72 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 72 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 72 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 72 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 72 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 72 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 72 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 72 "sample/tail_call_sequential.c"
    r0 = sequential28_helpers[1].address
#line 72 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 72 "sample/tail_call_sequential.c"
    if ((sequential28_helpers[1].tail_call) && (r0 == 0))
#line 72 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 72 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=28
#line 72 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(28))
#line 72 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=29
#line 72 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(29);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 72 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 72 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 72 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=29
#line 72 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(29);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 72 "sample/tail_call_sequential.c"
    r0 = sequential28_helpers[2].address
#line 72 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 72 "sample/tail_call_sequential.c"
    if ((sequential28_helpers[2].tail_call) && (r0 == 0))
#line 72 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 72 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 72 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 72 "sample/tail_call_sequential.c"
    return r0;
#line 72 "sample/tail_call_sequential.c"
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
#line 73 "sample/tail_call_sequential.c"
{
#line 73 "sample/tail_call_sequential.c"
    // Prologue
#line 73 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 73 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 73 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 73 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 73 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 73 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 73 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 73 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 73 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 73 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 73 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 73 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 73 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 73 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 73 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 73 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 73 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 73 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 73 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 73 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 73 "sample/tail_call_sequential.c"
    r0 = sequential29_helpers[0].address
#line 73 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 73 "sample/tail_call_sequential.c"
    if ((sequential29_helpers[0].tail_call) && (r0 == 0))
#line 73 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 73 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 73 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 73 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 73 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 73 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 73 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 73 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=959605857
#line 73 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479937141857;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 73 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 73 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 73 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 73 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 73 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 73 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 73 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 73 "sample/tail_call_sequential.c"
    r0 = sequential29_helpers[1].address
#line 73 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 73 "sample/tail_call_sequential.c"
    if ((sequential29_helpers[1].tail_call) && (r0 == 0))
#line 73 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 73 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=29
#line 73 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(29))
#line 73 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=30
#line 73 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(30);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 73 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 73 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 73 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=30
#line 73 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(30);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 73 "sample/tail_call_sequential.c"
    r0 = sequential29_helpers[2].address
#line 73 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 73 "sample/tail_call_sequential.c"
    if ((sequential29_helpers[2].tail_call) && (r0 == 0))
#line 73 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 73 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 73 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 73 "sample/tail_call_sequential.c"
    return r0;
#line 73 "sample/tail_call_sequential.c"
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
#line 47 "sample/tail_call_sequential.c"
{
#line 47 "sample/tail_call_sequential.c"
    // Prologue
#line 47 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 47 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 47 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 47 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 47 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 47 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 47 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 47 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 47 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 47 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 47 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 47 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 47 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 47 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 47 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 47 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 47 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 47 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 47 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 47 "sample/tail_call_sequential.c"
    r0 = sequential3_helpers[0].address
#line 47 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 47 "sample/tail_call_sequential.c"
    if ((sequential3_helpers[0].tail_call) && (r0 == 0))
#line 47 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 47 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 47 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 47 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 47 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 47 "sample/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 47 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976448609
#line 47 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834635873;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 47 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 47 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 47 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 47 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 47 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 47 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 47 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 47 "sample/tail_call_sequential.c"
    r0 = sequential3_helpers[1].address
#line 47 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 47 "sample/tail_call_sequential.c"
    if ((sequential3_helpers[1].tail_call) && (r0 == 0))
#line 47 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 47 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=3
#line 47 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(3))
#line 47 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=4
#line 47 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 47 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 47 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r0 offset=0 imm=0
#line 47 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=4
#line 47 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 47 "sample/tail_call_sequential.c"
    r0 = sequential3_helpers[2].address
#line 47 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 47 "sample/tail_call_sequential.c"
    if ((sequential3_helpers[2].tail_call) && (r0 == 0))
#line 47 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 47 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 47 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 47 "sample/tail_call_sequential.c"
    return r0;
#line 47 "sample/tail_call_sequential.c"
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
#line 74 "sample/tail_call_sequential.c"
{
#line 74 "sample/tail_call_sequential.c"
    // Prologue
#line 74 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 74 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 74 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 74 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 74 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 74 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 74 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 74 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 74 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 74 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 74 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 74 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 74 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 74 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 74 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 74 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 74 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 74 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 74 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 74 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 74 "sample/tail_call_sequential.c"
    r0 = sequential30_helpers[0].address
#line 74 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 74 "sample/tail_call_sequential.c"
    if ((sequential30_helpers[0].tail_call) && (r0 == 0))
#line 74 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 74 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 74 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 74 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 74 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 74 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 74 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 74 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=808676449
#line 74 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479786212449;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 74 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 74 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 74 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 74 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 74 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 74 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 74 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 74 "sample/tail_call_sequential.c"
    r0 = sequential30_helpers[1].address
#line 74 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 74 "sample/tail_call_sequential.c"
    if ((sequential30_helpers[1].tail_call) && (r0 == 0))
#line 74 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 74 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=30
#line 74 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(30))
#line 74 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=31
#line 74 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(31);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 74 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 74 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 74 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=31
#line 74 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(31);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 74 "sample/tail_call_sequential.c"
    r0 = sequential30_helpers[2].address
#line 74 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 74 "sample/tail_call_sequential.c"
    if ((sequential30_helpers[2].tail_call) && (r0 == 0))
#line 74 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 74 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 74 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 74 "sample/tail_call_sequential.c"
    return r0;
#line 74 "sample/tail_call_sequential.c"
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
#line 75 "sample/tail_call_sequential.c"
{
#line 75 "sample/tail_call_sequential.c"
    // Prologue
#line 75 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 75 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 75 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 75 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 75 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 75 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 75 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 75 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 75 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 75 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 75 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 75 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 75 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 75 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 75 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 75 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 75 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 75 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 75 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 75 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 75 "sample/tail_call_sequential.c"
    r0 = sequential31_helpers[0].address
#line 75 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 75 "sample/tail_call_sequential.c"
    if ((sequential31_helpers[0].tail_call) && (r0 == 0))
#line 75 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 75 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 75 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 75 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 75 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 75 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 75 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 75 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=825453665
#line 75 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479802989665;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 75 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 75 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 75 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 75 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 75 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 75 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 75 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 75 "sample/tail_call_sequential.c"
    r0 = sequential31_helpers[1].address
#line 75 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 75 "sample/tail_call_sequential.c"
    if ((sequential31_helpers[1].tail_call) && (r0 == 0))
#line 75 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 75 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=31
#line 75 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(31))
#line 75 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=32
#line 75 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(32);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 75 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 75 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 75 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=32
#line 75 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 75 "sample/tail_call_sequential.c"
    r0 = sequential31_helpers[2].address
#line 75 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 75 "sample/tail_call_sequential.c"
    if ((sequential31_helpers[2].tail_call) && (r0 == 0))
#line 75 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 75 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 75 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 75 "sample/tail_call_sequential.c"
    return r0;
#line 75 "sample/tail_call_sequential.c"
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
#line 76 "sample/tail_call_sequential.c"
{
#line 76 "sample/tail_call_sequential.c"
    // Prologue
#line 76 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 76 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 76 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 76 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 76 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 76 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 76 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 76 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 76 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 76 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 76 "sample/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 76 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 76 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 76 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 76 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 76 "sample/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 76 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 76 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 76 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 76 "sample/tail_call_sequential.c"
    r0 = sequential32_helpers[0].address
#line 76 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/tail_call_sequential.c"
    if ((sequential32_helpers[0].tail_call) && (r0 == 0))
#line 76 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 76 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 76 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 76 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 76 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 76 "sample/tail_call_sequential.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r9;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 76 "sample/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 76 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=842230881
#line 76 "sample/tail_call_sequential.c"
    r1 = (uint64_t)8514653479819766881;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 76 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 76 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 76 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 76 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 76 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 76 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 76 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 76 "sample/tail_call_sequential.c"
    r0 = sequential32_helpers[1].address
#line 76 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/tail_call_sequential.c"
    if ((sequential32_helpers[1].tail_call) && (r0 == 0))
#line 76 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 76 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=32
#line 76 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(32))
#line 76 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=33
#line 76 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(33);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 76 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 76 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r0 offset=0 imm=0
#line 76 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=33
#line 76 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(33);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 76 "sample/tail_call_sequential.c"
    r0 = sequential32_helpers[2].address
#line 76 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/tail_call_sequential.c"
    if ((sequential32_helpers[2].tail_call) && (r0 == 0))
#line 76 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 76 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 76 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 76 "sample/tail_call_sequential.c"
    return r0;
#line 76 "sample/tail_call_sequential.c"
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
#line 48 "sample/tail_call_sequential.c"
{
#line 48 "sample/tail_call_sequential.c"
    // Prologue
#line 48 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 48 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 48 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 48 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 48 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 48 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 48 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 48 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 48 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 48 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 48 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 48 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 48 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 48 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 48 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 48 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 48 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 48 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 48 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 48 "sample/tail_call_sequential.c"
    r0 = sequential4_helpers[0].address
#line 48 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 48 "sample/tail_call_sequential.c"
    if ((sequential4_helpers[0].tail_call) && (r0 == 0))
#line 48 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 48 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 48 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 48 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 48 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 48 "sample/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 48 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976514145
#line 48 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834701409;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 48 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 48 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 48 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 48 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 48 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 48 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 48 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 48 "sample/tail_call_sequential.c"
    r0 = sequential4_helpers[1].address
#line 48 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 48 "sample/tail_call_sequential.c"
    if ((sequential4_helpers[1].tail_call) && (r0 == 0))
#line 48 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 48 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=4
#line 48 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(4))
#line 48 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=5
#line 48 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 48 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 48 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r0 offset=0 imm=0
#line 48 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=5
#line 48 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(5);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 48 "sample/tail_call_sequential.c"
    r0 = sequential4_helpers[2].address
#line 48 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 48 "sample/tail_call_sequential.c"
    if ((sequential4_helpers[2].tail_call) && (r0 == 0))
#line 48 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 48 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 48 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 48 "sample/tail_call_sequential.c"
    return r0;
#line 48 "sample/tail_call_sequential.c"
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
#line 49 "sample/tail_call_sequential.c"
{
#line 49 "sample/tail_call_sequential.c"
    // Prologue
#line 49 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 49 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 49 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 49 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 49 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 49 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 49 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 49 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 49 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 49 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 49 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 49 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 49 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 49 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 49 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 49 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 49 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 49 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 49 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 49 "sample/tail_call_sequential.c"
    r0 = sequential5_helpers[0].address
#line 49 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 49 "sample/tail_call_sequential.c"
    if ((sequential5_helpers[0].tail_call) && (r0 == 0))
#line 49 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 49 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 49 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 49 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 49 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 49 "sample/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 49 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976579681
#line 49 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834766945;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 49 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 49 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 49 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 49 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 49 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 49 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 49 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 49 "sample/tail_call_sequential.c"
    r0 = sequential5_helpers[1].address
#line 49 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 49 "sample/tail_call_sequential.c"
    if ((sequential5_helpers[1].tail_call) && (r0 == 0))
#line 49 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 49 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=5
#line 49 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(5))
#line 49 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=6
#line 49 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 49 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 49 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r0 offset=0 imm=0
#line 49 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=6
#line 49 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(6);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 49 "sample/tail_call_sequential.c"
    r0 = sequential5_helpers[2].address
#line 49 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 49 "sample/tail_call_sequential.c"
    if ((sequential5_helpers[2].tail_call) && (r0 == 0))
#line 49 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 49 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 49 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 49 "sample/tail_call_sequential.c"
    return r0;
#line 49 "sample/tail_call_sequential.c"
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
#line 50 "sample/tail_call_sequential.c"
{
#line 50 "sample/tail_call_sequential.c"
    // Prologue
#line 50 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 50 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 50 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 50 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 50 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 50 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 50 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 50 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 50 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 50 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 50 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 50 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 50 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 50 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 50 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 50 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 50 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 50 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 50 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 50 "sample/tail_call_sequential.c"
    r0 = sequential6_helpers[0].address
#line 50 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 50 "sample/tail_call_sequential.c"
    if ((sequential6_helpers[0].tail_call) && (r0 == 0))
#line 50 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 50 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 50 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 50 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 50 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 50 "sample/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 50 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976645217
#line 50 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834832481;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 50 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 50 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 50 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 50 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 50 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 50 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 50 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 50 "sample/tail_call_sequential.c"
    r0 = sequential6_helpers[1].address
#line 50 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 50 "sample/tail_call_sequential.c"
    if ((sequential6_helpers[1].tail_call) && (r0 == 0))
#line 50 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 50 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=6
#line 50 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(6))
#line 50 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=7
#line 50 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 50 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 50 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r0 offset=0 imm=0
#line 50 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=7
#line 50 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(7);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 50 "sample/tail_call_sequential.c"
    r0 = sequential6_helpers[2].address
#line 50 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 50 "sample/tail_call_sequential.c"
    if ((sequential6_helpers[2].tail_call) && (r0 == 0))
#line 50 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 50 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 50 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 50 "sample/tail_call_sequential.c"
    return r0;
#line 50 "sample/tail_call_sequential.c"
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
#line 51 "sample/tail_call_sequential.c"
{
#line 51 "sample/tail_call_sequential.c"
    // Prologue
#line 51 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 51 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 51 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 51 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 51 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 51 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 51 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 51 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 51 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 51 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 51 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 51 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 51 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 51 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 51 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 51 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 51 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 51 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 51 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 51 "sample/tail_call_sequential.c"
    r0 = sequential7_helpers[0].address
#line 51 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 51 "sample/tail_call_sequential.c"
    if ((sequential7_helpers[0].tail_call) && (r0 == 0))
#line 51 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 51 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 51 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 51 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 51 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 51 "sample/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 51 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976710753
#line 51 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834898017;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 51 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 51 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 51 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 51 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 51 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 51 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 51 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 51 "sample/tail_call_sequential.c"
    r0 = sequential7_helpers[1].address
#line 51 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 51 "sample/tail_call_sequential.c"
    if ((sequential7_helpers[1].tail_call) && (r0 == 0))
#line 51 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 51 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=7
#line 51 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(7))
#line 51 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=8
#line 51 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 51 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 51 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r0 offset=0 imm=0
#line 51 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=8
#line 51 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(8);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 51 "sample/tail_call_sequential.c"
    r0 = sequential7_helpers[2].address
#line 51 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 51 "sample/tail_call_sequential.c"
    if ((sequential7_helpers[2].tail_call) && (r0 == 0))
#line 51 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 51 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 51 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 51 "sample/tail_call_sequential.c"
    return r0;
#line 51 "sample/tail_call_sequential.c"
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
#line 52 "sample/tail_call_sequential.c"
{
#line 52 "sample/tail_call_sequential.c"
    // Prologue
#line 52 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 52 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 52 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 52 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 52 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 52 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 52 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 52 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 52 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 52 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 52 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 52 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 52 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 52 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 52 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 52 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 52 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 52 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 52 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 52 "sample/tail_call_sequential.c"
    r0 = sequential8_helpers[0].address
#line 52 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 52 "sample/tail_call_sequential.c"
    if ((sequential8_helpers[0].tail_call) && (r0 == 0))
#line 52 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 52 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 52 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 52 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 52 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 52 "sample/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 52 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976776289
#line 52 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834963553;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 52 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 52 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 52 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 52 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 52 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 52 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 52 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 52 "sample/tail_call_sequential.c"
    r0 = sequential8_helpers[1].address
#line 52 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 52 "sample/tail_call_sequential.c"
    if ((sequential8_helpers[1].tail_call) && (r0 == 0))
#line 52 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 52 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=8
#line 52 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(8))
#line 52 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=9
#line 52 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 52 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 52 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r0 offset=0 imm=0
#line 52 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=9
#line 52 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(9);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 52 "sample/tail_call_sequential.c"
    r0 = sequential8_helpers[2].address
#line 52 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 52 "sample/tail_call_sequential.c"
    if ((sequential8_helpers[2].tail_call) && (r0 == 0))
#line 52 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 52 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 52 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 52 "sample/tail_call_sequential.c"
    return r0;
#line 52 "sample/tail_call_sequential.c"
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
#line 53 "sample/tail_call_sequential.c"
{
#line 53 "sample/tail_call_sequential.c"
    // Prologue
#line 53 "sample/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 53 "sample/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 53 "sample/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 53 "sample/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 53 "sample/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 53 "sample/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 53 "sample/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 53 "sample/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 53 "sample/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 53 "sample/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 53 "sample/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 53 "sample/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 53 "sample/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 53 "sample/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 53 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 53 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 53 "sample/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 53 "sample/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 53 "sample/tail_call_sequential.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 53 "sample/tail_call_sequential.c"
    r0 = sequential9_helpers[0].address
#line 53 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 53 "sample/tail_call_sequential.c"
    if ((sequential9_helpers[0].tail_call) && (r0 == 0))
#line 53 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 53 "sample/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 53 "sample/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 53 "sample/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0))
#line 53 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 53 "sample/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 53 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976841825
#line 53 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7022846986835029089;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 53 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 53 "sample/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 53 "sample/tail_call_sequential.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 53 "sample/tail_call_sequential.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 53 "sample/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 53 "sample/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 53 "sample/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 53 "sample/tail_call_sequential.c"
    r0 = sequential9_helpers[1].address
#line 53 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 53 "sample/tail_call_sequential.c"
    if ((sequential9_helpers[1].tail_call) && (r0 == 0))
#line 53 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 53 "sample/tail_call_sequential.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=9
#line 53 "sample/tail_call_sequential.c"
    if (r1 != IMMEDIATE(9))
#line 53 "sample/tail_call_sequential.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=10
#line 53 "sample/tail_call_sequential.c"
    r1 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 53 "sample/tail_call_sequential.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 53 "sample/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r0 offset=0 imm=0
#line 53 "sample/tail_call_sequential.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=10
#line 53 "sample/tail_call_sequential.c"
    r3 = IMMEDIATE(10);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 53 "sample/tail_call_sequential.c"
    r0 = sequential9_helpers[2].address
#line 53 "sample/tail_call_sequential.c"
         (r1, r2, r3, r4, r5);
#line 53 "sample/tail_call_sequential.c"
    if ((sequential9_helpers[2].tail_call) && (r0 == 0))
#line 53 "sample/tail_call_sequential.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 53 "sample/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 53 "sample/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 53 "sample/tail_call_sequential.c"
    return r0;
#line 53 "sample/tail_call_sequential.c"
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
    version->minor = 9;
    version->revision = 0;
}

metadata_table_t tail_call_sequential_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
