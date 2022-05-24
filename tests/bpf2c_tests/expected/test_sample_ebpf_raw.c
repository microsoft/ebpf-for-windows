// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from test_sample_ebpf.o

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
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         32,                 // Size in bytes of a map value.
         2,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         PIN_NONE,           // Pinning type for the map.
         0,                  // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "test_map"},
    {NULL,
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         32,                 // Size in bytes of a map value.
         2,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         PIN_NONE,           // Pinning type for the map.
         0,                  // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "utility_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 2;
}

static helper_function_entry_t test_program_entry_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 65537, "helper_id_65537"},
    {NULL, 65538, "helper_id_65538"},
    {NULL, 65536, "helper_id_65536"},
};

static GUID test_program_entry_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID test_program_entry_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t test_program_entry_maps[] = {
    0,
};

#pragma code_seg(push, "sample~1")
static uint64_t
test_program_entry(void* context)
#line 29 "sample/test_sample_ebpf.c"
{
#line 29 "sample/test_sample_ebpf.c"
    // Prologue
#line 29 "sample/test_sample_ebpf.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 29 "sample/test_sample_ebpf.c"
    register uint64_t r0 = 0;
#line 29 "sample/test_sample_ebpf.c"
    register uint64_t r1 = 0;
#line 29 "sample/test_sample_ebpf.c"
    register uint64_t r2 = 0;
#line 29 "sample/test_sample_ebpf.c"
    register uint64_t r3 = 0;
#line 29 "sample/test_sample_ebpf.c"
    register uint64_t r4 = 0;
#line 29 "sample/test_sample_ebpf.c"
    register uint64_t r5 = 0;
#line 29 "sample/test_sample_ebpf.c"
    register uint64_t r6 = 0;
#line 29 "sample/test_sample_ebpf.c"
    register uint64_t r7 = 0;
#line 29 "sample/test_sample_ebpf.c"
    register uint64_t r8 = 0;
#line 29 "sample/test_sample_ebpf.c"
    register uint64_t r10 = 0;

#line 29 "sample/test_sample_ebpf.c"
    r1 = (uintptr_t)context;
#line 29 "sample/test_sample_ebpf.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 29 "sample/test_sample_ebpf.c"
    r6 = r1;
    // EBPF_OP_LDDW pc=1 dst=r1 src=r0 offset=0 imm=0
#line 29 "sample/test_sample_ebpf.c"
    r1 = (uint64_t)4294967296;
    // EBPF_OP_STXDW pc=3 dst=r10 src=r1 offset=-8 imm=0
#line 32 "sample/test_sample_ebpf.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=4 dst=r2 src=r10 offset=0 imm=0
#line 32 "sample/test_sample_ebpf.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=5 dst=r2 src=r0 offset=0 imm=-8
#line 32 "sample/test_sample_ebpf.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=0
#line 35 "sample/test_sample_ebpf.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=8 dst=r0 src=r0 offset=0 imm=1
#line 35 "sample/test_sample_ebpf.c"
    r0 = test_program_entry_helpers[0].address
#line 35 "sample/test_sample_ebpf.c"
         (r1, r2, r3, r4, r5);
#line 35 "sample/test_sample_ebpf.c"
    if ((test_program_entry_helpers[0].tail_call) && (r0 == 0))
#line 35 "sample/test_sample_ebpf.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=9 dst=r8 src=r0 offset=0 imm=0
#line 35 "sample/test_sample_ebpf.c"
    r8 = r0;
    // EBPF_OP_MOV64_REG pc=10 dst=r2 src=r10 offset=0 imm=0
#line 36 "sample/test_sample_ebpf.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=11 dst=r2 src=r0 offset=0 imm=-4
#line 36 "sample/test_sample_ebpf.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=0
#line 36 "sample/test_sample_ebpf.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=14 dst=r0 src=r0 offset=0 imm=1
#line 36 "sample/test_sample_ebpf.c"
    r0 = test_program_entry_helpers[0].address
#line 36 "sample/test_sample_ebpf.c"
         (r1, r2, r3, r4, r5);
#line 36 "sample/test_sample_ebpf.c"
    if ((test_program_entry_helpers[0].tail_call) && (r0 == 0))
#line 36 "sample/test_sample_ebpf.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=15 dst=r7 src=r0 offset=0 imm=0
#line 36 "sample/test_sample_ebpf.c"
    r7 = r0;
    // EBPF_OP_JEQ_IMM pc=16 dst=r8 src=r0 offset=17 imm=0
#line 38 "sample/test_sample_ebpf.c"
    if (r8 == IMMEDIATE(0))
#line 38 "sample/test_sample_ebpf.c"
        goto label_1;
        // EBPF_OP_LDXDW pc=17 dst=r1 src=r6 offset=0 imm=0
#line 38 "sample/test_sample_ebpf.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=18 dst=r2 src=r6 offset=8 imm=0
#line 38 "sample/test_sample_ebpf.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_JGE_REG pc=19 dst=r1 src=r2 offset=14 imm=0
#line 38 "sample/test_sample_ebpf.c"
    if (r1 >= r2)
#line 38 "sample/test_sample_ebpf.c"
        goto label_1;
        // EBPF_OP_SUB64_REG pc=20 dst=r2 src=r1 offset=0 imm=0
#line 43 "sample/test_sample_ebpf.c"
    r2 -= r1;
    // EBPF_OP_MOV64_REG pc=21 dst=r3 src=r8 offset=0 imm=0
#line 42 "sample/test_sample_ebpf.c"
    r3 = r8;
    // EBPF_OP_MOV64_IMM pc=22 dst=r4 src=r0 offset=0 imm=32
#line 42 "sample/test_sample_ebpf.c"
    r4 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=23 dst=r0 src=r0 offset=0 imm=65537
#line 42 "sample/test_sample_ebpf.c"
    r0 = test_program_entry_helpers[1].address
#line 42 "sample/test_sample_ebpf.c"
         (r1, r2, r3, r4, r5);
#line 42 "sample/test_sample_ebpf.c"
    if ((test_program_entry_helpers[1].tail_call) && (r0 == 0))
#line 42 "sample/test_sample_ebpf.c"
        return 0;
        // EBPF_OP_JEQ_IMM pc=24 dst=r7 src=r0 offset=9 imm=0
#line 44 "sample/test_sample_ebpf.c"
    if (r7 == IMMEDIATE(0))
#line 44 "sample/test_sample_ebpf.c"
        goto label_1;
        // EBPF_OP_LDXDW pc=25 dst=r1 src=r6 offset=0 imm=0
#line 46 "sample/test_sample_ebpf.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=26 dst=r2 src=r6 offset=8 imm=0
#line 46 "sample/test_sample_ebpf.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=27 dst=r2 src=r1 offset=0 imm=0
#line 46 "sample/test_sample_ebpf.c"
    r2 -= r1;
    // EBPF_OP_MOV64_REG pc=28 dst=r3 src=r0 offset=0 imm=0
#line 45 "sample/test_sample_ebpf.c"
    r3 = r0;
    // EBPF_OP_MOV64_REG pc=29 dst=r4 src=r7 offset=0 imm=0
#line 45 "sample/test_sample_ebpf.c"
    r4 = r7;
    // EBPF_OP_MOV64_IMM pc=30 dst=r5 src=r0 offset=0 imm=32
#line 45 "sample/test_sample_ebpf.c"
    r5 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=31 dst=r0 src=r0 offset=0 imm=65538
#line 45 "sample/test_sample_ebpf.c"
    r0 = test_program_entry_helpers[2].address
#line 45 "sample/test_sample_ebpf.c"
         (r1, r2, r3, r4, r5);
#line 45 "sample/test_sample_ebpf.c"
    if ((test_program_entry_helpers[2].tail_call) && (r0 == 0))
#line 45 "sample/test_sample_ebpf.c"
        return 0;
        // EBPF_OP_MOV64_IMM pc=32 dst=r1 src=r0 offset=0 imm=0
#line 45 "sample/test_sample_ebpf.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=33 dst=r1 src=r0 offset=5 imm=0
#line 47 "sample/test_sample_ebpf.c"
    if ((int64_t)r1 > (int64_t)r0)
#line 47 "sample/test_sample_ebpf.c"
        goto label_2;
label_1:
    // EBPF_OP_MOV64_REG pc=34 dst=r1 src=r6 offset=0 imm=0
#line 53 "sample/test_sample_ebpf.c"
    r1 = r6;
    // EBPF_OP_CALL pc=35 dst=r0 src=r0 offset=0 imm=65536
#line 53 "sample/test_sample_ebpf.c"
    r0 = test_program_entry_helpers[3].address
#line 53 "sample/test_sample_ebpf.c"
         (r1, r2, r3, r4, r5);
#line 53 "sample/test_sample_ebpf.c"
    if ((test_program_entry_helpers[3].tail_call) && (r0 == 0))
#line 53 "sample/test_sample_ebpf.c"
        return 0;
        // EBPF_OP_MOV64_IMM pc=36 dst=r1 src=r0 offset=0 imm=0
#line 53 "sample/test_sample_ebpf.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=37 dst=r1 src=r0 offset=1 imm=0
#line 54 "sample/test_sample_ebpf.c"
    if ((int64_t)r1 > (int64_t)r0)
#line 54 "sample/test_sample_ebpf.c"
        goto label_2;
        // EBPF_OP_MOV64_IMM pc=38 dst=r0 src=r0 offset=0 imm=42
#line 54 "sample/test_sample_ebpf.c"
    r0 = IMMEDIATE(42);
label_2:
    // EBPF_OP_EXIT pc=39 dst=r0 src=r0 offset=0 imm=0
#line 62 "sample/test_sample_ebpf.c"
    return r0;
#line 62 "sample/test_sample_ebpf.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t test_utility_helpers_helpers[] = {
    {NULL, 6, "helper_id_6"},
    {NULL, 7, "helper_id_7"},
    {NULL, 8, "helper_id_8"},
    {NULL, 2, "helper_id_2"},
};

static GUID test_utility_helpers_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID test_utility_helpers_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t test_utility_helpers_maps[] = {
    1,
};

#pragma code_seg(push, "sample~2")
static uint64_t
test_utility_helpers(void* context)
#line 73 "sample/test_sample_ebpf.c"
{
#line 73 "sample/test_sample_ebpf.c"
    // Prologue
#line 73 "sample/test_sample_ebpf.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 73 "sample/test_sample_ebpf.c"
    register uint64_t r0 = 0;
#line 73 "sample/test_sample_ebpf.c"
    register uint64_t r1 = 0;
#line 73 "sample/test_sample_ebpf.c"
    register uint64_t r2 = 0;
#line 73 "sample/test_sample_ebpf.c"
    register uint64_t r3 = 0;
#line 73 "sample/test_sample_ebpf.c"
    register uint64_t r4 = 0;
#line 73 "sample/test_sample_ebpf.c"
    register uint64_t r5 = 0;
#line 73 "sample/test_sample_ebpf.c"
    register uint64_t r6 = 0;
#line 73 "sample/test_sample_ebpf.c"
    register uint64_t r10 = 0;

#line 73 "sample/test_sample_ebpf.c"
    r1 = (uintptr_t)context;
#line 73 "sample/test_sample_ebpf.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDDW pc=0 dst=r1 src=r0 offset=0 imm=0
#line 73 "sample/test_sample_ebpf.c"
    r1 = (uint64_t)4294967296;
    // EBPF_OP_STXDW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 12 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=3 dst=r1 src=r0 offset=0 imm=0
#line 12 "sample/./sample_common_routines.h"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=4 dst=r10 src=r1 offset=-16 imm=0
#line 13 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-24 imm=0
#line 13 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=6 dst=r10 src=r1 offset=-32 imm=0
#line 13 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=7 dst=r10 src=r1 offset=-40 imm=0
#line 13 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_CALL pc=8 dst=r0 src=r0 offset=0 imm=6
#line 16 "sample/./sample_common_routines.h"
    r0 = test_utility_helpers_helpers[0].address
#line 16 "sample/./sample_common_routines.h"
         (r1, r2, r3, r4, r5);
#line 16 "sample/./sample_common_routines.h"
    if ((test_utility_helpers_helpers[0].tail_call) && (r0 == 0))
#line 16 "sample/./sample_common_routines.h"
        return 0;
        // EBPF_OP_STXW pc=9 dst=r10 src=r0 offset=-40 imm=0
#line 16 "sample/./sample_common_routines.h"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint32_t)r0;
    // EBPF_OP_CALL pc=10 dst=r0 src=r0 offset=0 imm=7
#line 24 "sample/./sample_common_routines.h"
    r0 = test_utility_helpers_helpers[1].address
#line 24 "sample/./sample_common_routines.h"
         (r1, r2, r3, r4, r5);
#line 24 "sample/./sample_common_routines.h"
    if ((test_utility_helpers_helpers[1].tail_call) && (r0 == 0))
#line 24 "sample/./sample_common_routines.h"
        return 0;
        // EBPF_OP_STXDW pc=11 dst=r10 src=r0 offset=-24 imm=0
#line 24 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r0;
    // EBPF_OP_CALL pc=12 dst=r0 src=r0 offset=0 imm=7
#line 27 "sample/./sample_common_routines.h"
    r0 = test_utility_helpers_helpers[1].address
#line 27 "sample/./sample_common_routines.h"
         (r1, r2, r3, r4, r5);
#line 27 "sample/./sample_common_routines.h"
    if ((test_utility_helpers_helpers[1].tail_call) && (r0 == 0))
#line 27 "sample/./sample_common_routines.h"
        return 0;
        // EBPF_OP_STXDW pc=13 dst=r10 src=r0 offset=-32 imm=0
#line 27 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r0;
    // EBPF_OP_CALL pc=14 dst=r0 src=r0 offset=0 imm=8
#line 30 "sample/./sample_common_routines.h"
    r0 = test_utility_helpers_helpers[2].address
#line 30 "sample/./sample_common_routines.h"
         (r1, r2, r3, r4, r5);
#line 30 "sample/./sample_common_routines.h"
    if ((test_utility_helpers_helpers[2].tail_call) && (r0 == 0))
#line 30 "sample/./sample_common_routines.h"
        return 0;
        // EBPF_OP_STXW pc=15 dst=r10 src=r0 offset=-16 imm=0
#line 30 "sample/./sample_common_routines.h"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r0;
    // EBPF_OP_MOV64_REG pc=16 dst=r2 src=r10 offset=0 imm=0
#line 30 "sample/./sample_common_routines.h"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=17 dst=r2 src=r0 offset=0 imm=-8
#line 30 "sample/./sample_common_routines.h"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=18 dst=r6 src=r10 offset=0 imm=0
#line 30 "sample/./sample_common_routines.h"
    r6 = r10;
    // EBPF_OP_ADD64_IMM pc=19 dst=r6 src=r0 offset=0 imm=-40
#line 30 "sample/./sample_common_routines.h"
    r6 += IMMEDIATE(-40);
    // EBPF_OP_LDDW pc=20 dst=r1 src=r0 offset=0 imm=0
#line 33 "sample/./sample_common_routines.h"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_MOV64_REG pc=22 dst=r3 src=r6 offset=0 imm=0
#line 33 "sample/./sample_common_routines.h"
    r3 = r6;
    // EBPF_OP_MOV64_IMM pc=23 dst=r4 src=r0 offset=0 imm=0
#line 33 "sample/./sample_common_routines.h"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=2
#line 33 "sample/./sample_common_routines.h"
    r0 = test_utility_helpers_helpers[3].address
#line 33 "sample/./sample_common_routines.h"
         (r1, r2, r3, r4, r5);
#line 33 "sample/./sample_common_routines.h"
    if ((test_utility_helpers_helpers[3].tail_call) && (r0 == 0))
#line 33 "sample/./sample_common_routines.h"
        return 0;
        // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=6
#line 36 "sample/./sample_common_routines.h"
    r0 = test_utility_helpers_helpers[0].address
#line 36 "sample/./sample_common_routines.h"
         (r1, r2, r3, r4, r5);
#line 36 "sample/./sample_common_routines.h"
    if ((test_utility_helpers_helpers[0].tail_call) && (r0 == 0))
#line 36 "sample/./sample_common_routines.h"
        return 0;
        // EBPF_OP_STXW pc=26 dst=r10 src=r0 offset=-40 imm=0
#line 36 "sample/./sample_common_routines.h"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint32_t)r0;
    // EBPF_OP_CALL pc=27 dst=r0 src=r0 offset=0 imm=7
#line 39 "sample/./sample_common_routines.h"
    r0 = test_utility_helpers_helpers[1].address
#line 39 "sample/./sample_common_routines.h"
         (r1, r2, r3, r4, r5);
#line 39 "sample/./sample_common_routines.h"
    if ((test_utility_helpers_helpers[1].tail_call) && (r0 == 0))
#line 39 "sample/./sample_common_routines.h"
        return 0;
        // EBPF_OP_STXDW pc=28 dst=r10 src=r0 offset=-32 imm=0
#line 39 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r0;
    // EBPF_OP_CALL pc=29 dst=r0 src=r0 offset=0 imm=7
#line 42 "sample/./sample_common_routines.h"
    r0 = test_utility_helpers_helpers[1].address
#line 42 "sample/./sample_common_routines.h"
         (r1, r2, r3, r4, r5);
#line 42 "sample/./sample_common_routines.h"
    if ((test_utility_helpers_helpers[1].tail_call) && (r0 == 0))
#line 42 "sample/./sample_common_routines.h"
        return 0;
        // EBPF_OP_STXDW pc=30 dst=r10 src=r0 offset=-24 imm=0
#line 42 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r0;
    // EBPF_OP_MOV64_REG pc=31 dst=r2 src=r10 offset=0 imm=0
#line 45 "sample/./sample_common_routines.h"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=32 dst=r2 src=r0 offset=0 imm=-4
#line 45 "sample/./sample_common_routines.h"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=33 dst=r1 src=r0 offset=0 imm=0
#line 45 "sample/./sample_common_routines.h"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_MOV64_REG pc=35 dst=r3 src=r6 offset=0 imm=0
#line 45 "sample/./sample_common_routines.h"
    r3 = r6;
    // EBPF_OP_MOV64_IMM pc=36 dst=r4 src=r0 offset=0 imm=0
#line 45 "sample/./sample_common_routines.h"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=37 dst=r0 src=r0 offset=0 imm=2
#line 45 "sample/./sample_common_routines.h"
    r0 = test_utility_helpers_helpers[3].address
#line 45 "sample/./sample_common_routines.h"
         (r1, r2, r3, r4, r5);
#line 45 "sample/./sample_common_routines.h"
    if ((test_utility_helpers_helpers[3].tail_call) && (r0 == 0))
#line 45 "sample/./sample_common_routines.h"
        return 0;
        // EBPF_OP_MOV64_IMM pc=38 dst=r0 src=r0 offset=0 imm=0
#line 75 "sample/test_sample_ebpf.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=39 dst=r0 src=r0 offset=0 imm=0
#line 75 "sample/test_sample_ebpf.c"
    return r0;
#line 75 "sample/test_sample_ebpf.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        test_program_entry,
        "sample~1",
        "sample_ext",
        "test_program_entry",
        test_program_entry_maps,
        1,
        test_program_entry_helpers,
        4,
        40,
        &test_program_entry_program_type_guid,
        &test_program_entry_attach_type_guid,
    },
    {
        0,
        test_utility_helpers,
        "sample~2",
        "sample_ext/utility",
        "test_utility_helpers",
        test_utility_helpers_maps,
        1,
        test_utility_helpers_helpers,
        4,
        40,
        &test_utility_helpers_program_type_guid,
        &test_utility_helpers_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 2;
}

metadata_table_t test_sample_ebpf_metadata_table = {_get_programs, _get_maps, _get_hash};
