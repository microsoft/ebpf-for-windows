// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from printk.o

#include "bpf2c.h"

static void
_get_hash(_Outptr_result_buffer_maybenull_(*size) const uint8_t** hash, _Out_ size_t* size)
{
    *hash = NULL;
    *size = 0;
}
static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = NULL;
    *count = 0;
}

static helper_function_entry_t func_helpers[] = {
    {NULL, 12, "helper_id_12"},
    {NULL, 19, "helper_id_19"},
    {NULL, 13, "helper_id_13"},
    {NULL, 14, "helper_id_14"},
    {NULL, 15, "helper_id_15"},
};

static GUID func_program_type_guid = {0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID func_attach_type_guid = {0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
#pragma code_seg(push, "bind")
static uint64_t
func(void* context)
#line 18 "sample/printk.c"
{
#line 18 "sample/printk.c"
    // Prologue
#line 18 "sample/printk.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 18 "sample/printk.c"
    register uint64_t r0 = 0;
#line 18 "sample/printk.c"
    register uint64_t r1 = 0;
#line 18 "sample/printk.c"
    register uint64_t r2 = 0;
#line 18 "sample/printk.c"
    register uint64_t r3 = 0;
#line 18 "sample/printk.c"
    register uint64_t r4 = 0;
#line 18 "sample/printk.c"
    register uint64_t r5 = 0;
#line 18 "sample/printk.c"
    register uint64_t r6 = 0;
#line 18 "sample/printk.c"
    register uint64_t r7 = 0;
#line 18 "sample/printk.c"
    register uint64_t r8 = 0;
#line 18 "sample/printk.c"
    register uint64_t r9 = 0;
#line 18 "sample/printk.c"
    register uint64_t r10 = 0;

#line 18 "sample/printk.c"
    r1 = (uintptr_t)context;
#line 18 "sample/printk.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r7 src=r1 offset=0 imm=0
#line 18 "sample/printk.c"
    r7 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 18 "sample/printk.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=2 dst=r10 src=r1 offset=-20 imm=0
#line 23 "sample/printk.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=3 dst=r6 src=r0 offset=0 imm=1684828783
#line 23 "sample/printk.c"
    r6 = IMMEDIATE(1684828783);
    // EBPF_OP_STXW pc=4 dst=r10 src=r6 offset=-24 imm=0
#line 23 "sample/printk.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r6;
    // EBPF_OP_LDDW pc=5 dst=r9 src=r0 offset=0 imm=1819043144
#line 23 "sample/printk.c"
    r9 = (uint64_t)8583909746840200520;
    // EBPF_OP_STXDW pc=7 dst=r10 src=r9 offset=-32 imm=0
#line 23 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r9;
    // EBPF_OP_MOV64_REG pc=8 dst=r1 src=r10 offset=0 imm=0
#line 23 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=9 dst=r1 src=r0 offset=0 imm=-32
#line 23 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=10 dst=r2 src=r0 offset=0 imm=13
#line 23 "sample/printk.c"
    r2 = IMMEDIATE(13);
    // EBPF_OP_CALL pc=11 dst=r0 src=r0 offset=0 imm=12
#line 23 "sample/printk.c"
    r0 = func_helpers[0].address
#line 23 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 23 "sample/printk.c"
    if ((func_helpers[0].tail_call) && (r0 == 0))
#line 23 "sample/printk.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=12 dst=r8 src=r0 offset=0 imm=0
#line 23 "sample/printk.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=13 dst=r1 src=r0 offset=0 imm=10
#line 23 "sample/printk.c"
    r1 = IMMEDIATE(10);
    // EBPF_OP_STXH pc=14 dst=r10 src=r1 offset=-20 imm=0
#line 24 "sample/printk.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint16_t)r1;
    // EBPF_OP_STXW pc=15 dst=r10 src=r6 offset=-24 imm=0
#line 24 "sample/printk.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r6;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r9 offset=-32 imm=0
#line 24 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r9;
    // EBPF_OP_MOV64_REG pc=17 dst=r1 src=r10 offset=0 imm=0
#line 24 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=18 dst=r1 src=r0 offset=0 imm=-32
#line 24 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=19 dst=r2 src=r0 offset=0 imm=14
#line 24 "sample/printk.c"
    r2 = IMMEDIATE(14);
    // EBPF_OP_CALL pc=20 dst=r0 src=r0 offset=0 imm=12
#line 24 "sample/printk.c"
    r0 = func_helpers[0].address
#line 24 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 24 "sample/printk.c"
    if ((func_helpers[0].tail_call) && (r0 == 0))
#line 24 "sample/printk.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=21 dst=r6 src=r0 offset=0 imm=0
#line 24 "sample/printk.c"
    r6 = r0;
    // EBPF_OP_CALL pc=22 dst=r0 src=r0 offset=0 imm=19
#line 27 "sample/printk.c"
    r0 = func_helpers[1].address
#line 27 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 27 "sample/printk.c"
    if ((func_helpers[1].tail_call) && (r0 == 0))
#line 27 "sample/printk.c"
        return 0;
        // EBPF_OP_LDDW pc=23 dst=r1 src=r0 offset=0 imm=977553744
#line 27 "sample/printk.c"
    r1 = (uint64_t)32973392621881680;
    // EBPF_OP_STXDW pc=25 dst=r10 src=r1 offset=-32 imm=0
#line 28 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_ADD64_REG pc=26 dst=r6 src=r8 offset=0 imm=0
#line 24 "sample/printk.c"
    r6 += r8;
    // EBPF_OP_RSH64_IMM pc=27 dst=r0 src=r0 offset=0 imm=32
#line 28 "sample/printk.c"
    r0 >>= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=28 dst=r1 src=r10 offset=0 imm=0
#line 28 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=29 dst=r1 src=r0 offset=0 imm=-32
#line 28 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=30 dst=r2 src=r0 offset=0 imm=8
#line 28 "sample/printk.c"
    r2 = IMMEDIATE(8);
    // EBPF_OP_MOV64_REG pc=31 dst=r3 src=r0 offset=0 imm=0
#line 28 "sample/printk.c"
    r3 = r0;
    // EBPF_OP_CALL pc=32 dst=r0 src=r0 offset=0 imm=13
#line 28 "sample/printk.c"
    r0 = func_helpers[2].address
#line 28 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 28 "sample/printk.c"
    if ((func_helpers[2].tail_call) && (r0 == 0))
#line 28 "sample/printk.c"
        return 0;
        // EBPF_OP_ADD64_REG pc=33 dst=r6 src=r0 offset=0 imm=0
#line 28 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_MOV64_IMM pc=34 dst=r8 src=r0 offset=0 imm=117
#line 28 "sample/printk.c"
    r8 = IMMEDIATE(117);
    // EBPF_OP_STXH pc=35 dst=r10 src=r8 offset=-16 imm=0
#line 29 "sample/printk.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r8;
    // EBPF_OP_LDDW pc=36 dst=r1 src=r0 offset=0 imm=1414484560
#line 29 "sample/printk.c"
    r1 = (uint64_t)2675202291049386576;
    // EBPF_OP_STXDW pc=38 dst=r10 src=r1 offset=-24 imm=0
#line 29 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=39 dst=r9 src=r0 offset=0 imm=977553744
#line 29 "sample/printk.c"
    r9 = (uint64_t)2338816401835575632;
    // EBPF_OP_STXDW pc=41 dst=r10 src=r9 offset=-32 imm=0
#line 29 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r9;
    // EBPF_OP_LDXB pc=42 dst=r4 src=r7 offset=48 imm=0
#line 29 "sample/printk.c"
    r4 = *(uint8_t*)(uintptr_t)(r7 + OFFSET(48));
    // EBPF_OP_LDXDW pc=43 dst=r3 src=r7 offset=16 imm=0
#line 29 "sample/printk.c"
    r3 = *(uint64_t*)(uintptr_t)(r7 + OFFSET(16));
    // EBPF_OP_MOV64_REG pc=44 dst=r1 src=r10 offset=0 imm=0
#line 29 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=45 dst=r1 src=r0 offset=0 imm=-32
#line 29 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=46 dst=r2 src=r0 offset=0 imm=18
#line 29 "sample/printk.c"
    r2 = IMMEDIATE(18);
    // EBPF_OP_CALL pc=47 dst=r0 src=r0 offset=0 imm=14
#line 29 "sample/printk.c"
    r0 = func_helpers[3].address
#line 29 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 29 "sample/printk.c"
    if ((func_helpers[3].tail_call) && (r0 == 0))
#line 29 "sample/printk.c"
        return 0;
        // EBPF_OP_STXH pc=48 dst=r10 src=r8 offset=-4 imm=0
#line 31 "sample/printk.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint16_t)r8;
    // EBPF_OP_MOV64_IMM pc=49 dst=r1 src=r0 offset=0 imm=622869070
#line 31 "sample/printk.c"
    r1 = IMMEDIATE(622869070);
    // EBPF_OP_STXW pc=50 dst=r10 src=r1 offset=-8 imm=0
#line 31 "sample/printk.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=51 dst=r1 src=r0 offset=0 imm=1145118837
#line 31 "sample/printk.c"
    r1 = (uint64_t)4993456540003410037;
    // EBPF_OP_STXDW pc=53 dst=r10 src=r1 offset=-16 imm=0
#line 31 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=54 dst=r1 src=r0 offset=0 imm=1414484560
#line 31 "sample/printk.c"
    r1 = (uint64_t)2675202291049386576;
    // EBPF_OP_STXDW pc=56 dst=r10 src=r1 offset=-24 imm=0
#line 31 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=57 dst=r10 src=r9 offset=-32 imm=0
#line 31 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r9;
    // EBPF_OP_ADD64_REG pc=58 dst=r6 src=r0 offset=0 imm=0
#line 29 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_LDXB pc=59 dst=r5 src=r7 offset=40 imm=0
#line 31 "sample/printk.c"
    r5 = *(uint8_t*)(uintptr_t)(r7 + OFFSET(40));
    // EBPF_OP_LDXB pc=60 dst=r4 src=r7 offset=48 imm=0
#line 31 "sample/printk.c"
    r4 = *(uint8_t*)(uintptr_t)(r7 + OFFSET(48));
    // EBPF_OP_LDXDW pc=61 dst=r3 src=r7 offset=16 imm=0
#line 31 "sample/printk.c"
    r3 = *(uint64_t*)(uintptr_t)(r7 + OFFSET(16));
    // EBPF_OP_MOV64_REG pc=62 dst=r1 src=r10 offset=0 imm=0
#line 31 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=63 dst=r1 src=r0 offset=0 imm=-32
#line 31 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=64 dst=r2 src=r0 offset=0 imm=30
#line 31 "sample/printk.c"
    r2 = IMMEDIATE(30);
    // EBPF_OP_CALL pc=65 dst=r0 src=r0 offset=0 imm=15
#line 31 "sample/printk.c"
    r0 = func_helpers[4].address
#line 31 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 31 "sample/printk.c"
    if ((func_helpers[4].tail_call) && (r0 == 0))
#line 31 "sample/printk.c"
        return 0;
        // EBPF_OP_MOV64_IMM pc=66 dst=r1 src=r0 offset=0 imm=9504
#line 31 "sample/printk.c"
    r1 = IMMEDIATE(9504);
    // EBPF_OP_STXH pc=67 dst=r10 src=r1 offset=-28 imm=0
#line 35 "sample/printk.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=68 dst=r1 src=r0 offset=0 imm=826556738
#line 35 "sample/printk.c"
    r1 = IMMEDIATE(826556738);
    // EBPF_OP_STXW pc=69 dst=r10 src=r1 offset=-32 imm=0
#line 35 "sample/printk.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r1;
    // EBPF_OP_ADD64_REG pc=70 dst=r6 src=r0 offset=0 imm=0
#line 30 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_MOV64_IMM pc=71 dst=r8 src=r0 offset=0 imm=0
#line 30 "sample/printk.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=72 dst=r10 src=r8 offset=-26 imm=0
#line 35 "sample/printk.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-26)) = (uint8_t)r8;
    // EBPF_OP_MOV64_REG pc=73 dst=r1 src=r10 offset=0 imm=0
#line 35 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=74 dst=r1 src=r0 offset=0 imm=-32
#line 35 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=75 dst=r2 src=r0 offset=0 imm=7
#line 35 "sample/printk.c"
    r2 = IMMEDIATE(7);
    // EBPF_OP_CALL pc=76 dst=r0 src=r0 offset=0 imm=12
#line 35 "sample/printk.c"
    r0 = func_helpers[0].address
#line 35 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 35 "sample/printk.c"
    if ((func_helpers[0].tail_call) && (r0 == 0))
#line 35 "sample/printk.c"
        return 0;
        // EBPF_OP_LDDW pc=77 dst=r1 src=r0 offset=0 imm=843333954
#line 35 "sample/printk.c"
    r1 = (uint64_t)7812660273793483074;
    // EBPF_OP_STXDW pc=79 dst=r10 src=r1 offset=-32 imm=0
#line 36 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_ADD64_REG pc=80 dst=r6 src=r0 offset=0 imm=0
#line 35 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_STXB pc=81 dst=r10 src=r8 offset=-24 imm=0
#line 36 "sample/printk.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint8_t)r8;
    // EBPF_OP_MOV64_IMM pc=82 dst=r8 src=r0 offset=0 imm=0
#line 36 "sample/printk.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_MOV64_REG pc=83 dst=r1 src=r10 offset=0 imm=0
#line 36 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=84 dst=r1 src=r0 offset=0 imm=-32
#line 36 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=85 dst=r2 src=r0 offset=0 imm=9
#line 36 "sample/printk.c"
    r2 = IMMEDIATE(9);
    // EBPF_OP_CALL pc=86 dst=r0 src=r0 offset=0 imm=12
#line 36 "sample/printk.c"
    r0 = func_helpers[0].address
#line 36 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 36 "sample/printk.c"
    if ((func_helpers[0].tail_call) && (r0 == 0))
#line 36 "sample/printk.c"
        return 0;
        // EBPF_OP_LDDW pc=87 dst=r1 src=r0 offset=0 imm=860111170
#line 36 "sample/printk.c"
    r1 = (uint64_t)7220718397787750722;
    // EBPF_OP_STXDW pc=89 dst=r10 src=r1 offset=-32 imm=0
#line 37 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_ADD64_REG pc=90 dst=r6 src=r0 offset=0 imm=0
#line 36 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_STXB pc=91 dst=r10 src=r8 offset=-24 imm=0
#line 37 "sample/printk.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint8_t)r8;
    // EBPF_OP_LDXDW pc=92 dst=r3 src=r7 offset=16 imm=0
#line 37 "sample/printk.c"
    r3 = *(uint64_t*)(uintptr_t)(r7 + OFFSET(16));
    // EBPF_OP_MOV64_REG pc=93 dst=r1 src=r10 offset=0 imm=0
#line 37 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=94 dst=r1 src=r0 offset=0 imm=-32
#line 37 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=95 dst=r2 src=r0 offset=0 imm=9
#line 37 "sample/printk.c"
    r2 = IMMEDIATE(9);
    // EBPF_OP_CALL pc=96 dst=r0 src=r0 offset=0 imm=13
#line 37 "sample/printk.c"
    r0 = func_helpers[2].address
#line 37 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 37 "sample/printk.c"
    if ((func_helpers[2].tail_call) && (r0 == 0))
#line 37 "sample/printk.c"
        return 0;
        // EBPF_OP_LDDW pc=97 dst=r1 src=r0 offset=0 imm=876888386
#line 37 "sample/printk.c"
    r1 = (uint64_t)31566017637663042;
    // EBPF_OP_STXDW pc=99 dst=r10 src=r1 offset=-32 imm=0
#line 38 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_ADD64_REG pc=100 dst=r6 src=r0 offset=0 imm=0
#line 37 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_LDXDW pc=101 dst=r3 src=r7 offset=16 imm=0
#line 38 "sample/printk.c"
    r3 = *(uint64_t*)(uintptr_t)(r7 + OFFSET(16));
    // EBPF_OP_MOV64_REG pc=102 dst=r1 src=r10 offset=0 imm=0
#line 38 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=103 dst=r1 src=r0 offset=0 imm=-32
#line 38 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=104 dst=r2 src=r0 offset=0 imm=8
#line 38 "sample/printk.c"
    r2 = IMMEDIATE(8);
    // EBPF_OP_CALL pc=105 dst=r0 src=r0 offset=0 imm=13
#line 38 "sample/printk.c"
    r0 = func_helpers[2].address
#line 38 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 38 "sample/printk.c"
    if ((func_helpers[2].tail_call) && (r0 == 0))
#line 38 "sample/printk.c"
        return 0;
        // EBPF_OP_MOV64_IMM pc=106 dst=r1 src=r0 offset=0 imm=893665602
#line 38 "sample/printk.c"
    r1 = IMMEDIATE(893665602);
    // EBPF_OP_STXW pc=107 dst=r10 src=r1 offset=-32 imm=0
#line 42 "sample/printk.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r1;
    // EBPF_OP_ADD64_REG pc=108 dst=r6 src=r0 offset=0 imm=0
#line 38 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_STXB pc=109 dst=r10 src=r8 offset=-28 imm=0
#line 42 "sample/printk.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint8_t)r8;
    // EBPF_OP_LDXDW pc=110 dst=r3 src=r7 offset=16 imm=0
#line 42 "sample/printk.c"
    r3 = *(uint64_t*)(uintptr_t)(r7 + OFFSET(16));
    // EBPF_OP_MOV64_REG pc=111 dst=r1 src=r10 offset=0 imm=0
#line 42 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=112 dst=r1 src=r0 offset=0 imm=-32
#line 42 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=113 dst=r2 src=r0 offset=0 imm=5
#line 42 "sample/printk.c"
    r2 = IMMEDIATE(5);
    // EBPF_OP_CALL pc=114 dst=r0 src=r0 offset=0 imm=13
#line 42 "sample/printk.c"
    r0 = func_helpers[2].address
#line 42 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 42 "sample/printk.c"
    if ((func_helpers[2].tail_call) && (r0 == 0))
#line 42 "sample/printk.c"
        return 0;
        // EBPF_OP_LDDW pc=115 dst=r1 src=r0 offset=0 imm=910442818
#line 42 "sample/printk.c"
    r1 = (uint64_t)32973392554770754;
    // EBPF_OP_STXDW pc=117 dst=r10 src=r1 offset=-32 imm=0
#line 43 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_ADD64_REG pc=118 dst=r6 src=r0 offset=0 imm=0
#line 42 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_MOV64_REG pc=119 dst=r1 src=r10 offset=0 imm=0
#line 42 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=120 dst=r1 src=r0 offset=0 imm=-32
#line 42 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=121 dst=r2 src=r0 offset=0 imm=8
#line 43 "sample/printk.c"
    r2 = IMMEDIATE(8);
    // EBPF_OP_CALL pc=122 dst=r0 src=r0 offset=0 imm=12
#line 43 "sample/printk.c"
    r0 = func_helpers[0].address
#line 43 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 43 "sample/printk.c"
    if ((func_helpers[0].tail_call) && (r0 == 0))
#line 43 "sample/printk.c"
        return 0;
        // EBPF_OP_STXB pc=123 dst=r10 src=r8 offset=-22 imm=0
#line 46 "sample/printk.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-22)) = (uint8_t)r8;
    // EBPF_OP_MOV64_IMM pc=124 dst=r1 src=r0 offset=0 imm=25966
#line 46 "sample/printk.c"
    r1 = IMMEDIATE(25966);
    // EBPF_OP_STXH pc=125 dst=r10 src=r1 offset=-24 imm=0
#line 46 "sample/printk.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=126 dst=r1 src=r0 offset=0 imm=623915057
#line 46 "sample/printk.c"
    r1 = (uint64_t)8026575779790860337;
    // EBPF_OP_STXDW pc=128 dst=r10 src=r1 offset=-32 imm=0
#line 46 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_ADD64_REG pc=129 dst=r6 src=r0 offset=0 imm=0
#line 43 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_MOV64_REG pc=130 dst=r1 src=r10 offset=0 imm=0
#line 43 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=131 dst=r1 src=r0 offset=0 imm=-32
#line 43 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=132 dst=r2 src=r0 offset=0 imm=11
#line 46 "sample/printk.c"
    r2 = IMMEDIATE(11);
    // EBPF_OP_CALL pc=133 dst=r0 src=r0 offset=0 imm=12
#line 46 "sample/printk.c"
    r0 = func_helpers[0].address
#line 46 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 46 "sample/printk.c"
    if ((func_helpers[0].tail_call) && (r0 == 0))
#line 46 "sample/printk.c"
        return 0;
        // EBPF_OP_ADD64_REG pc=134 dst=r6 src=r0 offset=0 imm=0
#line 46 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_MOV64_REG pc=135 dst=r0 src=r6 offset=0 imm=0
#line 48 "sample/printk.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=136 dst=r0 src=r0 offset=0 imm=0
#line 48 "sample/printk.c"
    return r0;
#line 48 "sample/printk.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        func,
        "bind",
        "bind",
        "func",
        NULL,
        0,
        func_helpers,
        5,
        137,
        &func_program_type_guid,
        &func_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 1;
}

metadata_table_t printk_metadata_table = {_get_programs, _get_maps, _get_hash};
