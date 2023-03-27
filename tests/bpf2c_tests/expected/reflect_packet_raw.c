// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from reflect_packet.o

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

static GUID reflect_packet_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID reflect_packet_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
#pragma code_seg(push, "xdp/re~1")
static uint64_t
reflect_packet(void* context)
#line 23 "sample/reflect_packet.c"
{
#line 23 "sample/reflect_packet.c"
    // Prologue
#line 23 "sample/reflect_packet.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 23 "sample/reflect_packet.c"
    register uint64_t r0 = 0;
#line 23 "sample/reflect_packet.c"
    register uint64_t r1 = 0;
#line 23 "sample/reflect_packet.c"
    register uint64_t r2 = 0;
#line 23 "sample/reflect_packet.c"
    register uint64_t r3 = 0;
#line 23 "sample/reflect_packet.c"
    register uint64_t r4 = 0;
#line 23 "sample/reflect_packet.c"
    register uint64_t r5 = 0;
#line 23 "sample/reflect_packet.c"
    register uint64_t r10 = 0;

#line 23 "sample/reflect_packet.c"
    r1 = (uintptr_t)context;
#line 23 "sample/reflect_packet.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r0 src=r0 offset=0 imm=1
#line 23 "sample/reflect_packet.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_LDXDW pc=1 dst=r2 src=r1 offset=8 imm=0
#line 29 "sample/reflect_packet.c"
    r2 = *(uint64_t*)(uintptr_t)(r1 + OFFSET(8));
    // EBPF_OP_LDXDW pc=2 dst=r1 src=r1 offset=0 imm=0
#line 28 "sample/reflect_packet.c"
    r1 = *(uint64_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=3 dst=r3 src=r1 offset=0 imm=0
#line 29 "sample/reflect_packet.c"
    r3 = r1;
    // EBPF_OP_ADD64_IMM pc=4 dst=r3 src=r0 offset=0 imm=14
#line 29 "sample/reflect_packet.c"
    r3 += IMMEDIATE(14);
    // EBPF_OP_JGT_REG pc=5 dst=r3 src=r2 offset=203 imm=0
#line 29 "sample/reflect_packet.c"
    if (r3 > r2)
#line 29 "sample/reflect_packet.c"
        goto label_3;
        // EBPF_OP_LDXH pc=6 dst=r4 src=r1 offset=12 imm=0
#line 34 "sample/reflect_packet.c"
    r4 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(12));
    // EBPF_OP_JEQ_IMM pc=7 dst=r4 src=r0 offset=56 imm=56710
#line 34 "sample/reflect_packet.c"
    if (r4 == IMMEDIATE(56710))
#line 34 "sample/reflect_packet.c"
        goto label_1;
        // EBPF_OP_JNE_IMM pc=8 dst=r4 src=r0 offset=200 imm=8
#line 34 "sample/reflect_packet.c"
    if (r4 != IMMEDIATE(8))
#line 34 "sample/reflect_packet.c"
        goto label_3;
        // EBPF_OP_MOV64_REG pc=9 dst=r4 src=r1 offset=0 imm=0
#line 35 "sample/reflect_packet.c"
    r4 = r1;
    // EBPF_OP_ADD64_IMM pc=10 dst=r4 src=r0 offset=0 imm=34
#line 35 "sample/reflect_packet.c"
    r4 += IMMEDIATE(34);
    // EBPF_OP_JGT_REG pc=11 dst=r4 src=r2 offset=197 imm=0
#line 35 "sample/reflect_packet.c"
    if (r4 > r2)
#line 35 "sample/reflect_packet.c"
        goto label_3;
        // EBPF_OP_LDXB pc=12 dst=r4 src=r1 offset=23 imm=0
#line 41 "sample/reflect_packet.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(23));
    // EBPF_OP_JNE_IMM pc=13 dst=r4 src=r0 offset=195 imm=17
#line 41 "sample/reflect_packet.c"
    if (r4 != IMMEDIATE(17))
#line 41 "sample/reflect_packet.c"
        goto label_3;
        // EBPF_OP_LDXB pc=14 dst=r4 src=r1 offset=14 imm=0
#line 41 "sample/reflect_packet.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(14));
    // EBPF_OP_LSH64_IMM pc=15 dst=r4 src=r0 offset=0 imm=2
#line 41 "sample/reflect_packet.c"
    r4 <<= IMMEDIATE(2);
    // EBPF_OP_AND64_IMM pc=16 dst=r4 src=r0 offset=0 imm=60
#line 41 "sample/reflect_packet.c"
    r4 &= IMMEDIATE(60);
    // EBPF_OP_ADD64_REG pc=17 dst=r3 src=r4 offset=0 imm=0
#line 41 "sample/reflect_packet.c"
    r3 += r4;
    // EBPF_OP_MOV64_REG pc=18 dst=r4 src=r3 offset=0 imm=0
#line 41 "sample/reflect_packet.c"
    r4 = r3;
    // EBPF_OP_ADD64_IMM pc=19 dst=r4 src=r0 offset=0 imm=8
#line 41 "sample/reflect_packet.c"
    r4 += IMMEDIATE(8);
    // EBPF_OP_JGT_REG pc=20 dst=r4 src=r2 offset=188 imm=0
#line 41 "sample/reflect_packet.c"
    if (r4 > r2)
#line 41 "sample/reflect_packet.c"
        goto label_3;
        // EBPF_OP_LDXH pc=21 dst=r2 src=r3 offset=2 imm=0
#line 47 "sample/reflect_packet.c"
    r2 = *(uint16_t*)(uintptr_t)(r3 + OFFSET(2));
    // EBPF_OP_JNE_IMM pc=22 dst=r2 src=r0 offset=186 imm=7459
#line 47 "sample/reflect_packet.c"
    if (r2 != IMMEDIATE(7459))
#line 47 "sample/reflect_packet.c"
        goto label_3;
        // EBPF_OP_LDXB pc=23 dst=r2 src=r1 offset=5 imm=0
#line 15 "sample/./xdp_common.h"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(5));
    // EBPF_OP_LSH64_IMM pc=24 dst=r2 src=r0 offset=0 imm=8
#line 15 "sample/./xdp_common.h"
    r2 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=25 dst=r3 src=r1 offset=4 imm=0
#line 15 "sample/./xdp_common.h"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(4));
    // EBPF_OP_OR64_REG pc=26 dst=r2 src=r3 offset=0 imm=0
#line 15 "sample/./xdp_common.h"
    r2 |= r3;
    // EBPF_OP_STXH pc=27 dst=r10 src=r2 offset=-12 imm=0
#line 15 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r2;
    // EBPF_OP_LDXB pc=28 dst=r2 src=r1 offset=1 imm=0
#line 15 "sample/./xdp_common.h"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(1));
    // EBPF_OP_LSH64_IMM pc=29 dst=r2 src=r0 offset=0 imm=8
#line 15 "sample/./xdp_common.h"
    r2 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=30 dst=r3 src=r1 offset=0 imm=0
#line 15 "sample/./xdp_common.h"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_OR64_REG pc=31 dst=r2 src=r3 offset=0 imm=0
#line 15 "sample/./xdp_common.h"
    r2 |= r3;
    // EBPF_OP_LDXB pc=32 dst=r3 src=r1 offset=3 imm=0
#line 15 "sample/./xdp_common.h"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(3));
    // EBPF_OP_LSH64_IMM pc=33 dst=r3 src=r0 offset=0 imm=8
#line 15 "sample/./xdp_common.h"
    r3 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=34 dst=r4 src=r1 offset=2 imm=0
#line 15 "sample/./xdp_common.h"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(2));
    // EBPF_OP_OR64_REG pc=35 dst=r3 src=r4 offset=0 imm=0
#line 15 "sample/./xdp_common.h"
    r3 |= r4;
    // EBPF_OP_LSH64_IMM pc=36 dst=r3 src=r0 offset=0 imm=16
#line 15 "sample/./xdp_common.h"
    r3 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=37 dst=r3 src=r2 offset=0 imm=0
#line 15 "sample/./xdp_common.h"
    r3 |= r2;
    // EBPF_OP_STXW pc=38 dst=r10 src=r3 offset=-16 imm=0
#line 15 "sample/./xdp_common.h"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r3;
    // EBPF_OP_LDXH pc=39 dst=r2 src=r1 offset=6 imm=0
#line 16 "sample/./xdp_common.h"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(6));
    // EBPF_OP_STXH pc=40 dst=r1 src=r2 offset=0 imm=0
#line 16 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(0)) = (uint16_t)r2;
    // EBPF_OP_LDXH pc=41 dst=r2 src=r1 offset=8 imm=0
#line 16 "sample/./xdp_common.h"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(8));
    // EBPF_OP_STXH pc=42 dst=r1 src=r2 offset=2 imm=0
#line 16 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(2)) = (uint16_t)r2;
    // EBPF_OP_LDXH pc=43 dst=r2 src=r1 offset=10 imm=0
#line 16 "sample/./xdp_common.h"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(10));
    // EBPF_OP_STXH pc=44 dst=r1 src=r2 offset=4 imm=0
#line 16 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(4)) = (uint16_t)r2;
    // EBPF_OP_LDXW pc=45 dst=r2 src=r10 offset=-16 imm=0
#line 17 "sample/./xdp_common.h"
    r2 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=46 dst=r3 src=r2 offset=0 imm=0
#line 17 "sample/./xdp_common.h"
    r3 = r2;
    // EBPF_OP_RSH64_IMM pc=47 dst=r3 src=r0 offset=0 imm=16
#line 17 "sample/./xdp_common.h"
    r3 >>= IMMEDIATE(16);
    // EBPF_OP_STXB pc=48 dst=r1 src=r3 offset=8 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(8)) = (uint8_t)r3;
    // EBPF_OP_MOV64_REG pc=49 dst=r3 src=r2 offset=0 imm=0
#line 17 "sample/./xdp_common.h"
    r3 = r2;
    // EBPF_OP_RSH64_IMM pc=50 dst=r3 src=r0 offset=0 imm=24
#line 17 "sample/./xdp_common.h"
    r3 >>= IMMEDIATE(24);
    // EBPF_OP_STXB pc=51 dst=r1 src=r3 offset=9 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(9)) = (uint8_t)r3;
    // EBPF_OP_STXB pc=52 dst=r1 src=r2 offset=6 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(6)) = (uint8_t)r2;
    // EBPF_OP_RSH64_IMM pc=53 dst=r2 src=r0 offset=0 imm=8
#line 17 "sample/./xdp_common.h"
    r2 >>= IMMEDIATE(8);
    // EBPF_OP_STXB pc=54 dst=r1 src=r2 offset=7 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(7)) = (uint8_t)r2;
    // EBPF_OP_LDXH pc=55 dst=r2 src=r10 offset=-12 imm=0
#line 17 "sample/./xdp_common.h"
    r2 = *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12));
    // EBPF_OP_STXB pc=56 dst=r1 src=r2 offset=10 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(10)) = (uint8_t)r2;
    // EBPF_OP_RSH64_IMM pc=57 dst=r2 src=r0 offset=0 imm=8
#line 17 "sample/./xdp_common.h"
    r2 >>= IMMEDIATE(8);
    // EBPF_OP_STXB pc=58 dst=r1 src=r2 offset=11 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(11)) = (uint8_t)r2;
    // EBPF_OP_LDXW pc=59 dst=r2 src=r1 offset=30 imm=0
#line 23 "sample/./xdp_common.h"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(30));
    // EBPF_OP_LDXW pc=60 dst=r3 src=r1 offset=26 imm=0
#line 24 "sample/./xdp_common.h"
    r3 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(26));
    // EBPF_OP_STXW pc=61 dst=r1 src=r3 offset=30 imm=0
#line 24 "sample/./xdp_common.h"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(30)) = (uint32_t)r3;
    // EBPF_OP_STXW pc=62 dst=r1 src=r2 offset=26 imm=0
#line 25 "sample/./xdp_common.h"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(26)) = (uint32_t)r2;
    // EBPF_OP_JA pc=63 dst=r0 src=r0 offset=144 imm=0
#line 25 "sample/./xdp_common.h"
    goto label_2;
label_1:
    // EBPF_OP_MOV64_REG pc=64 dst=r3 src=r1 offset=0 imm=0
#line 55 "sample/reflect_packet.c"
    r3 = r1;
    // EBPF_OP_ADD64_IMM pc=65 dst=r3 src=r0 offset=0 imm=54
#line 55 "sample/reflect_packet.c"
    r3 += IMMEDIATE(54);
    // EBPF_OP_JGT_REG pc=66 dst=r3 src=r2 offset=142 imm=0
#line 55 "sample/reflect_packet.c"
    if (r3 > r2)
#line 55 "sample/reflect_packet.c"
        goto label_3;
        // EBPF_OP_MOV64_REG pc=67 dst=r3 src=r1 offset=0 imm=0
#line 55 "sample/reflect_packet.c"
    r3 = r1;
    // EBPF_OP_ADD64_IMM pc=68 dst=r3 src=r0 offset=0 imm=62
#line 55 "sample/reflect_packet.c"
    r3 += IMMEDIATE(62);
    // EBPF_OP_JGT_REG pc=69 dst=r3 src=r2 offset=139 imm=0
#line 61 "sample/reflect_packet.c"
    if (r3 > r2)
#line 61 "sample/reflect_packet.c"
        goto label_3;
        // EBPF_OP_LDXB pc=70 dst=r2 src=r1 offset=20 imm=0
#line 61 "sample/reflect_packet.c"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(20));
    // EBPF_OP_JNE_IMM pc=71 dst=r2 src=r0 offset=137 imm=17
#line 61 "sample/reflect_packet.c"
    if (r2 != IMMEDIATE(17))
#line 61 "sample/reflect_packet.c"
        goto label_3;
        // EBPF_OP_LDXH pc=72 dst=r2 src=r1 offset=56 imm=0
#line 67 "sample/reflect_packet.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(56));
    // EBPF_OP_JNE_IMM pc=73 dst=r2 src=r0 offset=135 imm=7459
#line 67 "sample/reflect_packet.c"
    if (r2 != IMMEDIATE(7459))
#line 67 "sample/reflect_packet.c"
        goto label_3;
        // EBPF_OP_LDXB pc=74 dst=r2 src=r1 offset=5 imm=0
#line 15 "sample/./xdp_common.h"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(5));
    // EBPF_OP_LSH64_IMM pc=75 dst=r2 src=r0 offset=0 imm=8
#line 15 "sample/./xdp_common.h"
    r2 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=76 dst=r3 src=r1 offset=4 imm=0
#line 15 "sample/./xdp_common.h"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(4));
    // EBPF_OP_OR64_REG pc=77 dst=r2 src=r3 offset=0 imm=0
#line 15 "sample/./xdp_common.h"
    r2 |= r3;
    // EBPF_OP_STXH pc=78 dst=r10 src=r2 offset=-12 imm=0
#line 15 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r2;
    // EBPF_OP_LDXB pc=79 dst=r2 src=r1 offset=1 imm=0
#line 15 "sample/./xdp_common.h"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(1));
    // EBPF_OP_LSH64_IMM pc=80 dst=r2 src=r0 offset=0 imm=8
#line 15 "sample/./xdp_common.h"
    r2 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=81 dst=r3 src=r1 offset=0 imm=0
#line 15 "sample/./xdp_common.h"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_OR64_REG pc=82 dst=r2 src=r3 offset=0 imm=0
#line 15 "sample/./xdp_common.h"
    r2 |= r3;
    // EBPF_OP_LDXB pc=83 dst=r3 src=r1 offset=3 imm=0
#line 15 "sample/./xdp_common.h"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(3));
    // EBPF_OP_LSH64_IMM pc=84 dst=r3 src=r0 offset=0 imm=8
#line 15 "sample/./xdp_common.h"
    r3 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=85 dst=r4 src=r1 offset=2 imm=0
#line 15 "sample/./xdp_common.h"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(2));
    // EBPF_OP_OR64_REG pc=86 dst=r3 src=r4 offset=0 imm=0
#line 15 "sample/./xdp_common.h"
    r3 |= r4;
    // EBPF_OP_LSH64_IMM pc=87 dst=r3 src=r0 offset=0 imm=16
#line 15 "sample/./xdp_common.h"
    r3 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=88 dst=r3 src=r2 offset=0 imm=0
#line 15 "sample/./xdp_common.h"
    r3 |= r2;
    // EBPF_OP_STXW pc=89 dst=r10 src=r3 offset=-16 imm=0
#line 15 "sample/./xdp_common.h"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r3;
    // EBPF_OP_LDXH pc=90 dst=r2 src=r1 offset=6 imm=0
#line 16 "sample/./xdp_common.h"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(6));
    // EBPF_OP_STXH pc=91 dst=r1 src=r2 offset=0 imm=0
#line 16 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(0)) = (uint16_t)r2;
    // EBPF_OP_LDXH pc=92 dst=r2 src=r1 offset=8 imm=0
#line 16 "sample/./xdp_common.h"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(8));
    // EBPF_OP_STXH pc=93 dst=r1 src=r2 offset=2 imm=0
#line 16 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(2)) = (uint16_t)r2;
    // EBPF_OP_LDXH pc=94 dst=r2 src=r1 offset=10 imm=0
#line 16 "sample/./xdp_common.h"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(10));
    // EBPF_OP_STXH pc=95 dst=r1 src=r2 offset=4 imm=0
#line 16 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(4)) = (uint16_t)r2;
    // EBPF_OP_LDXW pc=96 dst=r2 src=r10 offset=-16 imm=0
#line 17 "sample/./xdp_common.h"
    r2 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=97 dst=r3 src=r2 offset=0 imm=0
#line 17 "sample/./xdp_common.h"
    r3 = r2;
    // EBPF_OP_RSH64_IMM pc=98 dst=r3 src=r0 offset=0 imm=16
#line 17 "sample/./xdp_common.h"
    r3 >>= IMMEDIATE(16);
    // EBPF_OP_STXB pc=99 dst=r1 src=r3 offset=8 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(8)) = (uint8_t)r3;
    // EBPF_OP_MOV64_REG pc=100 dst=r3 src=r2 offset=0 imm=0
#line 17 "sample/./xdp_common.h"
    r3 = r2;
    // EBPF_OP_RSH64_IMM pc=101 dst=r3 src=r0 offset=0 imm=24
#line 17 "sample/./xdp_common.h"
    r3 >>= IMMEDIATE(24);
    // EBPF_OP_STXB pc=102 dst=r1 src=r3 offset=9 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(9)) = (uint8_t)r3;
    // EBPF_OP_STXB pc=103 dst=r1 src=r2 offset=6 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(6)) = (uint8_t)r2;
    // EBPF_OP_RSH64_IMM pc=104 dst=r2 src=r0 offset=0 imm=8
#line 17 "sample/./xdp_common.h"
    r2 >>= IMMEDIATE(8);
    // EBPF_OP_STXB pc=105 dst=r1 src=r2 offset=7 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(7)) = (uint8_t)r2;
    // EBPF_OP_LDXH pc=106 dst=r2 src=r10 offset=-12 imm=0
#line 17 "sample/./xdp_common.h"
    r2 = *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12));
    // EBPF_OP_STXB pc=107 dst=r1 src=r2 offset=10 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(10)) = (uint8_t)r2;
    // EBPF_OP_RSH64_IMM pc=108 dst=r2 src=r0 offset=0 imm=8
#line 17 "sample/./xdp_common.h"
    r2 >>= IMMEDIATE(8);
    // EBPF_OP_STXB pc=109 dst=r1 src=r2 offset=11 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(11)) = (uint8_t)r2;
    // EBPF_OP_LDXB pc=110 dst=r3 src=r1 offset=47 imm=0
#line 32 "sample/./xdp_common.h"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(47));
    // EBPF_OP_LSH64_IMM pc=111 dst=r3 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r3 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=112 dst=r2 src=r1 offset=46 imm=0
#line 32 "sample/./xdp_common.h"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(46));
    // EBPF_OP_OR64_REG pc=113 dst=r3 src=r2 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r3 |= r2;
    // EBPF_OP_LDXB pc=114 dst=r2 src=r1 offset=49 imm=0
#line 32 "sample/./xdp_common.h"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(49));
    // EBPF_OP_LSH64_IMM pc=115 dst=r2 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r2 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=116 dst=r4 src=r1 offset=48 imm=0
#line 32 "sample/./xdp_common.h"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(48));
    // EBPF_OP_OR64_REG pc=117 dst=r2 src=r4 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r2 |= r4;
    // EBPF_OP_LSH64_IMM pc=118 dst=r2 src=r0 offset=0 imm=16
#line 32 "sample/./xdp_common.h"
    r2 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=119 dst=r2 src=r3 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r2 |= r3;
    // EBPF_OP_LDXB pc=120 dst=r4 src=r1 offset=51 imm=0
#line 32 "sample/./xdp_common.h"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(51));
    // EBPF_OP_LSH64_IMM pc=121 dst=r4 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r4 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=122 dst=r3 src=r1 offset=50 imm=0
#line 32 "sample/./xdp_common.h"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(50));
    // EBPF_OP_OR64_REG pc=123 dst=r4 src=r3 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r4 |= r3;
    // EBPF_OP_LDXB pc=124 dst=r3 src=r1 offset=53 imm=0
#line 32 "sample/./xdp_common.h"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(53));
    // EBPF_OP_LSH64_IMM pc=125 dst=r3 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r3 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=126 dst=r5 src=r1 offset=52 imm=0
#line 32 "sample/./xdp_common.h"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(52));
    // EBPF_OP_OR64_REG pc=127 dst=r3 src=r5 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r3 |= r5;
    // EBPF_OP_LSH64_IMM pc=128 dst=r3 src=r0 offset=0 imm=16
#line 32 "sample/./xdp_common.h"
    r3 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=129 dst=r3 src=r4 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r3 |= r4;
    // EBPF_OP_LSH64_IMM pc=130 dst=r3 src=r0 offset=0 imm=32
#line 32 "sample/./xdp_common.h"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_OR64_REG pc=131 dst=r3 src=r2 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r3 |= r2;
    // EBPF_OP_LDXB pc=132 dst=r4 src=r1 offset=39 imm=0
#line 32 "sample/./xdp_common.h"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(39));
    // EBPF_OP_LSH64_IMM pc=133 dst=r4 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r4 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=134 dst=r2 src=r1 offset=38 imm=0
#line 32 "sample/./xdp_common.h"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(38));
    // EBPF_OP_OR64_REG pc=135 dst=r4 src=r2 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r4 |= r2;
    // EBPF_OP_LDXB pc=136 dst=r2 src=r1 offset=41 imm=0
#line 32 "sample/./xdp_common.h"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(41));
    // EBPF_OP_LSH64_IMM pc=137 dst=r2 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r2 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=138 dst=r5 src=r1 offset=40 imm=0
#line 32 "sample/./xdp_common.h"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_OR64_REG pc=139 dst=r2 src=r5 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r2 |= r5;
    // EBPF_OP_STXDW pc=140 dst=r10 src=r3 offset=-8 imm=0
#line 32 "sample/./xdp_common.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r3;
    // EBPF_OP_LSH64_IMM pc=141 dst=r2 src=r0 offset=0 imm=16
#line 32 "sample/./xdp_common.h"
    r2 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=142 dst=r2 src=r4 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r2 |= r4;
    // EBPF_OP_LDXB pc=143 dst=r3 src=r1 offset=43 imm=0
#line 32 "sample/./xdp_common.h"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(43));
    // EBPF_OP_LSH64_IMM pc=144 dst=r3 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r3 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=145 dst=r4 src=r1 offset=42 imm=0
#line 32 "sample/./xdp_common.h"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(42));
    // EBPF_OP_OR64_REG pc=146 dst=r3 src=r4 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r3 |= r4;
    // EBPF_OP_LDXB pc=147 dst=r4 src=r1 offset=45 imm=0
#line 32 "sample/./xdp_common.h"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(45));
    // EBPF_OP_LSH64_IMM pc=148 dst=r4 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r4 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=149 dst=r5 src=r1 offset=44 imm=0
#line 32 "sample/./xdp_common.h"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_OR64_REG pc=150 dst=r4 src=r5 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r4 |= r5;
    // EBPF_OP_LSH64_IMM pc=151 dst=r4 src=r0 offset=0 imm=16
#line 32 "sample/./xdp_common.h"
    r4 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=152 dst=r4 src=r3 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r4 |= r3;
    // EBPF_OP_LSH64_IMM pc=153 dst=r4 src=r0 offset=0 imm=32
#line 32 "sample/./xdp_common.h"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_OR64_REG pc=154 dst=r4 src=r2 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r4 |= r2;
    // EBPF_OP_STXDW pc=155 dst=r10 src=r4 offset=-16 imm=0
#line 32 "sample/./xdp_common.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r4;
    // EBPF_OP_LDXW pc=156 dst=r2 src=r1 offset=22 imm=0
#line 33 "sample/./xdp_common.h"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(22));
    // EBPF_OP_STXW pc=157 dst=r1 src=r2 offset=38 imm=0
#line 33 "sample/./xdp_common.h"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(38)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=158 dst=r2 src=r1 offset=26 imm=0
#line 33 "sample/./xdp_common.h"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(26));
    // EBPF_OP_STXW pc=159 dst=r1 src=r2 offset=42 imm=0
#line 33 "sample/./xdp_common.h"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(42)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=160 dst=r2 src=r1 offset=30 imm=0
#line 33 "sample/./xdp_common.h"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(30));
    // EBPF_OP_STXW pc=161 dst=r1 src=r2 offset=46 imm=0
#line 33 "sample/./xdp_common.h"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(46)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=162 dst=r2 src=r1 offset=34 imm=0
#line 33 "sample/./xdp_common.h"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(34));
    // EBPF_OP_STXW pc=163 dst=r1 src=r2 offset=50 imm=0
#line 33 "sample/./xdp_common.h"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(50)) = (uint32_t)r2;
    // EBPF_OP_LDXDW pc=164 dst=r2 src=r10 offset=-16 imm=0
#line 34 "sample/./xdp_common.h"
    r2 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=165 dst=r3 src=r2 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r3 = r2;
    // EBPF_OP_RSH64_IMM pc=166 dst=r3 src=r0 offset=0 imm=48
#line 34 "sample/./xdp_common.h"
    r3 >>= IMMEDIATE(48);
    // EBPF_OP_STXB pc=167 dst=r1 src=r3 offset=28 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(28)) = (uint8_t)r3;
    // EBPF_OP_MOV64_REG pc=168 dst=r3 src=r2 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r3 = r2;
    // EBPF_OP_RSH64_IMM pc=169 dst=r3 src=r0 offset=0 imm=56
#line 34 "sample/./xdp_common.h"
    r3 >>= IMMEDIATE(56);
    // EBPF_OP_STXB pc=170 dst=r1 src=r3 offset=29 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(29)) = (uint8_t)r3;
    // EBPF_OP_MOV64_REG pc=171 dst=r3 src=r2 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r3 = r2;
    // EBPF_OP_RSH64_IMM pc=172 dst=r3 src=r0 offset=0 imm=32
#line 34 "sample/./xdp_common.h"
    r3 >>= IMMEDIATE(32);
    // EBPF_OP_STXB pc=173 dst=r1 src=r3 offset=26 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(26)) = (uint8_t)r3;
    // EBPF_OP_MOV64_REG pc=174 dst=r3 src=r2 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r3 = r2;
    // EBPF_OP_RSH64_IMM pc=175 dst=r3 src=r0 offset=0 imm=40
#line 34 "sample/./xdp_common.h"
    r3 >>= IMMEDIATE(40);
    // EBPF_OP_STXB pc=176 dst=r1 src=r3 offset=27 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(27)) = (uint8_t)r3;
    // EBPF_OP_MOV64_REG pc=177 dst=r3 src=r2 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r3 = r2;
    // EBPF_OP_RSH64_IMM pc=178 dst=r3 src=r0 offset=0 imm=16
#line 34 "sample/./xdp_common.h"
    r3 >>= IMMEDIATE(16);
    // EBPF_OP_STXB pc=179 dst=r1 src=r3 offset=24 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(24)) = (uint8_t)r3;
    // EBPF_OP_MOV64_REG pc=180 dst=r3 src=r2 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r3 = r2;
    // EBPF_OP_RSH64_IMM pc=181 dst=r3 src=r0 offset=0 imm=24
#line 34 "sample/./xdp_common.h"
    r3 >>= IMMEDIATE(24);
    // EBPF_OP_STXB pc=182 dst=r1 src=r3 offset=25 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(25)) = (uint8_t)r3;
    // EBPF_OP_STXB pc=183 dst=r1 src=r2 offset=22 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(22)) = (uint8_t)r2;
    // EBPF_OP_RSH64_IMM pc=184 dst=r2 src=r0 offset=0 imm=8
#line 34 "sample/./xdp_common.h"
    r2 >>= IMMEDIATE(8);
    // EBPF_OP_STXB pc=185 dst=r1 src=r2 offset=23 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(23)) = (uint8_t)r2;
    // EBPF_OP_LDXDW pc=186 dst=r2 src=r10 offset=-8 imm=0
#line 34 "sample/./xdp_common.h"
    r2 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=187 dst=r3 src=r2 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r3 = r2;
    // EBPF_OP_RSH64_IMM pc=188 dst=r3 src=r0 offset=0 imm=48
#line 34 "sample/./xdp_common.h"
    r3 >>= IMMEDIATE(48);
    // EBPF_OP_STXB pc=189 dst=r1 src=r3 offset=36 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(36)) = (uint8_t)r3;
    // EBPF_OP_MOV64_REG pc=190 dst=r3 src=r2 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r3 = r2;
    // EBPF_OP_RSH64_IMM pc=191 dst=r3 src=r0 offset=0 imm=56
#line 34 "sample/./xdp_common.h"
    r3 >>= IMMEDIATE(56);
    // EBPF_OP_STXB pc=192 dst=r1 src=r3 offset=37 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(37)) = (uint8_t)r3;
    // EBPF_OP_MOV64_REG pc=193 dst=r3 src=r2 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r3 = r2;
    // EBPF_OP_RSH64_IMM pc=194 dst=r3 src=r0 offset=0 imm=32
#line 34 "sample/./xdp_common.h"
    r3 >>= IMMEDIATE(32);
    // EBPF_OP_STXB pc=195 dst=r1 src=r3 offset=34 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(34)) = (uint8_t)r3;
    // EBPF_OP_MOV64_REG pc=196 dst=r3 src=r2 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r3 = r2;
    // EBPF_OP_RSH64_IMM pc=197 dst=r3 src=r0 offset=0 imm=40
#line 34 "sample/./xdp_common.h"
    r3 >>= IMMEDIATE(40);
    // EBPF_OP_STXB pc=198 dst=r1 src=r3 offset=35 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(35)) = (uint8_t)r3;
    // EBPF_OP_MOV64_REG pc=199 dst=r3 src=r2 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r3 = r2;
    // EBPF_OP_RSH64_IMM pc=200 dst=r3 src=r0 offset=0 imm=16
#line 34 "sample/./xdp_common.h"
    r3 >>= IMMEDIATE(16);
    // EBPF_OP_STXB pc=201 dst=r1 src=r3 offset=32 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(32)) = (uint8_t)r3;
    // EBPF_OP_MOV64_REG pc=202 dst=r3 src=r2 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r3 = r2;
    // EBPF_OP_RSH64_IMM pc=203 dst=r3 src=r0 offset=0 imm=24
#line 34 "sample/./xdp_common.h"
    r3 >>= IMMEDIATE(24);
    // EBPF_OP_STXB pc=204 dst=r1 src=r3 offset=33 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(33)) = (uint8_t)r3;
    // EBPF_OP_STXB pc=205 dst=r1 src=r2 offset=30 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(30)) = (uint8_t)r2;
    // EBPF_OP_RSH64_IMM pc=206 dst=r2 src=r0 offset=0 imm=8
#line 34 "sample/./xdp_common.h"
    r2 >>= IMMEDIATE(8);
    // EBPF_OP_STXB pc=207 dst=r1 src=r2 offset=31 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(31)) = (uint8_t)r2;
label_2:
    // EBPF_OP_MOV64_IMM pc=208 dst=r0 src=r0 offset=0 imm=3
#line 34 "sample/./xdp_common.h"
    r0 = IMMEDIATE(3);
label_3:
    // EBPF_OP_EXIT pc=209 dst=r0 src=r0 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    return r0;
#line 34 "sample/./xdp_common.h"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        reflect_packet,
        "xdp/re~1",
        "xdp/reflect",
        "reflect_packet",
        NULL,
        0,
        NULL,
        0,
        210,
        &reflect_packet_program_type_guid,
        &reflect_packet_attach_type_guid,
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
    version->minor = 7;
    version->revision = 0;
}

metadata_table_t reflect_packet_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
