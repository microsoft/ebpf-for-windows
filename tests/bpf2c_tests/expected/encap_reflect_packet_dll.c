// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from encap_reflect_packet.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table encap_reflect_packet##_metadata_table
extern metadata_table_t metadata_table;

bool APIENTRY
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

__declspec(dllexport) metadata_table_t* get_metadata_table() { return &metadata_table; }

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

static helper_function_entry_t encap_reflect_packet_helpers[] = {
    {NULL, 65536, "helper_id_65536"},
    {NULL, 10, "helper_id_10"},
};

static GUID encap_reflect_packet_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID encap_reflect_packet_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
#pragma code_seg(push, "xdp/en~1")
static uint64_t
encap_reflect_packet(void* context)
#line 149 "sample/encap_reflect_packet.c"
{
#line 149 "sample/encap_reflect_packet.c"
    // Prologue
#line 149 "sample/encap_reflect_packet.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 149 "sample/encap_reflect_packet.c"
    register uint64_t r0 = 0;
#line 149 "sample/encap_reflect_packet.c"
    register uint64_t r1 = 0;
#line 149 "sample/encap_reflect_packet.c"
    register uint64_t r2 = 0;
#line 149 "sample/encap_reflect_packet.c"
    register uint64_t r3 = 0;
#line 149 "sample/encap_reflect_packet.c"
    register uint64_t r4 = 0;
#line 149 "sample/encap_reflect_packet.c"
    register uint64_t r5 = 0;
#line 149 "sample/encap_reflect_packet.c"
    register uint64_t r6 = 0;
#line 149 "sample/encap_reflect_packet.c"
    register uint64_t r10 = 0;

#line 149 "sample/encap_reflect_packet.c"
    r1 = (uintptr_t)context;
#line 149 "sample/encap_reflect_packet.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 149 "sample/encap_reflect_packet.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r0 src=r0 offset=0 imm=1
#line 149 "sample/encap_reflect_packet.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_LDXDW pc=2 dst=r1 src=r6 offset=8 imm=0
#line 155 "sample/encap_reflect_packet.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_LDXDW pc=3 dst=r2 src=r6 offset=0 imm=0
#line 154 "sample/encap_reflect_packet.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=4 dst=r3 src=r2 offset=0 imm=0
#line 155 "sample/encap_reflect_packet.c"
    r3 = r2;
    // EBPF_OP_ADD64_IMM pc=5 dst=r3 src=r0 offset=0 imm=14
#line 155 "sample/encap_reflect_packet.c"
    r3 += IMMEDIATE(14);
    // EBPF_OP_JGT_REG pc=6 dst=r3 src=r1 offset=290 imm=0
#line 155 "sample/encap_reflect_packet.c"
    if (r3 > r1)
#line 155 "sample/encap_reflect_packet.c"
        goto label_3;
    // EBPF_OP_LDXH pc=7 dst=r4 src=r2 offset=12 imm=0
#line 160 "sample/encap_reflect_packet.c"
    r4 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(12));
    // EBPF_OP_JEQ_IMM pc=8 dst=r4 src=r0 offset=105 imm=56710
#line 160 "sample/encap_reflect_packet.c"
    if (r4 == IMMEDIATE(56710))
#line 160 "sample/encap_reflect_packet.c"
        goto label_1;
    // EBPF_OP_JNE_IMM pc=9 dst=r4 src=r0 offset=287 imm=8
#line 160 "sample/encap_reflect_packet.c"
    if (r4 != IMMEDIATE(8))
#line 160 "sample/encap_reflect_packet.c"
        goto label_3;
    // EBPF_OP_MOV64_REG pc=10 dst=r4 src=r2 offset=0 imm=0
#line 161 "sample/encap_reflect_packet.c"
    r4 = r2;
    // EBPF_OP_ADD64_IMM pc=11 dst=r4 src=r0 offset=0 imm=34
#line 161 "sample/encap_reflect_packet.c"
    r4 += IMMEDIATE(34);
    // EBPF_OP_JGT_REG pc=12 dst=r4 src=r1 offset=284 imm=0
#line 161 "sample/encap_reflect_packet.c"
    if (r4 > r1)
#line 161 "sample/encap_reflect_packet.c"
        goto label_3;
    // EBPF_OP_LDXB pc=13 dst=r4 src=r2 offset=23 imm=0
#line 167 "sample/encap_reflect_packet.c"
    r4 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(23));
    // EBPF_OP_JNE_IMM pc=14 dst=r4 src=r0 offset=282 imm=17
#line 167 "sample/encap_reflect_packet.c"
    if (r4 != IMMEDIATE(17))
#line 167 "sample/encap_reflect_packet.c"
        goto label_3;
    // EBPF_OP_LDXB pc=15 dst=r2 src=r2 offset=14 imm=0
#line 167 "sample/encap_reflect_packet.c"
    r2 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(14));
    // EBPF_OP_LSH64_IMM pc=16 dst=r2 src=r0 offset=0 imm=2
#line 167 "sample/encap_reflect_packet.c"
    r2 <<= IMMEDIATE(2);
    // EBPF_OP_AND64_IMM pc=17 dst=r2 src=r0 offset=0 imm=60
#line 167 "sample/encap_reflect_packet.c"
    r2 &= IMMEDIATE(60);
    // EBPF_OP_ADD64_REG pc=18 dst=r3 src=r2 offset=0 imm=0
#line 167 "sample/encap_reflect_packet.c"
    r3 += r2;
    // EBPF_OP_MOV64_REG pc=19 dst=r2 src=r3 offset=0 imm=0
#line 167 "sample/encap_reflect_packet.c"
    r2 = r3;
    // EBPF_OP_ADD64_IMM pc=20 dst=r2 src=r0 offset=0 imm=8
#line 167 "sample/encap_reflect_packet.c"
    r2 += IMMEDIATE(8);
    // EBPF_OP_JGT_REG pc=21 dst=r2 src=r1 offset=275 imm=0
#line 167 "sample/encap_reflect_packet.c"
    if (r2 > r1)
#line 167 "sample/encap_reflect_packet.c"
        goto label_3;
    // EBPF_OP_LDXH pc=22 dst=r1 src=r3 offset=2 imm=0
#line 173 "sample/encap_reflect_packet.c"
    r1 = *(uint16_t*)(uintptr_t)(r3 + OFFSET(2));
    // EBPF_OP_JNE_IMM pc=23 dst=r1 src=r0 offset=273 imm=7459
#line 173 "sample/encap_reflect_packet.c"
    if (r1 != IMMEDIATE(7459))
#line 173 "sample/encap_reflect_packet.c"
        goto label_3;
    // EBPF_OP_MOV64_REG pc=24 dst=r1 src=r6 offset=0 imm=0
#line 22 "sample/encap_reflect_packet.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=25 dst=r2 src=r0 offset=0 imm=-20
#line 22 "sample/encap_reflect_packet.c"
    r2 = (uint64_t)4294967276;
    // EBPF_OP_CALL pc=27 dst=r0 src=r0 offset=0 imm=65536
#line 22 "sample/encap_reflect_packet.c"
    r0 = encap_reflect_packet_helpers[0].address
#line 22 "sample/encap_reflect_packet.c"
         (r1, r2, r3, r4, r5);
#line 22 "sample/encap_reflect_packet.c"
    if ((encap_reflect_packet_helpers[0].tail_call) && (r0 == 0))
#line 22 "sample/encap_reflect_packet.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=28 dst=r1 src=r0 offset=0 imm=0
#line 22 "sample/encap_reflect_packet.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=29 dst=r0 src=r0 offset=0 imm=2
#line 22 "sample/encap_reflect_packet.c"
    r0 = IMMEDIATE(2);
    // EBPF_OP_LSH64_IMM pc=30 dst=r1 src=r0 offset=0 imm=32
#line 22 "sample/encap_reflect_packet.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=31 dst=r1 src=r0 offset=0 imm=32
#line 22 "sample/encap_reflect_packet.c"
    r1 = (int64_t)r1 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=32 dst=r2 src=r0 offset=0 imm=0
#line 22 "sample/encap_reflect_packet.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=33 dst=r2 src=r1 offset=263 imm=0
#line 22 "sample/encap_reflect_packet.c"
    if ((int64_t)r2 > (int64_t)r1)
#line 22 "sample/encap_reflect_packet.c"
        goto label_3;
    // EBPF_OP_LDXDW pc=34 dst=r4 src=r6 offset=8 imm=0
#line 28 "sample/encap_reflect_packet.c"
    r4 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_LDXDW pc=35 dst=r6 src=r6 offset=0 imm=0
#line 27 "sample/encap_reflect_packet.c"
    r6 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=36 dst=r3 src=r6 offset=0 imm=0
#line 28 "sample/encap_reflect_packet.c"
    r3 = r6;
    // EBPF_OP_ADD64_IMM pc=37 dst=r3 src=r0 offset=0 imm=14
#line 28 "sample/encap_reflect_packet.c"
    r3 += IMMEDIATE(14);
    // EBPF_OP_JGT_REG pc=38 dst=r3 src=r4 offset=258 imm=0
#line 28 "sample/encap_reflect_packet.c"
    if (r3 > r4)
#line 28 "sample/encap_reflect_packet.c"
        goto label_3;
    // EBPF_OP_MOV64_REG pc=39 dst=r2 src=r6 offset=0 imm=0
#line 35 "sample/encap_reflect_packet.c"
    r2 = r6;
    // EBPF_OP_ADD64_IMM pc=40 dst=r2 src=r0 offset=0 imm=20
#line 35 "sample/encap_reflect_packet.c"
    r2 += IMMEDIATE(20);
    // EBPF_OP_JGT_REG pc=41 dst=r2 src=r4 offset=255 imm=0
#line 35 "sample/encap_reflect_packet.c"
    if (r2 > r4)
#line 35 "sample/encap_reflect_packet.c"
        goto label_3;
    // EBPF_OP_MOV64_REG pc=42 dst=r1 src=r6 offset=0 imm=0
#line 43 "sample/encap_reflect_packet.c"
    r1 = r6;
    // EBPF_OP_ADD64_IMM pc=43 dst=r1 src=r0 offset=0 imm=34
#line 43 "sample/encap_reflect_packet.c"
    r1 += IMMEDIATE(34);
    // EBPF_OP_JGT_REG pc=44 dst=r1 src=r4 offset=252 imm=0
#line 43 "sample/encap_reflect_packet.c"
    if (r1 > r4)
#line 43 "sample/encap_reflect_packet.c"
        goto label_3;
    // EBPF_OP_MOV64_REG pc=45 dst=r5 src=r6 offset=0 imm=0
#line 43 "sample/encap_reflect_packet.c"
    r5 = r6;
    // EBPF_OP_ADD64_IMM pc=46 dst=r5 src=r0 offset=0 imm=54
#line 43 "sample/encap_reflect_packet.c"
    r5 += IMMEDIATE(54);
    // EBPF_OP_JGT_REG pc=47 dst=r5 src=r4 offset=249 imm=0
#line 43 "sample/encap_reflect_packet.c"
    if (r5 > r4)
#line 43 "sample/encap_reflect_packet.c"
        goto label_3;
    // EBPF_OP_LDXH pc=48 dst=r4 src=r2 offset=4 imm=0
#line 56 "sample/encap_reflect_packet.c"
    r4 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(4));
    // EBPF_OP_STXH pc=49 dst=r6 src=r4 offset=4 imm=0
#line 56 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(4)) = (uint16_t)r4;
    // EBPF_OP_LDXH pc=50 dst=r4 src=r2 offset=0 imm=0
#line 56 "sample/encap_reflect_packet.c"
    r4 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(0));
    // EBPF_OP_STXH pc=51 dst=r6 src=r4 offset=0 imm=0
#line 56 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(0)) = (uint16_t)r4;
    // EBPF_OP_LDXH pc=52 dst=r4 src=r2 offset=2 imm=0
#line 56 "sample/encap_reflect_packet.c"
    r4 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(2));
    // EBPF_OP_STXH pc=53 dst=r6 src=r4 offset=2 imm=0
#line 56 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(2)) = (uint16_t)r4;
    // EBPF_OP_LDXH pc=54 dst=r4 src=r2 offset=12 imm=0
#line 56 "sample/encap_reflect_packet.c"
    r4 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(12));
    // EBPF_OP_STXH pc=55 dst=r6 src=r4 offset=12 imm=0
#line 56 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(12)) = (uint16_t)r4;
    // EBPF_OP_LDXH pc=56 dst=r4 src=r2 offset=10 imm=0
#line 56 "sample/encap_reflect_packet.c"
    r4 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(10));
    // EBPF_OP_STXH pc=57 dst=r6 src=r4 offset=10 imm=0
#line 56 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(10)) = (uint16_t)r4;
    // EBPF_OP_LDXH pc=58 dst=r5 src=r2 offset=8 imm=0
#line 56 "sample/encap_reflect_packet.c"
    r5 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(8));
    // EBPF_OP_LDXH pc=59 dst=r0 src=r2 offset=6 imm=0
#line 56 "sample/encap_reflect_packet.c"
    r0 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(6));
    // EBPF_OP_STXH pc=60 dst=r6 src=r4 offset=4 imm=0
#line 16 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(4)) = (uint16_t)r4;
    // EBPF_OP_STXH pc=61 dst=r6 src=r0 offset=6 imm=0
#line 56 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(6)) = (uint16_t)r0;
    // EBPF_OP_STXH pc=62 dst=r6 src=r0 offset=0 imm=0
#line 16 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(0)) = (uint16_t)r0;
    // EBPF_OP_STXH pc=63 dst=r6 src=r5 offset=8 imm=0
#line 56 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(8)) = (uint16_t)r5;
    // EBPF_OP_STXH pc=64 dst=r6 src=r5 offset=2 imm=0
#line 16 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(2)) = (uint16_t)r5;
    // EBPF_OP_LDXH pc=65 dst=r4 src=r2 offset=4 imm=0
#line 17 "sample/./xdp_common.h"
    r4 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(4));
    // EBPF_OP_STXH pc=66 dst=r6 src=r4 offset=10 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(10)) = (uint16_t)r4;
    // EBPF_OP_LDXH pc=67 dst=r4 src=r2 offset=2 imm=0
#line 17 "sample/./xdp_common.h"
    r4 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(2));
    // EBPF_OP_LDXH pc=68 dst=r2 src=r2 offset=0 imm=0
#line 17 "sample/./xdp_common.h"
    r2 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(0));
    // EBPF_OP_LDXW pc=69 dst=r5 src=r6 offset=50 imm=0
#line 23 "sample/./xdp_common.h"
    r5 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(50));
    // EBPF_OP_LDXW pc=70 dst=r0 src=r6 offset=46 imm=0
#line 24 "sample/./xdp_common.h"
    r0 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(46));
    // EBPF_OP_STXW pc=71 dst=r6 src=r0 offset=50 imm=0
#line 24 "sample/./xdp_common.h"
    *(uint32_t*)(uintptr_t)(r6 + OFFSET(50)) = (uint32_t)r0;
    // EBPF_OP_STXW pc=72 dst=r6 src=r5 offset=46 imm=0
#line 25 "sample/./xdp_common.h"
    *(uint32_t*)(uintptr_t)(r6 + OFFSET(46)) = (uint32_t)r5;
    // EBPF_OP_STXH pc=73 dst=r6 src=r2 offset=6 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(6)) = (uint16_t)r2;
    // EBPF_OP_STXH pc=74 dst=r6 src=r4 offset=8 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(8)) = (uint16_t)r4;
    // EBPF_OP_LDXW pc=75 dst=r2 src=r1 offset=16 imm=0
#line 64 "sample/encap_reflect_packet.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(16));
    // EBPF_OP_STXW pc=76 dst=r3 src=r2 offset=16 imm=0
#line 64 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r3 + OFFSET(16)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=77 dst=r2 src=r1 offset=0 imm=0
#line 64 "sample/encap_reflect_packet.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_STXW pc=78 dst=r3 src=r2 offset=0 imm=0
#line 64 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r3 + OFFSET(0)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=79 dst=r2 src=r1 offset=4 imm=0
#line 64 "sample/encap_reflect_packet.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(4));
    // EBPF_OP_STXW pc=80 dst=r3 src=r2 offset=4 imm=0
#line 64 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r3 + OFFSET(4)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=81 dst=r2 src=r1 offset=8 imm=0
#line 64 "sample/encap_reflect_packet.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(8));
    // EBPF_OP_STXW pc=82 dst=r3 src=r2 offset=8 imm=0
#line 64 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r3 + OFFSET(8)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=83 dst=r1 src=r1 offset=12 imm=0
#line 64 "sample/encap_reflect_packet.c"
    r1 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(12));
    // EBPF_OP_STXW pc=84 dst=r3 src=r1 offset=12 imm=0
#line 64 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r3 + OFFSET(12)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=85 dst=r1 src=r0 offset=0 imm=4
#line 64 "sample/encap_reflect_packet.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXB pc=86 dst=r6 src=r1 offset=23 imm=0
#line 67 "sample/encap_reflect_packet.c"
    *(uint8_t*)(uintptr_t)(r6 + OFFSET(23)) = (uint8_t)r1;
    // EBPF_OP_LDXB pc=87 dst=r1 src=r6 offset=14 imm=0
#line 68 "sample/encap_reflect_packet.c"
    r1 = *(uint8_t*)(uintptr_t)(r6 + OFFSET(14));
    // EBPF_OP_AND64_IMM pc=88 dst=r1 src=r0 offset=0 imm=240
#line 68 "sample/encap_reflect_packet.c"
    r1 &= IMMEDIATE(240);
    // EBPF_OP_OR64_IMM pc=89 dst=r1 src=r0 offset=0 imm=5
#line 68 "sample/encap_reflect_packet.c"
    r1 |= IMMEDIATE(5);
    // EBPF_OP_STXB pc=90 dst=r6 src=r1 offset=14 imm=0
#line 68 "sample/encap_reflect_packet.c"
    *(uint8_t*)(uintptr_t)(r6 + OFFSET(14)) = (uint8_t)r1;
    // EBPF_OP_LDXH pc=91 dst=r1 src=r6 offset=36 imm=0
#line 69 "sample/encap_reflect_packet.c"
    r1 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(36));
    // EBPF_OP_BE pc=92 dst=r1 src=r0 offset=0 imm=16
#line 69 "sample/encap_reflect_packet.c"
    r1 = htobe16((uint16_t)r1);
#line 69 "sample/encap_reflect_packet.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_ADD64_IMM pc=93 dst=r1 src=r0 offset=0 imm=20
#line 69 "sample/encap_reflect_packet.c"
    r1 += IMMEDIATE(20);
    // EBPF_OP_BE pc=94 dst=r1 src=r0 offset=0 imm=16
#line 69 "sample/encap_reflect_packet.c"
    r1 = htobe16((uint16_t)r1);
#line 69 "sample/encap_reflect_packet.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=95 dst=r6 src=r1 offset=16 imm=0
#line 69 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(16)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=96 dst=r1 src=r0 offset=0 imm=0
#line 69 "sample/encap_reflect_packet.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXH pc=97 dst=r6 src=r1 offset=24 imm=0
#line 71 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(24)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=98 dst=r1 src=r0 offset=0 imm=0
#line 73 "sample/encap_reflect_packet.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_MOV64_IMM pc=99 dst=r2 src=r0 offset=0 imm=0
#line 73 "sample/encap_reflect_packet.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_MOV64_IMM pc=100 dst=r4 src=r0 offset=0 imm=20
#line 73 "sample/encap_reflect_packet.c"
    r4 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=101 dst=r5 src=r0 offset=0 imm=0
#line 73 "sample/encap_reflect_packet.c"
    r5 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=102 dst=r0 src=r0 offset=0 imm=10
#line 73 "sample/encap_reflect_packet.c"
    r0 = encap_reflect_packet_helpers[1].address
#line 73 "sample/encap_reflect_packet.c"
         (r1, r2, r3, r4, r5);
#line 73 "sample/encap_reflect_packet.c"
    if ((encap_reflect_packet_helpers[1].tail_call) && (r0 == 0))
#line 73 "sample/encap_reflect_packet.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=103 dst=r1 src=r0 offset=0 imm=0
#line 41 "sample/./xdp_common.h"
    r1 = r0;
    // EBPF_OP_AND64_IMM pc=104 dst=r1 src=r0 offset=0 imm=65535
#line 41 "sample/./xdp_common.h"
    r1 &= IMMEDIATE(65535);
    // EBPF_OP_LSH64_IMM pc=105 dst=r0 src=r0 offset=0 imm=32
#line 73 "sample/encap_reflect_packet.c"
    r0 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=106 dst=r0 src=r0 offset=0 imm=48
#line 41 "sample/./xdp_common.h"
    r0 = (int64_t)r0 >> (uint32_t)IMMEDIATE(48);
    // EBPF_OP_ADD64_REG pc=107 dst=r0 src=r1 offset=0 imm=0
#line 41 "sample/./xdp_common.h"
    r0 += r1;
    // EBPF_OP_MOV64_REG pc=108 dst=r1 src=r0 offset=0 imm=0
#line 42 "sample/./xdp_common.h"
    r1 = r0;
    // EBPF_OP_RSH64_IMM pc=109 dst=r1 src=r0 offset=0 imm=16
#line 42 "sample/./xdp_common.h"
    r1 >>= IMMEDIATE(16);
    // EBPF_OP_ADD64_REG pc=110 dst=r1 src=r0 offset=0 imm=0
#line 42 "sample/./xdp_common.h"
    r1 += r0;
    // EBPF_OP_XOR64_IMM pc=111 dst=r1 src=r0 offset=0 imm=-1
#line 73 "sample/encap_reflect_packet.c"
    r1 ^= IMMEDIATE(-1);
    // EBPF_OP_STXH pc=112 dst=r6 src=r1 offset=24 imm=0
#line 72 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(24)) = (uint16_t)r1;
    // EBPF_OP_JA pc=113 dst=r0 src=r0 offset=182 imm=0
#line 72 "sample/encap_reflect_packet.c"
    goto label_2;
label_1:
    // EBPF_OP_MOV64_REG pc=114 dst=r3 src=r2 offset=0 imm=0
#line 178 "sample/encap_reflect_packet.c"
    r3 = r2;
    // EBPF_OP_ADD64_IMM pc=115 dst=r3 src=r0 offset=0 imm=54
#line 178 "sample/encap_reflect_packet.c"
    r3 += IMMEDIATE(54);
    // EBPF_OP_JGT_REG pc=116 dst=r3 src=r1 offset=180 imm=0
#line 178 "sample/encap_reflect_packet.c"
    if (r3 > r1)
#line 178 "sample/encap_reflect_packet.c"
        goto label_3;
    // EBPF_OP_MOV64_REG pc=117 dst=r3 src=r2 offset=0 imm=0
#line 178 "sample/encap_reflect_packet.c"
    r3 = r2;
    // EBPF_OP_ADD64_IMM pc=118 dst=r3 src=r0 offset=0 imm=62
#line 178 "sample/encap_reflect_packet.c"
    r3 += IMMEDIATE(62);
    // EBPF_OP_JGT_REG pc=119 dst=r3 src=r1 offset=177 imm=0
#line 184 "sample/encap_reflect_packet.c"
    if (r3 > r1)
#line 184 "sample/encap_reflect_packet.c"
        goto label_3;
    // EBPF_OP_LDXB pc=120 dst=r1 src=r2 offset=20 imm=0
#line 184 "sample/encap_reflect_packet.c"
    r1 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(20));
    // EBPF_OP_JNE_IMM pc=121 dst=r1 src=r0 offset=175 imm=17
#line 184 "sample/encap_reflect_packet.c"
    if (r1 != IMMEDIATE(17))
#line 184 "sample/encap_reflect_packet.c"
        goto label_3;
    // EBPF_OP_LDXH pc=122 dst=r1 src=r2 offset=56 imm=0
#line 190 "sample/encap_reflect_packet.c"
    r1 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(56));
    // EBPF_OP_JNE_IMM pc=123 dst=r1 src=r0 offset=173 imm=7459
#line 190 "sample/encap_reflect_packet.c"
    if (r1 != IMMEDIATE(7459))
#line 190 "sample/encap_reflect_packet.c"
        goto label_3;
    // EBPF_OP_MOV64_REG pc=124 dst=r1 src=r6 offset=0 imm=0
#line 87 "sample/encap_reflect_packet.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=125 dst=r2 src=r0 offset=0 imm=-40
#line 87 "sample/encap_reflect_packet.c"
    r2 = (uint64_t)4294967256;
    // EBPF_OP_CALL pc=127 dst=r0 src=r0 offset=0 imm=65536
#line 87 "sample/encap_reflect_packet.c"
    r0 = encap_reflect_packet_helpers[0].address
#line 87 "sample/encap_reflect_packet.c"
         (r1, r2, r3, r4, r5);
#line 87 "sample/encap_reflect_packet.c"
    if ((encap_reflect_packet_helpers[0].tail_call) && (r0 == 0))
#line 87 "sample/encap_reflect_packet.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=128 dst=r1 src=r0 offset=0 imm=0
#line 87 "sample/encap_reflect_packet.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=129 dst=r0 src=r0 offset=0 imm=2
#line 87 "sample/encap_reflect_packet.c"
    r0 = IMMEDIATE(2);
    // EBPF_OP_LSH64_IMM pc=130 dst=r1 src=r0 offset=0 imm=32
#line 87 "sample/encap_reflect_packet.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=131 dst=r1 src=r0 offset=0 imm=32
#line 87 "sample/encap_reflect_packet.c"
    r1 = (int64_t)r1 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=132 dst=r2 src=r0 offset=0 imm=0
#line 87 "sample/encap_reflect_packet.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=133 dst=r2 src=r1 offset=163 imm=0
#line 87 "sample/encap_reflect_packet.c"
    if ((int64_t)r2 > (int64_t)r1)
#line 87 "sample/encap_reflect_packet.c"
        goto label_3;
    // EBPF_OP_LDXDW pc=134 dst=r5 src=r6 offset=8 imm=0
#line 93 "sample/encap_reflect_packet.c"
    r5 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_LDXDW pc=135 dst=r1 src=r6 offset=0 imm=0
#line 92 "sample/encap_reflect_packet.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=136 dst=r2 src=r1 offset=0 imm=0
#line 93 "sample/encap_reflect_packet.c"
    r2 = r1;
    // EBPF_OP_ADD64_IMM pc=137 dst=r2 src=r0 offset=0 imm=14
#line 93 "sample/encap_reflect_packet.c"
    r2 += IMMEDIATE(14);
    // EBPF_OP_JGT_REG pc=138 dst=r2 src=r5 offset=158 imm=0
#line 93 "sample/encap_reflect_packet.c"
    if (r2 > r5)
#line 93 "sample/encap_reflect_packet.c"
        goto label_3;
    // EBPF_OP_MOV64_REG pc=139 dst=r4 src=r1 offset=0 imm=0
#line 100 "sample/encap_reflect_packet.c"
    r4 = r1;
    // EBPF_OP_ADD64_IMM pc=140 dst=r4 src=r0 offset=0 imm=40
#line 100 "sample/encap_reflect_packet.c"
    r4 += IMMEDIATE(40);
    // EBPF_OP_JGT_REG pc=141 dst=r4 src=r5 offset=155 imm=0
#line 100 "sample/encap_reflect_packet.c"
    if (r4 > r5)
#line 100 "sample/encap_reflect_packet.c"
        goto label_3;
    // EBPF_OP_MOV64_REG pc=142 dst=r3 src=r1 offset=0 imm=0
#line 108 "sample/encap_reflect_packet.c"
    r3 = r1;
    // EBPF_OP_ADD64_IMM pc=143 dst=r3 src=r0 offset=0 imm=54
#line 108 "sample/encap_reflect_packet.c"
    r3 += IMMEDIATE(54);
    // EBPF_OP_JGT_REG pc=144 dst=r3 src=r5 offset=152 imm=0
#line 108 "sample/encap_reflect_packet.c"
    if (r3 > r5)
#line 108 "sample/encap_reflect_packet.c"
        goto label_3;
    // EBPF_OP_MOV64_REG pc=145 dst=r6 src=r1 offset=0 imm=0
#line 108 "sample/encap_reflect_packet.c"
    r6 = r1;
    // EBPF_OP_ADD64_IMM pc=146 dst=r6 src=r0 offset=0 imm=94
#line 108 "sample/encap_reflect_packet.c"
    r6 += IMMEDIATE(94);
    // EBPF_OP_JGT_REG pc=147 dst=r6 src=r5 offset=149 imm=0
#line 108 "sample/encap_reflect_packet.c"
    if (r6 > r5)
#line 108 "sample/encap_reflect_packet.c"
        goto label_3;
    // EBPF_OP_LDXH pc=148 dst=r5 src=r4 offset=4 imm=0
#line 121 "sample/encap_reflect_packet.c"
    r5 = *(uint16_t*)(uintptr_t)(r4 + OFFSET(4));
    // EBPF_OP_STXH pc=149 dst=r1 src=r5 offset=4 imm=0
#line 121 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(4)) = (uint16_t)r5;
    // EBPF_OP_LDXH pc=150 dst=r5 src=r4 offset=0 imm=0
#line 121 "sample/encap_reflect_packet.c"
    r5 = *(uint16_t*)(uintptr_t)(r4 + OFFSET(0));
    // EBPF_OP_STXH pc=151 dst=r1 src=r5 offset=0 imm=0
#line 121 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(0)) = (uint16_t)r5;
    // EBPF_OP_LDXH pc=152 dst=r5 src=r4 offset=2 imm=0
#line 121 "sample/encap_reflect_packet.c"
    r5 = *(uint16_t*)(uintptr_t)(r4 + OFFSET(2));
    // EBPF_OP_STXH pc=153 dst=r1 src=r5 offset=2 imm=0
#line 121 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(2)) = (uint16_t)r5;
    // EBPF_OP_LDXH pc=154 dst=r5 src=r4 offset=12 imm=0
#line 121 "sample/encap_reflect_packet.c"
    r5 = *(uint16_t*)(uintptr_t)(r4 + OFFSET(12));
    // EBPF_OP_STXH pc=155 dst=r1 src=r5 offset=12 imm=0
#line 121 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(12)) = (uint16_t)r5;
    // EBPF_OP_LDXH pc=156 dst=r5 src=r4 offset=10 imm=0
#line 121 "sample/encap_reflect_packet.c"
    r5 = *(uint16_t*)(uintptr_t)(r4 + OFFSET(10));
    // EBPF_OP_STXH pc=157 dst=r1 src=r5 offset=10 imm=0
#line 121 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(10)) = (uint16_t)r5;
    // EBPF_OP_LDXH pc=158 dst=r0 src=r4 offset=8 imm=0
#line 121 "sample/encap_reflect_packet.c"
    r0 = *(uint16_t*)(uintptr_t)(r4 + OFFSET(8));
    // EBPF_OP_LDXH pc=159 dst=r6 src=r4 offset=6 imm=0
#line 121 "sample/encap_reflect_packet.c"
    r6 = *(uint16_t*)(uintptr_t)(r4 + OFFSET(6));
    // EBPF_OP_STXH pc=160 dst=r1 src=r5 offset=4 imm=0
#line 16 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(4)) = (uint16_t)r5;
    // EBPF_OP_STXH pc=161 dst=r1 src=r6 offset=6 imm=0
#line 121 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(6)) = (uint16_t)r6;
    // EBPF_OP_STXH pc=162 dst=r1 src=r6 offset=0 imm=0
#line 16 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(0)) = (uint16_t)r6;
    // EBPF_OP_STXH pc=163 dst=r1 src=r0 offset=8 imm=0
#line 121 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(8)) = (uint16_t)r0;
    // EBPF_OP_STXH pc=164 dst=r1 src=r0 offset=2 imm=0
#line 16 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(2)) = (uint16_t)r0;
    // EBPF_OP_LDXH pc=165 dst=r5 src=r4 offset=4 imm=0
#line 17 "sample/./xdp_common.h"
    r5 = *(uint16_t*)(uintptr_t)(r4 + OFFSET(4));
    // EBPF_OP_STXH pc=166 dst=r1 src=r5 offset=10 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(10)) = (uint16_t)r5;
    // EBPF_OP_LDXH pc=167 dst=r5 src=r4 offset=0 imm=0
#line 17 "sample/./xdp_common.h"
    r5 = *(uint16_t*)(uintptr_t)(r4 + OFFSET(0));
    // EBPF_OP_STXH pc=168 dst=r1 src=r5 offset=6 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(6)) = (uint16_t)r5;
    // EBPF_OP_LDXH pc=169 dst=r4 src=r4 offset=2 imm=0
#line 17 "sample/./xdp_common.h"
    r4 = *(uint16_t*)(uintptr_t)(r4 + OFFSET(2));
    // EBPF_OP_STXH pc=170 dst=r1 src=r4 offset=8 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(8)) = (uint16_t)r4;
    // EBPF_OP_LDXB pc=171 dst=r5 src=r1 offset=87 imm=0
#line 32 "sample/./xdp_common.h"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(87));
    // EBPF_OP_LSH64_IMM pc=172 dst=r5 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r5 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=173 dst=r4 src=r1 offset=86 imm=0
#line 32 "sample/./xdp_common.h"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(86));
    // EBPF_OP_OR64_REG pc=174 dst=r5 src=r4 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r5 |= r4;
    // EBPF_OP_LDXB pc=175 dst=r4 src=r1 offset=89 imm=0
#line 32 "sample/./xdp_common.h"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(89));
    // EBPF_OP_LSH64_IMM pc=176 dst=r4 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r4 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=177 dst=r0 src=r1 offset=88 imm=0
#line 32 "sample/./xdp_common.h"
    r0 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(88));
    // EBPF_OP_OR64_REG pc=178 dst=r4 src=r0 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r4 |= r0;
    // EBPF_OP_LSH64_IMM pc=179 dst=r4 src=r0 offset=0 imm=16
#line 32 "sample/./xdp_common.h"
    r4 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=180 dst=r4 src=r5 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r4 |= r5;
    // EBPF_OP_LDXB pc=181 dst=r0 src=r1 offset=91 imm=0
#line 32 "sample/./xdp_common.h"
    r0 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(91));
    // EBPF_OP_LSH64_IMM pc=182 dst=r0 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r0 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=183 dst=r5 src=r1 offset=90 imm=0
#line 32 "sample/./xdp_common.h"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(90));
    // EBPF_OP_OR64_REG pc=184 dst=r0 src=r5 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r0 |= r5;
    // EBPF_OP_LDXB pc=185 dst=r5 src=r1 offset=93 imm=0
#line 32 "sample/./xdp_common.h"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(93));
    // EBPF_OP_LSH64_IMM pc=186 dst=r5 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r5 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=187 dst=r6 src=r1 offset=92 imm=0
#line 32 "sample/./xdp_common.h"
    r6 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(92));
    // EBPF_OP_OR64_REG pc=188 dst=r5 src=r6 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r5 |= r6;
    // EBPF_OP_LSH64_IMM pc=189 dst=r5 src=r0 offset=0 imm=16
#line 32 "sample/./xdp_common.h"
    r5 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=190 dst=r5 src=r0 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r5 |= r0;
    // EBPF_OP_LSH64_IMM pc=191 dst=r5 src=r0 offset=0 imm=32
#line 32 "sample/./xdp_common.h"
    r5 <<= IMMEDIATE(32);
    // EBPF_OP_OR64_REG pc=192 dst=r5 src=r4 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r5 |= r4;
    // EBPF_OP_LDXB pc=193 dst=r0 src=r1 offset=79 imm=0
#line 32 "sample/./xdp_common.h"
    r0 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(79));
    // EBPF_OP_LSH64_IMM pc=194 dst=r0 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r0 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=195 dst=r4 src=r1 offset=78 imm=0
#line 32 "sample/./xdp_common.h"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(78));
    // EBPF_OP_OR64_REG pc=196 dst=r0 src=r4 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r0 |= r4;
    // EBPF_OP_LDXB pc=197 dst=r4 src=r1 offset=81 imm=0
#line 32 "sample/./xdp_common.h"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(81));
    // EBPF_OP_LSH64_IMM pc=198 dst=r4 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r4 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=199 dst=r6 src=r1 offset=80 imm=0
#line 32 "sample/./xdp_common.h"
    r6 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(80));
    // EBPF_OP_OR64_REG pc=200 dst=r4 src=r6 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r4 |= r6;
    // EBPF_OP_STXDW pc=201 dst=r10 src=r5 offset=-8 imm=0
#line 32 "sample/./xdp_common.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r5;
    // EBPF_OP_LSH64_IMM pc=202 dst=r4 src=r0 offset=0 imm=16
#line 32 "sample/./xdp_common.h"
    r4 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=203 dst=r4 src=r0 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r4 |= r0;
    // EBPF_OP_LDXB pc=204 dst=r5 src=r1 offset=83 imm=0
#line 32 "sample/./xdp_common.h"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(83));
    // EBPF_OP_LSH64_IMM pc=205 dst=r5 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r5 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=206 dst=r0 src=r1 offset=82 imm=0
#line 32 "sample/./xdp_common.h"
    r0 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(82));
    // EBPF_OP_OR64_REG pc=207 dst=r5 src=r0 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r5 |= r0;
    // EBPF_OP_LDXB pc=208 dst=r0 src=r1 offset=85 imm=0
#line 32 "sample/./xdp_common.h"
    r0 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(85));
    // EBPF_OP_LSH64_IMM pc=209 dst=r0 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r0 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=210 dst=r6 src=r1 offset=84 imm=0
#line 32 "sample/./xdp_common.h"
    r6 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(84));
    // EBPF_OP_OR64_REG pc=211 dst=r0 src=r6 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r0 |= r6;
    // EBPF_OP_LSH64_IMM pc=212 dst=r0 src=r0 offset=0 imm=16
#line 32 "sample/./xdp_common.h"
    r0 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=213 dst=r0 src=r5 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r0 |= r5;
    // EBPF_OP_LSH64_IMM pc=214 dst=r0 src=r0 offset=0 imm=32
#line 32 "sample/./xdp_common.h"
    r0 <<= IMMEDIATE(32);
    // EBPF_OP_OR64_REG pc=215 dst=r0 src=r4 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r0 |= r4;
    // EBPF_OP_STXDW pc=216 dst=r10 src=r0 offset=-16 imm=0
#line 32 "sample/./xdp_common.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r0;
    // EBPF_OP_LDXW pc=217 dst=r4 src=r1 offset=62 imm=0
#line 33 "sample/./xdp_common.h"
    r4 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(62));
    // EBPF_OP_STXW pc=218 dst=r1 src=r4 offset=78 imm=0
#line 33 "sample/./xdp_common.h"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(78)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=219 dst=r4 src=r1 offset=66 imm=0
#line 33 "sample/./xdp_common.h"
    r4 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(66));
    // EBPF_OP_STXW pc=220 dst=r1 src=r4 offset=82 imm=0
#line 33 "sample/./xdp_common.h"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(82)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=221 dst=r4 src=r1 offset=70 imm=0
#line 33 "sample/./xdp_common.h"
    r4 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(70));
    // EBPF_OP_STXW pc=222 dst=r1 src=r4 offset=86 imm=0
#line 33 "sample/./xdp_common.h"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(86)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=223 dst=r4 src=r1 offset=74 imm=0
#line 33 "sample/./xdp_common.h"
    r4 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(74));
    // EBPF_OP_STXW pc=224 dst=r1 src=r4 offset=90 imm=0
#line 33 "sample/./xdp_common.h"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(90)) = (uint32_t)r4;
    // EBPF_OP_LDXDW pc=225 dst=r4 src=r10 offset=-16 imm=0
#line 34 "sample/./xdp_common.h"
    r4 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=226 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=227 dst=r5 src=r0 offset=0 imm=48
#line 34 "sample/./xdp_common.h"
    r5 >>= IMMEDIATE(48);
    // EBPF_OP_STXB pc=228 dst=r1 src=r5 offset=68 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(68)) = (uint8_t)r5;
    // EBPF_OP_MOV64_REG pc=229 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=230 dst=r5 src=r0 offset=0 imm=56
#line 34 "sample/./xdp_common.h"
    r5 >>= IMMEDIATE(56);
    // EBPF_OP_STXB pc=231 dst=r1 src=r5 offset=69 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(69)) = (uint8_t)r5;
    // EBPF_OP_MOV64_REG pc=232 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=233 dst=r5 src=r0 offset=0 imm=32
#line 34 "sample/./xdp_common.h"
    r5 >>= IMMEDIATE(32);
    // EBPF_OP_STXB pc=234 dst=r1 src=r5 offset=66 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(66)) = (uint8_t)r5;
    // EBPF_OP_MOV64_REG pc=235 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=236 dst=r5 src=r0 offset=0 imm=40
#line 34 "sample/./xdp_common.h"
    r5 >>= IMMEDIATE(40);
    // EBPF_OP_STXB pc=237 dst=r1 src=r5 offset=67 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(67)) = (uint8_t)r5;
    // EBPF_OP_MOV64_REG pc=238 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=239 dst=r5 src=r0 offset=0 imm=16
#line 34 "sample/./xdp_common.h"
    r5 >>= IMMEDIATE(16);
    // EBPF_OP_STXB pc=240 dst=r1 src=r5 offset=64 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(64)) = (uint8_t)r5;
    // EBPF_OP_MOV64_REG pc=241 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=242 dst=r5 src=r0 offset=0 imm=24
#line 34 "sample/./xdp_common.h"
    r5 >>= IMMEDIATE(24);
    // EBPF_OP_STXB pc=243 dst=r1 src=r5 offset=65 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(65)) = (uint8_t)r5;
    // EBPF_OP_STXB pc=244 dst=r1 src=r4 offset=62 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(62)) = (uint8_t)r4;
    // EBPF_OP_RSH64_IMM pc=245 dst=r4 src=r0 offset=0 imm=8
#line 34 "sample/./xdp_common.h"
    r4 >>= IMMEDIATE(8);
    // EBPF_OP_STXB pc=246 dst=r1 src=r4 offset=63 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(63)) = (uint8_t)r4;
    // EBPF_OP_LDXDW pc=247 dst=r4 src=r10 offset=-8 imm=0
#line 34 "sample/./xdp_common.h"
    r4 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=248 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=249 dst=r5 src=r0 offset=0 imm=48
#line 34 "sample/./xdp_common.h"
    r5 >>= IMMEDIATE(48);
    // EBPF_OP_STXB pc=250 dst=r1 src=r5 offset=76 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(76)) = (uint8_t)r5;
    // EBPF_OP_MOV64_REG pc=251 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=252 dst=r5 src=r0 offset=0 imm=56
#line 34 "sample/./xdp_common.h"
    r5 >>= IMMEDIATE(56);
    // EBPF_OP_STXB pc=253 dst=r1 src=r5 offset=77 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(77)) = (uint8_t)r5;
    // EBPF_OP_MOV64_REG pc=254 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=255 dst=r5 src=r0 offset=0 imm=32
#line 34 "sample/./xdp_common.h"
    r5 >>= IMMEDIATE(32);
    // EBPF_OP_STXB pc=256 dst=r1 src=r5 offset=74 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(74)) = (uint8_t)r5;
    // EBPF_OP_MOV64_REG pc=257 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=258 dst=r5 src=r0 offset=0 imm=40
#line 34 "sample/./xdp_common.h"
    r5 >>= IMMEDIATE(40);
    // EBPF_OP_STXB pc=259 dst=r1 src=r5 offset=75 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(75)) = (uint8_t)r5;
    // EBPF_OP_MOV64_REG pc=260 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=261 dst=r5 src=r0 offset=0 imm=16
#line 34 "sample/./xdp_common.h"
    r5 >>= IMMEDIATE(16);
    // EBPF_OP_STXB pc=262 dst=r1 src=r5 offset=72 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(72)) = (uint8_t)r5;
    // EBPF_OP_MOV64_REG pc=263 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=264 dst=r5 src=r0 offset=0 imm=24
#line 34 "sample/./xdp_common.h"
    r5 >>= IMMEDIATE(24);
    // EBPF_OP_STXB pc=265 dst=r1 src=r5 offset=73 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(73)) = (uint8_t)r5;
    // EBPF_OP_STXB pc=266 dst=r1 src=r4 offset=70 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(70)) = (uint8_t)r4;
    // EBPF_OP_RSH64_IMM pc=267 dst=r4 src=r0 offset=0 imm=8
#line 34 "sample/./xdp_common.h"
    r4 >>= IMMEDIATE(8);
    // EBPF_OP_STXB pc=268 dst=r1 src=r4 offset=71 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(71)) = (uint8_t)r4;
    // EBPF_OP_LDXW pc=269 dst=r4 src=r3 offset=36 imm=0
#line 129 "sample/encap_reflect_packet.c"
    r4 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(36));
    // EBPF_OP_STXW pc=270 dst=r2 src=r4 offset=36 imm=0
#line 129 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r2 + OFFSET(36)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=271 dst=r4 src=r3 offset=32 imm=0
#line 129 "sample/encap_reflect_packet.c"
    r4 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(32));
    // EBPF_OP_STXW pc=272 dst=r2 src=r4 offset=32 imm=0
#line 129 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r2 + OFFSET(32)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=273 dst=r4 src=r3 offset=28 imm=0
#line 129 "sample/encap_reflect_packet.c"
    r4 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(28));
    // EBPF_OP_STXW pc=274 dst=r2 src=r4 offset=28 imm=0
#line 129 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r2 + OFFSET(28)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=275 dst=r4 src=r3 offset=24 imm=0
#line 129 "sample/encap_reflect_packet.c"
    r4 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(24));
    // EBPF_OP_STXW pc=276 dst=r2 src=r4 offset=24 imm=0
#line 129 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r2 + OFFSET(24)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=277 dst=r4 src=r3 offset=20 imm=0
#line 129 "sample/encap_reflect_packet.c"
    r4 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(20));
    // EBPF_OP_STXW pc=278 dst=r2 src=r4 offset=20 imm=0
#line 129 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r2 + OFFSET(20)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=279 dst=r4 src=r3 offset=16 imm=0
#line 129 "sample/encap_reflect_packet.c"
    r4 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(16));
    // EBPF_OP_STXW pc=280 dst=r2 src=r4 offset=16 imm=0
#line 129 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r2 + OFFSET(16)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=281 dst=r4 src=r3 offset=12 imm=0
#line 129 "sample/encap_reflect_packet.c"
    r4 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(12));
    // EBPF_OP_STXW pc=282 dst=r2 src=r4 offset=12 imm=0
#line 129 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r2 + OFFSET(12)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=283 dst=r4 src=r3 offset=8 imm=0
#line 129 "sample/encap_reflect_packet.c"
    r4 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(8));
    // EBPF_OP_STXW pc=284 dst=r2 src=r4 offset=8 imm=0
#line 129 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r2 + OFFSET(8)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=285 dst=r4 src=r3 offset=4 imm=0
#line 129 "sample/encap_reflect_packet.c"
    r4 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(4));
    // EBPF_OP_STXW pc=286 dst=r2 src=r4 offset=4 imm=0
#line 129 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r2 + OFFSET(4)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=287 dst=r3 src=r3 offset=0 imm=0
#line 129 "sample/encap_reflect_packet.c"
    r3 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(0));
    // EBPF_OP_STXW pc=288 dst=r2 src=r3 offset=0 imm=0
#line 129 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r2 + OFFSET(0)) = (uint32_t)r3;
    // EBPF_OP_MOV64_IMM pc=289 dst=r2 src=r0 offset=0 imm=41
#line 129 "sample/encap_reflect_packet.c"
    r2 = IMMEDIATE(41);
    // EBPF_OP_STXB pc=290 dst=r1 src=r2 offset=20 imm=0
#line 132 "sample/encap_reflect_packet.c"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(20)) = (uint8_t)r2;
    // EBPF_OP_LDXH pc=291 dst=r2 src=r1 offset=58 imm=0
#line 133 "sample/encap_reflect_packet.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(58));
    // EBPF_OP_BE pc=292 dst=r2 src=r0 offset=0 imm=16
#line 133 "sample/encap_reflect_packet.c"
    r2 = htobe16((uint16_t)r2);
#line 133 "sample/encap_reflect_packet.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_ADD64_IMM pc=293 dst=r2 src=r0 offset=0 imm=40
#line 133 "sample/encap_reflect_packet.c"
    r2 += IMMEDIATE(40);
    // EBPF_OP_BE pc=294 dst=r2 src=r0 offset=0 imm=16
#line 133 "sample/encap_reflect_packet.c"
    r2 = htobe16((uint16_t)r2);
#line 133 "sample/encap_reflect_packet.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_STXH pc=295 dst=r1 src=r2 offset=18 imm=0
#line 133 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(18)) = (uint16_t)r2;
label_2:
    // EBPF_OP_MOV64_IMM pc=296 dst=r0 src=r0 offset=0 imm=3
#line 133 "sample/encap_reflect_packet.c"
    r0 = IMMEDIATE(3);
label_3:
    // EBPF_OP_EXIT pc=297 dst=r0 src=r0 offset=0 imm=0
#line 198 "sample/encap_reflect_packet.c"
    return r0;
#line 198 "sample/encap_reflect_packet.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        encap_reflect_packet,
        "xdp/en~1",
        "xdp/encap_reflect",
        "encap_reflect_packet",
        NULL,
        0,
        encap_reflect_packet_helpers,
        2,
        298,
        &encap_reflect_packet_program_type_guid,
        &encap_reflect_packet_attach_type_guid,
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

metadata_table_t encap_reflect_packet_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
