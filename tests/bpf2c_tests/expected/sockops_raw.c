// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from sockops.o

#include "bpf2c.h"

static void
_get_hash(_Outptr_result_buffer_maybenull_(*size) const uint8_t** hash, _Out_ size_t* size)
{
    *hash = NULL;
    *size = 0;
}
#pragma data_seg(push, "maps")
static map_entry_t _maps[] = {
    {0,
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         56,                // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         2,                 // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         21,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "connection_map"},
    {0,
     {
         BPF_MAP_TYPE_RINGBUF, // Type of map.
         0,                    // Size in bytes of a map key.
         0,                    // Size in bytes of a map value.
         262144,               // Maximum number of entries allowed in the map.
         0,                    // Inner map index.
         LIBBPF_PIN_NONE,      // Pinning type for the map.
         27,                   // Identifier for a map template.
         0,                    // The id of the inner map template.
     },
     "audit_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 2;
}

static helper_function_entry_t connection_monitor_helpers[] = {
    {1, "helper_id_1"},
    {11, "helper_id_11"},
};

static GUID connection_monitor_program_type_guid = {
    0x43fb224d, 0x68f8, 0x46d6, {0xaa, 0x3f, 0xc8, 0x56, 0x51, 0x8c, 0xbb, 0x32}};
static GUID connection_monitor_attach_type_guid = {
    0x837d02cd, 0x3251, 0x4632, {0x8d, 0x94, 0x60, 0xd3, 0xb4, 0x57, 0x69, 0xf2}};
static uint16_t connection_monitor_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sockops")
static uint64_t
connection_monitor(void* context, const program_runtime_context_t* runtime_context)
#line 72 "sample/sockops.c"
{
#line 72 "sample/sockops.c"
    // Prologue
#line 72 "sample/sockops.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 72 "sample/sockops.c"
    register uint64_t r0 = 0;
#line 72 "sample/sockops.c"
    register uint64_t r1 = 0;
#line 72 "sample/sockops.c"
    register uint64_t r2 = 0;
#line 72 "sample/sockops.c"
    register uint64_t r3 = 0;
#line 72 "sample/sockops.c"
    register uint64_t r4 = 0;
#line 72 "sample/sockops.c"
    register uint64_t r5 = 0;
#line 72 "sample/sockops.c"
    register uint64_t r6 = 0;
#line 72 "sample/sockops.c"
    register uint64_t r7 = 0;
#line 72 "sample/sockops.c"
    register uint64_t r10 = 0;

#line 72 "sample/sockops.c"
    r1 = (uintptr_t)context;
#line 72 "sample/sockops.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r2 src=r0 offset=0 imm=2
#line 72 "sample/sockops.c"
    r2 = IMMEDIATE(2);
    // EBPF_OP_MOV64_IMM pc=1 dst=r3 src=r0 offset=0 imm=1
#line 72 "sample/sockops.c"
    r3 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=2 dst=r4 src=r1 offset=0 imm=0
#line 77 "sample/sockops.c"
    r4 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=3 dst=r4 src=r0 offset=8 imm=0
#line 77 "sample/sockops.c"
    if (r4 == IMMEDIATE(0)) {
#line 77 "sample/sockops.c"
        goto label_2;
#line 77 "sample/sockops.c"
    }
    // EBPF_OP_JEQ_IMM pc=4 dst=r4 src=r0 offset=5 imm=2
#line 77 "sample/sockops.c"
    if (r4 == IMMEDIATE(2)) {
#line 77 "sample/sockops.c"
        goto label_1;
#line 77 "sample/sockops.c"
    }
    // EBPF_OP_LDDW pc=5 dst=r0 src=r0 offset=0 imm=-1
#line 77 "sample/sockops.c"
    r0 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=7 dst=r4 src=r0 offset=162 imm=1
#line 77 "sample/sockops.c"
    if (r4 != IMMEDIATE(1)) {
#line 77 "sample/sockops.c"
        goto label_5;
#line 77 "sample/sockops.c"
    }
    // EBPF_OP_MOV64_IMM pc=8 dst=r3 src=r0 offset=0 imm=0
#line 77 "sample/sockops.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_JA pc=9 dst=r0 src=r0 offset=2 imm=0
#line 77 "sample/sockops.c"
    goto label_2;
label_1:
    // EBPF_OP_MOV64_IMM pc=10 dst=r3 src=r0 offset=0 imm=0
#line 77 "sample/sockops.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=0
#line 77 "sample/sockops.c"
    r2 = IMMEDIATE(0);
label_2:
    // EBPF_OP_LDXW pc=12 dst=r4 src=r1 offset=4 imm=0
#line 94 "sample/sockops.c"
    r4 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(4));
    // EBPF_OP_JNE_IMM pc=13 dst=r4 src=r0 offset=33 imm=2
#line 94 "sample/sockops.c"
    if (r4 != IMMEDIATE(2)) {
#line 94 "sample/sockops.c"
        goto label_3;
#line 94 "sample/sockops.c"
    }
    // EBPF_OP_MOV64_IMM pc=14 dst=r4 src=r0 offset=0 imm=0
#line 94 "sample/sockops.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=15 dst=r10 src=r4 offset=-8 imm=0
#line 36 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r4;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r4 offset=-16 imm=0
#line 36 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r4;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r4 offset=-24 imm=0
#line 36 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r4;
    // EBPF_OP_STXDW pc=18 dst=r10 src=r4 offset=-32 imm=0
#line 36 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r4;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r4 offset=-40 imm=0
#line 36 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r4;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r4 offset=-48 imm=0
#line 36 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r4;
    // EBPF_OP_STXDW pc=21 dst=r10 src=r4 offset=-56 imm=0
#line 36 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r4;
    // EBPF_OP_STXDW pc=22 dst=r10 src=r4 offset=-64 imm=0
#line 36 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r4;
    // EBPF_OP_LDXW pc=23 dst=r4 src=r1 offset=8 imm=0
#line 38 "sample/sockops.c"
    r4 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(8));
    // EBPF_OP_STXW pc=24 dst=r10 src=r4 offset=-64 imm=0
#line 38 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=25 dst=r4 src=r1 offset=24 imm=0
#line 39 "sample/sockops.c"
    r4 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_STXH pc=26 dst=r10 src=r4 offset=-48 imm=0
#line 39 "sample/sockops.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint16_t)r4;
    // EBPF_OP_LDXW pc=27 dst=r4 src=r1 offset=28 imm=0
#line 40 "sample/sockops.c"
    r4 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(28));
    // EBPF_OP_STXW pc=28 dst=r10 src=r4 offset=-44 imm=0
#line 40 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-44)) = (uint32_t)r4;
    // EBPF_OP_OR64_REG pc=29 dst=r2 src=r3 offset=0 imm=0
#line 44 "sample/sockops.c"
    r2 |= r3;
    // EBPF_OP_LDXW pc=30 dst=r3 src=r1 offset=44 imm=0
#line 41 "sample/sockops.c"
    r3 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_STXH pc=31 dst=r10 src=r3 offset=-28 imm=0
#line 41 "sample/sockops.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint16_t)r3;
    // EBPF_OP_LDXB pc=32 dst=r3 src=r1 offset=48 imm=0
#line 42 "sample/sockops.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(48));
    // EBPF_OP_STXW pc=33 dst=r10 src=r3 offset=-24 imm=0
#line 42 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r3;
    // EBPF_OP_LDXDW pc=34 dst=r1 src=r1 offset=56 imm=0
#line 43 "sample/sockops.c"
    r1 = *(uint64_t*)(uintptr_t)(r1 + OFFSET(56));
    // EBPF_OP_STXB pc=35 dst=r10 src=r2 offset=-8 imm=0
#line 45 "sample/sockops.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r2;
    // EBPF_OP_STXDW pc=36 dst=r10 src=r1 offset=-16 imm=0
#line 43 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=37 dst=r2 src=r10 offset=0 imm=0
#line 43 "sample/sockops.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=38 dst=r2 src=r0 offset=0 imm=-64
#line 43 "sample/sockops.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=39 dst=r1 src=r0 offset=0 imm=0
#line 26 "sample/sockops.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=41 dst=r0 src=r0 offset=0 imm=1
#line 26 "sample/sockops.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5);
#line 26 "sample/sockops.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 26 "sample/sockops.c"
        return 0;
#line 26 "sample/sockops.c"
    }
    // EBPF_OP_MOV64_REG pc=42 dst=r1 src=r0 offset=0 imm=0
#line 26 "sample/sockops.c"
    r1 = r0;
    // EBPF_OP_LDDW pc=43 dst=r0 src=r0 offset=0 imm=-1
#line 26 "sample/sockops.c"
    r0 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=45 dst=r1 src=r0 offset=124 imm=0
#line 26 "sample/sockops.c"
    if (r1 == IMMEDIATE(0)) {
#line 26 "sample/sockops.c"
        goto label_5;
#line 26 "sample/sockops.c"
    }
    // EBPF_OP_JA pc=46 dst=r0 src=r0 offset=116 imm=0
#line 26 "sample/sockops.c"
    goto label_4;
label_3:
    // EBPF_OP_MOV64_IMM pc=47 dst=r4 src=r0 offset=0 imm=0
#line 26 "sample/sockops.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=48 dst=r10 src=r4 offset=-8 imm=0
#line 57 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r4;
    // EBPF_OP_STXDW pc=49 dst=r10 src=r4 offset=-16 imm=0
#line 57 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r4;
    // EBPF_OP_STXDW pc=50 dst=r10 src=r4 offset=-24 imm=0
#line 57 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r4;
    // EBPF_OP_STXDW pc=51 dst=r10 src=r4 offset=-32 imm=0
#line 57 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r4;
    // EBPF_OP_STXDW pc=52 dst=r10 src=r4 offset=-40 imm=0
#line 57 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r4;
    // EBPF_OP_STXDW pc=53 dst=r10 src=r4 offset=-48 imm=0
#line 57 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r4;
    // EBPF_OP_LDXB pc=54 dst=r5 src=r1 offset=21 imm=0
#line 57 "sample/sockops.c"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(21));
    // EBPF_OP_LSH64_IMM pc=55 dst=r5 src=r0 offset=0 imm=8
#line 57 "sample/sockops.c"
    r5 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=56 dst=r4 src=r1 offset=20 imm=0
#line 57 "sample/sockops.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(20));
    // EBPF_OP_OR64_REG pc=57 dst=r5 src=r4 offset=0 imm=0
#line 57 "sample/sockops.c"
    r5 |= r4;
    // EBPF_OP_LDXB pc=58 dst=r4 src=r1 offset=23 imm=0
#line 57 "sample/sockops.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(23));
    // EBPF_OP_LSH64_IMM pc=59 dst=r4 src=r0 offset=0 imm=8
#line 57 "sample/sockops.c"
    r4 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=60 dst=r0 src=r1 offset=22 imm=0
#line 57 "sample/sockops.c"
    r0 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(22));
    // EBPF_OP_OR64_REG pc=61 dst=r4 src=r0 offset=0 imm=0
#line 57 "sample/sockops.c"
    r4 |= r0;
    // EBPF_OP_LDXB pc=62 dst=r6 src=r1 offset=17 imm=0
#line 57 "sample/sockops.c"
    r6 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(17));
    // EBPF_OP_LSH64_IMM pc=63 dst=r6 src=r0 offset=0 imm=8
#line 57 "sample/sockops.c"
    r6 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=64 dst=r0 src=r1 offset=16 imm=0
#line 57 "sample/sockops.c"
    r0 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(16));
    // EBPF_OP_OR64_REG pc=65 dst=r6 src=r0 offset=0 imm=0
#line 57 "sample/sockops.c"
    r6 |= r0;
    // EBPF_OP_LDXB pc=66 dst=r0 src=r1 offset=19 imm=0
#line 57 "sample/sockops.c"
    r0 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(19));
    // EBPF_OP_LSH64_IMM pc=67 dst=r0 src=r0 offset=0 imm=8
#line 57 "sample/sockops.c"
    r0 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=68 dst=r7 src=r1 offset=18 imm=0
#line 57 "sample/sockops.c"
    r7 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(18));
    // EBPF_OP_OR64_REG pc=69 dst=r0 src=r7 offset=0 imm=0
#line 57 "sample/sockops.c"
    r0 |= r7;
    // EBPF_OP_LSH64_IMM pc=70 dst=r0 src=r0 offset=0 imm=16
#line 57 "sample/sockops.c"
    r0 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_OR64_REG pc=71 dst=r0 src=r6 offset=0 imm=0
#line 57 "sample/sockops.c"
    r0 |= r6;
    // EBPF_OP_LSH64_IMM pc=72 dst=r4 src=r0 offset=0 imm=16
#line 57 "sample/sockops.c"
    r4 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_OR64_REG pc=73 dst=r4 src=r5 offset=0 imm=0
#line 57 "sample/sockops.c"
    r4 |= r5;
    // EBPF_OP_LDXB pc=74 dst=r6 src=r1 offset=9 imm=0
#line 57 "sample/sockops.c"
    r6 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(9));
    // EBPF_OP_LSH64_IMM pc=75 dst=r6 src=r0 offset=0 imm=8
#line 57 "sample/sockops.c"
    r6 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=76 dst=r5 src=r1 offset=8 imm=0
#line 57 "sample/sockops.c"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(8));
    // EBPF_OP_OR64_REG pc=77 dst=r6 src=r5 offset=0 imm=0
#line 57 "sample/sockops.c"
    r6 |= r5;
    // EBPF_OP_LDXB pc=78 dst=r5 src=r1 offset=11 imm=0
#line 57 "sample/sockops.c"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(11));
    // EBPF_OP_LSH64_IMM pc=79 dst=r5 src=r0 offset=0 imm=8
#line 57 "sample/sockops.c"
    r5 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=80 dst=r7 src=r1 offset=10 imm=0
#line 57 "sample/sockops.c"
    r7 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(10));
    // EBPF_OP_OR64_REG pc=81 dst=r5 src=r7 offset=0 imm=0
#line 57 "sample/sockops.c"
    r5 |= r7;
    // EBPF_OP_OR64_REG pc=82 dst=r2 src=r3 offset=0 imm=0
#line 64 "sample/sockops.c"
    r2 |= r3;
    // EBPF_OP_LSH64_IMM pc=83 dst=r4 src=r0 offset=0 imm=32
#line 57 "sample/sockops.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_OR64_REG pc=84 dst=r4 src=r0 offset=0 imm=0
#line 57 "sample/sockops.c"
    r4 |= r0;
    // EBPF_OP_STXDW pc=85 dst=r10 src=r4 offset=-56 imm=0
#line 57 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r4;
    // EBPF_OP_LSH64_IMM pc=86 dst=r5 src=r0 offset=0 imm=16
#line 57 "sample/sockops.c"
    r5 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_OR64_REG pc=87 dst=r5 src=r6 offset=0 imm=0
#line 57 "sample/sockops.c"
    r5 |= r6;
    // EBPF_OP_LDXB pc=88 dst=r3 src=r1 offset=13 imm=0
#line 57 "sample/sockops.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(13));
    // EBPF_OP_LSH64_IMM pc=89 dst=r3 src=r0 offset=0 imm=8
#line 57 "sample/sockops.c"
    r3 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=90 dst=r4 src=r1 offset=12 imm=0
#line 57 "sample/sockops.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(12));
    // EBPF_OP_OR64_REG pc=91 dst=r3 src=r4 offset=0 imm=0
#line 57 "sample/sockops.c"
    r3 |= r4;
    // EBPF_OP_LDXB pc=92 dst=r4 src=r1 offset=15 imm=0
#line 57 "sample/sockops.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(15));
    // EBPF_OP_LSH64_IMM pc=93 dst=r4 src=r0 offset=0 imm=8
#line 57 "sample/sockops.c"
    r4 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=94 dst=r0 src=r1 offset=14 imm=0
#line 57 "sample/sockops.c"
    r0 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(14));
    // EBPF_OP_OR64_REG pc=95 dst=r4 src=r0 offset=0 imm=0
#line 57 "sample/sockops.c"
    r4 |= r0;
    // EBPF_OP_LSH64_IMM pc=96 dst=r4 src=r0 offset=0 imm=16
#line 57 "sample/sockops.c"
    r4 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_OR64_REG pc=97 dst=r4 src=r3 offset=0 imm=0
#line 57 "sample/sockops.c"
    r4 |= r3;
    // EBPF_OP_LSH64_IMM pc=98 dst=r4 src=r0 offset=0 imm=32
#line 57 "sample/sockops.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_OR64_REG pc=99 dst=r4 src=r5 offset=0 imm=0
#line 57 "sample/sockops.c"
    r4 |= r5;
    // EBPF_OP_STXDW pc=100 dst=r10 src=r4 offset=-64 imm=0
#line 57 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r4;
    // EBPF_OP_LDXW pc=101 dst=r3 src=r1 offset=24 imm=0
#line 58 "sample/sockops.c"
    r3 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_STXH pc=102 dst=r10 src=r3 offset=-48 imm=0
#line 58 "sample/sockops.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint16_t)r3;
    // EBPF_OP_LDXB pc=103 dst=r5 src=r1 offset=41 imm=0
#line 60 "sample/sockops.c"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(41));
    // EBPF_OP_LSH64_IMM pc=104 dst=r5 src=r0 offset=0 imm=8
#line 60 "sample/sockops.c"
    r5 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=105 dst=r3 src=r1 offset=40 imm=0
#line 60 "sample/sockops.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_OR64_REG pc=106 dst=r5 src=r3 offset=0 imm=0
#line 60 "sample/sockops.c"
    r5 |= r3;
    // EBPF_OP_LDXB pc=107 dst=r3 src=r1 offset=43 imm=0
#line 60 "sample/sockops.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(43));
    // EBPF_OP_LSH64_IMM pc=108 dst=r3 src=r0 offset=0 imm=8
#line 60 "sample/sockops.c"
    r3 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=109 dst=r4 src=r1 offset=42 imm=0
#line 60 "sample/sockops.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(42));
    // EBPF_OP_OR64_REG pc=110 dst=r3 src=r4 offset=0 imm=0
#line 60 "sample/sockops.c"
    r3 |= r4;
    // EBPF_OP_LDXB pc=111 dst=r0 src=r1 offset=29 imm=0
#line 60 "sample/sockops.c"
    r0 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(29));
    // EBPF_OP_LSH64_IMM pc=112 dst=r0 src=r0 offset=0 imm=8
#line 60 "sample/sockops.c"
    r0 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=113 dst=r4 src=r1 offset=28 imm=0
#line 60 "sample/sockops.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(28));
    // EBPF_OP_OR64_REG pc=114 dst=r0 src=r4 offset=0 imm=0
#line 60 "sample/sockops.c"
    r0 |= r4;
    // EBPF_OP_LDXB pc=115 dst=r4 src=r1 offset=31 imm=0
#line 60 "sample/sockops.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(31));
    // EBPF_OP_LSH64_IMM pc=116 dst=r4 src=r0 offset=0 imm=8
#line 60 "sample/sockops.c"
    r4 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=117 dst=r6 src=r1 offset=30 imm=0
#line 60 "sample/sockops.c"
    r6 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(30));
    // EBPF_OP_OR64_REG pc=118 dst=r4 src=r6 offset=0 imm=0
#line 60 "sample/sockops.c"
    r4 |= r6;
    // EBPF_OP_LSH64_IMM pc=119 dst=r4 src=r0 offset=0 imm=16
#line 60 "sample/sockops.c"
    r4 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_OR64_REG pc=120 dst=r4 src=r0 offset=0 imm=0
#line 60 "sample/sockops.c"
    r4 |= r0;
    // EBPF_OP_LSH64_IMM pc=121 dst=r3 src=r0 offset=0 imm=16
#line 60 "sample/sockops.c"
    r3 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_OR64_REG pc=122 dst=r3 src=r5 offset=0 imm=0
#line 60 "sample/sockops.c"
    r3 |= r5;
    // EBPF_OP_LDXB pc=123 dst=r5 src=r1 offset=37 imm=0
#line 60 "sample/sockops.c"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(37));
    // EBPF_OP_LSH64_IMM pc=124 dst=r5 src=r0 offset=0 imm=8
#line 60 "sample/sockops.c"
    r5 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=125 dst=r0 src=r1 offset=36 imm=0
#line 60 "sample/sockops.c"
    r0 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(36));
    // EBPF_OP_OR64_REG pc=126 dst=r5 src=r0 offset=0 imm=0
#line 60 "sample/sockops.c"
    r5 |= r0;
    // EBPF_OP_LDXB pc=127 dst=r0 src=r1 offset=39 imm=0
#line 60 "sample/sockops.c"
    r0 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(39));
    // EBPF_OP_LSH64_IMM pc=128 dst=r0 src=r0 offset=0 imm=8
#line 60 "sample/sockops.c"
    r0 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=129 dst=r6 src=r1 offset=38 imm=0
#line 60 "sample/sockops.c"
    r6 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(38));
    // EBPF_OP_OR64_REG pc=130 dst=r0 src=r6 offset=0 imm=0
#line 60 "sample/sockops.c"
    r0 |= r6;
    // EBPF_OP_LSH64_IMM pc=131 dst=r0 src=r0 offset=0 imm=16
#line 60 "sample/sockops.c"
    r0 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_OR64_REG pc=132 dst=r0 src=r5 offset=0 imm=0
#line 60 "sample/sockops.c"
    r0 |= r5;
    // EBPF_OP_STXW pc=133 dst=r10 src=r0 offset=-36 imm=0
#line 60 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-36)) = (uint32_t)r0;
    // EBPF_OP_STXW pc=134 dst=r10 src=r3 offset=-32 imm=0
#line 60 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r3;
    // EBPF_OP_STXW pc=135 dst=r10 src=r4 offset=-44 imm=0
#line 60 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-44)) = (uint32_t)r4;
    // EBPF_OP_LDXB pc=136 dst=r3 src=r1 offset=33 imm=0
#line 60 "sample/sockops.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(33));
    // EBPF_OP_LSH64_IMM pc=137 dst=r3 src=r0 offset=0 imm=8
#line 60 "sample/sockops.c"
    r3 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=138 dst=r4 src=r1 offset=32 imm=0
#line 60 "sample/sockops.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(32));
    // EBPF_OP_OR64_REG pc=139 dst=r3 src=r4 offset=0 imm=0
#line 60 "sample/sockops.c"
    r3 |= r4;
    // EBPF_OP_LDXB pc=140 dst=r4 src=r1 offset=35 imm=0
#line 60 "sample/sockops.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(35));
    // EBPF_OP_LSH64_IMM pc=141 dst=r4 src=r0 offset=0 imm=8
#line 60 "sample/sockops.c"
    r4 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=142 dst=r5 src=r1 offset=34 imm=0
#line 60 "sample/sockops.c"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(34));
    // EBPF_OP_OR64_REG pc=143 dst=r4 src=r5 offset=0 imm=0
#line 60 "sample/sockops.c"
    r4 |= r5;
    // EBPF_OP_LSH64_IMM pc=144 dst=r4 src=r0 offset=0 imm=16
#line 60 "sample/sockops.c"
    r4 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_OR64_REG pc=145 dst=r4 src=r3 offset=0 imm=0
#line 60 "sample/sockops.c"
    r4 |= r3;
    // EBPF_OP_STXW pc=146 dst=r10 src=r4 offset=-40 imm=0
#line 60 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=147 dst=r3 src=r1 offset=44 imm=0
#line 61 "sample/sockops.c"
    r3 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_STXH pc=148 dst=r10 src=r3 offset=-28 imm=0
#line 61 "sample/sockops.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint16_t)r3;
    // EBPF_OP_LDXB pc=149 dst=r3 src=r1 offset=48 imm=0
#line 62 "sample/sockops.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(48));
    // EBPF_OP_STXW pc=150 dst=r10 src=r3 offset=-24 imm=0
#line 62 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r3;
    // EBPF_OP_LDXDW pc=151 dst=r1 src=r1 offset=56 imm=0
#line 63 "sample/sockops.c"
    r1 = *(uint64_t*)(uintptr_t)(r1 + OFFSET(56));
    // EBPF_OP_STXB pc=152 dst=r10 src=r2 offset=-8 imm=0
#line 65 "sample/sockops.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r2;
    // EBPF_OP_STXDW pc=153 dst=r10 src=r1 offset=-16 imm=0
#line 63 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=154 dst=r2 src=r10 offset=0 imm=0
#line 63 "sample/sockops.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=155 dst=r2 src=r0 offset=0 imm=-64
#line 63 "sample/sockops.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=156 dst=r1 src=r0 offset=0 imm=0
#line 26 "sample/sockops.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=158 dst=r0 src=r0 offset=0 imm=1
#line 26 "sample/sockops.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5);
#line 26 "sample/sockops.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 26 "sample/sockops.c"
        return 0;
#line 26 "sample/sockops.c"
    }
    // EBPF_OP_MOV64_REG pc=159 dst=r1 src=r0 offset=0 imm=0
#line 26 "sample/sockops.c"
    r1 = r0;
    // EBPF_OP_LDDW pc=160 dst=r0 src=r0 offset=0 imm=-1
#line 26 "sample/sockops.c"
    r0 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=162 dst=r1 src=r0 offset=7 imm=0
#line 26 "sample/sockops.c"
    if (r1 == IMMEDIATE(0)) {
#line 26 "sample/sockops.c"
        goto label_5;
#line 26 "sample/sockops.c"
    }
label_4:
    // EBPF_OP_MOV64_REG pc=163 dst=r2 src=r10 offset=0 imm=0
#line 26 "sample/sockops.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=164 dst=r2 src=r0 offset=0 imm=-64
#line 26 "sample/sockops.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=165 dst=r1 src=r0 offset=0 imm=0
#line 26 "sample/sockops.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=167 dst=r3 src=r0 offset=0 imm=64
#line 26 "sample/sockops.c"
    r3 = IMMEDIATE(64);
    // EBPF_OP_MOV64_IMM pc=168 dst=r4 src=r0 offset=0 imm=0
#line 26 "sample/sockops.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=169 dst=r0 src=r0 offset=0 imm=11
#line 26 "sample/sockops.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5);
#line 26 "sample/sockops.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 26 "sample/sockops.c"
        return 0;
#line 26 "sample/sockops.c"
    }
label_5:
    // EBPF_OP_EXIT pc=170 dst=r0 src=r0 offset=0 imm=0
#line 97 "sample/sockops.c"
    return r0;
#line 97 "sample/sockops.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        connection_monitor,
        "sockops",
        "sockops",
        "connection_monitor",
        connection_monitor_maps,
        2,
        connection_monitor_helpers,
        2,
        171,
        &connection_monitor_program_type_guid,
        &connection_monitor_attach_type_guid,
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
    version->minor = 17;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t sockops_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};
