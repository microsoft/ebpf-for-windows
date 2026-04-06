// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from sockops_flow_id.o

#include "bpf2c.h"

static void
_get_hash(_Outptr_result_buffer_maybenull_(*size) const uint8_t** hash, _Out_ size_t* size)
{
    *hash = NULL;
    *size = 0;
}

#pragma data_seg(push, "maps")
static map_entry_t _maps[] = {
    {
     {0, 0},
     {
         1,                 // Current Version.
         80,                // Struct size up to the last field.
         80,                // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         56,                // Size in bytes of a map key.
         8,                 // Size in bytes of a map value.
         10,                // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         21,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "flow_id_map"},
    {
     {0, 0},
     {
         1,                    // Current Version.
         80,                   // Struct size up to the last field.
         80,                   // Total struct size including padding.
     },
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
     "flow_id_audit_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 2;
}

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static helper_function_entry_t flow_id_monitor_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     65536,
     "helper_id_65536",
    },
    {
     {1, 40, 40}, // Version header.
     19,
     "helper_id_19",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
    {
     {1, 40, 40}, // Version header.
     11,
     "helper_id_11",
    },
};

static GUID flow_id_monitor_program_type_guid = {
    0x43fb224d, 0x68f8, 0x46d6, {0xaa, 0x3f, 0xc8, 0x56, 0x51, 0x8c, 0xbb, 0x32}};
static GUID flow_id_monitor_attach_type_guid = {
    0x837d02cd, 0x3251, 0x4632, {0x8d, 0x94, 0x60, 0xd3, 0xb4, 0x57, 0x69, 0xf2}};
static uint16_t flow_id_monitor_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sockops")
static uint64_t
flow_id_monitor(void* context, const program_runtime_context_t* runtime_context)
#line 109 "sample/sockops_flow_id.c"
{
#line 109 "sample/sockops_flow_id.c"
    // Prologue.
#line 109 "sample/sockops_flow_id.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 109 "sample/sockops_flow_id.c"
    register uint64_t r0 = 0;
#line 109 "sample/sockops_flow_id.c"
    register uint64_t r1 = 0;
#line 109 "sample/sockops_flow_id.c"
    register uint64_t r2 = 0;
#line 109 "sample/sockops_flow_id.c"
    register uint64_t r3 = 0;
#line 109 "sample/sockops_flow_id.c"
    register uint64_t r4 = 0;
#line 109 "sample/sockops_flow_id.c"
    register uint64_t r5 = 0;
#line 109 "sample/sockops_flow_id.c"
    register uint64_t r6 = 0;
#line 109 "sample/sockops_flow_id.c"
    register uint64_t r7 = 0;
#line 109 "sample/sockops_flow_id.c"
    register uint64_t r8 = 0;
#line 109 "sample/sockops_flow_id.c"
    register uint64_t r10 = 0;

#line 109 "sample/sockops_flow_id.c"
    r1 = (uintptr_t)context;
#line 109 "sample/sockops_flow_id.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r0 src=r0 offset=0 imm=0
#line 109 "sample/sockops_flow_id.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_LDXW pc=1 dst=r2 src=r1 offset=0 imm=0
#line 111 "sample/sockops_flow_id.c"
    READ_ONCE_32(r2, r1, OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=2 dst=r2 src=r0 offset=52 imm=0
#line 111 "sample/sockops_flow_id.c"
    if (r2 == IMMEDIATE(0)) {
#line 111 "sample/sockops_flow_id.c"
        goto label_2;
#line 111 "sample/sockops_flow_id.c"
    }
    // EBPF_OP_JEQ_IMM pc=3 dst=r2 src=r0 offset=26 imm=2
#line 111 "sample/sockops_flow_id.c"
    if (r2 == IMMEDIATE(2)) {
#line 111 "sample/sockops_flow_id.c"
        goto label_1;
#line 111 "sample/sockops_flow_id.c"
    }
    // EBPF_OP_JNE_IMM pc=4 dst=r2 src=r0 offset=205 imm=1
#line 111 "sample/sockops_flow_id.c"
    if (r2 != IMMEDIATE(1)) {
#line 111 "sample/sockops_flow_id.c"
        goto label_11;
#line 111 "sample/sockops_flow_id.c"
    }
    // EBPF_OP_LDXW pc=5 dst=r2 src=r1 offset=4 imm=0
#line 113 "sample/sockops_flow_id.c"
    READ_ONCE_32(r2, r1, OFFSET(4));
    // EBPF_OP_JEQ_IMM pc=6 dst=r2 src=r0 offset=147 imm=23
#line 113 "sample/sockops_flow_id.c"
    if (r2 == IMMEDIATE(23)) {
#line 113 "sample/sockops_flow_id.c"
        goto label_7;
#line 113 "sample/sockops_flow_id.c"
    }
    // EBPF_OP_JNE_IMM pc=7 dst=r2 src=r0 offset=202 imm=2
#line 113 "sample/sockops_flow_id.c"
    if (r2 != IMMEDIATE(2)) {
#line 113 "sample/sockops_flow_id.c"
        goto label_11;
#line 113 "sample/sockops_flow_id.c"
    }
    // EBPF_OP_MOV64_IMM pc=8 dst=r2 src=r0 offset=0 imm=0
#line 113 "sample/sockops_flow_id.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=9 dst=r10 src=r2 offset=-8 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-8));
    // EBPF_OP_STXDW pc=10 dst=r10 src=r2 offset=-16 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-16));
    // EBPF_OP_STXDW pc=11 dst=r10 src=r2 offset=-24 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-24));
    // EBPF_OP_STXDW pc=12 dst=r10 src=r2 offset=-32 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-32));
    // EBPF_OP_STXDW pc=13 dst=r10 src=r2 offset=-40 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-40));
    // EBPF_OP_STXDW pc=14 dst=r10 src=r2 offset=-48 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-48));
    // EBPF_OP_STXDW pc=15 dst=r10 src=r2 offset=-56 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-56));
    // EBPF_OP_STXDW pc=16 dst=r10 src=r2 offset=-64 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-64));
    // EBPF_OP_STXDW pc=17 dst=r10 src=r2 offset=-72 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-72));
    // EBPF_OP_STXDW pc=18 dst=r10 src=r2 offset=-80 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-80));
    // EBPF_OP_MOV64_REG pc=19 dst=r6 src=r1 offset=0 imm=0
#line 52 "sample/sockops_flow_id.c"
    r6 = r1;
    // EBPF_OP_CALL pc=20 dst=r0 src=r0 offset=0 imm=65536
#line 55 "sample/sockops_flow_id.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=21 dst=r7 src=r0 offset=0 imm=0
#line 55 "sample/sockops_flow_id.c"
    r7 = r0;
    // EBPF_OP_STXDW pc=22 dst=r10 src=r7 offset=-88 imm=0
#line 55 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-88));
    // EBPF_OP_LDXW pc=23 dst=r1 src=r6 offset=8 imm=0
#line 57 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(8));
    // EBPF_OP_STXW pc=24 dst=r10 src=r1 offset=-80 imm=0
#line 57 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-80));
    // EBPF_OP_LDXW pc=25 dst=r1 src=r6 offset=24 imm=0
#line 58 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(24));
    // EBPF_OP_STXH pc=26 dst=r10 src=r1 offset=-64 imm=0
#line 58 "sample/sockops_flow_id.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-64));
    // EBPF_OP_LDXW pc=27 dst=r1 src=r6 offset=28 imm=0
#line 59 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(28));
    // EBPF_OP_STXW pc=28 dst=r10 src=r1 offset=-60 imm=0
#line 59 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-60));
    // EBPF_OP_JA pc=29 dst=r0 src=r0 offset=151 imm=0
#line 59 "sample/sockops_flow_id.c"
    goto label_8;
label_1:
    // EBPF_OP_LDXW pc=30 dst=r2 src=r1 offset=4 imm=0
#line 127 "sample/sockops_flow_id.c"
    READ_ONCE_32(r2, r1, OFFSET(4));
    // EBPF_OP_JEQ_IMM pc=31 dst=r2 src=r0 offset=48 imm=23
#line 127 "sample/sockops_flow_id.c"
    if (r2 == IMMEDIATE(23)) {
#line 127 "sample/sockops_flow_id.c"
        goto label_3;
#line 127 "sample/sockops_flow_id.c"
    }
    // EBPF_OP_JNE_IMM pc=32 dst=r2 src=r0 offset=177 imm=2
#line 127 "sample/sockops_flow_id.c"
    if (r2 != IMMEDIATE(2)) {
#line 127 "sample/sockops_flow_id.c"
        goto label_11;
#line 127 "sample/sockops_flow_id.c"
    }
    // EBPF_OP_MOV64_IMM pc=33 dst=r8 src=r0 offset=0 imm=0
#line 127 "sample/sockops_flow_id.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=34 dst=r10 src=r8 offset=-8 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-8));
    // EBPF_OP_STXDW pc=35 dst=r10 src=r8 offset=-16 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-16));
    // EBPF_OP_STXDW pc=36 dst=r10 src=r8 offset=-24 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-24));
    // EBPF_OP_STXDW pc=37 dst=r10 src=r8 offset=-32 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-32));
    // EBPF_OP_STXDW pc=38 dst=r10 src=r8 offset=-40 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-40));
    // EBPF_OP_STXDW pc=39 dst=r10 src=r8 offset=-48 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-48));
    // EBPF_OP_STXDW pc=40 dst=r10 src=r8 offset=-56 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-56));
    // EBPF_OP_STXDW pc=41 dst=r10 src=r8 offset=-64 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-64));
    // EBPF_OP_STXDW pc=42 dst=r10 src=r8 offset=-72 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-72));
    // EBPF_OP_STXDW pc=43 dst=r10 src=r8 offset=-80 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-80));
    // EBPF_OP_MOV64_REG pc=44 dst=r6 src=r1 offset=0 imm=0
#line 52 "sample/sockops_flow_id.c"
    r6 = r1;
    // EBPF_OP_CALL pc=45 dst=r0 src=r0 offset=0 imm=65536
#line 55 "sample/sockops_flow_id.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=46 dst=r7 src=r0 offset=0 imm=0
#line 55 "sample/sockops_flow_id.c"
    r7 = r0;
    // EBPF_OP_STXDW pc=47 dst=r10 src=r7 offset=-88 imm=0
#line 55 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-88));
    // EBPF_OP_LDXW pc=48 dst=r1 src=r6 offset=8 imm=0
#line 57 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(8));
    // EBPF_OP_STXW pc=49 dst=r10 src=r1 offset=-80 imm=0
#line 57 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-80));
    // EBPF_OP_LDXW pc=50 dst=r1 src=r6 offset=24 imm=0
#line 58 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(24));
    // EBPF_OP_STXH pc=51 dst=r10 src=r1 offset=-64 imm=0
#line 58 "sample/sockops_flow_id.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-64));
    // EBPF_OP_LDXW pc=52 dst=r1 src=r6 offset=28 imm=0
#line 59 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(28));
    // EBPF_OP_STXW pc=53 dst=r10 src=r1 offset=-60 imm=0
#line 59 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-60));
    // EBPF_OP_JA pc=54 dst=r0 src=r0 offset=52 imm=0
#line 59 "sample/sockops_flow_id.c"
    goto label_4;
label_2:
    // EBPF_OP_LDXW pc=55 dst=r2 src=r1 offset=4 imm=0
#line 120 "sample/sockops_flow_id.c"
    READ_ONCE_32(r2, r1, OFFSET(4));
    // EBPF_OP_JEQ_IMM pc=56 dst=r2 src=r0 offset=61 imm=23
#line 120 "sample/sockops_flow_id.c"
    if (r2 == IMMEDIATE(23)) {
#line 120 "sample/sockops_flow_id.c"
        goto label_5;
#line 120 "sample/sockops_flow_id.c"
    }
    // EBPF_OP_JNE_IMM pc=57 dst=r2 src=r0 offset=152 imm=2
#line 120 "sample/sockops_flow_id.c"
    if (r2 != IMMEDIATE(2)) {
#line 120 "sample/sockops_flow_id.c"
        goto label_11;
#line 120 "sample/sockops_flow_id.c"
    }
    // EBPF_OP_MOV64_IMM pc=58 dst=r2 src=r0 offset=0 imm=0
#line 120 "sample/sockops_flow_id.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=59 dst=r10 src=r2 offset=-8 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-8));
    // EBPF_OP_STXDW pc=60 dst=r10 src=r2 offset=-16 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-16));
    // EBPF_OP_STXDW pc=61 dst=r10 src=r2 offset=-24 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-24));
    // EBPF_OP_STXDW pc=62 dst=r10 src=r2 offset=-32 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-32));
    // EBPF_OP_STXDW pc=63 dst=r10 src=r2 offset=-40 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-40));
    // EBPF_OP_STXDW pc=64 dst=r10 src=r2 offset=-48 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-48));
    // EBPF_OP_STXDW pc=65 dst=r10 src=r2 offset=-56 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-56));
    // EBPF_OP_STXDW pc=66 dst=r10 src=r2 offset=-64 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-64));
    // EBPF_OP_STXDW pc=67 dst=r10 src=r2 offset=-72 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-72));
    // EBPF_OP_STXDW pc=68 dst=r10 src=r2 offset=-80 imm=0
#line 52 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-80));
    // EBPF_OP_MOV64_REG pc=69 dst=r6 src=r1 offset=0 imm=0
#line 52 "sample/sockops_flow_id.c"
    r6 = r1;
    // EBPF_OP_CALL pc=70 dst=r0 src=r0 offset=0 imm=65536
#line 55 "sample/sockops_flow_id.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=71 dst=r7 src=r0 offset=0 imm=0
#line 55 "sample/sockops_flow_id.c"
    r7 = r0;
    // EBPF_OP_STXDW pc=72 dst=r10 src=r7 offset=-88 imm=0
#line 55 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-88));
    // EBPF_OP_LDXW pc=73 dst=r1 src=r6 offset=8 imm=0
#line 57 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(8));
    // EBPF_OP_STXW pc=74 dst=r10 src=r1 offset=-80 imm=0
#line 57 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-80));
    // EBPF_OP_LDXW pc=75 dst=r1 src=r6 offset=24 imm=0
#line 58 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(24));
    // EBPF_OP_STXH pc=76 dst=r10 src=r1 offset=-64 imm=0
#line 58 "sample/sockops_flow_id.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-64));
    // EBPF_OP_LDXW pc=77 dst=r1 src=r6 offset=28 imm=0
#line 59 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(28));
    // EBPF_OP_STXW pc=78 dst=r10 src=r1 offset=-60 imm=0
#line 59 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-60));
    // EBPF_OP_JA pc=79 dst=r0 src=r0 offset=65 imm=0
#line 59 "sample/sockops_flow_id.c"
    goto label_6;
label_3:
    // EBPF_OP_MOV64_REG pc=80 dst=r6 src=r1 offset=0 imm=0
#line 59 "sample/sockops_flow_id.c"
    r6 = r1;
    // EBPF_OP_CALL pc=81 dst=r0 src=r0 offset=0 imm=65536
#line 83 "sample/sockops_flow_id.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=82 dst=r7 src=r0 offset=0 imm=0
#line 83 "sample/sockops_flow_id.c"
    r7 = r0;
    // EBPF_OP_STXDW pc=83 dst=r10 src=r7 offset=-88 imm=0
#line 83 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-88));
    // EBPF_OP_MOV64_IMM pc=84 dst=r8 src=r0 offset=0 imm=0
#line 83 "sample/sockops_flow_id.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=85 dst=r10 src=r8 offset=-64 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-64));
    // EBPF_OP_STXDW pc=86 dst=r10 src=r8 offset=-56 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-56));
    // EBPF_OP_STXDW pc=87 dst=r10 src=r8 offset=-48 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-48));
    // EBPF_OP_STXDW pc=88 dst=r10 src=r8 offset=-40 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-40));
    // EBPF_OP_STXDW pc=89 dst=r10 src=r8 offset=-32 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-32));
    // EBPF_OP_STXDW pc=90 dst=r10 src=r8 offset=-24 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-24));
    // EBPF_OP_STXDW pc=91 dst=r10 src=r8 offset=-16 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-16));
    // EBPF_OP_STXDW pc=92 dst=r10 src=r8 offset=-8 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-8));
    // EBPF_OP_LDXDW pc=93 dst=r1 src=r6 offset=16 imm=0
#line 86 "sample/sockops_flow_id.c"
    READ_ONCE_64(r1, r6, OFFSET(16));
    // EBPF_OP_STXDW pc=94 dst=r10 src=r1 offset=-72 imm=0
#line 86 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-72));
    // EBPF_OP_LDXDW pc=95 dst=r1 src=r6 offset=8 imm=0
#line 86 "sample/sockops_flow_id.c"
    READ_ONCE_64(r1, r6, OFFSET(8));
    // EBPF_OP_STXDW pc=96 dst=r10 src=r1 offset=-80 imm=0
#line 86 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
    // EBPF_OP_LDXW pc=97 dst=r1 src=r6 offset=32 imm=0
#line 87 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(32));
    // EBPF_OP_STXW pc=98 dst=r10 src=r1 offset=-56 imm=0
#line 87 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-56));
    // EBPF_OP_LDXW pc=99 dst=r1 src=r6 offset=28 imm=0
#line 87 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(28));
    // EBPF_OP_STXW pc=100 dst=r10 src=r1 offset=-60 imm=0
#line 87 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-60));
    // EBPF_OP_LDXW pc=101 dst=r1 src=r6 offset=40 imm=0
#line 87 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(40));
    // EBPF_OP_STXW pc=102 dst=r10 src=r1 offset=-48 imm=0
#line 87 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-48));
    // EBPF_OP_LDXW pc=103 dst=r1 src=r6 offset=36 imm=0
#line 87 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(36));
    // EBPF_OP_STXW pc=104 dst=r10 src=r1 offset=-52 imm=0
#line 87 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-52));
    // EBPF_OP_LDXW pc=105 dst=r1 src=r6 offset=24 imm=0
#line 89 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(24));
    // EBPF_OP_STXH pc=106 dst=r10 src=r1 offset=-64 imm=0
#line 89 "sample/sockops_flow_id.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-64));
label_4:
    // EBPF_OP_LDXW pc=107 dst=r1 src=r6 offset=44 imm=0
#line 89 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(44));
    // EBPF_OP_STXH pc=108 dst=r10 src=r1 offset=-44 imm=0
#line 89 "sample/sockops_flow_id.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-44));
    // EBPF_OP_LDXB pc=109 dst=r1 src=r6 offset=48 imm=0
#line 89 "sample/sockops_flow_id.c"
    READ_ONCE_8(r1, r6, OFFSET(48));
    // EBPF_OP_STXW pc=110 dst=r10 src=r1 offset=-40 imm=0
#line 89 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-40));
    // EBPF_OP_LDXDW pc=111 dst=r1 src=r6 offset=56 imm=0
#line 89 "sample/sockops_flow_id.c"
    READ_ONCE_64(r1, r6, OFFSET(56));
    // EBPF_OP_STXDW pc=112 dst=r10 src=r1 offset=-32 imm=0
#line 89 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_CALL pc=113 dst=r0 src=r0 offset=0 imm=19
#line 89 "sample/sockops_flow_id.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_RSH64_IMM pc=114 dst=r0 src=r0 offset=0 imm=32
#line 89 "sample/sockops_flow_id.c"
    r0 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_STXDW pc=115 dst=r10 src=r0 offset=-16 imm=0
#line 89 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-16));
    // EBPF_OP_STXH pc=116 dst=r10 src=r8 offset=-4 imm=0
#line 89 "sample/sockops_flow_id.c"
    WRITE_ONCE_16(r10, (uint16_t)r8, OFFSET(-4));
    // EBPF_OP_JA pc=117 dst=r0 src=r0 offset=74 imm=0
#line 89 "sample/sockops_flow_id.c"
    goto label_10;
label_5:
    // EBPF_OP_MOV64_REG pc=118 dst=r6 src=r1 offset=0 imm=0
#line 89 "sample/sockops_flow_id.c"
    r6 = r1;
    // EBPF_OP_CALL pc=119 dst=r0 src=r0 offset=0 imm=65536
#line 83 "sample/sockops_flow_id.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=120 dst=r7 src=r0 offset=0 imm=0
#line 83 "sample/sockops_flow_id.c"
    r7 = r0;
    // EBPF_OP_STXDW pc=121 dst=r10 src=r7 offset=-88 imm=0
#line 83 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-88));
    // EBPF_OP_MOV64_IMM pc=122 dst=r1 src=r0 offset=0 imm=0
#line 83 "sample/sockops_flow_id.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=123 dst=r10 src=r1 offset=-64 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-64));
    // EBPF_OP_STXDW pc=124 dst=r10 src=r1 offset=-56 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-56));
    // EBPF_OP_STXDW pc=125 dst=r10 src=r1 offset=-48 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
    // EBPF_OP_STXDW pc=126 dst=r10 src=r1 offset=-40 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
    // EBPF_OP_STXDW pc=127 dst=r10 src=r1 offset=-32 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_STXDW pc=128 dst=r10 src=r1 offset=-24 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_STXDW pc=129 dst=r10 src=r1 offset=-16 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_STXDW pc=130 dst=r10 src=r1 offset=-8 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-8));
    // EBPF_OP_LDXDW pc=131 dst=r1 src=r6 offset=16 imm=0
#line 86 "sample/sockops_flow_id.c"
    READ_ONCE_64(r1, r6, OFFSET(16));
    // EBPF_OP_STXDW pc=132 dst=r10 src=r1 offset=-72 imm=0
#line 86 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-72));
    // EBPF_OP_LDXDW pc=133 dst=r1 src=r6 offset=8 imm=0
#line 86 "sample/sockops_flow_id.c"
    READ_ONCE_64(r1, r6, OFFSET(8));
    // EBPF_OP_STXDW pc=134 dst=r10 src=r1 offset=-80 imm=0
#line 86 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
    // EBPF_OP_LDXW pc=135 dst=r1 src=r6 offset=32 imm=0
#line 87 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(32));
    // EBPF_OP_STXW pc=136 dst=r10 src=r1 offset=-56 imm=0
#line 87 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-56));
    // EBPF_OP_LDXW pc=137 dst=r1 src=r6 offset=28 imm=0
#line 87 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(28));
    // EBPF_OP_STXW pc=138 dst=r10 src=r1 offset=-60 imm=0
#line 87 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-60));
    // EBPF_OP_LDXW pc=139 dst=r1 src=r6 offset=40 imm=0
#line 87 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(40));
    // EBPF_OP_STXW pc=140 dst=r10 src=r1 offset=-48 imm=0
#line 87 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-48));
    // EBPF_OP_LDXW pc=141 dst=r1 src=r6 offset=36 imm=0
#line 87 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(36));
    // EBPF_OP_STXW pc=142 dst=r10 src=r1 offset=-52 imm=0
#line 87 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-52));
    // EBPF_OP_LDXW pc=143 dst=r1 src=r6 offset=24 imm=0
#line 89 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(24));
    // EBPF_OP_STXH pc=144 dst=r10 src=r1 offset=-64 imm=0
#line 89 "sample/sockops_flow_id.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-64));
label_6:
    // EBPF_OP_LDXW pc=145 dst=r1 src=r6 offset=44 imm=0
#line 89 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(44));
    // EBPF_OP_STXH pc=146 dst=r10 src=r1 offset=-44 imm=0
#line 89 "sample/sockops_flow_id.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-44));
    // EBPF_OP_LDXB pc=147 dst=r1 src=r6 offset=48 imm=0
#line 89 "sample/sockops_flow_id.c"
    READ_ONCE_8(r1, r6, OFFSET(48));
    // EBPF_OP_STXW pc=148 dst=r10 src=r1 offset=-40 imm=0
#line 89 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-40));
    // EBPF_OP_LDXDW pc=149 dst=r1 src=r6 offset=56 imm=0
#line 89 "sample/sockops_flow_id.c"
    READ_ONCE_64(r1, r6, OFFSET(56));
    // EBPF_OP_STXDW pc=150 dst=r10 src=r1 offset=-32 imm=0
#line 89 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_CALL pc=151 dst=r0 src=r0 offset=0 imm=19
#line 89 "sample/sockops_flow_id.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_IMM pc=152 dst=r1 src=r0 offset=0 imm=257
#line 89 "sample/sockops_flow_id.c"
    r1 = IMMEDIATE(257);
    // EBPF_OP_JA pc=153 dst=r0 src=r0 offset=35 imm=0
#line 89 "sample/sockops_flow_id.c"
    goto label_9;
label_7:
    // EBPF_OP_MOV64_REG pc=154 dst=r6 src=r1 offset=0 imm=0
#line 89 "sample/sockops_flow_id.c"
    r6 = r1;
    // EBPF_OP_CALL pc=155 dst=r0 src=r0 offset=0 imm=65536
#line 83 "sample/sockops_flow_id.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=156 dst=r7 src=r0 offset=0 imm=0
#line 83 "sample/sockops_flow_id.c"
    r7 = r0;
    // EBPF_OP_STXDW pc=157 dst=r10 src=r7 offset=-88 imm=0
#line 83 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-88));
    // EBPF_OP_MOV64_IMM pc=158 dst=r1 src=r0 offset=0 imm=0
#line 83 "sample/sockops_flow_id.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=159 dst=r10 src=r1 offset=-64 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-64));
    // EBPF_OP_STXDW pc=160 dst=r10 src=r1 offset=-56 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-56));
    // EBPF_OP_STXDW pc=161 dst=r10 src=r1 offset=-48 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
    // EBPF_OP_STXDW pc=162 dst=r10 src=r1 offset=-40 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
    // EBPF_OP_STXDW pc=163 dst=r10 src=r1 offset=-32 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_STXDW pc=164 dst=r10 src=r1 offset=-24 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_STXDW pc=165 dst=r10 src=r1 offset=-16 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_STXDW pc=166 dst=r10 src=r1 offset=-8 imm=0
#line 80 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-8));
    // EBPF_OP_LDXDW pc=167 dst=r1 src=r6 offset=16 imm=0
#line 86 "sample/sockops_flow_id.c"
    READ_ONCE_64(r1, r6, OFFSET(16));
    // EBPF_OP_STXDW pc=168 dst=r10 src=r1 offset=-72 imm=0
#line 86 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-72));
    // EBPF_OP_LDXDW pc=169 dst=r1 src=r6 offset=8 imm=0
#line 86 "sample/sockops_flow_id.c"
    READ_ONCE_64(r1, r6, OFFSET(8));
    // EBPF_OP_STXDW pc=170 dst=r10 src=r1 offset=-80 imm=0
#line 86 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
    // EBPF_OP_LDXW pc=171 dst=r1 src=r6 offset=32 imm=0
#line 87 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(32));
    // EBPF_OP_STXW pc=172 dst=r10 src=r1 offset=-56 imm=0
#line 87 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-56));
    // EBPF_OP_LDXW pc=173 dst=r1 src=r6 offset=28 imm=0
#line 87 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(28));
    // EBPF_OP_STXW pc=174 dst=r10 src=r1 offset=-60 imm=0
#line 87 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-60));
    // EBPF_OP_LDXW pc=175 dst=r1 src=r6 offset=40 imm=0
#line 87 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(40));
    // EBPF_OP_STXW pc=176 dst=r10 src=r1 offset=-48 imm=0
#line 87 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-48));
    // EBPF_OP_LDXW pc=177 dst=r1 src=r6 offset=36 imm=0
#line 87 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(36));
    // EBPF_OP_STXW pc=178 dst=r10 src=r1 offset=-52 imm=0
#line 87 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-52));
    // EBPF_OP_LDXW pc=179 dst=r1 src=r6 offset=24 imm=0
#line 89 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(24));
    // EBPF_OP_STXH pc=180 dst=r10 src=r1 offset=-64 imm=0
#line 89 "sample/sockops_flow_id.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-64));
label_8:
    // EBPF_OP_LDXW pc=181 dst=r1 src=r6 offset=44 imm=0
#line 89 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(44));
    // EBPF_OP_STXH pc=182 dst=r10 src=r1 offset=-44 imm=0
#line 89 "sample/sockops_flow_id.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-44));
    // EBPF_OP_LDXB pc=183 dst=r1 src=r6 offset=48 imm=0
#line 89 "sample/sockops_flow_id.c"
    READ_ONCE_8(r1, r6, OFFSET(48));
    // EBPF_OP_STXW pc=184 dst=r10 src=r1 offset=-40 imm=0
#line 89 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-40));
    // EBPF_OP_LDXDW pc=185 dst=r1 src=r6 offset=56 imm=0
#line 89 "sample/sockops_flow_id.c"
    READ_ONCE_64(r1, r6, OFFSET(56));
    // EBPF_OP_STXDW pc=186 dst=r10 src=r1 offset=-32 imm=0
#line 89 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_CALL pc=187 dst=r0 src=r0 offset=0 imm=19
#line 89 "sample/sockops_flow_id.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_IMM pc=188 dst=r1 src=r0 offset=0 imm=256
#line 89 "sample/sockops_flow_id.c"
    r1 = IMMEDIATE(256);
label_9:
    // EBPF_OP_STXH pc=189 dst=r10 src=r1 offset=-4 imm=0
#line 89 "sample/sockops_flow_id.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-4));
    // EBPF_OP_RSH64_IMM pc=190 dst=r0 src=r0 offset=0 imm=32
#line 89 "sample/sockops_flow_id.c"
    r0 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_STXDW pc=191 dst=r10 src=r0 offset=-16 imm=0
#line 89 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-16));
label_10:
    // EBPF_OP_LDXW pc=192 dst=r1 src=r6 offset=0 imm=0
#line 89 "sample/sockops_flow_id.c"
    READ_ONCE_32(r1, r6, OFFSET(0));
    // EBPF_OP_STXW pc=193 dst=r10 src=r1 offset=-8 imm=0
#line 89 "sample/sockops_flow_id.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
    // EBPF_OP_STXDW pc=194 dst=r10 src=r7 offset=-24 imm=0
#line 89 "sample/sockops_flow_id.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-24));
    // EBPF_OP_MOV64_REG pc=195 dst=r6 src=r10 offset=0 imm=0
#line 89 "sample/sockops_flow_id.c"
    r6 = r10;
    // EBPF_OP_ADD64_IMM pc=196 dst=r6 src=r0 offset=0 imm=-80
#line 89 "sample/sockops_flow_id.c"
    r6 += IMMEDIATE(-80);
    // EBPF_OP_MOV64_REG pc=197 dst=r3 src=r10 offset=0 imm=0
#line 89 "sample/sockops_flow_id.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=198 dst=r3 src=r0 offset=0 imm=-88
#line 89 "sample/sockops_flow_id.c"
    r3 += IMMEDIATE(-88);
    // EBPF_OP_LDDW pc=199 dst=r1 src=r1 offset=0 imm=1
#line 89 "sample/sockops_flow_id.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_REG pc=201 dst=r2 src=r6 offset=0 imm=0
#line 89 "sample/sockops_flow_id.c"
    r2 = r6;
    // EBPF_OP_MOV64_IMM pc=202 dst=r4 src=r0 offset=0 imm=0
#line 89 "sample/sockops_flow_id.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=203 dst=r0 src=r0 offset=0 imm=2
#line 89 "sample/sockops_flow_id.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 89 "sample/sockops_flow_id.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[1].address);
    // EBPF_OP_LDDW pc=204 dst=r1 src=r1 offset=0 imm=2
#line 89 "sample/sockops_flow_id.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_REG pc=206 dst=r2 src=r6 offset=0 imm=0
#line 89 "sample/sockops_flow_id.c"
    r2 = r6;
    // EBPF_OP_MOV64_IMM pc=207 dst=r3 src=r0 offset=0 imm=80
#line 89 "sample/sockops_flow_id.c"
    r3 = IMMEDIATE(80);
    // EBPF_OP_MOV64_IMM pc=208 dst=r4 src=r0 offset=0 imm=0
#line 89 "sample/sockops_flow_id.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=209 dst=r0 src=r0 offset=0 imm=11
#line 89 "sample/sockops_flow_id.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
label_11:
    // EBPF_OP_EXIT pc=210 dst=r0 src=r0 offset=0 imm=0
#line 136 "sample/sockops_flow_id.c"
    return r0;
#line 109 "sample/sockops_flow_id.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        flow_id_monitor,
        "sockops",
        "sockops",
        "flow_id_monitor",
        flow_id_monitor_maps,
        2,
        flow_id_monitor_helpers,
        4,
        211,
        &flow_id_monitor_program_type_guid,
        &flow_id_monitor_attach_type_guid,
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
    version->major = 1;
    version->minor = 1;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t sockops_flow_id_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
