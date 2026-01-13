// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from bind_policy.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table bind_policy##_metadata_table
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

__declspec(dllexport) metadata_table_t*
get_metadata_table()
{
    return &metadata_table;
}

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
         16,                // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         100,               // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         21,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "bind_policy_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 1;
}

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static helper_function_entry_t authorize_bind_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     15,
     "helper_id_15",
    },
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID authorize_bind_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID authorize_bind_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t authorize_bind_maps[] = {
    0,
};

#pragma code_seg(push, "bind")
static uint64_t
authorize_bind(void* context, const program_runtime_context_t* runtime_context)
#line 165 "sample/bind_policy.c"
{
#line 165 "sample/bind_policy.c"
    // Prologue.
#line 165 "sample/bind_policy.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 165 "sample/bind_policy.c"
    register uint64_t r0 = 0;
#line 165 "sample/bind_policy.c"
    register uint64_t r1 = 0;
#line 165 "sample/bind_policy.c"
    register uint64_t r2 = 0;
#line 165 "sample/bind_policy.c"
    register uint64_t r3 = 0;
#line 165 "sample/bind_policy.c"
    register uint64_t r4 = 0;
#line 165 "sample/bind_policy.c"
    register uint64_t r5 = 0;
#line 165 "sample/bind_policy.c"
    register uint64_t r6 = 0;
#line 165 "sample/bind_policy.c"
    register uint64_t r7 = 0;
#line 165 "sample/bind_policy.c"
    register uint64_t r8 = 0;
#line 165 "sample/bind_policy.c"
    register uint64_t r10 = 0;

#line 165 "sample/bind_policy.c"
    r1 = (uintptr_t)context;
#line 165 "sample/bind_policy.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r0 src=r0 offset=0 imm=0
#line 165 "sample/bind_policy.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_LDXW pc=1 dst=r2 src=r1 offset=44 imm=0
#line 168 "sample/bind_policy.c"
    READ_ONCE_32(r2, r1, OFFSET(44));
    // EBPF_OP_JNE_IMM pc=2 dst=r2 src=r0 offset=145 imm=0
#line 168 "sample/bind_policy.c"
    if (r2 != IMMEDIATE(0)) {
#line 168 "sample/bind_policy.c"
        goto label_5;
#line 168 "sample/bind_policy.c"
    }
    // EBPF_OP_MOV64_IMM pc=3 dst=r8 src=r0 offset=0 imm=0
#line 168 "sample/bind_policy.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=4 dst=r10 src=r8 offset=-8 imm=0
#line 90 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-8));
    // EBPF_OP_LDXDW pc=5 dst=r3 src=r1 offset=16 imm=0
#line 102 "sample/bind_policy.c"
    READ_ONCE_64(r3, r1, OFFSET(16));
    // EBPF_OP_LDXH pc=6 dst=r4 src=r1 offset=26 imm=0
#line 95 "sample/bind_policy.c"
    READ_ONCE_16(r4, r1, OFFSET(26));
    // EBPF_OP_STXH pc=7 dst=r10 src=r4 offset=-8 imm=0
#line 103 "sample/bind_policy.c"
    WRITE_ONCE_16(r10, (uint16_t)r4, OFFSET(-8));
    // EBPF_OP_STXDW pc=8 dst=r10 src=r3 offset=-16 imm=0
#line 102 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r3, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=9 dst=r7 src=r1 offset=0 imm=0
#line 102 "sample/bind_policy.c"
    r7 = r1;
    // EBPF_OP_LDXB pc=10 dst=r5 src=r1 offset=48 imm=0
#line 104 "sample/bind_policy.c"
    READ_ONCE_8(r5, r1, OFFSET(48));
    // EBPF_OP_STXB pc=11 dst=r10 src=r5 offset=-6 imm=0
#line 104 "sample/bind_policy.c"
    WRITE_ONCE_8(r10, (uint8_t)r5, OFFSET(-6));
    // EBPF_OP_STXB pc=12 dst=r10 src=r8 offset=-24 imm=0
#line 105 "sample/bind_policy.c"
    WRITE_ONCE_8(r10, (uint8_t)r8, OFFSET(-24));
    // EBPF_OP_LDDW pc=13 dst=r1 src=r0 offset=0 imm=1819239279
#line 105 "sample/bind_policy.c"
    r1 = (uint64_t)753549458396898159;
    // EBPF_OP_STXDW pc=15 dst=r10 src=r1 offset=-32 imm=0
#line 105 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDDW pc=16 dst=r1 src=r0 offset=0 imm=539765108
#line 105 "sample/bind_policy.c"
    r1 = (uint64_t)8390050319277238644;
    // EBPF_OP_STXDW pc=18 dst=r10 src=r1 offset=-40 imm=0
#line 105 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
    // EBPF_OP_LDDW pc=19 dst=r1 src=r0 offset=0 imm=1965374836
#line 105 "sample/bind_policy.c"
    r1 = (uint64_t)7308823365138333044;
    // EBPF_OP_STXDW pc=21 dst=r10 src=r1 offset=-48 imm=0
#line 105 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
    // EBPF_OP_LDDW pc=22 dst=r1 src=r0 offset=0 imm=745892972
#line 105 "sample/bind_policy.c"
    r1 = (uint64_t)8245897541853736044;
    // EBPF_OP_STXDW pc=24 dst=r10 src=r1 offset=-56 imm=0
#line 105 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-56));
    // EBPF_OP_LDDW pc=25 dst=r1 src=r0 offset=0 imm=1344303727
#line 105 "sample/bind_policy.c"
    r1 = (uint64_t)2683376034650288751;
    // EBPF_OP_STXDW pc=27 dst=r10 src=r1 offset=-64 imm=0
#line 105 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-64));
    // EBPF_OP_LDDW pc=28 dst=r1 src=r0 offset=0 imm=1768714096
#line 105 "sample/bind_policy.c"
    r1 = (uint64_t)7359015259000827760;
    // EBPF_OP_STXDW pc=30 dst=r10 src=r1 offset=-72 imm=0
#line 105 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-72));
    // EBPF_OP_LDDW pc=31 dst=r1 src=r0 offset=0 imm=1646293109
#line 105 "sample/bind_policy.c"
    r1 = (uint64_t)2334111905781674101;
    // EBPF_OP_STXDW pc=33 dst=r10 src=r1 offset=-80 imm=0
#line 105 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
    // EBPF_OP_LDDW pc=34 dst=r1 src=r0 offset=0 imm=1802465100
#line 105 "sample/bind_policy.c"
    r1 = (uint64_t)2334956330867978060;
    // EBPF_OP_STXDW pc=36 dst=r10 src=r1 offset=-88 imm=0
#line 105 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
    // EBPF_OP_MOV64_REG pc=37 dst=r1 src=r10 offset=0 imm=0
#line 105 "sample/bind_policy.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=38 dst=r1 src=r0 offset=0 imm=-88
#line 105 "sample/bind_policy.c"
    r1 += IMMEDIATE(-88);
    // EBPF_OP_MOV64_IMM pc=39 dst=r2 src=r0 offset=0 imm=65
#line 105 "sample/bind_policy.c"
    r2 = IMMEDIATE(65);
    // EBPF_OP_CALL pc=40 dst=r0 src=r0 offset=0 imm=15
#line 105 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 105 "sample/bind_policy.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 105 "sample/bind_policy.c"
        return 0;
#line 105 "sample/bind_policy.c"
    }
    // EBPF_OP_MOV64_REG pc=41 dst=r2 src=r10 offset=0 imm=0
#line 105 "sample/bind_policy.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=42 dst=r2 src=r0 offset=0 imm=-16
#line 105 "sample/bind_policy.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=43 dst=r1 src=r1 offset=0 imm=1
#line 108 "sample/bind_policy.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=45 dst=r0 src=r0 offset=0 imm=1
#line 108 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 108 "sample/bind_policy.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 108 "sample/bind_policy.c"
        return 0;
#line 108 "sample/bind_policy.c"
    }
    // EBPF_OP_MOV64_REG pc=46 dst=r6 src=r0 offset=0 imm=0
#line 108 "sample/bind_policy.c"
    r6 = r0;
    // EBPF_OP_JEQ_IMM pc=47 dst=r6 src=r0 offset=23 imm=0
#line 109 "sample/bind_policy.c"
    if (r6 == IMMEDIATE(0)) {
#line 109 "sample/bind_policy.c"
        goto label_1;
#line 109 "sample/bind_policy.c"
    }
    // EBPF_OP_MOV64_IMM pc=48 dst=r1 src=r0 offset=0 imm=10
#line 109 "sample/bind_policy.c"
    r1 = IMMEDIATE(10);
    // EBPF_OP_STXH pc=49 dst=r10 src=r1 offset=-48 imm=0
#line 110 "sample/bind_policy.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-48));
    // EBPF_OP_LDDW pc=50 dst=r1 src=r0 offset=0 imm=1869182051
#line 110 "sample/bind_policy.c"
    r1 = (uint64_t)8441220621100741731;
    // EBPF_OP_STXDW pc=52 dst=r10 src=r1 offset=-56 imm=0
#line 110 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-56));
    // EBPF_OP_LDDW pc=53 dst=r1 src=r0 offset=0 imm=1667853423
#line 110 "sample/bind_policy.c"
    r1 = (uint64_t)4692815104753364079;
    // EBPF_OP_STXDW pc=55 dst=r10 src=r1 offset=-64 imm=0
#line 110 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-64));
    // EBPF_OP_LDDW pc=56 dst=r1 src=r0 offset=0 imm=1768038504
#line 110 "sample/bind_policy.c"
    r1 = (uint64_t)8079568156879888488;
    // EBPF_OP_STXDW pc=58 dst=r10 src=r1 offset=-72 imm=0
#line 110 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-72));
    // EBPF_OP_LDDW pc=59 dst=r1 src=r0 offset=0 imm=544498529
#line 110 "sample/bind_policy.c"
    r1 = (uint64_t)7166460028377129825;
    // EBPF_OP_STXDW pc=61 dst=r10 src=r1 offset=-80 imm=0
#line 110 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
    // EBPF_OP_LDDW pc=62 dst=r1 src=r0 offset=0 imm=1853189958
#line 110 "sample/bind_policy.c"
    r1 = (uint64_t)8675375872921136966;
    // EBPF_OP_STXDW pc=64 dst=r10 src=r1 offset=-88 imm=0
#line 110 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
    // EBPF_OP_LDXW pc=65 dst=r3 src=r6 offset=0 imm=0
#line 110 "sample/bind_policy.c"
    READ_ONCE_32(r3, r6, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=66 dst=r1 src=r10 offset=0 imm=0
#line 110 "sample/bind_policy.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=67 dst=r1 src=r0 offset=0 imm=-88
#line 110 "sample/bind_policy.c"
    r1 += IMMEDIATE(-88);
    // EBPF_OP_MOV64_IMM pc=68 dst=r2 src=r0 offset=0 imm=42
#line 110 "sample/bind_policy.c"
    r2 = IMMEDIATE(42);
    // EBPF_OP_CALL pc=69 dst=r0 src=r0 offset=0 imm=13
#line 110 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 110 "sample/bind_policy.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 110 "sample/bind_policy.c"
        return 0;
#line 110 "sample/bind_policy.c"
    }
    // EBPF_OP_JA pc=70 dst=r0 src=r0 offset=76 imm=0
#line 110 "sample/bind_policy.c"
    goto label_4;
label_1:
    // EBPF_OP_STXDW pc=71 dst=r10 src=r8 offset=-16 imm=0
#line 117 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=72 dst=r2 src=r10 offset=0 imm=0
#line 117 "sample/bind_policy.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=73 dst=r2 src=r0 offset=0 imm=-16
#line 117 "sample/bind_policy.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=74 dst=r1 src=r1 offset=0 imm=1
#line 118 "sample/bind_policy.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=76 dst=r0 src=r0 offset=0 imm=1
#line 118 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 118 "sample/bind_policy.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 118 "sample/bind_policy.c"
        return 0;
#line 118 "sample/bind_policy.c"
    }
    // EBPF_OP_MOV64_REG pc=77 dst=r6 src=r0 offset=0 imm=0
#line 118 "sample/bind_policy.c"
    r6 = r0;
    // EBPF_OP_JEQ_IMM pc=78 dst=r6 src=r0 offset=23 imm=0
#line 119 "sample/bind_policy.c"
    if (r6 == IMMEDIATE(0)) {
#line 119 "sample/bind_policy.c"
        goto label_2;
#line 119 "sample/bind_policy.c"
    }
    // EBPF_OP_MOV64_IMM pc=79 dst=r1 src=r0 offset=0 imm=0
#line 119 "sample/bind_policy.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=80 dst=r10 src=r1 offset=-48 imm=0
#line 120 "sample/bind_policy.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-48));
    // EBPF_OP_LDDW pc=81 dst=r1 src=r0 offset=0 imm=1852795252
#line 120 "sample/bind_policy.c"
    r1 = (uint64_t)753549458430454132;
    // EBPF_OP_STXDW pc=83 dst=r10 src=r1 offset=-56 imm=0
#line 120 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-56));
    // EBPF_OP_LDDW pc=84 dst=r1 src=r0 offset=0 imm=2036558188
#line 120 "sample/bind_policy.c"
    r1 = (uint64_t)7152033118757808492;
    // EBPF_OP_STXDW pc=86 dst=r10 src=r1 offset=-64 imm=0
#line 120 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-64));
    // EBPF_OP_LDDW pc=87 dst=r1 src=r0 offset=0 imm=1852400160
#line 120 "sample/bind_policy.c"
    r1 = (uint64_t)8029953751322812960;
    // EBPF_OP_STXDW pc=89 dst=r10 src=r1 offset=-72 imm=0
#line 120 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-72));
    // EBPF_OP_LDDW pc=90 dst=r1 src=r0 offset=0 imm=1647146098
#line 120 "sample/bind_policy.c"
    r1 = (uint64_t)7234315238536737906;
    // EBPF_OP_STXDW pc=92 dst=r10 src=r1 offset=-80 imm=0
#line 120 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
    // EBPF_OP_LDDW pc=93 dst=r1 src=r0 offset=0 imm=1853189958
#line 120 "sample/bind_policy.c"
    r1 = (uint64_t)8029953751323602758;
    // EBPF_OP_STXDW pc=95 dst=r10 src=r1 offset=-88 imm=0
#line 120 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
    // EBPF_OP_LDXW pc=96 dst=r3 src=r6 offset=0 imm=0
#line 120 "sample/bind_policy.c"
    READ_ONCE_32(r3, r6, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=97 dst=r1 src=r10 offset=0 imm=0
#line 120 "sample/bind_policy.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=98 dst=r1 src=r0 offset=0 imm=-88
#line 120 "sample/bind_policy.c"
    r1 += IMMEDIATE(-88);
    // EBPF_OP_MOV64_IMM pc=99 dst=r2 src=r0 offset=0 imm=41
#line 120 "sample/bind_policy.c"
    r2 = IMMEDIATE(41);
    // EBPF_OP_CALL pc=100 dst=r0 src=r0 offset=0 imm=13
#line 120 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 120 "sample/bind_policy.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 120 "sample/bind_policy.c"
        return 0;
#line 120 "sample/bind_policy.c"
    }
    // EBPF_OP_JA pc=101 dst=r0 src=r0 offset=45 imm=0
#line 120 "sample/bind_policy.c"
    goto label_4;
label_2:
    // EBPF_OP_LDXDW pc=102 dst=r1 src=r7 offset=16 imm=0
#line 127 "sample/bind_policy.c"
    READ_ONCE_64(r1, r7, OFFSET(16));
    // EBPF_OP_MOV64_IMM pc=103 dst=r2 src=r0 offset=0 imm=0
#line 127 "sample/bind_policy.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=104 dst=r10 src=r2 offset=-6 imm=0
#line 129 "sample/bind_policy.c"
    WRITE_ONCE_8(r10, (uint8_t)r2, OFFSET(-6));
    // EBPF_OP_STXH pc=105 dst=r10 src=r2 offset=-8 imm=0
#line 128 "sample/bind_policy.c"
    WRITE_ONCE_16(r10, (uint16_t)r2, OFFSET(-8));
    // EBPF_OP_STXDW pc=106 dst=r10 src=r1 offset=-16 imm=0
#line 127 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=107 dst=r2 src=r10 offset=0 imm=0
#line 127 "sample/bind_policy.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=108 dst=r2 src=r0 offset=0 imm=-16
#line 127 "sample/bind_policy.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=109 dst=r1 src=r1 offset=0 imm=1
#line 130 "sample/bind_policy.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=111 dst=r0 src=r0 offset=0 imm=1
#line 130 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 130 "sample/bind_policy.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 130 "sample/bind_policy.c"
        return 0;
#line 130 "sample/bind_policy.c"
    }
    // EBPF_OP_MOV64_REG pc=112 dst=r6 src=r0 offset=0 imm=0
#line 130 "sample/bind_policy.c"
    r6 = r0;
    // EBPF_OP_JEQ_IMM pc=113 dst=r6 src=r0 offset=23 imm=0
#line 131 "sample/bind_policy.c"
    if (r6 == IMMEDIATE(0)) {
#line 131 "sample/bind_policy.c"
        goto label_3;
#line 131 "sample/bind_policy.c"
    }
    // EBPF_OP_MOV64_IMM pc=114 dst=r1 src=r0 offset=0 imm=685349
#line 131 "sample/bind_policy.c"
    r1 = IMMEDIATE(685349);
    // EBPF_OP_STXW pc=115 dst=r10 src=r1 offset=-48 imm=0
#line 132 "sample/bind_policy.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-48));
    // EBPF_OP_LDDW pc=116 dst=r1 src=r0 offset=0 imm=1952661792
#line 132 "sample/bind_policy.c"
    r1 = (uint64_t)4426597982466687264;
    // EBPF_OP_STXDW pc=118 dst=r10 src=r1 offset=-56 imm=0
#line 132 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-56));
    // EBPF_OP_LDDW pc=119 dst=r1 src=r0 offset=0 imm=1819242528
#line 132 "sample/bind_policy.c"
    r1 = (uint64_t)4213508230823768096;
    // EBPF_OP_STXDW pc=121 dst=r10 src=r1 offset=-64 imm=0
#line 132 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-64));
    // EBPF_OP_LDDW pc=122 dst=r1 src=r0 offset=0 imm=543450483
#line 132 "sample/bind_policy.c"
    r1 = (uint64_t)7236837521402127731;
    // EBPF_OP_STXDW pc=124 dst=r10 src=r1 offset=-72 imm=0
#line 132 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-72));
    // EBPF_OP_LDDW pc=125 dst=r1 src=r0 offset=0 imm=1936024431
#line 132 "sample/bind_policy.c"
    r1 = (uint64_t)7017221143277167471;
    // EBPF_OP_STXDW pc=127 dst=r10 src=r1 offset=-80 imm=0
#line 132 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
    // EBPF_OP_LDDW pc=128 dst=r1 src=r0 offset=0 imm=1853189958
#line 132 "sample/bind_policy.c"
    r1 = (uint64_t)8246126533437386566;
    // EBPF_OP_STXDW pc=130 dst=r10 src=r1 offset=-88 imm=0
#line 132 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
    // EBPF_OP_LDXW pc=131 dst=r3 src=r6 offset=0 imm=0
#line 132 "sample/bind_policy.c"
    READ_ONCE_32(r3, r6, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=132 dst=r1 src=r10 offset=0 imm=0
#line 132 "sample/bind_policy.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=133 dst=r1 src=r0 offset=0 imm=-88
#line 132 "sample/bind_policy.c"
    r1 += IMMEDIATE(-88);
    // EBPF_OP_MOV64_IMM pc=134 dst=r2 src=r0 offset=0 imm=44
#line 132 "sample/bind_policy.c"
    r2 = IMMEDIATE(44);
    // EBPF_OP_CALL pc=135 dst=r0 src=r0 offset=0 imm=13
#line 132 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 132 "sample/bind_policy.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 132 "sample/bind_policy.c"
        return 0;
#line 132 "sample/bind_policy.c"
    }
    // EBPF_OP_JA pc=136 dst=r0 src=r0 offset=10 imm=0
#line 132 "sample/bind_policy.c"
    goto label_4;
label_3:
    // EBPF_OP_MOV64_IMM pc=137 dst=r1 src=r0 offset=0 imm=0
#line 132 "sample/bind_policy.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=138 dst=r10 src=r1 offset=-16 imm=0
#line 139 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=139 dst=r2 src=r10 offset=0 imm=0
#line 139 "sample/bind_policy.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=140 dst=r2 src=r0 offset=0 imm=-16
#line 139 "sample/bind_policy.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=141 dst=r1 src=r1 offset=0 imm=1
#line 140 "sample/bind_policy.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=143 dst=r0 src=r0 offset=0 imm=1
#line 140 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 140 "sample/bind_policy.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 140 "sample/bind_policy.c"
        return 0;
#line 140 "sample/bind_policy.c"
    }
    // EBPF_OP_MOV64_REG pc=144 dst=r6 src=r0 offset=0 imm=0
#line 140 "sample/bind_policy.c"
    r6 = r0;
    // EBPF_OP_MOV64_IMM pc=145 dst=r0 src=r0 offset=0 imm=0
#line 140 "sample/bind_policy.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_JEQ_IMM pc=146 dst=r6 src=r0 offset=1 imm=0
#line 141 "sample/bind_policy.c"
    if (r6 == IMMEDIATE(0)) {
#line 141 "sample/bind_policy.c"
        goto label_5;
#line 141 "sample/bind_policy.c"
    }
label_4:
    // EBPF_OP_LDXW pc=147 dst=r0 src=r6 offset=0 imm=0
#line 141 "sample/bind_policy.c"
    READ_ONCE_32(r0, r6, OFFSET(0));
label_5:
    // EBPF_OP_EXIT pc=148 dst=r0 src=r0 offset=0 imm=0
#line 174 "sample/bind_policy.c"
    return r0;
#line 165 "sample/bind_policy.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        authorize_bind,
        "bind",
        "bind",
        "authorize_bind",
        authorize_bind_maps,
        1,
        authorize_bind_helpers,
        3,
        149,
        &authorize_bind_program_type_guid,
        &authorize_bind_attach_type_guid,
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

metadata_table_t bind_policy_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
