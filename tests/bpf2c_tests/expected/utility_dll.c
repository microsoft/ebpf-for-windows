// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from utility.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table utility##_metadata_table
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

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = NULL;
    *count = 0;
}

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static helper_function_entry_t UtilityTest_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     23,
     "helper_id_23",
    },
    {
     {1, 40, 40}, // Version header.
     22,
     "helper_id_22",
    },
    {
     {1, 40, 40}, // Version header.
     24,
     "helper_id_24",
    },
    {
     {1, 40, 40}, // Version header.
     25,
     "helper_id_25",
    },
};

static GUID UtilityTest_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID UtilityTest_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
#pragma code_seg(push, "bind")
static uint64_t
UtilityTest(void* context, const program_runtime_context_t* runtime_context)
#line 24 "sample/utility.c"
{
#line 24 "sample/utility.c"
    // Prologue.
#line 24 "sample/utility.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 24 "sample/utility.c"
    register uint64_t r0 = 0;
#line 24 "sample/utility.c"
    register uint64_t r1 = 0;
#line 24 "sample/utility.c"
    register uint64_t r2 = 0;
#line 24 "sample/utility.c"
    register uint64_t r3 = 0;
#line 24 "sample/utility.c"
    register uint64_t r4 = 0;
#line 24 "sample/utility.c"
    register uint64_t r5 = 0;
#line 24 "sample/utility.c"
    register uint64_t r10 = 0;

#line 24 "sample/utility.c"
    r1 = (uintptr_t)context;
#line 24 "sample/utility.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV_IMM pc=0 dst=r1 src=r0 offset=0 imm=0
#line 24 "sample/utility.c"
    r1 = IMMEDIATE(0);
#line 24 "sample/utility.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=1 dst=r10 src=r1 offset=-4 imm=0
#line 26 "sample/utility.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint8_t)r1;
    // EBPF_OP_MOV_IMM pc=2 dst=r2 src=r0 offset=0 imm=1953719668
#line 26 "sample/utility.c"
    r2 = IMMEDIATE(1953719668);
#line 26 "sample/utility.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_STXW pc=3 dst=r10 src=r2 offset=-8 imm=0
#line 26 "sample/utility.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=4 dst=r10 src=r2 offset=-16 imm=0
#line 27 "sample/utility.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r2;
    // EBPF_OP_STXB pc=5 dst=r10 src=r1 offset=-12 imm=0
#line 27 "sample/utility.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint8_t)r1;
    // EBPF_OP_STXB pc=6 dst=r10 src=r1 offset=-22 imm=0
#line 28 "sample/utility.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-22)) = (uint8_t)r1;
    // EBPF_OP_MOV_IMM pc=7 dst=r1 src=r0 offset=0 imm=12345
#line 28 "sample/utility.c"
    r1 = IMMEDIATE(12345);
#line 28 "sample/utility.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 28 "sample/utility.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=9 dst=r1 src=r0 offset=0 imm=875770417
#line 28 "sample/utility.c"
    r1 = (uint64_t)4050765991979987505;
    // EBPF_OP_STXDW pc=11 dst=r10 src=r1 offset=-32 imm=0
#line 28 "sample/utility.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=12 dst=r1 src=r10 offset=0 imm=0
#line 28 "sample/utility.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=13 dst=r1 src=r0 offset=0 imm=-8
#line 28 "sample/utility.c"
    r1 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=14 dst=r3 src=r10 offset=0 imm=0
#line 28 "sample/utility.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=15 dst=r3 src=r0 offset=0 imm=-16
#line 28 "sample/utility.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_IMM pc=16 dst=r2 src=r0 offset=0 imm=4
#line 31 "sample/utility.c"
    r2 = IMMEDIATE(4);
    // EBPF_OP_MOV64_IMM pc=17 dst=r4 src=r0 offset=0 imm=4
#line 31 "sample/utility.c"
    r4 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=23
#line 31 "sample/utility.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 31 "sample/utility.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 31 "sample/utility.c"
        return 0;
#line 31 "sample/utility.c"
    }
    // EBPF_OP_MOV_REG pc=19 dst=r1 src=r0 offset=0 imm=0
#line 31 "sample/utility.c"
    r1 = r0;
#line 31 "sample/utility.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_MOV_IMM pc=20 dst=r0 src=r0 offset=0 imm=1
#line 31 "sample/utility.c"
    r0 = IMMEDIATE(1);
#line 31 "sample/utility.c"
    r0 &= UINT32_MAX;
    //  pc=21 dst=r1 src=r0 offset=80 imm=0
#line 31 "sample/utility.c"
    if ((uint32_t)r1 != IMMEDIATE(0)) {
#line 31 "sample/utility.c"
        goto label_1;
#line 31 "sample/utility.c"
    }
    // EBPF_OP_MOV_IMM pc=22 dst=r1 src=r0 offset=0 imm=84
#line 31 "sample/utility.c"
    r1 = IMMEDIATE(84);
#line 31 "sample/utility.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=23 dst=r10 src=r1 offset=-8 imm=0
#line 35 "sample/utility.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r1;
    // EBPF_OP_MOV64_REG pc=24 dst=r1 src=r10 offset=0 imm=0
#line 35 "sample/utility.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=25 dst=r1 src=r0 offset=0 imm=-8
#line 35 "sample/utility.c"
    r1 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=26 dst=r3 src=r10 offset=0 imm=0
#line 35 "sample/utility.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=27 dst=r3 src=r0 offset=0 imm=-16
#line 35 "sample/utility.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_IMM pc=28 dst=r2 src=r0 offset=0 imm=4
#line 37 "sample/utility.c"
    r2 = IMMEDIATE(4);
    // EBPF_OP_MOV64_IMM pc=29 dst=r4 src=r0 offset=0 imm=4
#line 37 "sample/utility.c"
    r4 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=30 dst=r0 src=r0 offset=0 imm=23
#line 37 "sample/utility.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 37 "sample/utility.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 37 "sample/utility.c"
        return 0;
#line 37 "sample/utility.c"
    }
    // EBPF_OP_MOV_REG pc=31 dst=r1 src=r0 offset=0 imm=0
#line 37 "sample/utility.c"
    r1 = r0;
#line 37 "sample/utility.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_MOV_IMM pc=32 dst=r0 src=r0 offset=0 imm=2
#line 37 "sample/utility.c"
    r0 = IMMEDIATE(2);
#line 37 "sample/utility.c"
    r0 &= UINT32_MAX;
    //  pc=33 dst=r1 src=r0 offset=68 imm=-1
#line 37 "sample/utility.c"
    if ((int32_t)r1 > IMMEDIATE(-1)) {
#line 37 "sample/utility.c"
        goto label_1;
#line 37 "sample/utility.c"
    }
    // EBPF_OP_MOV64_REG pc=34 dst=r1 src=r10 offset=0 imm=0
#line 37 "sample/utility.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=35 dst=r1 src=r0 offset=0 imm=-8
#line 37 "sample/utility.c"
    r1 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=36 dst=r3 src=r10 offset=0 imm=0
#line 37 "sample/utility.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=37 dst=r3 src=r0 offset=0 imm=-16
#line 37 "sample/utility.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_IMM pc=38 dst=r2 src=r0 offset=0 imm=3
#line 43 "sample/utility.c"
    r2 = IMMEDIATE(3);
    // EBPF_OP_MOV64_IMM pc=39 dst=r4 src=r0 offset=0 imm=4
#line 43 "sample/utility.c"
    r4 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=40 dst=r0 src=r0 offset=0 imm=23
#line 43 "sample/utility.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 43 "sample/utility.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 43 "sample/utility.c"
        return 0;
#line 43 "sample/utility.c"
    }
    // EBPF_OP_MOV_REG pc=41 dst=r1 src=r0 offset=0 imm=0
#line 43 "sample/utility.c"
    r1 = r0;
#line 43 "sample/utility.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_MOV_IMM pc=42 dst=r0 src=r0 offset=0 imm=3
#line 43 "sample/utility.c"
    r0 = IMMEDIATE(3);
#line 43 "sample/utility.c"
    r0 &= UINT32_MAX;
    //  pc=43 dst=r1 src=r0 offset=58 imm=-1
#line 43 "sample/utility.c"
    if ((int32_t)r1 > IMMEDIATE(-1)) {
#line 43 "sample/utility.c"
        goto label_1;
#line 43 "sample/utility.c"
    }
    // EBPF_OP_MOV_IMM pc=44 dst=r1 src=r0 offset=0 imm=1414743380
#line 43 "sample/utility.c"
    r1 = IMMEDIATE(1414743380);
#line 43 "sample/utility.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=45 dst=r10 src=r1 offset=-8 imm=0
#line 48 "sample/utility.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=46 dst=r1 src=r10 offset=0 imm=0
#line 48 "sample/utility.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=47 dst=r1 src=r0 offset=0 imm=-8
#line 48 "sample/utility.c"
    r1 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=48 dst=r3 src=r10 offset=0 imm=0
#line 48 "sample/utility.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=49 dst=r3 src=r0 offset=0 imm=-16
#line 48 "sample/utility.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_IMM pc=50 dst=r2 src=r0 offset=0 imm=4
#line 54 "sample/utility.c"
    r2 = IMMEDIATE(4);
    // EBPF_OP_MOV64_IMM pc=51 dst=r4 src=r0 offset=0 imm=4
#line 54 "sample/utility.c"
    r4 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=52 dst=r0 src=r0 offset=0 imm=22
#line 54 "sample/utility.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 54 "sample/utility.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 54 "sample/utility.c"
        return 0;
#line 54 "sample/utility.c"
    }
    // EBPF_OP_MOV64_REG pc=53 dst=r1 src=r0 offset=0 imm=0
#line 54 "sample/utility.c"
    r1 = r0;
    // EBPF_OP_MOV_IMM pc=54 dst=r0 src=r0 offset=0 imm=4
#line 54 "sample/utility.c"
    r0 = IMMEDIATE(4);
#line 54 "sample/utility.c"
    r0 &= UINT32_MAX;
    // EBPF_OP_JSLT_IMM pc=55 dst=r1 src=r0 offset=46 imm=0
#line 54 "sample/utility.c"
    if ((int64_t)r1 < IMMEDIATE(0)) {
#line 54 "sample/utility.c"
        goto label_1;
#line 54 "sample/utility.c"
    }
    // EBPF_OP_MOV_IMM pc=56 dst=r0 src=r0 offset=0 imm=5
#line 54 "sample/utility.c"
    r0 = IMMEDIATE(5);
#line 54 "sample/utility.c"
    r0 &= UINT32_MAX;
    // EBPF_OP_LDXB pc=57 dst=r1 src=r10 offset=-8 imm=0
#line 59 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8));
    //  pc=58 dst=r1 src=r0 offset=43 imm=116
#line 59 "sample/utility.c"
    if ((uint32_t)r1 != IMMEDIATE(116)) {
#line 59 "sample/utility.c"
        goto label_1;
#line 59 "sample/utility.c"
    }
    // EBPF_OP_LDXB pc=59 dst=r1 src=r10 offset=-7 imm=0
#line 59 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-7));
    //  pc=60 dst=r1 src=r0 offset=41 imm=101
#line 59 "sample/utility.c"
    if ((uint32_t)r1 != IMMEDIATE(101)) {
#line 59 "sample/utility.c"
        goto label_1;
#line 59 "sample/utility.c"
    }
    // EBPF_OP_LDXB pc=61 dst=r1 src=r10 offset=-6 imm=0
#line 59 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-6));
    //  pc=62 dst=r1 src=r0 offset=39 imm=115
#line 59 "sample/utility.c"
    if ((uint32_t)r1 != IMMEDIATE(115)) {
#line 59 "sample/utility.c"
        goto label_1;
#line 59 "sample/utility.c"
    }
    // EBPF_OP_LDXB pc=63 dst=r1 src=r10 offset=-5 imm=0
#line 59 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-5));
    //  pc=64 dst=r1 src=r0 offset=37 imm=116
#line 59 "sample/utility.c"
    if ((uint32_t)r1 != IMMEDIATE(116)) {
#line 59 "sample/utility.c"
        goto label_1;
#line 59 "sample/utility.c"
    }
    // EBPF_OP_MOV64_REG pc=65 dst=r1 src=r10 offset=0 imm=0
#line 59 "sample/utility.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=66 dst=r1 src=r0 offset=0 imm=-8
#line 59 "sample/utility.c"
    r1 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=67 dst=r2 src=r0 offset=0 imm=4
#line 64 "sample/utility.c"
    r2 = IMMEDIATE(4);
    // EBPF_OP_MOV_IMM pc=68 dst=r3 src=r0 offset=0 imm=0
#line 64 "sample/utility.c"
    r3 = IMMEDIATE(0);
#line 64 "sample/utility.c"
    r3 &= UINT32_MAX;
    // EBPF_OP_CALL pc=69 dst=r0 src=r0 offset=0 imm=24
#line 64 "sample/utility.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 64 "sample/utility.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 64 "sample/utility.c"
        return 0;
#line 64 "sample/utility.c"
    }
    // EBPF_OP_MOV64_REG pc=70 dst=r1 src=r0 offset=0 imm=0
#line 64 "sample/utility.c"
    r1 = r0;
    // EBPF_OP_MOV_IMM pc=71 dst=r0 src=r0 offset=0 imm=6
#line 64 "sample/utility.c"
    r0 = IMMEDIATE(6);
#line 64 "sample/utility.c"
    r0 &= UINT32_MAX;
    // EBPF_OP_JEQ_IMM pc=72 dst=r1 src=r0 offset=29 imm=0
#line 64 "sample/utility.c"
    if (r1 == IMMEDIATE(0)) {
#line 64 "sample/utility.c"
        goto label_1;
#line 64 "sample/utility.c"
    }
    // EBPF_OP_MOV_IMM pc=73 dst=r0 src=r0 offset=0 imm=7
#line 64 "sample/utility.c"
    r0 = IMMEDIATE(7);
#line 64 "sample/utility.c"
    r0 &= UINT32_MAX;
    // EBPF_OP_LDXB pc=74 dst=r1 src=r10 offset=-8 imm=0
#line 69 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8));
    //  pc=75 dst=r1 src=r0 offset=26 imm=0
#line 69 "sample/utility.c"
    if ((uint32_t)r1 != IMMEDIATE(0)) {
#line 69 "sample/utility.c"
        goto label_1;
#line 69 "sample/utility.c"
    }
    // EBPF_OP_LDXB pc=76 dst=r1 src=r10 offset=-7 imm=0
#line 69 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-7));
    //  pc=77 dst=r1 src=r0 offset=24 imm=0
#line 69 "sample/utility.c"
    if ((uint32_t)r1 != IMMEDIATE(0)) {
#line 69 "sample/utility.c"
        goto label_1;
#line 69 "sample/utility.c"
    }
    // EBPF_OP_LDXB pc=78 dst=r1 src=r10 offset=-6 imm=0
#line 69 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-6));
    //  pc=79 dst=r1 src=r0 offset=22 imm=0
#line 69 "sample/utility.c"
    if ((uint32_t)r1 != IMMEDIATE(0)) {
#line 69 "sample/utility.c"
        goto label_1;
#line 69 "sample/utility.c"
    }
    // EBPF_OP_LDXB pc=80 dst=r1 src=r10 offset=-5 imm=0
#line 69 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-5));
    //  pc=81 dst=r1 src=r0 offset=20 imm=0
#line 69 "sample/utility.c"
    if ((uint32_t)r1 != IMMEDIATE(0)) {
#line 69 "sample/utility.c"
        goto label_1;
#line 69 "sample/utility.c"
    }
    // EBPF_OP_MOV64_REG pc=82 dst=r1 src=r10 offset=0 imm=0
#line 74 "sample/utility.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=83 dst=r1 src=r0 offset=0 imm=-30
#line 74 "sample/utility.c"
    r1 += IMMEDIATE(-30);
    // EBPF_OP_MOV64_REG pc=84 dst=r3 src=r10 offset=0 imm=0
#line 74 "sample/utility.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=85 dst=r3 src=r0 offset=0 imm=-32
#line 74 "sample/utility.c"
    r3 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=86 dst=r2 src=r0 offset=0 imm=4
#line 74 "sample/utility.c"
    r2 = IMMEDIATE(4);
    // EBPF_OP_MOV64_IMM pc=87 dst=r4 src=r0 offset=0 imm=4
#line 74 "sample/utility.c"
    r4 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=88 dst=r0 src=r0 offset=0 imm=25
#line 74 "sample/utility.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/utility.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 74 "sample/utility.c"
        return 0;
#line 74 "sample/utility.c"
    }
    // EBPF_OP_MOV64_REG pc=89 dst=r1 src=r0 offset=0 imm=0
#line 74 "sample/utility.c"
    r1 = r0;
    // EBPF_OP_MOV_IMM pc=90 dst=r0 src=r0 offset=0 imm=8
#line 74 "sample/utility.c"
    r0 = IMMEDIATE(8);
#line 74 "sample/utility.c"
    r0 &= UINT32_MAX;
    // EBPF_OP_JSLT_IMM pc=91 dst=r1 src=r0 offset=10 imm=0
#line 74 "sample/utility.c"
    if ((int64_t)r1 < IMMEDIATE(0)) {
#line 74 "sample/utility.c"
        goto label_1;
#line 74 "sample/utility.c"
    }
    // EBPF_OP_MOV_IMM pc=92 dst=r0 src=r0 offset=0 imm=9
#line 74 "sample/utility.c"
    r0 = IMMEDIATE(9);
#line 74 "sample/utility.c"
    r0 &= UINT32_MAX;
    // EBPF_OP_LDXB pc=93 dst=r1 src=r10 offset=-30 imm=0
#line 79 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-30));
    //  pc=94 dst=r1 src=r0 offset=7 imm=49
#line 79 "sample/utility.c"
    if ((uint32_t)r1 != IMMEDIATE(49)) {
#line 79 "sample/utility.c"
        goto label_1;
#line 79 "sample/utility.c"
    }
    // EBPF_OP_LDXB pc=95 dst=r1 src=r10 offset=-29 imm=0
#line 79 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-29));
    //  pc=96 dst=r1 src=r0 offset=5 imm=50
#line 79 "sample/utility.c"
    if ((uint32_t)r1 != IMMEDIATE(50)) {
#line 79 "sample/utility.c"
        goto label_1;
#line 79 "sample/utility.c"
    }
    // EBPF_OP_LDXB pc=97 dst=r1 src=r10 offset=-28 imm=0
#line 79 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-28));
    //  pc=98 dst=r1 src=r0 offset=3 imm=51
#line 79 "sample/utility.c"
    if ((uint32_t)r1 != IMMEDIATE(51)) {
#line 79 "sample/utility.c"
        goto label_1;
#line 79 "sample/utility.c"
    }
    // EBPF_OP_LDXB pc=99 dst=r1 src=r10 offset=-27 imm=0
#line 79 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-27));
    //  pc=100 dst=r1 src=r0 offset=1 imm=52
#line 79 "sample/utility.c"
    if ((uint32_t)r1 != IMMEDIATE(52)) {
#line 79 "sample/utility.c"
        goto label_1;
#line 79 "sample/utility.c"
    }
    // EBPF_OP_MOV_IMM pc=101 dst=r0 src=r0 offset=0 imm=0
#line 79 "sample/utility.c"
    r0 = IMMEDIATE(0);
#line 79 "sample/utility.c"
    r0 &= UINT32_MAX;
label_1:
    // EBPF_OP_EXIT pc=102 dst=r0 src=r0 offset=0 imm=0
#line 84 "sample/utility.c"
    return r0;
#line 24 "sample/utility.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        UtilityTest,
        "bind",
        "bind",
        "UtilityTest",
        NULL,
        0,
        UtilityTest_helpers,
        4,
        103,
        &UtilityTest_program_type_guid,
        &UtilityTest_attach_type_guid,
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
    version->minor = 22;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t utility_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
