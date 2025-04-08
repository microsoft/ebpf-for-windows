// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from strings.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table strings##_metadata_table
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

static helper_function_entry_t StringOpsTest_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     29,
     "helper_id_29",
    },
    {
     {1, 40, 40}, // Version header.
     27,
     "helper_id_27",
    },
    {
     {1, 40, 40}, // Version header.
     23,
     "helper_id_23",
    },
    {
     {1, 40, 40}, // Version header.
     28,
     "helper_id_28",
    },
};

static GUID StringOpsTest_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID StringOpsTest_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
#pragma code_seg(push, "bind")
static uint64_t
StringOpsTest(void* context, const program_runtime_context_t* runtime_context)
#line 25 "sample/strings.c"
{
#line 25 "sample/strings.c"
    // Prologue.
#line 25 "sample/strings.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 25 "sample/strings.c"
    register uint64_t r0 = 0;
#line 25 "sample/strings.c"
    register uint64_t r1 = 0;
#line 25 "sample/strings.c"
    register uint64_t r2 = 0;
#line 25 "sample/strings.c"
    register uint64_t r3 = 0;
#line 25 "sample/strings.c"
    register uint64_t r4 = 0;
#line 25 "sample/strings.c"
    register uint64_t r5 = 0;
#line 25 "sample/strings.c"
    register uint64_t r10 = 0;

#line 25 "sample/strings.c"
    r1 = (uintptr_t)context;
#line 25 "sample/strings.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r1 src=r0 offset=0 imm=0
#line 25 "sample/strings.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r1 offset=-8 imm=0
#line 27 "sample/strings.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_STXDW pc=2 dst=r10 src=r1 offset=-16 imm=0
#line 27 "sample/strings.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=3 dst=r10 src=r1 offset=-24 imm=0
#line 27 "sample/strings.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=4 dst=r2 src=r0 offset=0 imm=97
#line 27 "sample/strings.c"
    r2 = IMMEDIATE(97);
    // EBPF_OP_STXH pc=5 dst=r10 src=r2 offset=-28 imm=0
#line 28 "sample/strings.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint16_t)r2;
    // EBPF_OP_MOV64_IMM pc=6 dst=r2 src=r0 offset=0 imm=1752198241
#line 28 "sample/strings.c"
    r2 = IMMEDIATE(1752198241);
    // EBPF_OP_STXW pc=7 dst=r10 src=r2 offset=-32 imm=0
#line 28 "sample/strings.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r2;
    // EBPF_OP_MOV64_IMM pc=8 dst=r2 src=r0 offset=0 imm=1634102369
#line 28 "sample/strings.c"
    r2 = IMMEDIATE(1634102369);
    // EBPF_OP_STXW pc=9 dst=r10 src=r2 offset=-40 imm=0
#line 29 "sample/strings.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint32_t)r2;
    // EBPF_OP_STXB pc=10 dst=r10 src=r1 offset=-36 imm=0
#line 29 "sample/strings.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-36)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=7304801
#line 29 "sample/strings.c"
    r2 = IMMEDIATE(7304801);
    // EBPF_OP_STXW pc=12 dst=r10 src=r2 offset=-48 imm=0
#line 30 "sample/strings.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint32_t)r2;
    // EBPF_OP_LDDW pc=13 dst=r2 src=r0 offset=0 imm=1752198241
#line 30 "sample/strings.c"
    r2 = (uint64_t)8242150686405454945;
    // EBPF_OP_STXDW pc=15 dst=r10 src=r2 offset=-56 imm=0
#line 30 "sample/strings.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r2;
    // EBPF_OP_STXB pc=16 dst=r10 src=r1 offset=-57 imm=0
#line 31 "sample/strings.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-57)) = (uint8_t)r1;
    // EBPF_OP_MOV64_REG pc=17 dst=r1 src=r10 offset=0 imm=0
#line 31 "sample/strings.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=18 dst=r1 src=r0 offset=0 imm=-57
#line 31 "sample/strings.c"
    r1 += IMMEDIATE(-57);
    // EBPF_OP_MOV64_IMM pc=19 dst=r2 src=r0 offset=0 imm=0
#line 33 "sample/strings.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=20 dst=r0 src=r0 offset=0 imm=29
#line 33 "sample/strings.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 33 "sample/strings.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 33 "sample/strings.c"
        return 0;
#line 33 "sample/strings.c"
    }
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r0 offset=0 imm=0
#line 33 "sample/strings.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=22 dst=r0 src=r0 offset=0 imm=1
#line 33 "sample/strings.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JNE_IMM pc=23 dst=r1 src=r0 offset=76 imm=0
#line 33 "sample/strings.c"
    if (r1 != IMMEDIATE(0)) {
#line 33 "sample/strings.c"
        goto label_2;
#line 33 "sample/strings.c"
    }
    // EBPF_OP_MOV64_REG pc=24 dst=r1 src=r10 offset=0 imm=0
#line 33 "sample/strings.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=25 dst=r1 src=r0 offset=0 imm=-24
#line 37 "sample/strings.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=26 dst=r2 src=r0 offset=0 imm=20
#line 37 "sample/strings.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_CALL pc=27 dst=r0 src=r0 offset=0 imm=29
#line 37 "sample/strings.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 37 "sample/strings.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 37 "sample/strings.c"
        return 0;
#line 37 "sample/strings.c"
    }
    // EBPF_OP_MOV64_REG pc=28 dst=r1 src=r0 offset=0 imm=0
#line 37 "sample/strings.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=29 dst=r0 src=r0 offset=0 imm=2
#line 37 "sample/strings.c"
    r0 = IMMEDIATE(2);
    // EBPF_OP_JNE_IMM pc=30 dst=r1 src=r0 offset=69 imm=0
#line 37 "sample/strings.c"
    if (r1 != IMMEDIATE(0)) {
#line 37 "sample/strings.c"
        goto label_2;
#line 37 "sample/strings.c"
    }
    // EBPF_OP_MOV64_REG pc=31 dst=r1 src=r10 offset=0 imm=0
#line 37 "sample/strings.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=32 dst=r1 src=r0 offset=0 imm=-32
#line 41 "sample/strings.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=33 dst=r2 src=r0 offset=0 imm=6
#line 41 "sample/strings.c"
    r2 = IMMEDIATE(6);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=29
#line 41 "sample/strings.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 41 "sample/strings.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 41 "sample/strings.c"
        return 0;
#line 41 "sample/strings.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r1 src=r0 offset=0 imm=0
#line 41 "sample/strings.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=36 dst=r0 src=r0 offset=0 imm=3
#line 41 "sample/strings.c"
    r0 = IMMEDIATE(3);
    // EBPF_OP_JNE_IMM pc=37 dst=r1 src=r0 offset=62 imm=5
#line 41 "sample/strings.c"
    if (r1 != IMMEDIATE(5)) {
#line 41 "sample/strings.c"
        goto label_2;
#line 41 "sample/strings.c"
    }
    // EBPF_OP_MOV64_REG pc=38 dst=r1 src=r10 offset=0 imm=0
#line 41 "sample/strings.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=39 dst=r1 src=r0 offset=0 imm=-56
#line 45 "sample/strings.c"
    r1 += IMMEDIATE(-56);
    // EBPF_OP_MOV64_IMM pc=40 dst=r2 src=r0 offset=0 imm=12
#line 45 "sample/strings.c"
    r2 = IMMEDIATE(12);
    // EBPF_OP_CALL pc=41 dst=r0 src=r0 offset=0 imm=29
#line 45 "sample/strings.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 45 "sample/strings.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 45 "sample/strings.c"
        return 0;
#line 45 "sample/strings.c"
    }
    // EBPF_OP_MOV64_REG pc=42 dst=r1 src=r0 offset=0 imm=0
#line 45 "sample/strings.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=43 dst=r0 src=r0 offset=0 imm=4
#line 45 "sample/strings.c"
    r0 = IMMEDIATE(4);
    // EBPF_OP_JNE_IMM pc=44 dst=r1 src=r0 offset=55 imm=5
#line 45 "sample/strings.c"
    if (r1 != IMMEDIATE(5)) {
#line 45 "sample/strings.c"
        goto label_2;
#line 45 "sample/strings.c"
    }
    // EBPF_OP_MOV64_REG pc=45 dst=r1 src=r10 offset=0 imm=0
#line 45 "sample/strings.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=46 dst=r1 src=r0 offset=0 imm=-24
#line 49 "sample/strings.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_REG pc=47 dst=r3 src=r10 offset=0 imm=0
#line 49 "sample/strings.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=48 dst=r3 src=r0 offset=0 imm=-32
#line 49 "sample/strings.c"
    r3 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=49 dst=r2 src=r0 offset=0 imm=20
#line 49 "sample/strings.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=50 dst=r4 src=r0 offset=0 imm=6
#line 49 "sample/strings.c"
    r4 = IMMEDIATE(6);
    // EBPF_OP_CALL pc=51 dst=r0 src=r0 offset=0 imm=27
#line 49 "sample/strings.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 49 "sample/strings.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 49 "sample/strings.c"
        return 0;
#line 49 "sample/strings.c"
    }
    // EBPF_OP_MOV64_REG pc=52 dst=r1 src=r0 offset=0 imm=0
#line 49 "sample/strings.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=53 dst=r0 src=r0 offset=0 imm=5
#line 49 "sample/strings.c"
    r0 = IMMEDIATE(5);
    // EBPF_OP_LSH64_IMM pc=54 dst=r1 src=r0 offset=0 imm=32
#line 49 "sample/strings.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=55 dst=r1 src=r0 offset=0 imm=32
#line 49 "sample/strings.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JNE_IMM pc=56 dst=r1 src=r0 offset=43 imm=0
#line 49 "sample/strings.c"
    if (r1 != IMMEDIATE(0)) {
#line 49 "sample/strings.c"
        goto label_2;
#line 49 "sample/strings.c"
    }
    // EBPF_OP_MOV64_REG pc=57 dst=r1 src=r10 offset=0 imm=0
#line 49 "sample/strings.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=58 dst=r1 src=r0 offset=0 imm=-24
#line 55 "sample/strings.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_REG pc=59 dst=r3 src=r10 offset=0 imm=0
#line 55 "sample/strings.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=60 dst=r3 src=r0 offset=0 imm=-32
#line 55 "sample/strings.c"
    r3 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=61 dst=r2 src=r0 offset=0 imm=6
#line 55 "sample/strings.c"
    r2 = IMMEDIATE(6);
    // EBPF_OP_MOV64_IMM pc=62 dst=r4 src=r0 offset=0 imm=6
#line 55 "sample/strings.c"
    r4 = IMMEDIATE(6);
    // EBPF_OP_CALL pc=63 dst=r0 src=r0 offset=0 imm=23
#line 55 "sample/strings.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 55 "sample/strings.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 55 "sample/strings.c"
        return 0;
#line 55 "sample/strings.c"
    }
    // EBPF_OP_MOV64_REG pc=64 dst=r1 src=r0 offset=0 imm=0
#line 55 "sample/strings.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=65 dst=r1 src=r0 offset=0 imm=32
#line 55 "sample/strings.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=66 dst=r1 src=r0 offset=0 imm=32
#line 55 "sample/strings.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_IMM pc=67 dst=r0 src=r0 offset=0 imm=6
#line 55 "sample/strings.c"
    r0 = IMMEDIATE(6);
    // EBPF_OP_JNE_IMM pc=68 dst=r1 src=r0 offset=31 imm=0
#line 55 "sample/strings.c"
    if (r1 != IMMEDIATE(0)) {
#line 55 "sample/strings.c"
        goto label_2;
#line 55 "sample/strings.c"
    }
    // EBPF_OP_MOV64_REG pc=69 dst=r1 src=r10 offset=0 imm=0
#line 55 "sample/strings.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=70 dst=r1 src=r0 offset=0 imm=-24
#line 59 "sample/strings.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_REG pc=71 dst=r3 src=r10 offset=0 imm=0
#line 59 "sample/strings.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=72 dst=r3 src=r0 offset=0 imm=-40
#line 59 "sample/strings.c"
    r3 += IMMEDIATE(-40);
    // EBPF_OP_MOV64_IMM pc=73 dst=r2 src=r0 offset=0 imm=20
#line 59 "sample/strings.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=74 dst=r4 src=r0 offset=0 imm=5
#line 59 "sample/strings.c"
    r4 = IMMEDIATE(5);
    // EBPF_OP_CALL pc=75 dst=r0 src=r0 offset=0 imm=28
#line 59 "sample/strings.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 59 "sample/strings.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 59 "sample/strings.c"
        return 0;
#line 59 "sample/strings.c"
    }
    // EBPF_OP_MOV64_REG pc=76 dst=r1 src=r0 offset=0 imm=0
#line 59 "sample/strings.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=77 dst=r0 src=r0 offset=0 imm=7
#line 59 "sample/strings.c"
    r0 = IMMEDIATE(7);
    // EBPF_OP_LSH64_IMM pc=78 dst=r1 src=r0 offset=0 imm=32
#line 59 "sample/strings.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=79 dst=r1 src=r0 offset=0 imm=32
#line 59 "sample/strings.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JNE_IMM pc=80 dst=r1 src=r0 offset=19 imm=0
#line 59 "sample/strings.c"
    if (r1 != IMMEDIATE(0)) {
#line 59 "sample/strings.c"
        goto label_2;
#line 59 "sample/strings.c"
    }
    // EBPF_OP_MOV64_IMM pc=81 dst=r1 src=r0 offset=0 imm=97
#line 59 "sample/strings.c"
    r1 = IMMEDIATE(97);
    // EBPF_OP_STXH pc=82 dst=r10 src=r1 offset=-64 imm=0
#line 64 "sample/strings.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=83 dst=r1 src=r0 offset=0 imm=1752198241
#line 64 "sample/strings.c"
    r1 = (uint64_t)7380380960345320545;
    // EBPF_OP_STXDW pc=85 dst=r10 src=r1 offset=-72 imm=0
#line 64 "sample/strings.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=86 dst=r1 src=r10 offset=0 imm=0
#line 64 "sample/strings.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=87 dst=r1 src=r0 offset=0 imm=-24
#line 64 "sample/strings.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_REG pc=88 dst=r3 src=r10 offset=0 imm=0
#line 64 "sample/strings.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=89 dst=r3 src=r0 offset=0 imm=-72
#line 64 "sample/strings.c"
    r3 += IMMEDIATE(-72);
    // EBPF_OP_MOV64_IMM pc=90 dst=r2 src=r0 offset=0 imm=10
#line 68 "sample/strings.c"
    r2 = IMMEDIATE(10);
    // EBPF_OP_MOV64_IMM pc=91 dst=r4 src=r0 offset=0 imm=10
#line 68 "sample/strings.c"
    r4 = IMMEDIATE(10);
    // EBPF_OP_CALL pc=92 dst=r0 src=r0 offset=0 imm=23
#line 68 "sample/strings.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 68 "sample/strings.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 68 "sample/strings.c"
        return 0;
#line 68 "sample/strings.c"
    }
    // EBPF_OP_MOV64_REG pc=93 dst=r1 src=r0 offset=0 imm=0
#line 68 "sample/strings.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=94 dst=r1 src=r0 offset=0 imm=32
#line 68 "sample/strings.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=95 dst=r1 src=r0 offset=0 imm=32
#line 68 "sample/strings.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_IMM pc=96 dst=r0 src=r0 offset=0 imm=1
#line 68 "sample/strings.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JNE_IMM pc=97 dst=r1 src=r0 offset=1 imm=0
#line 68 "sample/strings.c"
    if (r1 != IMMEDIATE(0)) {
#line 68 "sample/strings.c"
        goto label_1;
#line 68 "sample/strings.c"
    }
    // EBPF_OP_MOV64_IMM pc=98 dst=r0 src=r0 offset=0 imm=0
#line 68 "sample/strings.c"
    r0 = IMMEDIATE(0);
label_1:
    // EBPF_OP_LSH64_IMM pc=99 dst=r0 src=r0 offset=0 imm=3
#line 68 "sample/strings.c"
    r0 <<= (IMMEDIATE(3) & 63);
label_2:
    // EBPF_OP_EXIT pc=100 dst=r0 src=r0 offset=0 imm=0
#line 73 "sample/strings.c"
    return r0;
#line 25 "sample/strings.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        StringOpsTest,
        "bind",
        "bind",
        "StringOpsTest",
        NULL,
        0,
        StringOpsTest_helpers,
        4,
        101,
        &StringOpsTest_program_type_guid,
        &StringOpsTest_attach_type_guid,
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
    version->minor = 21;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t strings_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
