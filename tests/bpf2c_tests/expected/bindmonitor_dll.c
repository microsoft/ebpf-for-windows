// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from bindmonitor.o

#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>

#include <stdio.h>

#include "bpf2c.h"

#define metadata_table bindmonitor##_metadata_table
extern metadata_table_t metadata_table;

BOOL APIENTRY
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

void
division_by_zero(uint32_t address)
{
    fprintf(stderr, "Divide by zero at address %d\n", address);
}

#define FIND_METADATA_ENTRTY(NAME, X) \
    if (std::string(NAME) == #X)      \
        return &X;

metadata_table_t*
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
static map_entry_t _maps[] = {
    {NULL,
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         8,                 // Size in bytes of a map key.
         68,                // Size in bytes of a map value.
         1024,              // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         PIN_NONE,          // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "process_map"},
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
     "limits_map"},
};

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 2;
}

static helper_function_entry_t BindMonitor_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 2, "helper_id_2"},
    {NULL, 3, "helper_id_3"},
};

static GUID BindMonitor_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_maps[] = {
    0,
    1,
};

static uint64_t
BindMonitor(void* context)
{
#line 78 "sample/bindmonitor.c"
    // Prologue
#line 78 "sample/bindmonitor.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 78 "sample/bindmonitor.c"
    register uint64_t r0 = 0;
#line 78 "sample/bindmonitor.c"
    register uint64_t r1 = 0;
#line 78 "sample/bindmonitor.c"
    register uint64_t r2 = 0;
#line 78 "sample/bindmonitor.c"
    register uint64_t r3 = 0;
#line 78 "sample/bindmonitor.c"
    register uint64_t r4 = 0;
#line 78 "sample/bindmonitor.c"
    register uint64_t r5 = 0;
#line 78 "sample/bindmonitor.c"
    register uint64_t r6 = 0;
#line 78 "sample/bindmonitor.c"
    register uint64_t r7 = 0;
#line 78 "sample/bindmonitor.c"
    register uint64_t r8 = 0;
#line 78 "sample/bindmonitor.c"
    register uint64_t r9 = 0;
#line 78 "sample/bindmonitor.c"
    register uint64_t r10 = 0;

#line 78 "sample/bindmonitor.c"
    r1 = (uintptr_t)context;
#line 78 "sample/bindmonitor.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 78 "sample/bindmonitor.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r8 src=r0 offset=0 imm=0
#line 78 "sample/bindmonitor.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r8 offset=-84 imm=0
#line 80 "sample/bindmonitor.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-84)) = (uint32_t)r8;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 80 "sample/bindmonitor.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-84
#line 80 "sample/bindmonitor.c"
    r2 += IMMEDIATE(-84);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/bindmonitor.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 82 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[0].address
#line 82 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[0].tail_call) && (r0 == 0))
#line 82 "sample/bindmonitor.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r7 src=r0 offset=0 imm=0
#line 82 "sample/bindmonitor.c"
    r7 = r0;
    // EBPF_OP_JEQ_IMM pc=9 dst=r7 src=r0 offset=82 imm=0
#line 83 "sample/bindmonitor.c"
    if (r7 == IMMEDIATE(0))
#line 83 "sample/bindmonitor.c"
        goto label_9;
        // EBPF_OP_LDXW pc=10 dst=r1 src=r7 offset=0 imm=0
#line 83 "sample/bindmonitor.c"
    r1 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=11 dst=r1 src=r0 offset=80 imm=0
#line 83 "sample/bindmonitor.c"
    if (r1 == IMMEDIATE(0))
#line 83 "sample/bindmonitor.c"
        goto label_9;
        // EBPF_OP_LDXDW pc=12 dst=r1 src=r6 offset=16 imm=0
#line 42 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(16));
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-8 imm=0
#line 42 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=14 dst=r1 src=r0 offset=0 imm=0
#line 42 "sample/bindmonitor.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=15 dst=r10 src=r1 offset=-16 imm=0
#line 44 "sample/bindmonitor.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 44 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-32 imm=0
#line 44 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=18 dst=r10 src=r1 offset=-40 imm=0
#line 44 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-48 imm=0
#line 44 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-56 imm=0
#line 44 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=21 dst=r10 src=r1 offset=-64 imm=0
#line 44 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=22 dst=r10 src=r1 offset=-72 imm=0
#line 44 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=23 dst=r10 src=r1 offset=-80 imm=0
#line 44 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=24 dst=r2 src=r10 offset=0 imm=0
#line 44 "sample/bindmonitor.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=25 dst=r2 src=r0 offset=0 imm=-8
#line 44 "sample/bindmonitor.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=26 dst=r1 src=r0 offset=0 imm=0
#line 47 "sample/bindmonitor.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=28 dst=r0 src=r0 offset=0 imm=1
#line 47 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[0].address
#line 47 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 47 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[0].tail_call) && (r0 == 0))
#line 47 "sample/bindmonitor.c"
        return 0;
        // EBPF_OP_JEQ_IMM pc=29 dst=r0 src=r0 offset=1 imm=0
#line 48 "sample/bindmonitor.c"
    if (r0 == IMMEDIATE(0))
#line 48 "sample/bindmonitor.c"
        goto label_1;
        // EBPF_OP_JA pc=30 dst=r0 src=r0 offset=33 imm=0
#line 48 "sample/bindmonitor.c"
    goto label_3;
label_1:
    // EBPF_OP_LDXW pc=31 dst=r1 src=r6 offset=44 imm=0
#line 51 "sample/bindmonitor.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_JNE_IMM pc=32 dst=r1 src=r0 offset=58 imm=0
#line 51 "sample/bindmonitor.c"
    if (r1 != IMMEDIATE(0))
#line 51 "sample/bindmonitor.c"
        goto label_8;
        // EBPF_OP_LDXDW pc=33 dst=r1 src=r6 offset=0 imm=0
#line 54 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=34 dst=r1 src=r0 offset=56 imm=0
#line 54 "sample/bindmonitor.c"
    if (r1 == IMMEDIATE(0))
#line 54 "sample/bindmonitor.c"
        goto label_8;
        // EBPF_OP_LDXDW pc=35 dst=r1 src=r6 offset=8 imm=0
#line 54 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_JEQ_IMM pc=36 dst=r1 src=r0 offset=54 imm=0
#line 54 "sample/bindmonitor.c"
    if (r1 == IMMEDIATE(0))
#line 54 "sample/bindmonitor.c"
        goto label_8;
        // EBPF_OP_MOV64_REG pc=37 dst=r8 src=r10 offset=0 imm=0
#line 54 "sample/bindmonitor.c"
    r8 = r10;
    // EBPF_OP_ADD64_IMM pc=38 dst=r8 src=r0 offset=0 imm=-8
#line 54 "sample/bindmonitor.c"
    r8 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=39 dst=r3 src=r10 offset=0 imm=0
#line 54 "sample/bindmonitor.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=40 dst=r3 src=r0 offset=0 imm=-80
#line 54 "sample/bindmonitor.c"
    r3 += IMMEDIATE(-80);
    // EBPF_OP_MOV64_IMM pc=41 dst=r9 src=r0 offset=0 imm=0
#line 54 "sample/bindmonitor.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=42 dst=r1 src=r0 offset=0 imm=0
#line 57 "sample/bindmonitor.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_REG pc=44 dst=r2 src=r8 offset=0 imm=0
#line 57 "sample/bindmonitor.c"
    r2 = r8;
    // EBPF_OP_MOV64_IMM pc=45 dst=r4 src=r0 offset=0 imm=0
#line 57 "sample/bindmonitor.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=46 dst=r0 src=r0 offset=0 imm=2
#line 57 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[1].address
#line 57 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 57 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[1].tail_call) && (r0 == 0))
#line 57 "sample/bindmonitor.c"
        return 0;
        // EBPF_OP_LDDW pc=47 dst=r1 src=r0 offset=0 imm=0
#line 58 "sample/bindmonitor.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_REG pc=49 dst=r2 src=r8 offset=0 imm=0
#line 58 "sample/bindmonitor.c"
    r2 = r8;
    // EBPF_OP_CALL pc=50 dst=r0 src=r0 offset=0 imm=1
#line 58 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[0].address
#line 58 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 58 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[0].tail_call) && (r0 == 0))
#line 58 "sample/bindmonitor.c"
        return 0;
        // EBPF_OP_JEQ_IMM pc=51 dst=r0 src=r0 offset=39 imm=0
#line 59 "sample/bindmonitor.c"
    if (r0 == IMMEDIATE(0))
#line 59 "sample/bindmonitor.c"
        goto label_8;
        // EBPF_OP_MOV64_REG pc=52 dst=r1 src=r0 offset=0 imm=0
#line 59 "sample/bindmonitor.c"
    r1 = r0;
    // EBPF_OP_ADD64_IMM pc=53 dst=r1 src=r0 offset=0 imm=4
#line 59 "sample/bindmonitor.c"
    r1 += IMMEDIATE(4);
label_2:
    // EBPF_OP_LDXDW pc=54 dst=r2 src=r6 offset=0 imm=0
#line 63 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_ADD64_REG pc=55 dst=r2 src=r9 offset=0 imm=0
#line 63 "sample/bindmonitor.c"
    r2 += r9;
    // EBPF_OP_LDXDW pc=56 dst=r3 src=r6 offset=8 imm=0
#line 63 "sample/bindmonitor.c"
    r3 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_JGE_REG pc=57 dst=r2 src=r3 offset=6 imm=0
#line 63 "sample/bindmonitor.c"
    if (r2 >= r3)
#line 63 "sample/bindmonitor.c"
        goto label_3;
        // EBPF_OP_MOV64_REG pc=58 dst=r3 src=r1 offset=0 imm=0
#line 66 "sample/bindmonitor.c"
    r3 = r1;
    // EBPF_OP_ADD64_REG pc=59 dst=r3 src=r9 offset=0 imm=0
#line 66 "sample/bindmonitor.c"
    r3 += r9;
    // EBPF_OP_LDXB pc=60 dst=r2 src=r2 offset=0 imm=0
#line 66 "sample/bindmonitor.c"
    r2 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(0));
    // EBPF_OP_STXB pc=61 dst=r3 src=r2 offset=0 imm=0
#line 66 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r3 + OFFSET(0)) = (uint8_t)r2;
    // EBPF_OP_ADD64_IMM pc=62 dst=r9 src=r0 offset=0 imm=1
#line 62 "sample/bindmonitor.c"
    r9 += IMMEDIATE(1);
    // EBPF_OP_JNE_IMM pc=63 dst=r9 src=r0 offset=-10 imm=64
#line 62 "sample/bindmonitor.c"
    if (r9 != IMMEDIATE(64))
#line 62 "sample/bindmonitor.c"
        goto label_2;
label_3:
    // EBPF_OP_LDXW pc=64 dst=r1 src=r6 offset=44 imm=0
#line 92 "sample/bindmonitor.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_JEQ_IMM pc=65 dst=r1 src=r0 offset=3 imm=0
#line 92 "sample/bindmonitor.c"
    if (r1 == IMMEDIATE(0))
#line 92 "sample/bindmonitor.c"
        goto label_4;
        // EBPF_OP_JEQ_IMM pc=66 dst=r1 src=r0 offset=9 imm=2
#line 92 "sample/bindmonitor.c"
    if (r1 == IMMEDIATE(2))
#line 92 "sample/bindmonitor.c"
        goto label_5;
        // EBPF_OP_LDXW pc=67 dst=r1 src=r0 offset=0 imm=0
#line 108 "sample/bindmonitor.c"
    r1 = *(uint32_t*)(uintptr_t)(r0 + OFFSET(0));
    // EBPF_OP_JA pc=68 dst=r0 src=r0 offset=11 imm=0
#line 108 "sample/bindmonitor.c"
    goto label_6;
label_4:
    // EBPF_OP_MOV64_IMM pc=69 dst=r8 src=r0 offset=0 imm=1
#line 108 "sample/bindmonitor.c"
    r8 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=70 dst=r1 src=r0 offset=0 imm=0
#line 94 "sample/bindmonitor.c"
    r1 = *(uint32_t*)(uintptr_t)(r0 + OFFSET(0));
    // EBPF_OP_LDXW pc=71 dst=r2 src=r7 offset=0 imm=0
#line 94 "sample/bindmonitor.c"
    r2 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_JGE_REG pc=72 dst=r1 src=r2 offset=19 imm=0
#line 94 "sample/bindmonitor.c"
    if (r1 >= r2)
#line 94 "sample/bindmonitor.c"
        goto label_9;
        // EBPF_OP_ADD64_IMM pc=73 dst=r1 src=r0 offset=0 imm=1
#line 98 "sample/bindmonitor.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=74 dst=r0 src=r1 offset=0 imm=0
#line 98 "sample/bindmonitor.c"
    *(uint32_t*)(uintptr_t)(r0 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_JA pc=75 dst=r0 src=r0 offset=15 imm=0
#line 98 "sample/bindmonitor.c"
    goto label_8;
label_5:
    // EBPF_OP_LDXW pc=76 dst=r1 src=r0 offset=0 imm=0
#line 101 "sample/bindmonitor.c"
    r1 = *(uint32_t*)(uintptr_t)(r0 + OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=77 dst=r1 src=r0 offset=6 imm=0
#line 101 "sample/bindmonitor.c"
    if (r1 == IMMEDIATE(0))
#line 101 "sample/bindmonitor.c"
        goto label_7;
        // EBPF_OP_ADD64_IMM pc=78 dst=r1 src=r0 offset=0 imm=-1
#line 102 "sample/bindmonitor.c"
    r1 += IMMEDIATE(-1);
    // EBPF_OP_STXW pc=79 dst=r0 src=r1 offset=0 imm=0
#line 102 "sample/bindmonitor.c"
    *(uint32_t*)(uintptr_t)(r0 + OFFSET(0)) = (uint32_t)r1;
label_6:
    // EBPF_OP_MOV64_IMM pc=80 dst=r8 src=r0 offset=0 imm=0
#line 102 "sample/bindmonitor.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_LSH64_IMM pc=81 dst=r1 src=r0 offset=0 imm=32
#line 108 "sample/bindmonitor.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=82 dst=r1 src=r0 offset=0 imm=32
#line 108 "sample/bindmonitor.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=83 dst=r1 src=r0 offset=8 imm=0
#line 108 "sample/bindmonitor.c"
    if (r1 != IMMEDIATE(0))
#line 108 "sample/bindmonitor.c"
        goto label_9;
label_7:
    // EBPF_OP_LDXDW pc=84 dst=r1 src=r6 offset=16 imm=0
#line 109 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(16));
    // EBPF_OP_STXDW pc=85 dst=r10 src=r1 offset=-80 imm=0
#line 109 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=86 dst=r2 src=r10 offset=0 imm=0
#line 109 "sample/bindmonitor.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=87 dst=r2 src=r0 offset=0 imm=-80
#line 109 "sample/bindmonitor.c"
    r2 += IMMEDIATE(-80);
    // EBPF_OP_LDDW pc=88 dst=r1 src=r0 offset=0 imm=0
#line 110 "sample/bindmonitor.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=90 dst=r0 src=r0 offset=0 imm=3
#line 110 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[2].address
#line 110 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 110 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[2].tail_call) && (r0 == 0))
#line 110 "sample/bindmonitor.c"
        return 0;
label_8:
    // EBPF_OP_MOV64_IMM pc=91 dst=r8 src=r0 offset=0 imm=0
#line 110 "sample/bindmonitor.c"
    r8 = IMMEDIATE(0);
label_9:
    // EBPF_OP_MOV64_REG pc=92 dst=r0 src=r8 offset=0 imm=0
#line 114 "sample/bindmonitor.c"
    r0 = r8;
    // EBPF_OP_EXIT pc=93 dst=r0 src=r0 offset=0 imm=0
#line 114 "sample/bindmonitor.c"
    return r0;
#line 114 "sample/bindmonitor.c"
}
#line __LINE__ __FILE__

static program_entry_t _programs[] = {
    {
        BindMonitor,
        "bind",
        "BindMonitor",
        BindMonitor_maps,
        2,
        BindMonitor_helpers,
        3,
        94,
        &BindMonitor_program_type_guid,
        &BindMonitor_attach_type_guid,
    },
};

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 1;
}

metadata_table_t bindmonitor_metadata_table = {_get_programs, _get_maps, _get_hash};
