// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from bindmonitor.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table bindmonitor##_metadata_table
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
#pragma data_seg(push, "maps")
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
         BPF_MAP_TYPE_HASH, // Type of map.
         8,                 // Size in bytes of a map key.
         16,                // Size in bytes of a map value.
         1024,              // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         PIN_NONE,          // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "audit_map"},
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
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 3;
}

static helper_function_entry_t BindMonitor_helpers[] = {
    {NULL, 19, "helper_id_19"},
    {NULL, 20, "helper_id_20"},
    {NULL, 21, "helper_id_21"},
    {NULL, 2, "helper_id_2"},
    {NULL, 1, "helper_id_1"},
    {NULL, 3, "helper_id_3"},
};

static GUID BindMonitor_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_maps[] = {
    0,
    1,
    2,
};

#pragma code_seg(push, "bind")
static uint64_t
BindMonitor(void* context)
#line 301 "sample/bindmonitor.c"
{
#line 301 "sample/bindmonitor.c"
    // Prologue
#line 301 "sample/bindmonitor.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 301 "sample/bindmonitor.c"
    register uint64_t r0 = 0;
#line 301 "sample/bindmonitor.c"
    register uint64_t r1 = 0;
#line 301 "sample/bindmonitor.c"
    register uint64_t r2 = 0;
#line 301 "sample/bindmonitor.c"
    register uint64_t r3 = 0;
#line 301 "sample/bindmonitor.c"
    register uint64_t r4 = 0;
#line 301 "sample/bindmonitor.c"
    register uint64_t r5 = 0;
#line 301 "sample/bindmonitor.c"
    register uint64_t r6 = 0;
#line 301 "sample/bindmonitor.c"
    register uint64_t r7 = 0;
#line 301 "sample/bindmonitor.c"
    register uint64_t r8 = 0;
#line 301 "sample/bindmonitor.c"
    register uint64_t r10 = 0;

#line 301 "sample/bindmonitor.c"
    r1 = (uintptr_t)context;
#line 301 "sample/bindmonitor.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 301 "sample/bindmonitor.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r8 src=r0 offset=0 imm=0
#line 301 "sample/bindmonitor.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r8 offset=-84 imm=0
#line 303 "sample/bindmonitor.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-84)) = (uint32_t)r8;
    // EBPF_OP_CALL pc=3 dst=r0 src=r0 offset=0 imm=19
#line 52 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[0].address
#line 52 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 52 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[0].tail_call) && (r0 == 0))
#line 52 "sample/bindmonitor.c"
        return 0;
    // EBPF_OP_STXDW pc=4 dst=r10 src=r0 offset=-8 imm=0
#line 52 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r0;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r8 offset=-72 imm=0
#line 53 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r8;
    // EBPF_OP_STXDW pc=6 dst=r10 src=r8 offset=-80 imm=0
#line 53 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r8;
    // EBPF_OP_MOV64_REG pc=7 dst=r1 src=r6 offset=0 imm=0
#line 55 "sample/bindmonitor.c"
    r1 = r6;
    // EBPF_OP_CALL pc=8 dst=r0 src=r0 offset=0 imm=20
#line 55 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[1].address
#line 55 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 55 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[1].tail_call) && (r0 == 0))
#line 55 "sample/bindmonitor.c"
        return 0;
    // EBPF_OP_STXDW pc=9 dst=r10 src=r0 offset=-80 imm=0
#line 55 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r0;
    // EBPF_OP_MOV64_REG pc=10 dst=r1 src=r6 offset=0 imm=0
#line 56 "sample/bindmonitor.c"
    r1 = r6;
    // EBPF_OP_CALL pc=11 dst=r0 src=r0 offset=0 imm=21
#line 56 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[2].address
#line 56 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 56 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[2].tail_call) && (r0 == 0))
#line 56 "sample/bindmonitor.c"
        return 0;
    // EBPF_OP_STXW pc=12 dst=r10 src=r0 offset=-72 imm=0
#line 56 "sample/bindmonitor.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r0;
    // EBPF_OP_MOV64_REG pc=13 dst=r2 src=r10 offset=0 imm=0
#line 56 "sample/bindmonitor.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=14 dst=r2 src=r0 offset=0 imm=-8
#line 56 "sample/bindmonitor.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=15 dst=r3 src=r10 offset=0 imm=0
#line 56 "sample/bindmonitor.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=16 dst=r3 src=r0 offset=0 imm=-80
#line 56 "sample/bindmonitor.c"
    r3 += IMMEDIATE(-80);
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=0
#line 58 "sample/bindmonitor.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_MOV64_IMM pc=19 dst=r4 src=r0 offset=0 imm=0
#line 58 "sample/bindmonitor.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=20 dst=r0 src=r0 offset=0 imm=2
#line 58 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[3].address
#line 58 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 58 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[3].tail_call) && (r0 == 0))
#line 58 "sample/bindmonitor.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=21 dst=r2 src=r10 offset=0 imm=0
#line 58 "sample/bindmonitor.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r2 src=r0 offset=0 imm=-84
#line 58 "sample/bindmonitor.c"
    r2 += IMMEDIATE(-84);
    // EBPF_OP_LDDW pc=23 dst=r1 src=r0 offset=0 imm=0
#line 308 "sample/bindmonitor.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=1
#line 308 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[4].address
#line 308 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 308 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[4].tail_call) && (r0 == 0))
#line 308 "sample/bindmonitor.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=26 dst=r7 src=r0 offset=0 imm=0
#line 308 "sample/bindmonitor.c"
    r7 = r0;
    // EBPF_OP_JEQ_IMM pc=27 dst=r7 src=r0 offset=519 imm=0
#line 309 "sample/bindmonitor.c"
    if (r7 == IMMEDIATE(0))
#line 309 "sample/bindmonitor.c"
        goto label_9;
    // EBPF_OP_LDXW pc=28 dst=r1 src=r7 offset=0 imm=0
#line 309 "sample/bindmonitor.c"
    r1 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=29 dst=r1 src=r0 offset=517 imm=0
#line 309 "sample/bindmonitor.c"
    if (r1 == IMMEDIATE(0))
#line 309 "sample/bindmonitor.c"
        goto label_9;
    // EBPF_OP_LDXDW pc=30 dst=r1 src=r6 offset=16 imm=0
#line 64 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(16));
    // EBPF_OP_STXDW pc=31 dst=r10 src=r1 offset=-8 imm=0
#line 64 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=32 dst=r1 src=r0 offset=0 imm=0
#line 64 "sample/bindmonitor.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=33 dst=r10 src=r1 offset=-16 imm=0
#line 66 "sample/bindmonitor.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_STXDW pc=34 dst=r10 src=r1 offset=-24 imm=0
#line 66 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=35 dst=r10 src=r1 offset=-32 imm=0
#line 66 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=36 dst=r10 src=r1 offset=-40 imm=0
#line 66 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=37 dst=r10 src=r1 offset=-48 imm=0
#line 66 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=38 dst=r10 src=r1 offset=-56 imm=0
#line 66 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=39 dst=r10 src=r1 offset=-64 imm=0
#line 66 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=40 dst=r10 src=r1 offset=-72 imm=0
#line 66 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=41 dst=r10 src=r1 offset=-80 imm=0
#line 66 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=42 dst=r2 src=r10 offset=0 imm=0
#line 66 "sample/bindmonitor.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=43 dst=r2 src=r0 offset=0 imm=-8
#line 66 "sample/bindmonitor.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=44 dst=r1 src=r0 offset=0 imm=0
#line 69 "sample/bindmonitor.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=46 dst=r0 src=r0 offset=0 imm=1
#line 69 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[4].address
#line 69 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 69 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[4].tail_call) && (r0 == 0))
#line 69 "sample/bindmonitor.c"
        return 0;
    // EBPF_OP_JEQ_IMM pc=47 dst=r0 src=r0 offset=7 imm=0
#line 70 "sample/bindmonitor.c"
    if (r0 == IMMEDIATE(0))
#line 70 "sample/bindmonitor.c"
        goto label_3;
label_1:
    // EBPF_OP_MOV64_IMM pc=48 dst=r8 src=r0 offset=0 imm=0
#line 70 "sample/bindmonitor.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_JEQ_IMM pc=49 dst=r0 src=r0 offset=497 imm=0
#line 315 "sample/bindmonitor.c"
    if (r0 == IMMEDIATE(0))
#line 315 "sample/bindmonitor.c"
        goto label_9;
label_2:
    // EBPF_OP_LDXW pc=50 dst=r1 src=r6 offset=44 imm=0
#line 319 "sample/bindmonitor.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_JEQ_IMM pc=51 dst=r1 src=r0 offset=488 imm=0
#line 319 "sample/bindmonitor.c"
    if (r1 == IMMEDIATE(0))
#line 319 "sample/bindmonitor.c"
        goto label_7;
    // EBPF_OP_JEQ_IMM pc=52 dst=r1 src=r0 offset=471 imm=2
#line 319 "sample/bindmonitor.c"
    if (r1 == IMMEDIATE(2))
#line 319 "sample/bindmonitor.c"
        goto label_4;
    // EBPF_OP_LDXW pc=53 dst=r1 src=r0 offset=0 imm=0
#line 336 "sample/bindmonitor.c"
    r1 = *(uint32_t*)(uintptr_t)(r0 + OFFSET(0));
    // EBPF_OP_JA pc=54 dst=r0 src=r0 offset=473 imm=0
#line 336 "sample/bindmonitor.c"
    goto label_5;
label_3:
    // EBPF_OP_LDXW pc=55 dst=r1 src=r6 offset=44 imm=0
#line 74 "sample/bindmonitor.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_JNE_IMM pc=56 dst=r1 src=r0 offset=489 imm=0
#line 74 "sample/bindmonitor.c"
    if (r1 != IMMEDIATE(0))
#line 74 "sample/bindmonitor.c"
        goto label_8;
    // EBPF_OP_LDXDW pc=57 dst=r1 src=r6 offset=0 imm=0
#line 78 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=58 dst=r1 src=r0 offset=487 imm=0
#line 78 "sample/bindmonitor.c"
    if (r1 == IMMEDIATE(0))
#line 78 "sample/bindmonitor.c"
        goto label_8;
    // EBPF_OP_LDXDW pc=59 dst=r1 src=r6 offset=8 imm=0
#line 78 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_JEQ_IMM pc=60 dst=r1 src=r0 offset=485 imm=0
#line 78 "sample/bindmonitor.c"
    if (r1 == IMMEDIATE(0))
#line 78 "sample/bindmonitor.c"
        goto label_8;
    // EBPF_OP_MOV64_REG pc=61 dst=r8 src=r10 offset=0 imm=0
#line 78 "sample/bindmonitor.c"
    r8 = r10;
    // EBPF_OP_ADD64_IMM pc=62 dst=r8 src=r0 offset=0 imm=-8
#line 78 "sample/bindmonitor.c"
    r8 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=63 dst=r3 src=r10 offset=0 imm=0
#line 78 "sample/bindmonitor.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=64 dst=r3 src=r0 offset=0 imm=-80
#line 78 "sample/bindmonitor.c"
    r3 += IMMEDIATE(-80);
    // EBPF_OP_LDDW pc=65 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/bindmonitor.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_REG pc=67 dst=r2 src=r8 offset=0 imm=0
#line 82 "sample/bindmonitor.c"
    r2 = r8;
    // EBPF_OP_MOV64_IMM pc=68 dst=r4 src=r0 offset=0 imm=0
#line 82 "sample/bindmonitor.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=69 dst=r0 src=r0 offset=0 imm=2
#line 82 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[3].address
#line 82 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[3].tail_call) && (r0 == 0))
#line 82 "sample/bindmonitor.c"
        return 0;
    // EBPF_OP_LDDW pc=70 dst=r1 src=r0 offset=0 imm=0
#line 83 "sample/bindmonitor.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_REG pc=72 dst=r2 src=r8 offset=0 imm=0
#line 83 "sample/bindmonitor.c"
    r2 = r8;
    // EBPF_OP_CALL pc=73 dst=r0 src=r0 offset=0 imm=1
#line 83 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[4].address
#line 83 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 83 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[4].tail_call) && (r0 == 0))
#line 83 "sample/bindmonitor.c"
        return 0;
    // EBPF_OP_JEQ_IMM pc=74 dst=r0 src=r0 offset=471 imm=0
#line 84 "sample/bindmonitor.c"
    if (r0 == IMMEDIATE(0))
#line 84 "sample/bindmonitor.c"
        goto label_8;
    // EBPF_OP_LDXDW pc=75 dst=r1 src=r6 offset=0 imm=0
#line 98 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=76 dst=r2 src=r6 offset=8 imm=0
#line 98 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=77 dst=r2 src=r1 offset=0 imm=0
#line 98 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=78 dst=r3 src=r0 offset=0 imm=1
#line 98 "sample/bindmonitor.c"
    r3 = IMMEDIATE(1);
    // EBPF_OP_JSGT_REG pc=79 dst=r3 src=r2 offset=-32 imm=0
#line 98 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 98 "sample/bindmonitor.c"
        goto label_1;
    // EBPF_OP_LDXB pc=80 dst=r1 src=r1 offset=0 imm=0
#line 99 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_STXB pc=81 dst=r0 src=r1 offset=4 imm=0
#line 99 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(4)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=82 dst=r1 src=r6 offset=0 imm=0
#line 101 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=83 dst=r2 src=r6 offset=8 imm=0
#line 101 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=84 dst=r2 src=r1 offset=0 imm=0
#line 101 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=85 dst=r3 src=r0 offset=0 imm=2
#line 101 "sample/bindmonitor.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_JSGT_REG pc=86 dst=r3 src=r2 offset=-37 imm=0
#line 101 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 101 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=87 dst=r1 src=r1 offset=1 imm=0
#line 102 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(1));
    // EBPF_OP_STXB pc=88 dst=r0 src=r1 offset=5 imm=0
#line 102 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(5)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=89 dst=r1 src=r6 offset=0 imm=0
#line 104 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=90 dst=r2 src=r6 offset=8 imm=0
#line 104 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=91 dst=r2 src=r1 offset=0 imm=0
#line 104 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=92 dst=r3 src=r0 offset=0 imm=3
#line 104 "sample/bindmonitor.c"
    r3 = IMMEDIATE(3);
    // EBPF_OP_JSGT_REG pc=93 dst=r3 src=r2 offset=-44 imm=0
#line 104 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 104 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=94 dst=r1 src=r1 offset=2 imm=0
#line 105 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(2));
    // EBPF_OP_STXB pc=95 dst=r0 src=r1 offset=6 imm=0
#line 105 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(6)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=96 dst=r1 src=r6 offset=0 imm=0
#line 107 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=97 dst=r2 src=r6 offset=8 imm=0
#line 107 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=98 dst=r2 src=r1 offset=0 imm=0
#line 107 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=99 dst=r3 src=r0 offset=0 imm=4
#line 107 "sample/bindmonitor.c"
    r3 = IMMEDIATE(4);
    // EBPF_OP_JSGT_REG pc=100 dst=r3 src=r2 offset=-51 imm=0
#line 107 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 107 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=101 dst=r1 src=r1 offset=3 imm=0
#line 108 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(3));
    // EBPF_OP_STXB pc=102 dst=r0 src=r1 offset=7 imm=0
#line 108 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(7)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=103 dst=r1 src=r6 offset=0 imm=0
#line 110 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=104 dst=r2 src=r6 offset=8 imm=0
#line 110 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=105 dst=r2 src=r1 offset=0 imm=0
#line 110 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=106 dst=r3 src=r0 offset=0 imm=5
#line 110 "sample/bindmonitor.c"
    r3 = IMMEDIATE(5);
    // EBPF_OP_JSGT_REG pc=107 dst=r3 src=r2 offset=-58 imm=0
#line 110 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 110 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=108 dst=r1 src=r1 offset=4 imm=0
#line 111 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(4));
    // EBPF_OP_STXB pc=109 dst=r0 src=r1 offset=8 imm=0
#line 111 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(8)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=110 dst=r1 src=r6 offset=0 imm=0
#line 113 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=111 dst=r2 src=r6 offset=8 imm=0
#line 113 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=112 dst=r2 src=r1 offset=0 imm=0
#line 113 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=113 dst=r3 src=r0 offset=0 imm=6
#line 113 "sample/bindmonitor.c"
    r3 = IMMEDIATE(6);
    // EBPF_OP_JSGT_REG pc=114 dst=r3 src=r2 offset=-65 imm=0
#line 113 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 113 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=115 dst=r1 src=r1 offset=5 imm=0
#line 114 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(5));
    // EBPF_OP_STXB pc=116 dst=r0 src=r1 offset=9 imm=0
#line 114 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(9)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=117 dst=r1 src=r6 offset=0 imm=0
#line 116 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=118 dst=r2 src=r6 offset=8 imm=0
#line 116 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=119 dst=r2 src=r1 offset=0 imm=0
#line 116 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=120 dst=r3 src=r0 offset=0 imm=7
#line 116 "sample/bindmonitor.c"
    r3 = IMMEDIATE(7);
    // EBPF_OP_JSGT_REG pc=121 dst=r3 src=r2 offset=-72 imm=0
#line 116 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 116 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=122 dst=r1 src=r1 offset=6 imm=0
#line 117 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(6));
    // EBPF_OP_STXB pc=123 dst=r0 src=r1 offset=10 imm=0
#line 117 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(10)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=124 dst=r1 src=r6 offset=0 imm=0
#line 119 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=125 dst=r2 src=r6 offset=8 imm=0
#line 119 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=126 dst=r2 src=r1 offset=0 imm=0
#line 119 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=127 dst=r3 src=r0 offset=0 imm=8
#line 119 "sample/bindmonitor.c"
    r3 = IMMEDIATE(8);
    // EBPF_OP_JSGT_REG pc=128 dst=r3 src=r2 offset=-79 imm=0
#line 119 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 119 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=129 dst=r1 src=r1 offset=7 imm=0
#line 120 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(7));
    // EBPF_OP_STXB pc=130 dst=r0 src=r1 offset=11 imm=0
#line 120 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(11)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=131 dst=r1 src=r6 offset=0 imm=0
#line 122 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=132 dst=r2 src=r6 offset=8 imm=0
#line 122 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=133 dst=r2 src=r1 offset=0 imm=0
#line 122 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=134 dst=r3 src=r0 offset=0 imm=9
#line 122 "sample/bindmonitor.c"
    r3 = IMMEDIATE(9);
    // EBPF_OP_JSGT_REG pc=135 dst=r3 src=r2 offset=-86 imm=0
#line 122 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 122 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=136 dst=r1 src=r1 offset=8 imm=0
#line 123 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(8));
    // EBPF_OP_STXB pc=137 dst=r0 src=r1 offset=12 imm=0
#line 123 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(12)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=138 dst=r1 src=r6 offset=0 imm=0
#line 125 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=139 dst=r2 src=r6 offset=8 imm=0
#line 125 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=140 dst=r2 src=r1 offset=0 imm=0
#line 125 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=141 dst=r3 src=r0 offset=0 imm=10
#line 125 "sample/bindmonitor.c"
    r3 = IMMEDIATE(10);
    // EBPF_OP_JSGT_REG pc=142 dst=r3 src=r2 offset=-93 imm=0
#line 125 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 125 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=143 dst=r1 src=r1 offset=9 imm=0
#line 126 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(9));
    // EBPF_OP_STXB pc=144 dst=r0 src=r1 offset=13 imm=0
#line 126 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(13)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=145 dst=r1 src=r6 offset=0 imm=0
#line 128 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=146 dst=r2 src=r6 offset=8 imm=0
#line 128 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=147 dst=r2 src=r1 offset=0 imm=0
#line 128 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=148 dst=r3 src=r0 offset=0 imm=11
#line 128 "sample/bindmonitor.c"
    r3 = IMMEDIATE(11);
    // EBPF_OP_JSGT_REG pc=149 dst=r3 src=r2 offset=-100 imm=0
#line 128 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 128 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=150 dst=r1 src=r1 offset=10 imm=0
#line 129 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(10));
    // EBPF_OP_STXB pc=151 dst=r0 src=r1 offset=14 imm=0
#line 129 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(14)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=152 dst=r1 src=r6 offset=0 imm=0
#line 131 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=153 dst=r2 src=r6 offset=8 imm=0
#line 131 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=154 dst=r2 src=r1 offset=0 imm=0
#line 131 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=155 dst=r3 src=r0 offset=0 imm=12
#line 131 "sample/bindmonitor.c"
    r3 = IMMEDIATE(12);
    // EBPF_OP_JSGT_REG pc=156 dst=r3 src=r2 offset=-107 imm=0
#line 131 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 131 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=157 dst=r1 src=r1 offset=11 imm=0
#line 132 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(11));
    // EBPF_OP_STXB pc=158 dst=r0 src=r1 offset=15 imm=0
#line 132 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(15)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=159 dst=r1 src=r6 offset=0 imm=0
#line 134 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=160 dst=r2 src=r6 offset=8 imm=0
#line 134 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=161 dst=r2 src=r1 offset=0 imm=0
#line 134 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=162 dst=r3 src=r0 offset=0 imm=13
#line 134 "sample/bindmonitor.c"
    r3 = IMMEDIATE(13);
    // EBPF_OP_JSGT_REG pc=163 dst=r3 src=r2 offset=-114 imm=0
#line 134 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 134 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=164 dst=r1 src=r1 offset=12 imm=0
#line 135 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(12));
    // EBPF_OP_STXB pc=165 dst=r0 src=r1 offset=16 imm=0
#line 135 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(16)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=166 dst=r1 src=r6 offset=0 imm=0
#line 137 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=167 dst=r2 src=r6 offset=8 imm=0
#line 137 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=168 dst=r2 src=r1 offset=0 imm=0
#line 137 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=169 dst=r3 src=r0 offset=0 imm=14
#line 137 "sample/bindmonitor.c"
    r3 = IMMEDIATE(14);
    // EBPF_OP_JSGT_REG pc=170 dst=r3 src=r2 offset=-121 imm=0
#line 137 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 137 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=171 dst=r1 src=r1 offset=13 imm=0
#line 138 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(13));
    // EBPF_OP_STXB pc=172 dst=r0 src=r1 offset=17 imm=0
#line 138 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(17)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=173 dst=r1 src=r6 offset=0 imm=0
#line 140 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=174 dst=r2 src=r6 offset=8 imm=0
#line 140 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=175 dst=r2 src=r1 offset=0 imm=0
#line 140 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=176 dst=r3 src=r0 offset=0 imm=15
#line 140 "sample/bindmonitor.c"
    r3 = IMMEDIATE(15);
    // EBPF_OP_JSGT_REG pc=177 dst=r3 src=r2 offset=-128 imm=0
#line 140 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 140 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=178 dst=r1 src=r1 offset=14 imm=0
#line 141 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(14));
    // EBPF_OP_STXB pc=179 dst=r0 src=r1 offset=18 imm=0
#line 141 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(18)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=180 dst=r1 src=r6 offset=0 imm=0
#line 143 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=181 dst=r2 src=r6 offset=8 imm=0
#line 143 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=182 dst=r2 src=r1 offset=0 imm=0
#line 143 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=183 dst=r3 src=r0 offset=0 imm=16
#line 143 "sample/bindmonitor.c"
    r3 = IMMEDIATE(16);
    // EBPF_OP_JSGT_REG pc=184 dst=r3 src=r2 offset=-135 imm=0
#line 143 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 143 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=185 dst=r1 src=r1 offset=15 imm=0
#line 144 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(15));
    // EBPF_OP_STXB pc=186 dst=r0 src=r1 offset=19 imm=0
#line 144 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(19)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=187 dst=r1 src=r6 offset=0 imm=0
#line 146 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=188 dst=r2 src=r6 offset=8 imm=0
#line 146 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=189 dst=r2 src=r1 offset=0 imm=0
#line 146 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=190 dst=r3 src=r0 offset=0 imm=17
#line 146 "sample/bindmonitor.c"
    r3 = IMMEDIATE(17);
    // EBPF_OP_JSGT_REG pc=191 dst=r3 src=r2 offset=-142 imm=0
#line 146 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 146 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=192 dst=r1 src=r1 offset=16 imm=0
#line 147 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(16));
    // EBPF_OP_STXB pc=193 dst=r0 src=r1 offset=20 imm=0
#line 147 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(20)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=194 dst=r1 src=r6 offset=0 imm=0
#line 149 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=195 dst=r2 src=r6 offset=8 imm=0
#line 149 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=196 dst=r2 src=r1 offset=0 imm=0
#line 149 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=197 dst=r3 src=r0 offset=0 imm=18
#line 149 "sample/bindmonitor.c"
    r3 = IMMEDIATE(18);
    // EBPF_OP_JSGT_REG pc=198 dst=r3 src=r2 offset=-149 imm=0
#line 149 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 149 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=199 dst=r1 src=r1 offset=17 imm=0
#line 150 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(17));
    // EBPF_OP_STXB pc=200 dst=r0 src=r1 offset=21 imm=0
#line 150 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(21)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=201 dst=r1 src=r6 offset=0 imm=0
#line 152 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=202 dst=r2 src=r6 offset=8 imm=0
#line 152 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=203 dst=r2 src=r1 offset=0 imm=0
#line 152 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=204 dst=r3 src=r0 offset=0 imm=19
#line 152 "sample/bindmonitor.c"
    r3 = IMMEDIATE(19);
    // EBPF_OP_JSGT_REG pc=205 dst=r3 src=r2 offset=-156 imm=0
#line 152 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 152 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=206 dst=r1 src=r1 offset=18 imm=0
#line 153 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(18));
    // EBPF_OP_STXB pc=207 dst=r0 src=r1 offset=22 imm=0
#line 153 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(22)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=208 dst=r1 src=r6 offset=0 imm=0
#line 155 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=209 dst=r2 src=r6 offset=8 imm=0
#line 155 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=210 dst=r2 src=r1 offset=0 imm=0
#line 155 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=211 dst=r3 src=r0 offset=0 imm=20
#line 155 "sample/bindmonitor.c"
    r3 = IMMEDIATE(20);
    // EBPF_OP_JSGT_REG pc=212 dst=r3 src=r2 offset=-163 imm=0
#line 155 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 155 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=213 dst=r1 src=r1 offset=19 imm=0
#line 156 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(19));
    // EBPF_OP_STXB pc=214 dst=r0 src=r1 offset=23 imm=0
#line 156 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(23)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=215 dst=r1 src=r6 offset=0 imm=0
#line 158 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=216 dst=r2 src=r6 offset=8 imm=0
#line 158 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=217 dst=r2 src=r1 offset=0 imm=0
#line 158 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=218 dst=r3 src=r0 offset=0 imm=21
#line 158 "sample/bindmonitor.c"
    r3 = IMMEDIATE(21);
    // EBPF_OP_JSGT_REG pc=219 dst=r3 src=r2 offset=-170 imm=0
#line 158 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 158 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=220 dst=r1 src=r1 offset=20 imm=0
#line 159 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(20));
    // EBPF_OP_STXB pc=221 dst=r0 src=r1 offset=24 imm=0
#line 159 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(24)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=222 dst=r1 src=r6 offset=0 imm=0
#line 161 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=223 dst=r2 src=r6 offset=8 imm=0
#line 161 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=224 dst=r2 src=r1 offset=0 imm=0
#line 161 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=225 dst=r3 src=r0 offset=0 imm=22
#line 161 "sample/bindmonitor.c"
    r3 = IMMEDIATE(22);
    // EBPF_OP_JSGT_REG pc=226 dst=r3 src=r2 offset=-177 imm=0
#line 161 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 161 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=227 dst=r1 src=r1 offset=21 imm=0
#line 162 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(21));
    // EBPF_OP_STXB pc=228 dst=r0 src=r1 offset=25 imm=0
#line 162 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(25)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=229 dst=r1 src=r6 offset=0 imm=0
#line 164 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=230 dst=r2 src=r6 offset=8 imm=0
#line 164 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=231 dst=r2 src=r1 offset=0 imm=0
#line 164 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=232 dst=r3 src=r0 offset=0 imm=23
#line 164 "sample/bindmonitor.c"
    r3 = IMMEDIATE(23);
    // EBPF_OP_JSGT_REG pc=233 dst=r3 src=r2 offset=-184 imm=0
#line 164 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 164 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=234 dst=r1 src=r1 offset=22 imm=0
#line 165 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(22));
    // EBPF_OP_STXB pc=235 dst=r0 src=r1 offset=26 imm=0
#line 165 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(26)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=236 dst=r1 src=r6 offset=0 imm=0
#line 167 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=237 dst=r2 src=r6 offset=8 imm=0
#line 167 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=238 dst=r2 src=r1 offset=0 imm=0
#line 167 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=239 dst=r3 src=r0 offset=0 imm=24
#line 167 "sample/bindmonitor.c"
    r3 = IMMEDIATE(24);
    // EBPF_OP_JSGT_REG pc=240 dst=r3 src=r2 offset=-191 imm=0
#line 167 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 167 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=241 dst=r1 src=r1 offset=23 imm=0
#line 168 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(23));
    // EBPF_OP_STXB pc=242 dst=r0 src=r1 offset=27 imm=0
#line 168 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(27)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=243 dst=r1 src=r6 offset=0 imm=0
#line 170 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=244 dst=r2 src=r6 offset=8 imm=0
#line 170 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=245 dst=r2 src=r1 offset=0 imm=0
#line 170 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=246 dst=r3 src=r0 offset=0 imm=25
#line 170 "sample/bindmonitor.c"
    r3 = IMMEDIATE(25);
    // EBPF_OP_JSGT_REG pc=247 dst=r3 src=r2 offset=-198 imm=0
#line 170 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 170 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=248 dst=r1 src=r1 offset=24 imm=0
#line 171 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_STXB pc=249 dst=r0 src=r1 offset=28 imm=0
#line 171 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(28)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=250 dst=r1 src=r6 offset=0 imm=0
#line 173 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=251 dst=r2 src=r6 offset=8 imm=0
#line 173 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=252 dst=r2 src=r1 offset=0 imm=0
#line 173 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=253 dst=r3 src=r0 offset=0 imm=26
#line 173 "sample/bindmonitor.c"
    r3 = IMMEDIATE(26);
    // EBPF_OP_JSGT_REG pc=254 dst=r3 src=r2 offset=-205 imm=0
#line 173 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 173 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=255 dst=r1 src=r1 offset=25 imm=0
#line 174 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(25));
    // EBPF_OP_STXB pc=256 dst=r0 src=r1 offset=29 imm=0
#line 174 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(29)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=257 dst=r1 src=r6 offset=0 imm=0
#line 176 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=258 dst=r2 src=r6 offset=8 imm=0
#line 176 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=259 dst=r2 src=r1 offset=0 imm=0
#line 176 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=260 dst=r3 src=r0 offset=0 imm=27
#line 176 "sample/bindmonitor.c"
    r3 = IMMEDIATE(27);
    // EBPF_OP_JSGT_REG pc=261 dst=r3 src=r2 offset=-212 imm=0
#line 176 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 176 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=262 dst=r1 src=r1 offset=26 imm=0
#line 177 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(26));
    // EBPF_OP_STXB pc=263 dst=r0 src=r1 offset=30 imm=0
#line 177 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(30)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=264 dst=r1 src=r6 offset=0 imm=0
#line 179 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=265 dst=r2 src=r6 offset=8 imm=0
#line 179 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=266 dst=r2 src=r1 offset=0 imm=0
#line 179 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=267 dst=r3 src=r0 offset=0 imm=28
#line 179 "sample/bindmonitor.c"
    r3 = IMMEDIATE(28);
    // EBPF_OP_JSGT_REG pc=268 dst=r3 src=r2 offset=-219 imm=0
#line 179 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 179 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=269 dst=r1 src=r1 offset=27 imm=0
#line 180 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(27));
    // EBPF_OP_STXB pc=270 dst=r0 src=r1 offset=31 imm=0
#line 180 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(31)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=271 dst=r1 src=r6 offset=0 imm=0
#line 182 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=272 dst=r2 src=r6 offset=8 imm=0
#line 182 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=273 dst=r2 src=r1 offset=0 imm=0
#line 182 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=274 dst=r3 src=r0 offset=0 imm=29
#line 182 "sample/bindmonitor.c"
    r3 = IMMEDIATE(29);
    // EBPF_OP_JSGT_REG pc=275 dst=r3 src=r2 offset=-226 imm=0
#line 182 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 182 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=276 dst=r1 src=r1 offset=28 imm=0
#line 183 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(28));
    // EBPF_OP_STXB pc=277 dst=r0 src=r1 offset=32 imm=0
#line 183 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(32)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=278 dst=r1 src=r6 offset=0 imm=0
#line 185 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=279 dst=r2 src=r6 offset=8 imm=0
#line 185 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=280 dst=r2 src=r1 offset=0 imm=0
#line 185 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=281 dst=r3 src=r0 offset=0 imm=30
#line 185 "sample/bindmonitor.c"
    r3 = IMMEDIATE(30);
    // EBPF_OP_JSGT_REG pc=282 dst=r3 src=r2 offset=-233 imm=0
#line 185 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 185 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=283 dst=r1 src=r1 offset=29 imm=0
#line 186 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(29));
    // EBPF_OP_STXB pc=284 dst=r0 src=r1 offset=33 imm=0
#line 186 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(33)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=285 dst=r1 src=r6 offset=0 imm=0
#line 188 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=286 dst=r2 src=r6 offset=8 imm=0
#line 188 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=287 dst=r2 src=r1 offset=0 imm=0
#line 188 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=288 dst=r3 src=r0 offset=0 imm=31
#line 188 "sample/bindmonitor.c"
    r3 = IMMEDIATE(31);
    // EBPF_OP_JSGT_REG pc=289 dst=r3 src=r2 offset=-240 imm=0
#line 188 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 188 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=290 dst=r1 src=r1 offset=30 imm=0
#line 189 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(30));
    // EBPF_OP_STXB pc=291 dst=r0 src=r1 offset=34 imm=0
#line 189 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(34)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=292 dst=r1 src=r6 offset=0 imm=0
#line 191 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=293 dst=r2 src=r6 offset=8 imm=0
#line 191 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=294 dst=r2 src=r1 offset=0 imm=0
#line 191 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=295 dst=r3 src=r0 offset=0 imm=32
#line 191 "sample/bindmonitor.c"
    r3 = IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=296 dst=r3 src=r2 offset=-247 imm=0
#line 191 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 191 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=297 dst=r1 src=r1 offset=31 imm=0
#line 192 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(31));
    // EBPF_OP_STXB pc=298 dst=r0 src=r1 offset=35 imm=0
#line 192 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(35)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=299 dst=r1 src=r6 offset=0 imm=0
#line 194 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=300 dst=r2 src=r6 offset=8 imm=0
#line 194 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=301 dst=r2 src=r1 offset=0 imm=0
#line 194 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=302 dst=r3 src=r0 offset=0 imm=33
#line 194 "sample/bindmonitor.c"
    r3 = IMMEDIATE(33);
    // EBPF_OP_JSGT_REG pc=303 dst=r3 src=r2 offset=-254 imm=0
#line 194 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 194 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=304 dst=r1 src=r1 offset=32 imm=0
#line 195 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(32));
    // EBPF_OP_STXB pc=305 dst=r0 src=r1 offset=36 imm=0
#line 195 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(36)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=306 dst=r1 src=r6 offset=0 imm=0
#line 197 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=307 dst=r2 src=r6 offset=8 imm=0
#line 197 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=308 dst=r2 src=r1 offset=0 imm=0
#line 197 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=309 dst=r3 src=r0 offset=0 imm=34
#line 197 "sample/bindmonitor.c"
    r3 = IMMEDIATE(34);
    // EBPF_OP_JSGT_REG pc=310 dst=r3 src=r2 offset=-261 imm=0
#line 197 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 197 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=311 dst=r1 src=r1 offset=33 imm=0
#line 198 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(33));
    // EBPF_OP_STXB pc=312 dst=r0 src=r1 offset=37 imm=0
#line 198 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(37)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=313 dst=r1 src=r6 offset=0 imm=0
#line 200 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=314 dst=r2 src=r6 offset=8 imm=0
#line 200 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=315 dst=r2 src=r1 offset=0 imm=0
#line 200 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=316 dst=r3 src=r0 offset=0 imm=35
#line 200 "sample/bindmonitor.c"
    r3 = IMMEDIATE(35);
    // EBPF_OP_JSGT_REG pc=317 dst=r3 src=r2 offset=-268 imm=0
#line 200 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 200 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=318 dst=r1 src=r1 offset=34 imm=0
#line 201 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(34));
    // EBPF_OP_STXB pc=319 dst=r0 src=r1 offset=38 imm=0
#line 201 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(38)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=320 dst=r1 src=r6 offset=0 imm=0
#line 203 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=321 dst=r2 src=r6 offset=8 imm=0
#line 203 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=322 dst=r2 src=r1 offset=0 imm=0
#line 203 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=323 dst=r3 src=r0 offset=0 imm=36
#line 203 "sample/bindmonitor.c"
    r3 = IMMEDIATE(36);
    // EBPF_OP_JSGT_REG pc=324 dst=r3 src=r2 offset=-275 imm=0
#line 203 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 203 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=325 dst=r1 src=r1 offset=35 imm=0
#line 204 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(35));
    // EBPF_OP_STXB pc=326 dst=r0 src=r1 offset=39 imm=0
#line 204 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(39)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=327 dst=r1 src=r6 offset=0 imm=0
#line 206 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=328 dst=r2 src=r6 offset=8 imm=0
#line 206 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=329 dst=r2 src=r1 offset=0 imm=0
#line 206 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=330 dst=r3 src=r0 offset=0 imm=37
#line 206 "sample/bindmonitor.c"
    r3 = IMMEDIATE(37);
    // EBPF_OP_JSGT_REG pc=331 dst=r3 src=r2 offset=-282 imm=0
#line 206 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 206 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=332 dst=r1 src=r1 offset=36 imm=0
#line 207 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(36));
    // EBPF_OP_STXB pc=333 dst=r0 src=r1 offset=40 imm=0
#line 207 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(40)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=334 dst=r1 src=r6 offset=0 imm=0
#line 209 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=335 dst=r2 src=r6 offset=8 imm=0
#line 209 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=336 dst=r2 src=r1 offset=0 imm=0
#line 209 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=337 dst=r3 src=r0 offset=0 imm=38
#line 209 "sample/bindmonitor.c"
    r3 = IMMEDIATE(38);
    // EBPF_OP_JSGT_REG pc=338 dst=r3 src=r2 offset=-289 imm=0
#line 209 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 209 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=339 dst=r1 src=r1 offset=37 imm=0
#line 210 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(37));
    // EBPF_OP_STXB pc=340 dst=r0 src=r1 offset=41 imm=0
#line 210 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(41)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=341 dst=r1 src=r6 offset=0 imm=0
#line 212 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=342 dst=r2 src=r6 offset=8 imm=0
#line 212 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=343 dst=r2 src=r1 offset=0 imm=0
#line 212 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=344 dst=r3 src=r0 offset=0 imm=39
#line 212 "sample/bindmonitor.c"
    r3 = IMMEDIATE(39);
    // EBPF_OP_JSGT_REG pc=345 dst=r3 src=r2 offset=-296 imm=0
#line 212 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 212 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=346 dst=r1 src=r1 offset=38 imm=0
#line 213 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(38));
    // EBPF_OP_STXB pc=347 dst=r0 src=r1 offset=42 imm=0
#line 213 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(42)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=348 dst=r1 src=r6 offset=0 imm=0
#line 215 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=349 dst=r2 src=r6 offset=8 imm=0
#line 215 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=350 dst=r2 src=r1 offset=0 imm=0
#line 215 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=351 dst=r3 src=r0 offset=0 imm=40
#line 215 "sample/bindmonitor.c"
    r3 = IMMEDIATE(40);
    // EBPF_OP_JSGT_REG pc=352 dst=r3 src=r2 offset=-303 imm=0
#line 215 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 215 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=353 dst=r1 src=r1 offset=39 imm=0
#line 216 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(39));
    // EBPF_OP_STXB pc=354 dst=r0 src=r1 offset=43 imm=0
#line 216 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(43)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=355 dst=r1 src=r6 offset=0 imm=0
#line 218 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=356 dst=r2 src=r6 offset=8 imm=0
#line 218 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=357 dst=r2 src=r1 offset=0 imm=0
#line 218 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=358 dst=r3 src=r0 offset=0 imm=41
#line 218 "sample/bindmonitor.c"
    r3 = IMMEDIATE(41);
    // EBPF_OP_JSGT_REG pc=359 dst=r3 src=r2 offset=-310 imm=0
#line 218 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 218 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=360 dst=r1 src=r1 offset=40 imm=0
#line 219 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_STXB pc=361 dst=r0 src=r1 offset=44 imm=0
#line 219 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(44)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=362 dst=r1 src=r6 offset=0 imm=0
#line 221 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=363 dst=r2 src=r6 offset=8 imm=0
#line 221 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=364 dst=r2 src=r1 offset=0 imm=0
#line 221 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=365 dst=r3 src=r0 offset=0 imm=42
#line 221 "sample/bindmonitor.c"
    r3 = IMMEDIATE(42);
    // EBPF_OP_JSGT_REG pc=366 dst=r3 src=r2 offset=-317 imm=0
#line 221 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 221 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=367 dst=r1 src=r1 offset=41 imm=0
#line 222 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(41));
    // EBPF_OP_STXB pc=368 dst=r0 src=r1 offset=45 imm=0
#line 222 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(45)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=369 dst=r1 src=r6 offset=0 imm=0
#line 224 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=370 dst=r2 src=r6 offset=8 imm=0
#line 224 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=371 dst=r2 src=r1 offset=0 imm=0
#line 224 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=372 dst=r3 src=r0 offset=0 imm=43
#line 224 "sample/bindmonitor.c"
    r3 = IMMEDIATE(43);
    // EBPF_OP_JSGT_REG pc=373 dst=r3 src=r2 offset=-324 imm=0
#line 224 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 224 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=374 dst=r1 src=r1 offset=42 imm=0
#line 225 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(42));
    // EBPF_OP_STXB pc=375 dst=r0 src=r1 offset=46 imm=0
#line 225 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(46)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=376 dst=r1 src=r6 offset=0 imm=0
#line 227 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=377 dst=r2 src=r6 offset=8 imm=0
#line 227 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=378 dst=r2 src=r1 offset=0 imm=0
#line 227 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=379 dst=r3 src=r0 offset=0 imm=44
#line 227 "sample/bindmonitor.c"
    r3 = IMMEDIATE(44);
    // EBPF_OP_JSGT_REG pc=380 dst=r3 src=r2 offset=-331 imm=0
#line 227 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 227 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=381 dst=r1 src=r1 offset=43 imm=0
#line 228 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(43));
    // EBPF_OP_STXB pc=382 dst=r0 src=r1 offset=47 imm=0
#line 228 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(47)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=383 dst=r1 src=r6 offset=0 imm=0
#line 230 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=384 dst=r2 src=r6 offset=8 imm=0
#line 230 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=385 dst=r2 src=r1 offset=0 imm=0
#line 230 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=386 dst=r3 src=r0 offset=0 imm=45
#line 230 "sample/bindmonitor.c"
    r3 = IMMEDIATE(45);
    // EBPF_OP_JSGT_REG pc=387 dst=r3 src=r2 offset=-338 imm=0
#line 230 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 230 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=388 dst=r1 src=r1 offset=44 imm=0
#line 231 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_STXB pc=389 dst=r0 src=r1 offset=48 imm=0
#line 231 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(48)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=390 dst=r1 src=r6 offset=0 imm=0
#line 233 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=391 dst=r2 src=r6 offset=8 imm=0
#line 233 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=392 dst=r2 src=r1 offset=0 imm=0
#line 233 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=393 dst=r3 src=r0 offset=0 imm=46
#line 233 "sample/bindmonitor.c"
    r3 = IMMEDIATE(46);
    // EBPF_OP_JSGT_REG pc=394 dst=r3 src=r2 offset=-345 imm=0
#line 233 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 233 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=395 dst=r1 src=r1 offset=45 imm=0
#line 234 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(45));
    // EBPF_OP_STXB pc=396 dst=r0 src=r1 offset=49 imm=0
#line 234 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(49)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=397 dst=r1 src=r6 offset=0 imm=0
#line 236 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=398 dst=r2 src=r6 offset=8 imm=0
#line 236 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=399 dst=r2 src=r1 offset=0 imm=0
#line 236 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=400 dst=r3 src=r0 offset=0 imm=47
#line 236 "sample/bindmonitor.c"
    r3 = IMMEDIATE(47);
    // EBPF_OP_JSGT_REG pc=401 dst=r3 src=r2 offset=-352 imm=0
#line 236 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 236 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=402 dst=r1 src=r1 offset=46 imm=0
#line 237 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(46));
    // EBPF_OP_STXB pc=403 dst=r0 src=r1 offset=50 imm=0
#line 237 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(50)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=404 dst=r1 src=r6 offset=0 imm=0
#line 239 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=405 dst=r2 src=r6 offset=8 imm=0
#line 239 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=406 dst=r2 src=r1 offset=0 imm=0
#line 239 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=407 dst=r3 src=r0 offset=0 imm=48
#line 239 "sample/bindmonitor.c"
    r3 = IMMEDIATE(48);
    // EBPF_OP_JSGT_REG pc=408 dst=r3 src=r2 offset=-359 imm=0
#line 239 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 239 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=409 dst=r1 src=r1 offset=47 imm=0
#line 240 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(47));
    // EBPF_OP_STXB pc=410 dst=r0 src=r1 offset=51 imm=0
#line 240 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(51)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=411 dst=r1 src=r6 offset=0 imm=0
#line 242 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=412 dst=r2 src=r6 offset=8 imm=0
#line 242 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=413 dst=r2 src=r1 offset=0 imm=0
#line 242 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=414 dst=r3 src=r0 offset=0 imm=49
#line 242 "sample/bindmonitor.c"
    r3 = IMMEDIATE(49);
    // EBPF_OP_JSGT_REG pc=415 dst=r3 src=r2 offset=-366 imm=0
#line 242 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 242 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=416 dst=r1 src=r1 offset=48 imm=0
#line 243 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(48));
    // EBPF_OP_STXB pc=417 dst=r0 src=r1 offset=52 imm=0
#line 243 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(52)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=418 dst=r1 src=r6 offset=0 imm=0
#line 245 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=419 dst=r2 src=r6 offset=8 imm=0
#line 245 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=420 dst=r2 src=r1 offset=0 imm=0
#line 245 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=421 dst=r3 src=r0 offset=0 imm=50
#line 245 "sample/bindmonitor.c"
    r3 = IMMEDIATE(50);
    // EBPF_OP_JSGT_REG pc=422 dst=r3 src=r2 offset=-373 imm=0
#line 245 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 245 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=423 dst=r1 src=r1 offset=49 imm=0
#line 246 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(49));
    // EBPF_OP_STXB pc=424 dst=r0 src=r1 offset=53 imm=0
#line 246 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(53)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=425 dst=r1 src=r6 offset=0 imm=0
#line 248 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=426 dst=r2 src=r6 offset=8 imm=0
#line 248 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=427 dst=r2 src=r1 offset=0 imm=0
#line 248 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=428 dst=r3 src=r0 offset=0 imm=51
#line 248 "sample/bindmonitor.c"
    r3 = IMMEDIATE(51);
    // EBPF_OP_JSGT_REG pc=429 dst=r3 src=r2 offset=-380 imm=0
#line 248 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 248 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=430 dst=r1 src=r1 offset=50 imm=0
#line 249 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(50));
    // EBPF_OP_STXB pc=431 dst=r0 src=r1 offset=54 imm=0
#line 249 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(54)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=432 dst=r1 src=r6 offset=0 imm=0
#line 251 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=433 dst=r2 src=r6 offset=8 imm=0
#line 251 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=434 dst=r2 src=r1 offset=0 imm=0
#line 251 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=435 dst=r3 src=r0 offset=0 imm=52
#line 251 "sample/bindmonitor.c"
    r3 = IMMEDIATE(52);
    // EBPF_OP_JSGT_REG pc=436 dst=r3 src=r2 offset=-387 imm=0
#line 251 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 251 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=437 dst=r1 src=r1 offset=51 imm=0
#line 252 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(51));
    // EBPF_OP_STXB pc=438 dst=r0 src=r1 offset=55 imm=0
#line 252 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(55)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=439 dst=r1 src=r6 offset=0 imm=0
#line 254 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=440 dst=r2 src=r6 offset=8 imm=0
#line 254 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=441 dst=r2 src=r1 offset=0 imm=0
#line 254 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=442 dst=r3 src=r0 offset=0 imm=53
#line 254 "sample/bindmonitor.c"
    r3 = IMMEDIATE(53);
    // EBPF_OP_JSGT_REG pc=443 dst=r3 src=r2 offset=-394 imm=0
#line 254 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 254 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=444 dst=r1 src=r1 offset=52 imm=0
#line 255 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(52));
    // EBPF_OP_STXB pc=445 dst=r0 src=r1 offset=56 imm=0
#line 255 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(56)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=446 dst=r1 src=r6 offset=0 imm=0
#line 257 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=447 dst=r2 src=r6 offset=8 imm=0
#line 257 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=448 dst=r2 src=r1 offset=0 imm=0
#line 257 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=449 dst=r3 src=r0 offset=0 imm=54
#line 257 "sample/bindmonitor.c"
    r3 = IMMEDIATE(54);
    // EBPF_OP_JSGT_REG pc=450 dst=r3 src=r2 offset=-401 imm=0
#line 257 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 257 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=451 dst=r1 src=r1 offset=53 imm=0
#line 258 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(53));
    // EBPF_OP_STXB pc=452 dst=r0 src=r1 offset=57 imm=0
#line 258 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(57)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=453 dst=r1 src=r6 offset=0 imm=0
#line 260 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=454 dst=r2 src=r6 offset=8 imm=0
#line 260 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=455 dst=r2 src=r1 offset=0 imm=0
#line 260 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=456 dst=r3 src=r0 offset=0 imm=55
#line 260 "sample/bindmonitor.c"
    r3 = IMMEDIATE(55);
    // EBPF_OP_JSGT_REG pc=457 dst=r3 src=r2 offset=-408 imm=0
#line 260 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 260 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=458 dst=r1 src=r1 offset=54 imm=0
#line 261 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(54));
    // EBPF_OP_STXB pc=459 dst=r0 src=r1 offset=58 imm=0
#line 261 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(58)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=460 dst=r1 src=r6 offset=0 imm=0
#line 263 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=461 dst=r2 src=r6 offset=8 imm=0
#line 263 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=462 dst=r2 src=r1 offset=0 imm=0
#line 263 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=463 dst=r3 src=r0 offset=0 imm=56
#line 263 "sample/bindmonitor.c"
    r3 = IMMEDIATE(56);
    // EBPF_OP_JSGT_REG pc=464 dst=r3 src=r2 offset=-415 imm=0
#line 263 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 263 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=465 dst=r1 src=r1 offset=55 imm=0
#line 264 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(55));
    // EBPF_OP_STXB pc=466 dst=r0 src=r1 offset=59 imm=0
#line 264 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(59)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=467 dst=r1 src=r6 offset=0 imm=0
#line 266 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=468 dst=r2 src=r6 offset=8 imm=0
#line 266 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=469 dst=r2 src=r1 offset=0 imm=0
#line 266 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=470 dst=r3 src=r0 offset=0 imm=57
#line 266 "sample/bindmonitor.c"
    r3 = IMMEDIATE(57);
    // EBPF_OP_JSGT_REG pc=471 dst=r3 src=r2 offset=-422 imm=0
#line 266 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 266 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=472 dst=r1 src=r1 offset=56 imm=0
#line 267 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(56));
    // EBPF_OP_STXB pc=473 dst=r0 src=r1 offset=60 imm=0
#line 267 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(60)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=474 dst=r1 src=r6 offset=0 imm=0
#line 269 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=475 dst=r2 src=r6 offset=8 imm=0
#line 269 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=476 dst=r2 src=r1 offset=0 imm=0
#line 269 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=477 dst=r3 src=r0 offset=0 imm=58
#line 269 "sample/bindmonitor.c"
    r3 = IMMEDIATE(58);
    // EBPF_OP_JSGT_REG pc=478 dst=r3 src=r2 offset=-429 imm=0
#line 269 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 269 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=479 dst=r1 src=r1 offset=57 imm=0
#line 270 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(57));
    // EBPF_OP_STXB pc=480 dst=r0 src=r1 offset=61 imm=0
#line 270 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(61)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=481 dst=r1 src=r6 offset=0 imm=0
#line 272 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=482 dst=r2 src=r6 offset=8 imm=0
#line 272 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=483 dst=r2 src=r1 offset=0 imm=0
#line 272 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=484 dst=r3 src=r0 offset=0 imm=59
#line 272 "sample/bindmonitor.c"
    r3 = IMMEDIATE(59);
    // EBPF_OP_JSGT_REG pc=485 dst=r3 src=r2 offset=-436 imm=0
#line 272 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 272 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=486 dst=r1 src=r1 offset=58 imm=0
#line 273 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(58));
    // EBPF_OP_STXB pc=487 dst=r0 src=r1 offset=62 imm=0
#line 273 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(62)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=488 dst=r1 src=r6 offset=0 imm=0
#line 275 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=489 dst=r2 src=r6 offset=8 imm=0
#line 275 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=490 dst=r2 src=r1 offset=0 imm=0
#line 275 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=491 dst=r3 src=r0 offset=0 imm=60
#line 275 "sample/bindmonitor.c"
    r3 = IMMEDIATE(60);
    // EBPF_OP_JSGT_REG pc=492 dst=r3 src=r2 offset=-443 imm=0
#line 275 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 275 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=493 dst=r1 src=r1 offset=59 imm=0
#line 276 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(59));
    // EBPF_OP_STXB pc=494 dst=r0 src=r1 offset=63 imm=0
#line 276 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(63)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=495 dst=r1 src=r6 offset=0 imm=0
#line 278 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=496 dst=r2 src=r6 offset=8 imm=0
#line 278 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=497 dst=r2 src=r1 offset=0 imm=0
#line 278 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=498 dst=r3 src=r0 offset=0 imm=61
#line 278 "sample/bindmonitor.c"
    r3 = IMMEDIATE(61);
    // EBPF_OP_JSGT_REG pc=499 dst=r3 src=r2 offset=-450 imm=0
#line 278 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 278 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=500 dst=r1 src=r1 offset=60 imm=0
#line 279 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(60));
    // EBPF_OP_STXB pc=501 dst=r0 src=r1 offset=64 imm=0
#line 279 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(64)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=502 dst=r1 src=r6 offset=0 imm=0
#line 281 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=503 dst=r2 src=r6 offset=8 imm=0
#line 281 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=504 dst=r2 src=r1 offset=0 imm=0
#line 281 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=505 dst=r3 src=r0 offset=0 imm=62
#line 281 "sample/bindmonitor.c"
    r3 = IMMEDIATE(62);
    // EBPF_OP_JSGT_REG pc=506 dst=r3 src=r2 offset=-457 imm=0
#line 281 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 281 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=507 dst=r1 src=r1 offset=61 imm=0
#line 282 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(61));
    // EBPF_OP_STXB pc=508 dst=r0 src=r1 offset=65 imm=0
#line 282 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(65)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=509 dst=r1 src=r6 offset=0 imm=0
#line 284 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=510 dst=r2 src=r6 offset=8 imm=0
#line 284 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=511 dst=r2 src=r1 offset=0 imm=0
#line 284 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=512 dst=r3 src=r0 offset=0 imm=63
#line 284 "sample/bindmonitor.c"
    r3 = IMMEDIATE(63);
    // EBPF_OP_JSGT_REG pc=513 dst=r3 src=r2 offset=-464 imm=0
#line 284 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 284 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=514 dst=r1 src=r1 offset=62 imm=0
#line 285 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(62));
    // EBPF_OP_STXB pc=515 dst=r0 src=r1 offset=66 imm=0
#line 285 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(66)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=516 dst=r1 src=r6 offset=0 imm=0
#line 287 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=517 dst=r2 src=r6 offset=8 imm=0
#line 287 "sample/bindmonitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=518 dst=r2 src=r1 offset=0 imm=0
#line 287 "sample/bindmonitor.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=519 dst=r3 src=r0 offset=0 imm=64
#line 287 "sample/bindmonitor.c"
    r3 = IMMEDIATE(64);
    // EBPF_OP_JSGT_REG pc=520 dst=r3 src=r2 offset=-471 imm=0
#line 287 "sample/bindmonitor.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 287 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_LDXB pc=521 dst=r1 src=r1 offset=63 imm=0
#line 288 "sample/bindmonitor.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(63));
    // EBPF_OP_STXB pc=522 dst=r0 src=r1 offset=67 imm=0
#line 288 "sample/bindmonitor.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(67)) = (uint8_t)r1;
    // EBPF_OP_JA pc=523 dst=r0 src=r0 offset=-474 imm=0
#line 288 "sample/bindmonitor.c"
    goto label_2;
label_4:
    // EBPF_OP_LDXW pc=524 dst=r1 src=r0 offset=0 imm=0
#line 328 "sample/bindmonitor.c"
    r1 = *(uint32_t*)(uintptr_t)(r0 + OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=525 dst=r1 src=r0 offset=6 imm=0
#line 328 "sample/bindmonitor.c"
    if (r1 == IMMEDIATE(0))
#line 328 "sample/bindmonitor.c"
        goto label_6;
    // EBPF_OP_ADD64_IMM pc=526 dst=r1 src=r0 offset=0 imm=-1
#line 329 "sample/bindmonitor.c"
    r1 += IMMEDIATE(-1);
    // EBPF_OP_STXW pc=527 dst=r0 src=r1 offset=0 imm=0
#line 329 "sample/bindmonitor.c"
    *(uint32_t*)(uintptr_t)(r0 + OFFSET(0)) = (uint32_t)r1;
label_5:
    // EBPF_OP_MOV64_IMM pc=528 dst=r8 src=r0 offset=0 imm=0
#line 329 "sample/bindmonitor.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_LSH64_IMM pc=529 dst=r1 src=r0 offset=0 imm=32
#line 336 "sample/bindmonitor.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=530 dst=r1 src=r0 offset=0 imm=32
#line 336 "sample/bindmonitor.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=531 dst=r1 src=r0 offset=15 imm=0
#line 336 "sample/bindmonitor.c"
    if (r1 != IMMEDIATE(0))
#line 336 "sample/bindmonitor.c"
        goto label_9;
label_6:
    // EBPF_OP_LDXDW pc=532 dst=r1 src=r6 offset=16 imm=0
#line 337 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(16));
    // EBPF_OP_STXDW pc=533 dst=r10 src=r1 offset=-80 imm=0
#line 337 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=534 dst=r2 src=r10 offset=0 imm=0
#line 337 "sample/bindmonitor.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=535 dst=r2 src=r0 offset=0 imm=-80
#line 337 "sample/bindmonitor.c"
    r2 += IMMEDIATE(-80);
    // EBPF_OP_LDDW pc=536 dst=r1 src=r0 offset=0 imm=0
#line 338 "sample/bindmonitor.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=538 dst=r0 src=r0 offset=0 imm=3
#line 338 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[5].address
#line 338 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 338 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[5].tail_call) && (r0 == 0))
#line 338 "sample/bindmonitor.c"
        return 0;
    // EBPF_OP_JA pc=539 dst=r0 src=r0 offset=6 imm=0
#line 338 "sample/bindmonitor.c"
    goto label_8;
label_7:
    // EBPF_OP_MOV64_IMM pc=540 dst=r8 src=r0 offset=0 imm=1
#line 338 "sample/bindmonitor.c"
    r8 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=541 dst=r1 src=r0 offset=0 imm=0
#line 321 "sample/bindmonitor.c"
    r1 = *(uint32_t*)(uintptr_t)(r0 + OFFSET(0));
    // EBPF_OP_LDXW pc=542 dst=r2 src=r7 offset=0 imm=0
#line 321 "sample/bindmonitor.c"
    r2 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_JGE_REG pc=543 dst=r1 src=r2 offset=3 imm=0
#line 321 "sample/bindmonitor.c"
    if (r1 >= r2)
#line 321 "sample/bindmonitor.c"
        goto label_9;
    // EBPF_OP_ADD64_IMM pc=544 dst=r1 src=r0 offset=0 imm=1
#line 325 "sample/bindmonitor.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=545 dst=r0 src=r1 offset=0 imm=0
#line 325 "sample/bindmonitor.c"
    *(uint32_t*)(uintptr_t)(r0 + OFFSET(0)) = (uint32_t)r1;
label_8:
    // EBPF_OP_MOV64_IMM pc=546 dst=r8 src=r0 offset=0 imm=0
#line 325 "sample/bindmonitor.c"
    r8 = IMMEDIATE(0);
label_9:
    // EBPF_OP_MOV64_REG pc=547 dst=r0 src=r8 offset=0 imm=0
#line 342 "sample/bindmonitor.c"
    r0 = r8;
    // EBPF_OP_EXIT pc=548 dst=r0 src=r0 offset=0 imm=0
#line 342 "sample/bindmonitor.c"
    return r0;
#line 342 "sample/bindmonitor.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        BindMonitor,
        "bind",
        "bind",
        "BindMonitor",
        BindMonitor_maps,
        3,
        BindMonitor_helpers,
        6,
        549,
        &BindMonitor_program_type_guid,
        &BindMonitor_attach_type_guid,
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

metadata_table_t bindmonitor_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
