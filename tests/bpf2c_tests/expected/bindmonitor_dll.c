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
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         18,                // Identifier for a map template.
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
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         23,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "limits_map"},
    {NULL,
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         8,                 // Size in bytes of a map key.
         16,                // Size in bytes of a map value.
         1024,              // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         29,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "audit_map"},
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
    {NULL, 22, "helper_id_22"},
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
#line 112 "sample/bindmonitor.c"
{
#line 112 "sample/bindmonitor.c"
    // Prologue
#line 112 "sample/bindmonitor.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 112 "sample/bindmonitor.c"
    register uint64_t r0 = 0;
#line 112 "sample/bindmonitor.c"
    register uint64_t r1 = 0;
#line 112 "sample/bindmonitor.c"
    register uint64_t r2 = 0;
#line 112 "sample/bindmonitor.c"
    register uint64_t r3 = 0;
#line 112 "sample/bindmonitor.c"
    register uint64_t r4 = 0;
#line 112 "sample/bindmonitor.c"
    register uint64_t r5 = 0;
#line 112 "sample/bindmonitor.c"
    register uint64_t r6 = 0;
#line 112 "sample/bindmonitor.c"
    register uint64_t r7 = 0;
#line 112 "sample/bindmonitor.c"
    register uint64_t r8 = 0;
#line 112 "sample/bindmonitor.c"
    register uint64_t r9 = 0;
#line 112 "sample/bindmonitor.c"
    register uint64_t r10 = 0;

#line 112 "sample/bindmonitor.c"
    r1 = (uintptr_t)context;
#line 112 "sample/bindmonitor.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 112 "sample/bindmonitor.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r8 src=r0 offset=0 imm=0
#line 112 "sample/bindmonitor.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r8 offset=-84 imm=0
#line 114 "sample/bindmonitor.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-84)) = (uint32_t)r8;
    // EBPF_OP_CALL pc=3 dst=r0 src=r0 offset=0 imm=19
#line 61 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[0].address
#line 61 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 61 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[0].tail_call) && (r0 == 0))
#line 61 "sample/bindmonitor.c"
        return 0;
    // EBPF_OP_STXDW pc=4 dst=r10 src=r0 offset=-8 imm=0
#line 61 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r0;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r8 offset=-72 imm=0
#line 62 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r8;
    // EBPF_OP_STXDW pc=6 dst=r10 src=r8 offset=-80 imm=0
#line 62 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r8;
    // EBPF_OP_MOV64_REG pc=7 dst=r1 src=r6 offset=0 imm=0
#line 64 "sample/bindmonitor.c"
    r1 = r6;
    // EBPF_OP_CALL pc=8 dst=r0 src=r0 offset=0 imm=20
#line 64 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[1].address
#line 64 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 64 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[1].tail_call) && (r0 == 0))
#line 64 "sample/bindmonitor.c"
        return 0;
    // EBPF_OP_STXDW pc=9 dst=r10 src=r0 offset=-80 imm=0
#line 64 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r0;
    // EBPF_OP_MOV64_REG pc=10 dst=r1 src=r6 offset=0 imm=0
#line 65 "sample/bindmonitor.c"
    r1 = r6;
    // EBPF_OP_CALL pc=11 dst=r0 src=r0 offset=0 imm=21
#line 65 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[2].address
#line 65 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 65 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[2].tail_call) && (r0 == 0))
#line 65 "sample/bindmonitor.c"
        return 0;
    // EBPF_OP_STXW pc=12 dst=r10 src=r0 offset=-72 imm=0
#line 65 "sample/bindmonitor.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r0;
    // EBPF_OP_MOV64_REG pc=13 dst=r2 src=r10 offset=0 imm=0
#line 65 "sample/bindmonitor.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=14 dst=r2 src=r0 offset=0 imm=-8
#line 65 "sample/bindmonitor.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=15 dst=r3 src=r10 offset=0 imm=0
#line 65 "sample/bindmonitor.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=16 dst=r3 src=r0 offset=0 imm=-80
#line 65 "sample/bindmonitor.c"
    r3 += IMMEDIATE(-80);
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=0
#line 67 "sample/bindmonitor.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_MOV64_IMM pc=19 dst=r4 src=r0 offset=0 imm=0
#line 67 "sample/bindmonitor.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=20 dst=r0 src=r0 offset=0 imm=2
#line 67 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[3].address
#line 67 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 67 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[3].tail_call) && (r0 == 0))
#line 67 "sample/bindmonitor.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=21 dst=r2 src=r10 offset=0 imm=0
#line 67 "sample/bindmonitor.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r2 src=r0 offset=0 imm=-84
#line 67 "sample/bindmonitor.c"
    r2 += IMMEDIATE(-84);
    // EBPF_OP_LDDW pc=23 dst=r1 src=r0 offset=0 imm=0
#line 119 "sample/bindmonitor.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=1
#line 119 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[4].address
#line 119 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 119 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[4].tail_call) && (r0 == 0))
#line 119 "sample/bindmonitor.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=26 dst=r7 src=r0 offset=0 imm=0
#line 119 "sample/bindmonitor.c"
    r7 = r0;
    // EBPF_OP_JEQ_IMM pc=27 dst=r7 src=r0 offset=77 imm=0
#line 120 "sample/bindmonitor.c"
    if (r7 == IMMEDIATE(0))
#line 120 "sample/bindmonitor.c"
        goto label_7;
    // EBPF_OP_LDXW pc=28 dst=r1 src=r7 offset=0 imm=0
#line 120 "sample/bindmonitor.c"
    r1 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=29 dst=r1 src=r0 offset=75 imm=0
#line 120 "sample/bindmonitor.c"
    if (r1 == IMMEDIATE(0))
#line 120 "sample/bindmonitor.c"
        goto label_7;
    // EBPF_OP_LDXDW pc=30 dst=r1 src=r6 offset=16 imm=0
#line 73 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(16));
    // EBPF_OP_STXDW pc=31 dst=r10 src=r1 offset=-8 imm=0
#line 73 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=32 dst=r1 src=r0 offset=0 imm=0
#line 73 "sample/bindmonitor.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=33 dst=r10 src=r1 offset=-16 imm=0
#line 75 "sample/bindmonitor.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_STXDW pc=34 dst=r10 src=r1 offset=-24 imm=0
#line 75 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=35 dst=r10 src=r1 offset=-32 imm=0
#line 75 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=36 dst=r10 src=r1 offset=-40 imm=0
#line 75 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=37 dst=r10 src=r1 offset=-48 imm=0
#line 75 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=38 dst=r10 src=r1 offset=-56 imm=0
#line 75 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=39 dst=r10 src=r1 offset=-64 imm=0
#line 75 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=40 dst=r10 src=r1 offset=-72 imm=0
#line 75 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=41 dst=r10 src=r1 offset=-80 imm=0
#line 75 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=42 dst=r2 src=r10 offset=0 imm=0
#line 75 "sample/bindmonitor.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=43 dst=r2 src=r0 offset=0 imm=-8
#line 75 "sample/bindmonitor.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=44 dst=r1 src=r0 offset=0 imm=0
#line 78 "sample/bindmonitor.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=46 dst=r0 src=r0 offset=0 imm=1
#line 78 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[4].address
#line 78 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 78 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[4].tail_call) && (r0 == 0))
#line 78 "sample/bindmonitor.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=47 dst=r9 src=r0 offset=0 imm=0
#line 78 "sample/bindmonitor.c"
    r9 = r0;
    // EBPF_OP_JNE_IMM pc=48 dst=r9 src=r0 offset=28 imm=0
#line 79 "sample/bindmonitor.c"
    if (r9 != IMMEDIATE(0))
#line 79 "sample/bindmonitor.c"
        goto label_1;
    // EBPF_OP_LDXW pc=49 dst=r1 src=r6 offset=44 imm=0
#line 83 "sample/bindmonitor.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_JNE_IMM pc=50 dst=r1 src=r0 offset=53 imm=0
#line 83 "sample/bindmonitor.c"
    if (r1 != IMMEDIATE(0))
#line 83 "sample/bindmonitor.c"
        goto label_6;
    // EBPF_OP_LDXDW pc=51 dst=r1 src=r6 offset=0 imm=0
#line 87 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=52 dst=r1 src=r0 offset=51 imm=0
#line 87 "sample/bindmonitor.c"
    if (r1 == IMMEDIATE(0))
#line 87 "sample/bindmonitor.c"
        goto label_6;
    // EBPF_OP_LDXDW pc=53 dst=r1 src=r6 offset=8 imm=0
#line 87 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_JEQ_IMM pc=54 dst=r1 src=r0 offset=49 imm=0
#line 87 "sample/bindmonitor.c"
    if (r1 == IMMEDIATE(0))
#line 87 "sample/bindmonitor.c"
        goto label_6;
    // EBPF_OP_MOV64_REG pc=55 dst=r8 src=r10 offset=0 imm=0
#line 87 "sample/bindmonitor.c"
    r8 = r10;
    // EBPF_OP_ADD64_IMM pc=56 dst=r8 src=r0 offset=0 imm=-8
#line 87 "sample/bindmonitor.c"
    r8 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=57 dst=r3 src=r10 offset=0 imm=0
#line 87 "sample/bindmonitor.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=58 dst=r3 src=r0 offset=0 imm=-80
#line 87 "sample/bindmonitor.c"
    r3 += IMMEDIATE(-80);
    // EBPF_OP_LDDW pc=59 dst=r1 src=r0 offset=0 imm=0
#line 91 "sample/bindmonitor.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_REG pc=61 dst=r2 src=r8 offset=0 imm=0
#line 91 "sample/bindmonitor.c"
    r2 = r8;
    // EBPF_OP_MOV64_IMM pc=62 dst=r4 src=r0 offset=0 imm=0
#line 91 "sample/bindmonitor.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=63 dst=r0 src=r0 offset=0 imm=2
#line 91 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[3].address
#line 91 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 91 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[3].tail_call) && (r0 == 0))
#line 91 "sample/bindmonitor.c"
        return 0;
    // EBPF_OP_LDDW pc=64 dst=r1 src=r0 offset=0 imm=0
#line 92 "sample/bindmonitor.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_REG pc=66 dst=r2 src=r8 offset=0 imm=0
#line 92 "sample/bindmonitor.c"
    r2 = r8;
    // EBPF_OP_CALL pc=67 dst=r0 src=r0 offset=0 imm=1
#line 92 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[4].address
#line 92 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 92 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[4].tail_call) && (r0 == 0))
#line 92 "sample/bindmonitor.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=68 dst=r9 src=r0 offset=0 imm=0
#line 92 "sample/bindmonitor.c"
    r9 = r0;
    // EBPF_OP_JEQ_IMM pc=69 dst=r9 src=r0 offset=34 imm=0
#line 93 "sample/bindmonitor.c"
    if (r9 == IMMEDIATE(0))
#line 93 "sample/bindmonitor.c"
        goto label_6;
    // EBPF_OP_LDXDW pc=70 dst=r3 src=r6 offset=0 imm=0
#line 97 "sample/bindmonitor.c"
    r3 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=71 dst=r4 src=r6 offset=8 imm=0
#line 97 "sample/bindmonitor.c"
    r4 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=72 dst=r4 src=r3 offset=0 imm=0
#line 97 "sample/bindmonitor.c"
    r4 -= r3;
    // EBPF_OP_MOV64_REG pc=73 dst=r1 src=r9 offset=0 imm=0
#line 97 "sample/bindmonitor.c"
    r1 = r9;
    // EBPF_OP_ADD64_IMM pc=74 dst=r1 src=r0 offset=0 imm=4
#line 97 "sample/bindmonitor.c"
    r1 += IMMEDIATE(4);
    // EBPF_OP_MOV64_IMM pc=75 dst=r2 src=r0 offset=0 imm=64
#line 97 "sample/bindmonitor.c"
    r2 = IMMEDIATE(64);
    // EBPF_OP_CALL pc=76 dst=r0 src=r0 offset=0 imm=22
#line 97 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[5].address
#line 97 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 97 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[5].tail_call) && (r0 == 0))
#line 97 "sample/bindmonitor.c"
        return 0;
label_1:
    // EBPF_OP_LDXW pc=77 dst=r1 src=r6 offset=44 imm=0
#line 130 "sample/bindmonitor.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_JEQ_IMM pc=78 dst=r1 src=r0 offset=3 imm=0
#line 130 "sample/bindmonitor.c"
    if (r1 == IMMEDIATE(0))
#line 130 "sample/bindmonitor.c"
        goto label_2;
    // EBPF_OP_JEQ_IMM pc=79 dst=r1 src=r0 offset=9 imm=2
#line 130 "sample/bindmonitor.c"
    if (r1 == IMMEDIATE(2))
#line 130 "sample/bindmonitor.c"
        goto label_3;
    // EBPF_OP_LDXW pc=80 dst=r1 src=r9 offset=0 imm=0
#line 147 "sample/bindmonitor.c"
    r1 = *(uint32_t*)(uintptr_t)(r9 + OFFSET(0));
    // EBPF_OP_JA pc=81 dst=r0 src=r0 offset=11 imm=0
#line 147 "sample/bindmonitor.c"
    goto label_4;
label_2:
    // EBPF_OP_MOV64_IMM pc=82 dst=r8 src=r0 offset=0 imm=1
#line 147 "sample/bindmonitor.c"
    r8 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=83 dst=r1 src=r9 offset=0 imm=0
#line 132 "sample/bindmonitor.c"
    r1 = *(uint32_t*)(uintptr_t)(r9 + OFFSET(0));
    // EBPF_OP_LDXW pc=84 dst=r2 src=r7 offset=0 imm=0
#line 132 "sample/bindmonitor.c"
    r2 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_JGE_REG pc=85 dst=r1 src=r2 offset=19 imm=0
#line 132 "sample/bindmonitor.c"
    if (r1 >= r2)
#line 132 "sample/bindmonitor.c"
        goto label_7;
    // EBPF_OP_ADD64_IMM pc=86 dst=r1 src=r0 offset=0 imm=1
#line 136 "sample/bindmonitor.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=87 dst=r9 src=r1 offset=0 imm=0
#line 136 "sample/bindmonitor.c"
    *(uint32_t*)(uintptr_t)(r9 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_JA pc=88 dst=r0 src=r0 offset=15 imm=0
#line 136 "sample/bindmonitor.c"
    goto label_6;
label_3:
    // EBPF_OP_LDXW pc=89 dst=r1 src=r9 offset=0 imm=0
#line 139 "sample/bindmonitor.c"
    r1 = *(uint32_t*)(uintptr_t)(r9 + OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=90 dst=r1 src=r0 offset=6 imm=0
#line 139 "sample/bindmonitor.c"
    if (r1 == IMMEDIATE(0))
#line 139 "sample/bindmonitor.c"
        goto label_5;
    // EBPF_OP_ADD64_IMM pc=91 dst=r1 src=r0 offset=0 imm=-1
#line 140 "sample/bindmonitor.c"
    r1 += IMMEDIATE(-1);
    // EBPF_OP_STXW pc=92 dst=r9 src=r1 offset=0 imm=0
#line 140 "sample/bindmonitor.c"
    *(uint32_t*)(uintptr_t)(r9 + OFFSET(0)) = (uint32_t)r1;
label_4:
    // EBPF_OP_MOV64_IMM pc=93 dst=r8 src=r0 offset=0 imm=0
#line 140 "sample/bindmonitor.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_LSH64_IMM pc=94 dst=r1 src=r0 offset=0 imm=32
#line 147 "sample/bindmonitor.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=95 dst=r1 src=r0 offset=0 imm=32
#line 147 "sample/bindmonitor.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JNE_IMM pc=96 dst=r1 src=r0 offset=8 imm=0
#line 147 "sample/bindmonitor.c"
    if (r1 != IMMEDIATE(0))
#line 147 "sample/bindmonitor.c"
        goto label_7;
label_5:
    // EBPF_OP_LDXDW pc=97 dst=r1 src=r6 offset=16 imm=0
#line 148 "sample/bindmonitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(16));
    // EBPF_OP_STXDW pc=98 dst=r10 src=r1 offset=-80 imm=0
#line 148 "sample/bindmonitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=99 dst=r2 src=r10 offset=0 imm=0
#line 148 "sample/bindmonitor.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=100 dst=r2 src=r0 offset=0 imm=-80
#line 148 "sample/bindmonitor.c"
    r2 += IMMEDIATE(-80);
    // EBPF_OP_LDDW pc=101 dst=r1 src=r0 offset=0 imm=0
#line 149 "sample/bindmonitor.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=103 dst=r0 src=r0 offset=0 imm=3
#line 149 "sample/bindmonitor.c"
    r0 = BindMonitor_helpers[6].address
#line 149 "sample/bindmonitor.c"
         (r1, r2, r3, r4, r5);
#line 149 "sample/bindmonitor.c"
    if ((BindMonitor_helpers[6].tail_call) && (r0 == 0))
#line 149 "sample/bindmonitor.c"
        return 0;
label_6:
    // EBPF_OP_MOV64_IMM pc=104 dst=r8 src=r0 offset=0 imm=0
#line 149 "sample/bindmonitor.c"
    r8 = IMMEDIATE(0);
label_7:
    // EBPF_OP_MOV64_REG pc=105 dst=r0 src=r8 offset=0 imm=0
#line 153 "sample/bindmonitor.c"
    r0 = r8;
    // EBPF_OP_EXIT pc=106 dst=r0 src=r0 offset=0 imm=0
#line 153 "sample/bindmonitor.c"
    return r0;
#line 153 "sample/bindmonitor.c"
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
        7,
        107,
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
    version->minor = 15;
    version->revision = 1;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t bindmonitor_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};
