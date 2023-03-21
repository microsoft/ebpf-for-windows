// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from bindmonitor_tailcall.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table bindmonitor_tailcall##_metadata_table
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
    {NULL,
     {
         BPF_MAP_TYPE_PROG_ARRAY, // Type of map.
         4,                       // Size in bytes of a map key.
         4,                       // Size in bytes of a map value.
         8,                       // Maximum number of entries allowed in the map.
         0,                       // Inner map index.
         PIN_NONE,                // Pinning type for the map.
         0,                       // Identifier for a map template.
         0,                       // The id of the inner map template.
     },
     "prog_array_map"},
    {NULL,
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         4,                 // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         1000,              // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         PIN_NONE,          // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "dummy_map"},
    {NULL,
     {
         BPF_MAP_TYPE_ARRAY_OF_MAPS, // Type of map.
         4,                          // Size in bytes of a map key.
         4,                          // Size in bytes of a map value.
         1,                          // Maximum number of entries allowed in the map.
         0,                          // Inner map index.
         PIN_NONE,                   // Pinning type for the map.
         0,                          // Identifier for a map template.
         10,                         // The id of the inner map template.
     },
     "dummy_outer_map"},
    {NULL,
     {
         BPF_MAP_TYPE_HASH_OF_MAPS, // Type of map.
         4,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         10,                        // Maximum number of entries allowed in the map.
         6,                         // Inner map index.
         PIN_NONE,                  // Pinning type for the map.
         0,                         // Identifier for a map template.
         0,                         // The id of the inner map template.
     },
     "dummy_outer_idx_map"},
    {NULL,
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         4,                 // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         1,                 // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         PIN_NONE,          // Pinning type for the map.
         10,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "dummy_inner_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 7;
}

static helper_function_entry_t BindMonitor_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_maps[] = {
    2,
    3,
};

#pragma code_seg(push, "bind")
static uint64_t
BindMonitor(void* context)
#line 315 "sample/bindmonitor_tailcall.c"
{
#line 315 "sample/bindmonitor_tailcall.c"
    // Prologue
#line 315 "sample/bindmonitor_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 315 "sample/bindmonitor_tailcall.c"
    register uint64_t r0 = 0;
#line 315 "sample/bindmonitor_tailcall.c"
    register uint64_t r1 = 0;
#line 315 "sample/bindmonitor_tailcall.c"
    register uint64_t r2 = 0;
#line 315 "sample/bindmonitor_tailcall.c"
    register uint64_t r3 = 0;
#line 315 "sample/bindmonitor_tailcall.c"
    register uint64_t r4 = 0;
#line 315 "sample/bindmonitor_tailcall.c"
    register uint64_t r5 = 0;
#line 315 "sample/bindmonitor_tailcall.c"
    register uint64_t r6 = 0;
#line 315 "sample/bindmonitor_tailcall.c"
    register uint64_t r10 = 0;

#line 315 "sample/bindmonitor_tailcall.c"
    r1 = (uintptr_t)context;
#line 315 "sample/bindmonitor_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 315 "sample/bindmonitor_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 315 "sample/bindmonitor_tailcall.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 317 "sample/bindmonitor_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 317 "sample/bindmonitor_tailcall.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 317 "sample/bindmonitor_tailcall.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 318 "sample/bindmonitor_tailcall.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 318 "sample/bindmonitor_tailcall.c"
    r0 = BindMonitor_helpers[0].address
#line 318 "sample/bindmonitor_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 318 "sample/bindmonitor_tailcall.c"
    if ((BindMonitor_helpers[0].tail_call) && (r0 == 0))
#line 318 "sample/bindmonitor_tailcall.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=8 dst=r0 src=r0 offset=5 imm=0
#line 320 "sample/bindmonitor_tailcall.c"
    if (r0 != IMMEDIATE(0))
#line 320 "sample/bindmonitor_tailcall.c"
        goto label_1;
        // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r6 offset=0 imm=0
#line 323 "sample/bindmonitor_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=10 dst=r2 src=r0 offset=0 imm=0
#line 323 "sample/bindmonitor_tailcall.c"
    r2 = POINTER(_maps[2].address);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=0
#line 323 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=5
#line 323 "sample/bindmonitor_tailcall.c"
    r0 = BindMonitor_helpers[1].address
#line 323 "sample/bindmonitor_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 323 "sample/bindmonitor_tailcall.c"
    if ((BindMonitor_helpers[1].tail_call) && (r0 == 0))
#line 323 "sample/bindmonitor_tailcall.c"
        return 0;
label_1:
    // EBPF_OP_MOV64_IMM pc=14 dst=r0 src=r0 offset=0 imm=1
#line 326 "sample/bindmonitor_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=15 dst=r0 src=r0 offset=0 imm=0
#line 326 "sample/bindmonitor_tailcall.c"
    return r0;
#line 326 "sample/bindmonitor_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee0_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee0_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee0_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee0_maps[] = {
    2,
    3,
};

#pragma code_seg(push, "bind/0")
static uint64_t
BindMonitor_Callee0(void* context)
#line 331 "sample/bindmonitor_tailcall.c"
{
#line 331 "sample/bindmonitor_tailcall.c"
    // Prologue
#line 331 "sample/bindmonitor_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 331 "sample/bindmonitor_tailcall.c"
    register uint64_t r0 = 0;
#line 331 "sample/bindmonitor_tailcall.c"
    register uint64_t r1 = 0;
#line 331 "sample/bindmonitor_tailcall.c"
    register uint64_t r2 = 0;
#line 331 "sample/bindmonitor_tailcall.c"
    register uint64_t r3 = 0;
#line 331 "sample/bindmonitor_tailcall.c"
    register uint64_t r4 = 0;
#line 331 "sample/bindmonitor_tailcall.c"
    register uint64_t r5 = 0;
#line 331 "sample/bindmonitor_tailcall.c"
    register uint64_t r6 = 0;
#line 331 "sample/bindmonitor_tailcall.c"
    register uint64_t r10 = 0;

#line 331 "sample/bindmonitor_tailcall.c"
    r1 = (uintptr_t)context;
#line 331 "sample/bindmonitor_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 331 "sample/bindmonitor_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 331 "sample/bindmonitor_tailcall.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 333 "sample/bindmonitor_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 333 "sample/bindmonitor_tailcall.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 333 "sample/bindmonitor_tailcall.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 334 "sample/bindmonitor_tailcall.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 334 "sample/bindmonitor_tailcall.c"
    r0 = BindMonitor_Callee0_helpers[0].address
#line 334 "sample/bindmonitor_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 334 "sample/bindmonitor_tailcall.c"
    if ((BindMonitor_Callee0_helpers[0].tail_call) && (r0 == 0))
#line 334 "sample/bindmonitor_tailcall.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=8 dst=r0 src=r0 offset=5 imm=0
#line 336 "sample/bindmonitor_tailcall.c"
    if (r0 != IMMEDIATE(0))
#line 336 "sample/bindmonitor_tailcall.c"
        goto label_1;
        // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r6 offset=0 imm=0
#line 339 "sample/bindmonitor_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=10 dst=r2 src=r0 offset=0 imm=0
#line 339 "sample/bindmonitor_tailcall.c"
    r2 = POINTER(_maps[2].address);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=1
#line 339 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(1);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=5
#line 339 "sample/bindmonitor_tailcall.c"
    r0 = BindMonitor_Callee0_helpers[1].address
#line 339 "sample/bindmonitor_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 339 "sample/bindmonitor_tailcall.c"
    if ((BindMonitor_Callee0_helpers[1].tail_call) && (r0 == 0))
#line 339 "sample/bindmonitor_tailcall.c"
        return 0;
label_1:
    // EBPF_OP_MOV64_IMM pc=14 dst=r0 src=r0 offset=0 imm=1
#line 342 "sample/bindmonitor_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=15 dst=r0 src=r0 offset=0 imm=0
#line 342 "sample/bindmonitor_tailcall.c"
    return r0;
#line 342 "sample/bindmonitor_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee1_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 2, "helper_id_2"},
    {NULL, 3, "helper_id_3"},
};

static GUID BindMonitor_Callee1_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee1_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee1_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "bind/1")
static uint64_t
BindMonitor_Callee1(void* context)
#line 347 "sample/bindmonitor_tailcall.c"
{
#line 347 "sample/bindmonitor_tailcall.c"
    // Prologue
#line 347 "sample/bindmonitor_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 347 "sample/bindmonitor_tailcall.c"
    register uint64_t r0 = 0;
#line 347 "sample/bindmonitor_tailcall.c"
    register uint64_t r1 = 0;
#line 347 "sample/bindmonitor_tailcall.c"
    register uint64_t r2 = 0;
#line 347 "sample/bindmonitor_tailcall.c"
    register uint64_t r3 = 0;
#line 347 "sample/bindmonitor_tailcall.c"
    register uint64_t r4 = 0;
#line 347 "sample/bindmonitor_tailcall.c"
    register uint64_t r5 = 0;
#line 347 "sample/bindmonitor_tailcall.c"
    register uint64_t r6 = 0;
#line 347 "sample/bindmonitor_tailcall.c"
    register uint64_t r7 = 0;
#line 347 "sample/bindmonitor_tailcall.c"
    register uint64_t r8 = 0;
#line 347 "sample/bindmonitor_tailcall.c"
    register uint64_t r10 = 0;

#line 347 "sample/bindmonitor_tailcall.c"
    r1 = (uintptr_t)context;
#line 347 "sample/bindmonitor_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 347 "sample/bindmonitor_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r8 src=r0 offset=0 imm=0
#line 347 "sample/bindmonitor_tailcall.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r8 offset=-84 imm=0
#line 349 "sample/bindmonitor_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-84)) = (uint32_t)r8;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 349 "sample/bindmonitor_tailcall.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-84
#line 349 "sample/bindmonitor_tailcall.c"
    r2 += IMMEDIATE(-84);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 351 "sample/bindmonitor_tailcall.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 351 "sample/bindmonitor_tailcall.c"
    r0 = BindMonitor_Callee1_helpers[0].address
#line 351 "sample/bindmonitor_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 351 "sample/bindmonitor_tailcall.c"
    if ((BindMonitor_Callee1_helpers[0].tail_call) && (r0 == 0))
#line 351 "sample/bindmonitor_tailcall.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r7 src=r0 offset=0 imm=0
#line 351 "sample/bindmonitor_tailcall.c"
    r7 = r0;
    // EBPF_OP_JEQ_IMM pc=9 dst=r7 src=r0 offset=519 imm=0
#line 352 "sample/bindmonitor_tailcall.c"
    if (r7 == IMMEDIATE(0))
#line 352 "sample/bindmonitor_tailcall.c"
        goto label_9;
        // EBPF_OP_LDXW pc=10 dst=r1 src=r7 offset=0 imm=0
#line 352 "sample/bindmonitor_tailcall.c"
    r1 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=11 dst=r1 src=r0 offset=517 imm=0
#line 352 "sample/bindmonitor_tailcall.c"
    if (r1 == IMMEDIATE(0))
#line 352 "sample/bindmonitor_tailcall.c"
        goto label_9;
        // EBPF_OP_LDXDW pc=12 dst=r1 src=r6 offset=16 imm=0
#line 78 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(16));
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-8 imm=0
#line 78 "sample/bindmonitor_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=14 dst=r1 src=r0 offset=0 imm=0
#line 78 "sample/bindmonitor_tailcall.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=15 dst=r10 src=r1 offset=-16 imm=0
#line 80 "sample/bindmonitor_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 80 "sample/bindmonitor_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-32 imm=0
#line 80 "sample/bindmonitor_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=18 dst=r10 src=r1 offset=-40 imm=0
#line 80 "sample/bindmonitor_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-48 imm=0
#line 80 "sample/bindmonitor_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-56 imm=0
#line 80 "sample/bindmonitor_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=21 dst=r10 src=r1 offset=-64 imm=0
#line 80 "sample/bindmonitor_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=22 dst=r10 src=r1 offset=-72 imm=0
#line 80 "sample/bindmonitor_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=23 dst=r10 src=r1 offset=-80 imm=0
#line 80 "sample/bindmonitor_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=24 dst=r2 src=r10 offset=0 imm=0
#line 80 "sample/bindmonitor_tailcall.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=25 dst=r2 src=r0 offset=0 imm=-8
#line 80 "sample/bindmonitor_tailcall.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=26 dst=r1 src=r0 offset=0 imm=0
#line 83 "sample/bindmonitor_tailcall.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=28 dst=r0 src=r0 offset=0 imm=1
#line 83 "sample/bindmonitor_tailcall.c"
    r0 = BindMonitor_Callee1_helpers[0].address
#line 83 "sample/bindmonitor_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 83 "sample/bindmonitor_tailcall.c"
    if ((BindMonitor_Callee1_helpers[0].tail_call) && (r0 == 0))
#line 83 "sample/bindmonitor_tailcall.c"
        return 0;
        // EBPF_OP_JEQ_IMM pc=29 dst=r0 src=r0 offset=7 imm=0
#line 84 "sample/bindmonitor_tailcall.c"
    if (r0 == IMMEDIATE(0))
#line 84 "sample/bindmonitor_tailcall.c"
        goto label_3;
label_1:
    // EBPF_OP_MOV64_IMM pc=30 dst=r8 src=r0 offset=0 imm=0
#line 84 "sample/bindmonitor_tailcall.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_JEQ_IMM pc=31 dst=r0 src=r0 offset=497 imm=0
#line 358 "sample/bindmonitor_tailcall.c"
    if (r0 == IMMEDIATE(0))
#line 358 "sample/bindmonitor_tailcall.c"
        goto label_9;
label_2:
    // EBPF_OP_LDXW pc=32 dst=r1 src=r6 offset=44 imm=0
#line 362 "sample/bindmonitor_tailcall.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_JEQ_IMM pc=33 dst=r1 src=r0 offset=488 imm=0
#line 362 "sample/bindmonitor_tailcall.c"
    if (r1 == IMMEDIATE(0))
#line 362 "sample/bindmonitor_tailcall.c"
        goto label_7;
        // EBPF_OP_JEQ_IMM pc=34 dst=r1 src=r0 offset=471 imm=2
#line 362 "sample/bindmonitor_tailcall.c"
    if (r1 == IMMEDIATE(2))
#line 362 "sample/bindmonitor_tailcall.c"
        goto label_4;
        // EBPF_OP_LDXW pc=35 dst=r1 src=r0 offset=0 imm=0
#line 379 "sample/bindmonitor_tailcall.c"
    r1 = *(uint32_t*)(uintptr_t)(r0 + OFFSET(0));
    // EBPF_OP_JA pc=36 dst=r0 src=r0 offset=473 imm=0
#line 379 "sample/bindmonitor_tailcall.c"
    goto label_5;
label_3:
    // EBPF_OP_LDXW pc=37 dst=r1 src=r6 offset=44 imm=0
#line 88 "sample/bindmonitor_tailcall.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_JNE_IMM pc=38 dst=r1 src=r0 offset=489 imm=0
#line 88 "sample/bindmonitor_tailcall.c"
    if (r1 != IMMEDIATE(0))
#line 88 "sample/bindmonitor_tailcall.c"
        goto label_8;
        // EBPF_OP_LDXDW pc=39 dst=r1 src=r6 offset=0 imm=0
#line 92 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=40 dst=r1 src=r0 offset=487 imm=0
#line 92 "sample/bindmonitor_tailcall.c"
    if (r1 == IMMEDIATE(0))
#line 92 "sample/bindmonitor_tailcall.c"
        goto label_8;
        // EBPF_OP_LDXDW pc=41 dst=r1 src=r6 offset=8 imm=0
#line 92 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_JEQ_IMM pc=42 dst=r1 src=r0 offset=485 imm=0
#line 92 "sample/bindmonitor_tailcall.c"
    if (r1 == IMMEDIATE(0))
#line 92 "sample/bindmonitor_tailcall.c"
        goto label_8;
        // EBPF_OP_MOV64_REG pc=43 dst=r8 src=r10 offset=0 imm=0
#line 92 "sample/bindmonitor_tailcall.c"
    r8 = r10;
    // EBPF_OP_ADD64_IMM pc=44 dst=r8 src=r0 offset=0 imm=-8
#line 92 "sample/bindmonitor_tailcall.c"
    r8 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=45 dst=r3 src=r10 offset=0 imm=0
#line 92 "sample/bindmonitor_tailcall.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=46 dst=r3 src=r0 offset=0 imm=-80
#line 92 "sample/bindmonitor_tailcall.c"
    r3 += IMMEDIATE(-80);
    // EBPF_OP_LDDW pc=47 dst=r1 src=r0 offset=0 imm=0
#line 96 "sample/bindmonitor_tailcall.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_REG pc=49 dst=r2 src=r8 offset=0 imm=0
#line 96 "sample/bindmonitor_tailcall.c"
    r2 = r8;
    // EBPF_OP_MOV64_IMM pc=50 dst=r4 src=r0 offset=0 imm=0
#line 96 "sample/bindmonitor_tailcall.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=51 dst=r0 src=r0 offset=0 imm=2
#line 96 "sample/bindmonitor_tailcall.c"
    r0 = BindMonitor_Callee1_helpers[1].address
#line 96 "sample/bindmonitor_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 96 "sample/bindmonitor_tailcall.c"
    if ((BindMonitor_Callee1_helpers[1].tail_call) && (r0 == 0))
#line 96 "sample/bindmonitor_tailcall.c"
        return 0;
        // EBPF_OP_LDDW pc=52 dst=r1 src=r0 offset=0 imm=0
#line 97 "sample/bindmonitor_tailcall.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_REG pc=54 dst=r2 src=r8 offset=0 imm=0
#line 97 "sample/bindmonitor_tailcall.c"
    r2 = r8;
    // EBPF_OP_CALL pc=55 dst=r0 src=r0 offset=0 imm=1
#line 97 "sample/bindmonitor_tailcall.c"
    r0 = BindMonitor_Callee1_helpers[0].address
#line 97 "sample/bindmonitor_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 97 "sample/bindmonitor_tailcall.c"
    if ((BindMonitor_Callee1_helpers[0].tail_call) && (r0 == 0))
#line 97 "sample/bindmonitor_tailcall.c"
        return 0;
        // EBPF_OP_JEQ_IMM pc=56 dst=r0 src=r0 offset=471 imm=0
#line 98 "sample/bindmonitor_tailcall.c"
    if (r0 == IMMEDIATE(0))
#line 98 "sample/bindmonitor_tailcall.c"
        goto label_8;
        // EBPF_OP_LDXDW pc=57 dst=r1 src=r6 offset=0 imm=0
#line 112 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=58 dst=r2 src=r6 offset=8 imm=0
#line 112 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=59 dst=r2 src=r1 offset=0 imm=0
#line 112 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=60 dst=r3 src=r0 offset=0 imm=1
#line 112 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(1);
    // EBPF_OP_JSGT_REG pc=61 dst=r3 src=r2 offset=-32 imm=0
#line 112 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 112 "sample/bindmonitor_tailcall.c"
        goto label_1;
        // EBPF_OP_LDXB pc=62 dst=r1 src=r1 offset=0 imm=0
#line 113 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_STXB pc=63 dst=r0 src=r1 offset=4 imm=0
#line 113 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(4)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=64 dst=r1 src=r6 offset=0 imm=0
#line 115 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=65 dst=r2 src=r6 offset=8 imm=0
#line 115 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=66 dst=r2 src=r1 offset=0 imm=0
#line 115 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=67 dst=r3 src=r0 offset=0 imm=2
#line 115 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_JSGT_REG pc=68 dst=r3 src=r2 offset=-37 imm=0
#line 115 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 115 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=69 dst=r1 src=r1 offset=1 imm=0
#line 116 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(1));
    // EBPF_OP_STXB pc=70 dst=r0 src=r1 offset=5 imm=0
#line 116 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(5)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=71 dst=r1 src=r6 offset=0 imm=0
#line 118 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=72 dst=r2 src=r6 offset=8 imm=0
#line 118 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=73 dst=r2 src=r1 offset=0 imm=0
#line 118 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=74 dst=r3 src=r0 offset=0 imm=3
#line 118 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(3);
    // EBPF_OP_JSGT_REG pc=75 dst=r3 src=r2 offset=-44 imm=0
#line 118 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 118 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=76 dst=r1 src=r1 offset=2 imm=0
#line 119 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(2));
    // EBPF_OP_STXB pc=77 dst=r0 src=r1 offset=6 imm=0
#line 119 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(6)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=78 dst=r1 src=r6 offset=0 imm=0
#line 121 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=79 dst=r2 src=r6 offset=8 imm=0
#line 121 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=80 dst=r2 src=r1 offset=0 imm=0
#line 121 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=81 dst=r3 src=r0 offset=0 imm=4
#line 121 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(4);
    // EBPF_OP_JSGT_REG pc=82 dst=r3 src=r2 offset=-51 imm=0
#line 121 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 121 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=83 dst=r1 src=r1 offset=3 imm=0
#line 122 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(3));
    // EBPF_OP_STXB pc=84 dst=r0 src=r1 offset=7 imm=0
#line 122 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(7)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=85 dst=r1 src=r6 offset=0 imm=0
#line 124 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=86 dst=r2 src=r6 offset=8 imm=0
#line 124 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=87 dst=r2 src=r1 offset=0 imm=0
#line 124 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=88 dst=r3 src=r0 offset=0 imm=5
#line 124 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(5);
    // EBPF_OP_JSGT_REG pc=89 dst=r3 src=r2 offset=-58 imm=0
#line 124 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 124 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=90 dst=r1 src=r1 offset=4 imm=0
#line 125 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(4));
    // EBPF_OP_STXB pc=91 dst=r0 src=r1 offset=8 imm=0
#line 125 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(8)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=92 dst=r1 src=r6 offset=0 imm=0
#line 127 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=93 dst=r2 src=r6 offset=8 imm=0
#line 127 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=94 dst=r2 src=r1 offset=0 imm=0
#line 127 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=95 dst=r3 src=r0 offset=0 imm=6
#line 127 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(6);
    // EBPF_OP_JSGT_REG pc=96 dst=r3 src=r2 offset=-65 imm=0
#line 127 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 127 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=97 dst=r1 src=r1 offset=5 imm=0
#line 128 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(5));
    // EBPF_OP_STXB pc=98 dst=r0 src=r1 offset=9 imm=0
#line 128 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(9)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=99 dst=r1 src=r6 offset=0 imm=0
#line 130 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=100 dst=r2 src=r6 offset=8 imm=0
#line 130 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=101 dst=r2 src=r1 offset=0 imm=0
#line 130 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=102 dst=r3 src=r0 offset=0 imm=7
#line 130 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(7);
    // EBPF_OP_JSGT_REG pc=103 dst=r3 src=r2 offset=-72 imm=0
#line 130 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 130 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=104 dst=r1 src=r1 offset=6 imm=0
#line 131 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(6));
    // EBPF_OP_STXB pc=105 dst=r0 src=r1 offset=10 imm=0
#line 131 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(10)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=106 dst=r1 src=r6 offset=0 imm=0
#line 133 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=107 dst=r2 src=r6 offset=8 imm=0
#line 133 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=108 dst=r2 src=r1 offset=0 imm=0
#line 133 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=109 dst=r3 src=r0 offset=0 imm=8
#line 133 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(8);
    // EBPF_OP_JSGT_REG pc=110 dst=r3 src=r2 offset=-79 imm=0
#line 133 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 133 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=111 dst=r1 src=r1 offset=7 imm=0
#line 134 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(7));
    // EBPF_OP_STXB pc=112 dst=r0 src=r1 offset=11 imm=0
#line 134 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(11)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=113 dst=r1 src=r6 offset=0 imm=0
#line 136 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=114 dst=r2 src=r6 offset=8 imm=0
#line 136 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=115 dst=r2 src=r1 offset=0 imm=0
#line 136 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=116 dst=r3 src=r0 offset=0 imm=9
#line 136 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(9);
    // EBPF_OP_JSGT_REG pc=117 dst=r3 src=r2 offset=-86 imm=0
#line 136 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 136 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=118 dst=r1 src=r1 offset=8 imm=0
#line 137 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(8));
    // EBPF_OP_STXB pc=119 dst=r0 src=r1 offset=12 imm=0
#line 137 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(12)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=120 dst=r1 src=r6 offset=0 imm=0
#line 139 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=121 dst=r2 src=r6 offset=8 imm=0
#line 139 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=122 dst=r2 src=r1 offset=0 imm=0
#line 139 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=123 dst=r3 src=r0 offset=0 imm=10
#line 139 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(10);
    // EBPF_OP_JSGT_REG pc=124 dst=r3 src=r2 offset=-93 imm=0
#line 139 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 139 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=125 dst=r1 src=r1 offset=9 imm=0
#line 140 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(9));
    // EBPF_OP_STXB pc=126 dst=r0 src=r1 offset=13 imm=0
#line 140 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(13)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=127 dst=r1 src=r6 offset=0 imm=0
#line 142 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=128 dst=r2 src=r6 offset=8 imm=0
#line 142 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=129 dst=r2 src=r1 offset=0 imm=0
#line 142 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=130 dst=r3 src=r0 offset=0 imm=11
#line 142 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(11);
    // EBPF_OP_JSGT_REG pc=131 dst=r3 src=r2 offset=-100 imm=0
#line 142 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 142 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=132 dst=r1 src=r1 offset=10 imm=0
#line 143 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(10));
    // EBPF_OP_STXB pc=133 dst=r0 src=r1 offset=14 imm=0
#line 143 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(14)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=134 dst=r1 src=r6 offset=0 imm=0
#line 145 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=135 dst=r2 src=r6 offset=8 imm=0
#line 145 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=136 dst=r2 src=r1 offset=0 imm=0
#line 145 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=137 dst=r3 src=r0 offset=0 imm=12
#line 145 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(12);
    // EBPF_OP_JSGT_REG pc=138 dst=r3 src=r2 offset=-107 imm=0
#line 145 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 145 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=139 dst=r1 src=r1 offset=11 imm=0
#line 146 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(11));
    // EBPF_OP_STXB pc=140 dst=r0 src=r1 offset=15 imm=0
#line 146 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(15)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=141 dst=r1 src=r6 offset=0 imm=0
#line 148 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=142 dst=r2 src=r6 offset=8 imm=0
#line 148 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=143 dst=r2 src=r1 offset=0 imm=0
#line 148 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=144 dst=r3 src=r0 offset=0 imm=13
#line 148 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(13);
    // EBPF_OP_JSGT_REG pc=145 dst=r3 src=r2 offset=-114 imm=0
#line 148 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 148 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=146 dst=r1 src=r1 offset=12 imm=0
#line 149 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(12));
    // EBPF_OP_STXB pc=147 dst=r0 src=r1 offset=16 imm=0
#line 149 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(16)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=148 dst=r1 src=r6 offset=0 imm=0
#line 151 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=149 dst=r2 src=r6 offset=8 imm=0
#line 151 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=150 dst=r2 src=r1 offset=0 imm=0
#line 151 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=151 dst=r3 src=r0 offset=0 imm=14
#line 151 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(14);
    // EBPF_OP_JSGT_REG pc=152 dst=r3 src=r2 offset=-121 imm=0
#line 151 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 151 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=153 dst=r1 src=r1 offset=13 imm=0
#line 152 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(13));
    // EBPF_OP_STXB pc=154 dst=r0 src=r1 offset=17 imm=0
#line 152 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(17)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=155 dst=r1 src=r6 offset=0 imm=0
#line 154 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=156 dst=r2 src=r6 offset=8 imm=0
#line 154 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=157 dst=r2 src=r1 offset=0 imm=0
#line 154 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=158 dst=r3 src=r0 offset=0 imm=15
#line 154 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(15);
    // EBPF_OP_JSGT_REG pc=159 dst=r3 src=r2 offset=-128 imm=0
#line 154 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 154 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=160 dst=r1 src=r1 offset=14 imm=0
#line 155 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(14));
    // EBPF_OP_STXB pc=161 dst=r0 src=r1 offset=18 imm=0
#line 155 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(18)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=162 dst=r1 src=r6 offset=0 imm=0
#line 157 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=163 dst=r2 src=r6 offset=8 imm=0
#line 157 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=164 dst=r2 src=r1 offset=0 imm=0
#line 157 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=165 dst=r3 src=r0 offset=0 imm=16
#line 157 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(16);
    // EBPF_OP_JSGT_REG pc=166 dst=r3 src=r2 offset=-135 imm=0
#line 157 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 157 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=167 dst=r1 src=r1 offset=15 imm=0
#line 158 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(15));
    // EBPF_OP_STXB pc=168 dst=r0 src=r1 offset=19 imm=0
#line 158 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(19)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=169 dst=r1 src=r6 offset=0 imm=0
#line 160 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=170 dst=r2 src=r6 offset=8 imm=0
#line 160 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=171 dst=r2 src=r1 offset=0 imm=0
#line 160 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=172 dst=r3 src=r0 offset=0 imm=17
#line 160 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(17);
    // EBPF_OP_JSGT_REG pc=173 dst=r3 src=r2 offset=-142 imm=0
#line 160 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 160 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=174 dst=r1 src=r1 offset=16 imm=0
#line 161 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(16));
    // EBPF_OP_STXB pc=175 dst=r0 src=r1 offset=20 imm=0
#line 161 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(20)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=176 dst=r1 src=r6 offset=0 imm=0
#line 163 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=177 dst=r2 src=r6 offset=8 imm=0
#line 163 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=178 dst=r2 src=r1 offset=0 imm=0
#line 163 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=179 dst=r3 src=r0 offset=0 imm=18
#line 163 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(18);
    // EBPF_OP_JSGT_REG pc=180 dst=r3 src=r2 offset=-149 imm=0
#line 163 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 163 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=181 dst=r1 src=r1 offset=17 imm=0
#line 164 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(17));
    // EBPF_OP_STXB pc=182 dst=r0 src=r1 offset=21 imm=0
#line 164 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(21)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=183 dst=r1 src=r6 offset=0 imm=0
#line 166 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=184 dst=r2 src=r6 offset=8 imm=0
#line 166 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=185 dst=r2 src=r1 offset=0 imm=0
#line 166 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=186 dst=r3 src=r0 offset=0 imm=19
#line 166 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(19);
    // EBPF_OP_JSGT_REG pc=187 dst=r3 src=r2 offset=-156 imm=0
#line 166 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 166 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=188 dst=r1 src=r1 offset=18 imm=0
#line 167 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(18));
    // EBPF_OP_STXB pc=189 dst=r0 src=r1 offset=22 imm=0
#line 167 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(22)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=190 dst=r1 src=r6 offset=0 imm=0
#line 169 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=191 dst=r2 src=r6 offset=8 imm=0
#line 169 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=192 dst=r2 src=r1 offset=0 imm=0
#line 169 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=193 dst=r3 src=r0 offset=0 imm=20
#line 169 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(20);
    // EBPF_OP_JSGT_REG pc=194 dst=r3 src=r2 offset=-163 imm=0
#line 169 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 169 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=195 dst=r1 src=r1 offset=19 imm=0
#line 170 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(19));
    // EBPF_OP_STXB pc=196 dst=r0 src=r1 offset=23 imm=0
#line 170 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(23)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=197 dst=r1 src=r6 offset=0 imm=0
#line 172 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=198 dst=r2 src=r6 offset=8 imm=0
#line 172 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=199 dst=r2 src=r1 offset=0 imm=0
#line 172 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=200 dst=r3 src=r0 offset=0 imm=21
#line 172 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(21);
    // EBPF_OP_JSGT_REG pc=201 dst=r3 src=r2 offset=-170 imm=0
#line 172 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 172 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=202 dst=r1 src=r1 offset=20 imm=0
#line 173 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(20));
    // EBPF_OP_STXB pc=203 dst=r0 src=r1 offset=24 imm=0
#line 173 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(24)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=204 dst=r1 src=r6 offset=0 imm=0
#line 175 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=205 dst=r2 src=r6 offset=8 imm=0
#line 175 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=206 dst=r2 src=r1 offset=0 imm=0
#line 175 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=207 dst=r3 src=r0 offset=0 imm=22
#line 175 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(22);
    // EBPF_OP_JSGT_REG pc=208 dst=r3 src=r2 offset=-177 imm=0
#line 175 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 175 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=209 dst=r1 src=r1 offset=21 imm=0
#line 176 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(21));
    // EBPF_OP_STXB pc=210 dst=r0 src=r1 offset=25 imm=0
#line 176 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(25)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=211 dst=r1 src=r6 offset=0 imm=0
#line 178 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=212 dst=r2 src=r6 offset=8 imm=0
#line 178 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=213 dst=r2 src=r1 offset=0 imm=0
#line 178 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=214 dst=r3 src=r0 offset=0 imm=23
#line 178 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(23);
    // EBPF_OP_JSGT_REG pc=215 dst=r3 src=r2 offset=-184 imm=0
#line 178 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 178 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=216 dst=r1 src=r1 offset=22 imm=0
#line 179 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(22));
    // EBPF_OP_STXB pc=217 dst=r0 src=r1 offset=26 imm=0
#line 179 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(26)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=218 dst=r1 src=r6 offset=0 imm=0
#line 181 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=219 dst=r2 src=r6 offset=8 imm=0
#line 181 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=220 dst=r2 src=r1 offset=0 imm=0
#line 181 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=221 dst=r3 src=r0 offset=0 imm=24
#line 181 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(24);
    // EBPF_OP_JSGT_REG pc=222 dst=r3 src=r2 offset=-191 imm=0
#line 181 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 181 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=223 dst=r1 src=r1 offset=23 imm=0
#line 182 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(23));
    // EBPF_OP_STXB pc=224 dst=r0 src=r1 offset=27 imm=0
#line 182 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(27)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=225 dst=r1 src=r6 offset=0 imm=0
#line 184 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=226 dst=r2 src=r6 offset=8 imm=0
#line 184 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=227 dst=r2 src=r1 offset=0 imm=0
#line 184 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=228 dst=r3 src=r0 offset=0 imm=25
#line 184 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(25);
    // EBPF_OP_JSGT_REG pc=229 dst=r3 src=r2 offset=-198 imm=0
#line 184 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 184 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=230 dst=r1 src=r1 offset=24 imm=0
#line 185 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_STXB pc=231 dst=r0 src=r1 offset=28 imm=0
#line 185 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(28)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=232 dst=r1 src=r6 offset=0 imm=0
#line 187 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=233 dst=r2 src=r6 offset=8 imm=0
#line 187 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=234 dst=r2 src=r1 offset=0 imm=0
#line 187 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=235 dst=r3 src=r0 offset=0 imm=26
#line 187 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(26);
    // EBPF_OP_JSGT_REG pc=236 dst=r3 src=r2 offset=-205 imm=0
#line 187 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 187 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=237 dst=r1 src=r1 offset=25 imm=0
#line 188 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(25));
    // EBPF_OP_STXB pc=238 dst=r0 src=r1 offset=29 imm=0
#line 188 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(29)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=239 dst=r1 src=r6 offset=0 imm=0
#line 190 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=240 dst=r2 src=r6 offset=8 imm=0
#line 190 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=241 dst=r2 src=r1 offset=0 imm=0
#line 190 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=242 dst=r3 src=r0 offset=0 imm=27
#line 190 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(27);
    // EBPF_OP_JSGT_REG pc=243 dst=r3 src=r2 offset=-212 imm=0
#line 190 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 190 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=244 dst=r1 src=r1 offset=26 imm=0
#line 191 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(26));
    // EBPF_OP_STXB pc=245 dst=r0 src=r1 offset=30 imm=0
#line 191 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(30)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=246 dst=r1 src=r6 offset=0 imm=0
#line 193 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=247 dst=r2 src=r6 offset=8 imm=0
#line 193 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=248 dst=r2 src=r1 offset=0 imm=0
#line 193 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=249 dst=r3 src=r0 offset=0 imm=28
#line 193 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(28);
    // EBPF_OP_JSGT_REG pc=250 dst=r3 src=r2 offset=-219 imm=0
#line 193 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 193 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=251 dst=r1 src=r1 offset=27 imm=0
#line 194 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(27));
    // EBPF_OP_STXB pc=252 dst=r0 src=r1 offset=31 imm=0
#line 194 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(31)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=253 dst=r1 src=r6 offset=0 imm=0
#line 196 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=254 dst=r2 src=r6 offset=8 imm=0
#line 196 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=255 dst=r2 src=r1 offset=0 imm=0
#line 196 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=256 dst=r3 src=r0 offset=0 imm=29
#line 196 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(29);
    // EBPF_OP_JSGT_REG pc=257 dst=r3 src=r2 offset=-226 imm=0
#line 196 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 196 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=258 dst=r1 src=r1 offset=28 imm=0
#line 197 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(28));
    // EBPF_OP_STXB pc=259 dst=r0 src=r1 offset=32 imm=0
#line 197 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(32)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=260 dst=r1 src=r6 offset=0 imm=0
#line 199 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=261 dst=r2 src=r6 offset=8 imm=0
#line 199 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=262 dst=r2 src=r1 offset=0 imm=0
#line 199 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=263 dst=r3 src=r0 offset=0 imm=30
#line 199 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(30);
    // EBPF_OP_JSGT_REG pc=264 dst=r3 src=r2 offset=-233 imm=0
#line 199 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 199 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=265 dst=r1 src=r1 offset=29 imm=0
#line 200 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(29));
    // EBPF_OP_STXB pc=266 dst=r0 src=r1 offset=33 imm=0
#line 200 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(33)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=267 dst=r1 src=r6 offset=0 imm=0
#line 202 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=268 dst=r2 src=r6 offset=8 imm=0
#line 202 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=269 dst=r2 src=r1 offset=0 imm=0
#line 202 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=270 dst=r3 src=r0 offset=0 imm=31
#line 202 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(31);
    // EBPF_OP_JSGT_REG pc=271 dst=r3 src=r2 offset=-240 imm=0
#line 202 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 202 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=272 dst=r1 src=r1 offset=30 imm=0
#line 203 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(30));
    // EBPF_OP_STXB pc=273 dst=r0 src=r1 offset=34 imm=0
#line 203 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(34)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=274 dst=r1 src=r6 offset=0 imm=0
#line 205 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=275 dst=r2 src=r6 offset=8 imm=0
#line 205 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=276 dst=r2 src=r1 offset=0 imm=0
#line 205 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=277 dst=r3 src=r0 offset=0 imm=32
#line 205 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=278 dst=r3 src=r2 offset=-247 imm=0
#line 205 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 205 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=279 dst=r1 src=r1 offset=31 imm=0
#line 206 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(31));
    // EBPF_OP_STXB pc=280 dst=r0 src=r1 offset=35 imm=0
#line 206 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(35)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=281 dst=r1 src=r6 offset=0 imm=0
#line 208 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=282 dst=r2 src=r6 offset=8 imm=0
#line 208 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=283 dst=r2 src=r1 offset=0 imm=0
#line 208 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=284 dst=r3 src=r0 offset=0 imm=33
#line 208 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(33);
    // EBPF_OP_JSGT_REG pc=285 dst=r3 src=r2 offset=-254 imm=0
#line 208 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 208 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=286 dst=r1 src=r1 offset=32 imm=0
#line 209 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(32));
    // EBPF_OP_STXB pc=287 dst=r0 src=r1 offset=36 imm=0
#line 209 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(36)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=288 dst=r1 src=r6 offset=0 imm=0
#line 211 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=289 dst=r2 src=r6 offset=8 imm=0
#line 211 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=290 dst=r2 src=r1 offset=0 imm=0
#line 211 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=291 dst=r3 src=r0 offset=0 imm=34
#line 211 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(34);
    // EBPF_OP_JSGT_REG pc=292 dst=r3 src=r2 offset=-261 imm=0
#line 211 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 211 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=293 dst=r1 src=r1 offset=33 imm=0
#line 212 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(33));
    // EBPF_OP_STXB pc=294 dst=r0 src=r1 offset=37 imm=0
#line 212 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(37)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=295 dst=r1 src=r6 offset=0 imm=0
#line 214 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=296 dst=r2 src=r6 offset=8 imm=0
#line 214 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=297 dst=r2 src=r1 offset=0 imm=0
#line 214 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=298 dst=r3 src=r0 offset=0 imm=35
#line 214 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(35);
    // EBPF_OP_JSGT_REG pc=299 dst=r3 src=r2 offset=-268 imm=0
#line 214 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 214 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=300 dst=r1 src=r1 offset=34 imm=0
#line 215 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(34));
    // EBPF_OP_STXB pc=301 dst=r0 src=r1 offset=38 imm=0
#line 215 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(38)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=302 dst=r1 src=r6 offset=0 imm=0
#line 217 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=303 dst=r2 src=r6 offset=8 imm=0
#line 217 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=304 dst=r2 src=r1 offset=0 imm=0
#line 217 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=305 dst=r3 src=r0 offset=0 imm=36
#line 217 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(36);
    // EBPF_OP_JSGT_REG pc=306 dst=r3 src=r2 offset=-275 imm=0
#line 217 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 217 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=307 dst=r1 src=r1 offset=35 imm=0
#line 218 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(35));
    // EBPF_OP_STXB pc=308 dst=r0 src=r1 offset=39 imm=0
#line 218 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(39)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=309 dst=r1 src=r6 offset=0 imm=0
#line 220 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=310 dst=r2 src=r6 offset=8 imm=0
#line 220 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=311 dst=r2 src=r1 offset=0 imm=0
#line 220 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=312 dst=r3 src=r0 offset=0 imm=37
#line 220 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(37);
    // EBPF_OP_JSGT_REG pc=313 dst=r3 src=r2 offset=-282 imm=0
#line 220 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 220 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=314 dst=r1 src=r1 offset=36 imm=0
#line 221 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(36));
    // EBPF_OP_STXB pc=315 dst=r0 src=r1 offset=40 imm=0
#line 221 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(40)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=316 dst=r1 src=r6 offset=0 imm=0
#line 223 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=317 dst=r2 src=r6 offset=8 imm=0
#line 223 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=318 dst=r2 src=r1 offset=0 imm=0
#line 223 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=319 dst=r3 src=r0 offset=0 imm=38
#line 223 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(38);
    // EBPF_OP_JSGT_REG pc=320 dst=r3 src=r2 offset=-289 imm=0
#line 223 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 223 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=321 dst=r1 src=r1 offset=37 imm=0
#line 224 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(37));
    // EBPF_OP_STXB pc=322 dst=r0 src=r1 offset=41 imm=0
#line 224 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(41)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=323 dst=r1 src=r6 offset=0 imm=0
#line 226 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=324 dst=r2 src=r6 offset=8 imm=0
#line 226 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=325 dst=r2 src=r1 offset=0 imm=0
#line 226 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=326 dst=r3 src=r0 offset=0 imm=39
#line 226 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(39);
    // EBPF_OP_JSGT_REG pc=327 dst=r3 src=r2 offset=-296 imm=0
#line 226 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 226 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=328 dst=r1 src=r1 offset=38 imm=0
#line 227 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(38));
    // EBPF_OP_STXB pc=329 dst=r0 src=r1 offset=42 imm=0
#line 227 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(42)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=330 dst=r1 src=r6 offset=0 imm=0
#line 229 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=331 dst=r2 src=r6 offset=8 imm=0
#line 229 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=332 dst=r2 src=r1 offset=0 imm=0
#line 229 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=333 dst=r3 src=r0 offset=0 imm=40
#line 229 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(40);
    // EBPF_OP_JSGT_REG pc=334 dst=r3 src=r2 offset=-303 imm=0
#line 229 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 229 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=335 dst=r1 src=r1 offset=39 imm=0
#line 230 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(39));
    // EBPF_OP_STXB pc=336 dst=r0 src=r1 offset=43 imm=0
#line 230 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(43)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=337 dst=r1 src=r6 offset=0 imm=0
#line 232 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=338 dst=r2 src=r6 offset=8 imm=0
#line 232 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=339 dst=r2 src=r1 offset=0 imm=0
#line 232 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=340 dst=r3 src=r0 offset=0 imm=41
#line 232 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(41);
    // EBPF_OP_JSGT_REG pc=341 dst=r3 src=r2 offset=-310 imm=0
#line 232 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 232 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=342 dst=r1 src=r1 offset=40 imm=0
#line 233 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_STXB pc=343 dst=r0 src=r1 offset=44 imm=0
#line 233 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(44)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=344 dst=r1 src=r6 offset=0 imm=0
#line 235 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=345 dst=r2 src=r6 offset=8 imm=0
#line 235 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=346 dst=r2 src=r1 offset=0 imm=0
#line 235 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=347 dst=r3 src=r0 offset=0 imm=42
#line 235 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(42);
    // EBPF_OP_JSGT_REG pc=348 dst=r3 src=r2 offset=-317 imm=0
#line 235 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 235 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=349 dst=r1 src=r1 offset=41 imm=0
#line 236 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(41));
    // EBPF_OP_STXB pc=350 dst=r0 src=r1 offset=45 imm=0
#line 236 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(45)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=351 dst=r1 src=r6 offset=0 imm=0
#line 238 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=352 dst=r2 src=r6 offset=8 imm=0
#line 238 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=353 dst=r2 src=r1 offset=0 imm=0
#line 238 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=354 dst=r3 src=r0 offset=0 imm=43
#line 238 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(43);
    // EBPF_OP_JSGT_REG pc=355 dst=r3 src=r2 offset=-324 imm=0
#line 238 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 238 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=356 dst=r1 src=r1 offset=42 imm=0
#line 239 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(42));
    // EBPF_OP_STXB pc=357 dst=r0 src=r1 offset=46 imm=0
#line 239 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(46)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=358 dst=r1 src=r6 offset=0 imm=0
#line 241 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=359 dst=r2 src=r6 offset=8 imm=0
#line 241 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=360 dst=r2 src=r1 offset=0 imm=0
#line 241 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=361 dst=r3 src=r0 offset=0 imm=44
#line 241 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(44);
    // EBPF_OP_JSGT_REG pc=362 dst=r3 src=r2 offset=-331 imm=0
#line 241 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 241 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=363 dst=r1 src=r1 offset=43 imm=0
#line 242 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(43));
    // EBPF_OP_STXB pc=364 dst=r0 src=r1 offset=47 imm=0
#line 242 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(47)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=365 dst=r1 src=r6 offset=0 imm=0
#line 244 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=366 dst=r2 src=r6 offset=8 imm=0
#line 244 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=367 dst=r2 src=r1 offset=0 imm=0
#line 244 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=368 dst=r3 src=r0 offset=0 imm=45
#line 244 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(45);
    // EBPF_OP_JSGT_REG pc=369 dst=r3 src=r2 offset=-338 imm=0
#line 244 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 244 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=370 dst=r1 src=r1 offset=44 imm=0
#line 245 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_STXB pc=371 dst=r0 src=r1 offset=48 imm=0
#line 245 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(48)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=372 dst=r1 src=r6 offset=0 imm=0
#line 247 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=373 dst=r2 src=r6 offset=8 imm=0
#line 247 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=374 dst=r2 src=r1 offset=0 imm=0
#line 247 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=375 dst=r3 src=r0 offset=0 imm=46
#line 247 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(46);
    // EBPF_OP_JSGT_REG pc=376 dst=r3 src=r2 offset=-345 imm=0
#line 247 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 247 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=377 dst=r1 src=r1 offset=45 imm=0
#line 248 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(45));
    // EBPF_OP_STXB pc=378 dst=r0 src=r1 offset=49 imm=0
#line 248 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(49)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=379 dst=r1 src=r6 offset=0 imm=0
#line 250 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=380 dst=r2 src=r6 offset=8 imm=0
#line 250 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=381 dst=r2 src=r1 offset=0 imm=0
#line 250 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=382 dst=r3 src=r0 offset=0 imm=47
#line 250 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(47);
    // EBPF_OP_JSGT_REG pc=383 dst=r3 src=r2 offset=-352 imm=0
#line 250 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 250 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=384 dst=r1 src=r1 offset=46 imm=0
#line 251 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(46));
    // EBPF_OP_STXB pc=385 dst=r0 src=r1 offset=50 imm=0
#line 251 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(50)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=386 dst=r1 src=r6 offset=0 imm=0
#line 253 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=387 dst=r2 src=r6 offset=8 imm=0
#line 253 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=388 dst=r2 src=r1 offset=0 imm=0
#line 253 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=389 dst=r3 src=r0 offset=0 imm=48
#line 253 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(48);
    // EBPF_OP_JSGT_REG pc=390 dst=r3 src=r2 offset=-359 imm=0
#line 253 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 253 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=391 dst=r1 src=r1 offset=47 imm=0
#line 254 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(47));
    // EBPF_OP_STXB pc=392 dst=r0 src=r1 offset=51 imm=0
#line 254 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(51)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=393 dst=r1 src=r6 offset=0 imm=0
#line 256 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=394 dst=r2 src=r6 offset=8 imm=0
#line 256 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=395 dst=r2 src=r1 offset=0 imm=0
#line 256 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=396 dst=r3 src=r0 offset=0 imm=49
#line 256 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(49);
    // EBPF_OP_JSGT_REG pc=397 dst=r3 src=r2 offset=-366 imm=0
#line 256 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 256 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=398 dst=r1 src=r1 offset=48 imm=0
#line 257 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(48));
    // EBPF_OP_STXB pc=399 dst=r0 src=r1 offset=52 imm=0
#line 257 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(52)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=400 dst=r1 src=r6 offset=0 imm=0
#line 259 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=401 dst=r2 src=r6 offset=8 imm=0
#line 259 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=402 dst=r2 src=r1 offset=0 imm=0
#line 259 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=403 dst=r3 src=r0 offset=0 imm=50
#line 259 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(50);
    // EBPF_OP_JSGT_REG pc=404 dst=r3 src=r2 offset=-373 imm=0
#line 259 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 259 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=405 dst=r1 src=r1 offset=49 imm=0
#line 260 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(49));
    // EBPF_OP_STXB pc=406 dst=r0 src=r1 offset=53 imm=0
#line 260 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(53)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=407 dst=r1 src=r6 offset=0 imm=0
#line 262 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=408 dst=r2 src=r6 offset=8 imm=0
#line 262 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=409 dst=r2 src=r1 offset=0 imm=0
#line 262 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=410 dst=r3 src=r0 offset=0 imm=51
#line 262 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(51);
    // EBPF_OP_JSGT_REG pc=411 dst=r3 src=r2 offset=-380 imm=0
#line 262 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 262 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=412 dst=r1 src=r1 offset=50 imm=0
#line 263 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(50));
    // EBPF_OP_STXB pc=413 dst=r0 src=r1 offset=54 imm=0
#line 263 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(54)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=414 dst=r1 src=r6 offset=0 imm=0
#line 265 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=415 dst=r2 src=r6 offset=8 imm=0
#line 265 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=416 dst=r2 src=r1 offset=0 imm=0
#line 265 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=417 dst=r3 src=r0 offset=0 imm=52
#line 265 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(52);
    // EBPF_OP_JSGT_REG pc=418 dst=r3 src=r2 offset=-387 imm=0
#line 265 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 265 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=419 dst=r1 src=r1 offset=51 imm=0
#line 266 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(51));
    // EBPF_OP_STXB pc=420 dst=r0 src=r1 offset=55 imm=0
#line 266 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(55)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=421 dst=r1 src=r6 offset=0 imm=0
#line 268 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=422 dst=r2 src=r6 offset=8 imm=0
#line 268 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=423 dst=r2 src=r1 offset=0 imm=0
#line 268 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=424 dst=r3 src=r0 offset=0 imm=53
#line 268 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(53);
    // EBPF_OP_JSGT_REG pc=425 dst=r3 src=r2 offset=-394 imm=0
#line 268 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 268 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=426 dst=r1 src=r1 offset=52 imm=0
#line 269 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(52));
    // EBPF_OP_STXB pc=427 dst=r0 src=r1 offset=56 imm=0
#line 269 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(56)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=428 dst=r1 src=r6 offset=0 imm=0
#line 271 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=429 dst=r2 src=r6 offset=8 imm=0
#line 271 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=430 dst=r2 src=r1 offset=0 imm=0
#line 271 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=431 dst=r3 src=r0 offset=0 imm=54
#line 271 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(54);
    // EBPF_OP_JSGT_REG pc=432 dst=r3 src=r2 offset=-401 imm=0
#line 271 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 271 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=433 dst=r1 src=r1 offset=53 imm=0
#line 272 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(53));
    // EBPF_OP_STXB pc=434 dst=r0 src=r1 offset=57 imm=0
#line 272 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(57)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=435 dst=r1 src=r6 offset=0 imm=0
#line 274 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=436 dst=r2 src=r6 offset=8 imm=0
#line 274 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=437 dst=r2 src=r1 offset=0 imm=0
#line 274 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=438 dst=r3 src=r0 offset=0 imm=55
#line 274 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(55);
    // EBPF_OP_JSGT_REG pc=439 dst=r3 src=r2 offset=-408 imm=0
#line 274 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 274 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=440 dst=r1 src=r1 offset=54 imm=0
#line 275 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(54));
    // EBPF_OP_STXB pc=441 dst=r0 src=r1 offset=58 imm=0
#line 275 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(58)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=442 dst=r1 src=r6 offset=0 imm=0
#line 277 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=443 dst=r2 src=r6 offset=8 imm=0
#line 277 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=444 dst=r2 src=r1 offset=0 imm=0
#line 277 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=445 dst=r3 src=r0 offset=0 imm=56
#line 277 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(56);
    // EBPF_OP_JSGT_REG pc=446 dst=r3 src=r2 offset=-415 imm=0
#line 277 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 277 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=447 dst=r1 src=r1 offset=55 imm=0
#line 278 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(55));
    // EBPF_OP_STXB pc=448 dst=r0 src=r1 offset=59 imm=0
#line 278 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(59)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=449 dst=r1 src=r6 offset=0 imm=0
#line 280 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=450 dst=r2 src=r6 offset=8 imm=0
#line 280 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=451 dst=r2 src=r1 offset=0 imm=0
#line 280 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=452 dst=r3 src=r0 offset=0 imm=57
#line 280 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(57);
    // EBPF_OP_JSGT_REG pc=453 dst=r3 src=r2 offset=-422 imm=0
#line 280 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 280 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=454 dst=r1 src=r1 offset=56 imm=0
#line 281 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(56));
    // EBPF_OP_STXB pc=455 dst=r0 src=r1 offset=60 imm=0
#line 281 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(60)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=456 dst=r1 src=r6 offset=0 imm=0
#line 283 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=457 dst=r2 src=r6 offset=8 imm=0
#line 283 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=458 dst=r2 src=r1 offset=0 imm=0
#line 283 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=459 dst=r3 src=r0 offset=0 imm=58
#line 283 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(58);
    // EBPF_OP_JSGT_REG pc=460 dst=r3 src=r2 offset=-429 imm=0
#line 283 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 283 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=461 dst=r1 src=r1 offset=57 imm=0
#line 284 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(57));
    // EBPF_OP_STXB pc=462 dst=r0 src=r1 offset=61 imm=0
#line 284 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(61)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=463 dst=r1 src=r6 offset=0 imm=0
#line 286 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=464 dst=r2 src=r6 offset=8 imm=0
#line 286 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=465 dst=r2 src=r1 offset=0 imm=0
#line 286 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=466 dst=r3 src=r0 offset=0 imm=59
#line 286 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(59);
    // EBPF_OP_JSGT_REG pc=467 dst=r3 src=r2 offset=-436 imm=0
#line 286 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 286 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=468 dst=r1 src=r1 offset=58 imm=0
#line 287 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(58));
    // EBPF_OP_STXB pc=469 dst=r0 src=r1 offset=62 imm=0
#line 287 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(62)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=470 dst=r1 src=r6 offset=0 imm=0
#line 289 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=471 dst=r2 src=r6 offset=8 imm=0
#line 289 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=472 dst=r2 src=r1 offset=0 imm=0
#line 289 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=473 dst=r3 src=r0 offset=0 imm=60
#line 289 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(60);
    // EBPF_OP_JSGT_REG pc=474 dst=r3 src=r2 offset=-443 imm=0
#line 289 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 289 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=475 dst=r1 src=r1 offset=59 imm=0
#line 290 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(59));
    // EBPF_OP_STXB pc=476 dst=r0 src=r1 offset=63 imm=0
#line 290 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(63)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=477 dst=r1 src=r6 offset=0 imm=0
#line 292 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=478 dst=r2 src=r6 offset=8 imm=0
#line 292 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=479 dst=r2 src=r1 offset=0 imm=0
#line 292 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=480 dst=r3 src=r0 offset=0 imm=61
#line 292 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(61);
    // EBPF_OP_JSGT_REG pc=481 dst=r3 src=r2 offset=-450 imm=0
#line 292 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 292 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=482 dst=r1 src=r1 offset=60 imm=0
#line 293 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(60));
    // EBPF_OP_STXB pc=483 dst=r0 src=r1 offset=64 imm=0
#line 293 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(64)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=484 dst=r1 src=r6 offset=0 imm=0
#line 295 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=485 dst=r2 src=r6 offset=8 imm=0
#line 295 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=486 dst=r2 src=r1 offset=0 imm=0
#line 295 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=487 dst=r3 src=r0 offset=0 imm=62
#line 295 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(62);
    // EBPF_OP_JSGT_REG pc=488 dst=r3 src=r2 offset=-457 imm=0
#line 295 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 295 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=489 dst=r1 src=r1 offset=61 imm=0
#line 296 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(61));
    // EBPF_OP_STXB pc=490 dst=r0 src=r1 offset=65 imm=0
#line 296 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(65)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=491 dst=r1 src=r6 offset=0 imm=0
#line 298 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=492 dst=r2 src=r6 offset=8 imm=0
#line 298 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=493 dst=r2 src=r1 offset=0 imm=0
#line 298 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=494 dst=r3 src=r0 offset=0 imm=63
#line 298 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(63);
    // EBPF_OP_JSGT_REG pc=495 dst=r3 src=r2 offset=-464 imm=0
#line 298 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 298 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=496 dst=r1 src=r1 offset=62 imm=0
#line 299 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(62));
    // EBPF_OP_STXB pc=497 dst=r0 src=r1 offset=66 imm=0
#line 299 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(66)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=498 dst=r1 src=r6 offset=0 imm=0
#line 301 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=499 dst=r2 src=r6 offset=8 imm=0
#line 301 "sample/bindmonitor_tailcall.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=500 dst=r2 src=r1 offset=0 imm=0
#line 301 "sample/bindmonitor_tailcall.c"
    r2 -= r1;
    // EBPF_OP_MOV64_IMM pc=501 dst=r3 src=r0 offset=0 imm=64
#line 301 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(64);
    // EBPF_OP_JSGT_REG pc=502 dst=r3 src=r2 offset=-471 imm=0
#line 301 "sample/bindmonitor_tailcall.c"
    if ((int64_t)r3 > (int64_t)r2)
#line 301 "sample/bindmonitor_tailcall.c"
        goto label_2;
        // EBPF_OP_LDXB pc=503 dst=r1 src=r1 offset=63 imm=0
#line 302 "sample/bindmonitor_tailcall.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(63));
    // EBPF_OP_STXB pc=504 dst=r0 src=r1 offset=67 imm=0
#line 302 "sample/bindmonitor_tailcall.c"
    *(uint8_t*)(uintptr_t)(r0 + OFFSET(67)) = (uint8_t)r1;
    // EBPF_OP_JA pc=505 dst=r0 src=r0 offset=-474 imm=0
#line 302 "sample/bindmonitor_tailcall.c"
    goto label_2;
label_4:
    // EBPF_OP_LDXW pc=506 dst=r1 src=r0 offset=0 imm=0
#line 371 "sample/bindmonitor_tailcall.c"
    r1 = *(uint32_t*)(uintptr_t)(r0 + OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=507 dst=r1 src=r0 offset=6 imm=0
#line 371 "sample/bindmonitor_tailcall.c"
    if (r1 == IMMEDIATE(0))
#line 371 "sample/bindmonitor_tailcall.c"
        goto label_6;
        // EBPF_OP_ADD64_IMM pc=508 dst=r1 src=r0 offset=0 imm=-1
#line 372 "sample/bindmonitor_tailcall.c"
    r1 += IMMEDIATE(-1);
    // EBPF_OP_STXW pc=509 dst=r0 src=r1 offset=0 imm=0
#line 372 "sample/bindmonitor_tailcall.c"
    *(uint32_t*)(uintptr_t)(r0 + OFFSET(0)) = (uint32_t)r1;
label_5:
    // EBPF_OP_MOV64_IMM pc=510 dst=r8 src=r0 offset=0 imm=0
#line 372 "sample/bindmonitor_tailcall.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_LSH64_IMM pc=511 dst=r1 src=r0 offset=0 imm=32
#line 379 "sample/bindmonitor_tailcall.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=512 dst=r1 src=r0 offset=0 imm=32
#line 379 "sample/bindmonitor_tailcall.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=513 dst=r1 src=r0 offset=15 imm=0
#line 379 "sample/bindmonitor_tailcall.c"
    if (r1 != IMMEDIATE(0))
#line 379 "sample/bindmonitor_tailcall.c"
        goto label_9;
label_6:
    // EBPF_OP_LDXDW pc=514 dst=r1 src=r6 offset=16 imm=0
#line 380 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(16));
    // EBPF_OP_STXDW pc=515 dst=r10 src=r1 offset=-80 imm=0
#line 380 "sample/bindmonitor_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=516 dst=r2 src=r10 offset=0 imm=0
#line 380 "sample/bindmonitor_tailcall.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=517 dst=r2 src=r0 offset=0 imm=-80
#line 380 "sample/bindmonitor_tailcall.c"
    r2 += IMMEDIATE(-80);
    // EBPF_OP_LDDW pc=518 dst=r1 src=r0 offset=0 imm=0
#line 381 "sample/bindmonitor_tailcall.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=520 dst=r0 src=r0 offset=0 imm=3
#line 381 "sample/bindmonitor_tailcall.c"
    r0 = BindMonitor_Callee1_helpers[2].address
#line 381 "sample/bindmonitor_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 381 "sample/bindmonitor_tailcall.c"
    if ((BindMonitor_Callee1_helpers[2].tail_call) && (r0 == 0))
#line 381 "sample/bindmonitor_tailcall.c"
        return 0;
        // EBPF_OP_JA pc=521 dst=r0 src=r0 offset=6 imm=0
#line 381 "sample/bindmonitor_tailcall.c"
    goto label_8;
label_7:
    // EBPF_OP_MOV64_IMM pc=522 dst=r8 src=r0 offset=0 imm=1
#line 381 "sample/bindmonitor_tailcall.c"
    r8 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=523 dst=r1 src=r0 offset=0 imm=0
#line 364 "sample/bindmonitor_tailcall.c"
    r1 = *(uint32_t*)(uintptr_t)(r0 + OFFSET(0));
    // EBPF_OP_LDXW pc=524 dst=r2 src=r7 offset=0 imm=0
#line 364 "sample/bindmonitor_tailcall.c"
    r2 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_JGE_REG pc=525 dst=r1 src=r2 offset=3 imm=0
#line 364 "sample/bindmonitor_tailcall.c"
    if (r1 >= r2)
#line 364 "sample/bindmonitor_tailcall.c"
        goto label_9;
        // EBPF_OP_ADD64_IMM pc=526 dst=r1 src=r0 offset=0 imm=1
#line 368 "sample/bindmonitor_tailcall.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=527 dst=r0 src=r1 offset=0 imm=0
#line 368 "sample/bindmonitor_tailcall.c"
    *(uint32_t*)(uintptr_t)(r0 + OFFSET(0)) = (uint32_t)r1;
label_8:
    // EBPF_OP_MOV64_IMM pc=528 dst=r8 src=r0 offset=0 imm=0
#line 368 "sample/bindmonitor_tailcall.c"
    r8 = IMMEDIATE(0);
label_9:
    // EBPF_OP_MOV64_REG pc=529 dst=r0 src=r8 offset=0 imm=0
#line 385 "sample/bindmonitor_tailcall.c"
    r0 = r8;
    // EBPF_OP_EXIT pc=530 dst=r0 src=r0 offset=0 imm=0
#line 385 "sample/bindmonitor_tailcall.c"
    return r0;
#line 385 "sample/bindmonitor_tailcall.c"
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
        2,
        BindMonitor_helpers,
        2,
        16,
        &BindMonitor_program_type_guid,
        &BindMonitor_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee0,
        "bind/0",
        "bind/0",
        "BindMonitor_Callee0",
        BindMonitor_Callee0_maps,
        2,
        BindMonitor_Callee0_helpers,
        2,
        16,
        &BindMonitor_Callee0_program_type_guid,
        &BindMonitor_Callee0_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee1,
        "bind/1",
        "bind/1",
        "BindMonitor_Callee1",
        BindMonitor_Callee1_maps,
        2,
        BindMonitor_Callee1_helpers,
        3,
        531,
        &BindMonitor_Callee1_program_type_guid,
        &BindMonitor_Callee1_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 3;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = 0;
    version->minor = 7;
    version->revision = 0;
}

metadata_table_t bindmonitor_tailcall_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
