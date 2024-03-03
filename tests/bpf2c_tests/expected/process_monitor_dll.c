// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from process_monitor.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table process_monitor##_metadata_table
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
         264,               // Size in bytes of a map value.
         1024,              // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         16,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "process_map"},
    {NULL,
     {
         BPF_MAP_TYPE_RINGBUF, // Type of map.
         0,                    // Size in bytes of a map key.
         0,                    // Size in bytes of a map value.
         65536,                // Maximum number of entries allowed in the map.
         0,                    // Inner map index.
         LIBBPF_PIN_NONE,      // Pinning type for the map.
         22,                   // Identifier for a map template.
         0,                    // The id of the inner map template.
     },
     "process_ringbuf"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 2;
}

static helper_function_entry_t ProcessMonitor_helpers[] = {
    {NULL, 22, "helper_id_22"},
    {NULL, 2, "helper_id_2"},
    {NULL, 3, "helper_id_3"},
    {NULL, 11, "helper_id_11"},
};

static GUID ProcessMonitor_program_type_guid = {
    0x22ea7b37, 0x1043, 0x4d0d, {0xb6, 0x0d, 0xca, 0xfa, 0x1c, 0x7b, 0x63, 0x8e}};
static GUID ProcessMonitor_attach_type_guid = {
    0x66e20687, 0x9805, 0x4458, {0xa0, 0xdb, 0x38, 0xe2, 0x20, 0xd3, 0x16, 0x85}};
static uint16_t ProcessMonitor_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "process")
static uint64_t
ProcessMonitor(void* context)
#line 64 "sample/process_monitor.c"
{
#line 64 "sample/process_monitor.c"
    // Prologue
#line 64 "sample/process_monitor.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 64 "sample/process_monitor.c"
    register uint64_t r0 = 0;
#line 64 "sample/process_monitor.c"
    register uint64_t r1 = 0;
#line 64 "sample/process_monitor.c"
    register uint64_t r2 = 0;
#line 64 "sample/process_monitor.c"
    register uint64_t r3 = 0;
#line 64 "sample/process_monitor.c"
    register uint64_t r4 = 0;
#line 64 "sample/process_monitor.c"
    register uint64_t r5 = 0;
#line 64 "sample/process_monitor.c"
    register uint64_t r10 = 0;

#line 64 "sample/process_monitor.c"
    r1 = (uintptr_t)context;
#line 64 "sample/process_monitor.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXW pc=0 dst=r2 src=r1 offset=48 imm=0
#line 64 "sample/process_monitor.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(48));
    // EBPF_OP_JEQ_IMM pc=1 dst=r2 src=r0 offset=60 imm=1
#line 64 "sample/process_monitor.c"
    if (r2 == IMMEDIATE(1))
#line 64 "sample/process_monitor.c"
        goto label_1;
        // EBPF_OP_JNE_IMM pc=2 dst=r2 src=r0 offset=74 imm=0
#line 64 "sample/process_monitor.c"
    if (r2 != IMMEDIATE(0))
#line 64 "sample/process_monitor.c"
        goto label_3;
        // EBPF_OP_MOV64_IMM pc=3 dst=r2 src=r0 offset=0 imm=0
#line 64 "sample/process_monitor.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=4 dst=r10 src=r2 offset=-8 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r2 offset=-16 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=6 dst=r10 src=r2 offset=-24 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=7 dst=r10 src=r2 offset=-32 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r2 offset=-40 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=9 dst=r10 src=r2 offset=-48 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=10 dst=r10 src=r2 offset=-56 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=11 dst=r10 src=r2 offset=-64 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=12 dst=r10 src=r2 offset=-72 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r2 offset=-80 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r2 offset=-88 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=15 dst=r10 src=r2 offset=-96 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r2 offset=-104 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r2 offset=-112 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=18 dst=r10 src=r2 offset=-120 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r2 offset=-128 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-128)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r2 offset=-136 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-136)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=21 dst=r10 src=r2 offset=-144 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-144)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=22 dst=r10 src=r2 offset=-152 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-152)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=23 dst=r10 src=r2 offset=-160 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-160)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=24 dst=r10 src=r2 offset=-168 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-168)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=25 dst=r10 src=r2 offset=-176 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-176)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=26 dst=r10 src=r2 offset=-184 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-184)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=27 dst=r10 src=r2 offset=-192 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-192)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=28 dst=r10 src=r2 offset=-200 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-200)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=29 dst=r10 src=r2 offset=-208 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-208)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=30 dst=r10 src=r2 offset=-216 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-216)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=31 dst=r10 src=r2 offset=-224 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-224)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=32 dst=r10 src=r2 offset=-232 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-232)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=33 dst=r10 src=r2 offset=-240 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-240)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=34 dst=r10 src=r2 offset=-248 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-248)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=35 dst=r10 src=r2 offset=-256 imm=0
#line 66 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-256)) = (uint64_t)r2;
    // EBPF_OP_LDXDW pc=36 dst=r2 src=r1 offset=24 imm=0
#line 67 "sample/process_monitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_STXDW pc=37 dst=r10 src=r2 offset=-264 imm=0
#line 67 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-264)) = (uint64_t)r2;
    // EBPF_OP_LDXDW pc=38 dst=r2 src=r1 offset=16 imm=0
#line 68 "sample/process_monitor.c"
    r2 = *(uint64_t*)(uintptr_t)(r1 + OFFSET(16));
    // EBPF_OP_STXDW pc=39 dst=r10 src=r2 offset=-272 imm=0
#line 68 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-272)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=40 dst=r10 src=r2 offset=-280 imm=0
#line 69 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-280)) = (uint64_t)r2;
    // EBPF_OP_LDXDW pc=41 dst=r3 src=r1 offset=0 imm=0
#line 74 "sample/process_monitor.c"
    r3 = *(uint64_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_LDXDW pc=42 dst=r4 src=r1 offset=8 imm=0
#line 75 "sample/process_monitor.c"
    r4 = *(uint64_t*)(uintptr_t)(r1 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=43 dst=r4 src=r3 offset=0 imm=0
#line 75 "sample/process_monitor.c"
    r4 -= r3;
    // EBPF_OP_MOV64_REG pc=44 dst=r1 src=r10 offset=0 imm=0
#line 66 "sample/process_monitor.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=45 dst=r1 src=r0 offset=0 imm=-256
#line 66 "sample/process_monitor.c"
    r1 += IMMEDIATE(-256);
    // EBPF_OP_MOV64_IMM pc=46 dst=r2 src=r0 offset=0 imm=256
#line 71 "sample/process_monitor.c"
    r2 = IMMEDIATE(256);
    // EBPF_OP_CALL pc=47 dst=r0 src=r0 offset=0 imm=22
#line 71 "sample/process_monitor.c"
    r0 = ProcessMonitor_helpers[0].address
#line 71 "sample/process_monitor.c"
         (r1, r2, r3, r4, r5);
#line 71 "sample/process_monitor.c"
    if ((ProcessMonitor_helpers[0].tail_call) && (r0 == 0))
#line 71 "sample/process_monitor.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=48 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/process_monitor.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=49 dst=r2 src=r0 offset=0 imm=-280
#line 66 "sample/process_monitor.c"
    r2 += IMMEDIATE(-280);
    // EBPF_OP_MOV64_REG pc=50 dst=r3 src=r10 offset=0 imm=0
#line 66 "sample/process_monitor.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=51 dst=r3 src=r0 offset=0 imm=-264
#line 66 "sample/process_monitor.c"
    r3 += IMMEDIATE(-264);
    // EBPF_OP_LDDW pc=52 dst=r1 src=r0 offset=0 imm=0
#line 77 "sample/process_monitor.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=54 dst=r4 src=r0 offset=0 imm=0
#line 77 "sample/process_monitor.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=55 dst=r0 src=r0 offset=0 imm=2
#line 77 "sample/process_monitor.c"
    r0 = ProcessMonitor_helpers[1].address
#line 77 "sample/process_monitor.c"
         (r1, r2, r3, r4, r5);
#line 77 "sample/process_monitor.c"
    if ((ProcessMonitor_helpers[1].tail_call) && (r0 == 0))
#line 77 "sample/process_monitor.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=56 dst=r2 src=r10 offset=0 imm=0
#line 77 "sample/process_monitor.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=57 dst=r2 src=r0 offset=0 imm=-272
#line 66 "sample/process_monitor.c"
    r2 += IMMEDIATE(-272);
    // EBPF_OP_LDDW pc=58 dst=r1 src=r0 offset=0 imm=0
#line 78 "sample/process_monitor.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_MOV64_IMM pc=60 dst=r3 src=r0 offset=0 imm=272
#line 78 "sample/process_monitor.c"
    r3 = IMMEDIATE(272);
    // EBPF_OP_JA pc=61 dst=r0 src=r0 offset=13 imm=0
#line 78 "sample/process_monitor.c"
    goto label_2;
label_1:
    // EBPF_OP_LDXDW pc=62 dst=r1 src=r1 offset=16 imm=0
#line 80 "sample/process_monitor.c"
    r1 = *(uint64_t*)(uintptr_t)(r1 + OFFSET(16));
    // EBPF_OP_STXDW pc=63 dst=r10 src=r1 offset=-272 imm=0
#line 80 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-272)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=64 dst=r10 src=r1 offset=-280 imm=0
#line 81 "sample/process_monitor.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-280)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=65 dst=r2 src=r10 offset=0 imm=0
#line 81 "sample/process_monitor.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=66 dst=r2 src=r0 offset=0 imm=-280
#line 80 "sample/process_monitor.c"
    r2 += IMMEDIATE(-280);
    // EBPF_OP_LDDW pc=67 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/process_monitor.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=69 dst=r0 src=r0 offset=0 imm=3
#line 82 "sample/process_monitor.c"
    r0 = ProcessMonitor_helpers[2].address
#line 82 "sample/process_monitor.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/process_monitor.c"
    if ((ProcessMonitor_helpers[2].tail_call) && (r0 == 0))
#line 82 "sample/process_monitor.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=70 dst=r2 src=r10 offset=0 imm=0
#line 82 "sample/process_monitor.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=71 dst=r2 src=r0 offset=0 imm=-272
#line 80 "sample/process_monitor.c"
    r2 += IMMEDIATE(-272);
    // EBPF_OP_LDDW pc=72 dst=r1 src=r0 offset=0 imm=0
#line 83 "sample/process_monitor.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_MOV64_IMM pc=74 dst=r3 src=r0 offset=0 imm=8
#line 83 "sample/process_monitor.c"
    r3 = IMMEDIATE(8);
label_2:
    // EBPF_OP_MOV64_IMM pc=75 dst=r4 src=r0 offset=0 imm=0
#line 83 "sample/process_monitor.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=76 dst=r0 src=r0 offset=0 imm=11
#line 83 "sample/process_monitor.c"
    r0 = ProcessMonitor_helpers[3].address
#line 83 "sample/process_monitor.c"
         (r1, r2, r3, r4, r5);
#line 83 "sample/process_monitor.c"
    if ((ProcessMonitor_helpers[3].tail_call) && (r0 == 0))
#line 83 "sample/process_monitor.c"
        return 0;
label_3:
    // EBPF_OP_MOV64_IMM pc=77 dst=r0 src=r0 offset=0 imm=0
#line 85 "sample/process_monitor.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=78 dst=r0 src=r0 offset=0 imm=0
#line 85 "sample/process_monitor.c"
    return r0;
#line 85 "sample/process_monitor.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        ProcessMonitor,
        "process",
        "process",
        "ProcessMonitor",
        ProcessMonitor_maps,
        2,
        ProcessMonitor_helpers,
        4,
        79,
        &ProcessMonitor_program_type_guid,
        &ProcessMonitor_attach_type_guid,
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
    version->minor = 14;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t process_monitor_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};
