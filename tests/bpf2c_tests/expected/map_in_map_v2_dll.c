// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from map_in_map_v2.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table map_in_map_v2##_metadata_table
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
         BPF_MAP_TYPE_ARRAY_OF_MAPS, // Type of map.
         4,                          // Size in bytes of a map key.
         4,                          // Size in bytes of a map value.
         1,                          // Maximum number of entries allowed in the map.
         0,                          // Inner map index.
         PIN_NONE,                   // Pinning type for the map.
         0,                          // Identifier for a map template.
         10,                         // The id of the inner map template.
     },
     "outer_map"},
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
     "inner_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 2;
}

static helper_function_entry_t lookup_helpers[] = {
    {NULL, 1, "helper_id_1"},
};

static GUID lookup_program_type_guid = {0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID lookup_attach_type_guid = {0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t lookup_maps[] = {
    0,
};

#pragma code_seg(push, "xdp_prog")
static uint64_t
lookup(void* context)
#line 35 "sample/map_in_map_v2.c"
{
#line 35 "sample/map_in_map_v2.c"
    // Prologue
#line 35 "sample/map_in_map_v2.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 35 "sample/map_in_map_v2.c"
    register uint64_t r0 = 0;
#line 35 "sample/map_in_map_v2.c"
    register uint64_t r1 = 0;
#line 35 "sample/map_in_map_v2.c"
    register uint64_t r2 = 0;
#line 35 "sample/map_in_map_v2.c"
    register uint64_t r3 = 0;
#line 35 "sample/map_in_map_v2.c"
    register uint64_t r4 = 0;
#line 35 "sample/map_in_map_v2.c"
    register uint64_t r5 = 0;
#line 35 "sample/map_in_map_v2.c"
    register uint64_t r6 = 0;
#line 35 "sample/map_in_map_v2.c"
    register uint64_t r10 = 0;

#line 35 "sample/map_in_map_v2.c"
    r1 = (uintptr_t)context;
#line 35 "sample/map_in_map_v2.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=0
#line 35 "sample/map_in_map_v2.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r6 offset=-4 imm=0
#line 37 "sample/map_in_map_v2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2 dst=r2 src=r10 offset=0 imm=0
#line 37 "sample/map_in_map_v2.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=3 dst=r2 src=r0 offset=0 imm=-4
#line 37 "sample/map_in_map_v2.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=4 dst=r1 src=r0 offset=0 imm=0
#line 38 "sample/map_in_map_v2.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=6 dst=r0 src=r0 offset=0 imm=1
#line 38 "sample/map_in_map_v2.c"
    r0 = lookup_helpers[0].address
#line 38 "sample/map_in_map_v2.c"
         (r1, r2, r3, r4, r5);
#line 38 "sample/map_in_map_v2.c"
    if ((lookup_helpers[0].tail_call) && (r0 == 0))
#line 38 "sample/map_in_map_v2.c"
        return 0;
        // EBPF_OP_JEQ_IMM pc=7 dst=r0 src=r0 offset=9 imm=0
#line 39 "sample/map_in_map_v2.c"
    if (r0 == IMMEDIATE(0))
#line 39 "sample/map_in_map_v2.c"
        goto label_2;
        // EBPF_OP_MOV64_IMM pc=8 dst=r6 src=r0 offset=0 imm=0
#line 39 "sample/map_in_map_v2.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=9 dst=r10 src=r6 offset=-8 imm=0
#line 40 "sample/map_in_map_v2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=10 dst=r2 src=r10 offset=0 imm=0
#line 40 "sample/map_in_map_v2.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=11 dst=r2 src=r0 offset=0 imm=-8
#line 40 "sample/map_in_map_v2.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=12 dst=r1 src=r0 offset=0 imm=0
#line 41 "sample/map_in_map_v2.c"
    r1 = r0;
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=1
#line 41 "sample/map_in_map_v2.c"
    r0 = lookup_helpers[0].address
#line 41 "sample/map_in_map_v2.c"
         (r1, r2, r3, r4, r5);
#line 41 "sample/map_in_map_v2.c"
    if ((lookup_helpers[0].tail_call) && (r0 == 0))
#line 41 "sample/map_in_map_v2.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=14 dst=r0 src=r0 offset=1 imm=0
#line 42 "sample/map_in_map_v2.c"
    if (r0 != IMMEDIATE(0))
#line 42 "sample/map_in_map_v2.c"
        goto label_1;
        // EBPF_OP_JA pc=15 dst=r0 src=r0 offset=1 imm=0
#line 42 "sample/map_in_map_v2.c"
    goto label_2;
label_1:
    // EBPF_OP_LDXW pc=16 dst=r6 src=r0 offset=0 imm=0
#line 43 "sample/map_in_map_v2.c"
    r6 = *(uint32_t*)(uintptr_t)(r0 + OFFSET(0));
label_2:
    // EBPF_OP_MOV64_REG pc=17 dst=r0 src=r6 offset=0 imm=0
#line 47 "sample/map_in_map_v2.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=18 dst=r0 src=r0 offset=0 imm=0
#line 47 "sample/map_in_map_v2.c"
    return r0;
#line 47 "sample/map_in_map_v2.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        lookup,
        "xdp_prog",
        "xdp_prog",
        "lookup",
        lookup_maps,
        1,
        lookup_helpers,
        1,
        19,
        &lookup_program_type_guid,
        &lookup_attach_type_guid,
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
    version->minor = 6;
    version->revision = 0;
}

metadata_table_t map_in_map_v2_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
