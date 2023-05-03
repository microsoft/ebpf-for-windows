// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from map_reuse.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table map_reuse##_metadata_table
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
         BPF_MAP_TYPE_HASH_OF_MAPS, // Type of map.
         4,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         1,                         // Maximum number of entries allowed in the map.
         1,                         // Inner map index.
         PIN_GLOBAL_NS,             // Pinning type for the map.
         0,                         // Identifier for a map template.
         0,                         // The id of the inner map template.
     },
     "outer_map"},
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
     "inner_map"},
    {NULL,
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         PIN_GLOBAL_NS,      // Pinning type for the map.
         0,                  // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "port_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 3;
}

static helper_function_entry_t lookup_update_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 2, "helper_id_2"},
};

static GUID lookup_update_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID lookup_update_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t lookup_update_maps[] = {
    0,
    2,
};

#pragma code_seg(push, "xdp_prog")
static uint64_t
lookup_update(void* context)
#line 45 "sample/map_reuse.c"
{
#line 45 "sample/map_reuse.c"
    // Prologue
#line 45 "sample/map_reuse.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 45 "sample/map_reuse.c"
    register uint64_t r0 = 0;
#line 45 "sample/map_reuse.c"
    register uint64_t r1 = 0;
#line 45 "sample/map_reuse.c"
    register uint64_t r2 = 0;
#line 45 "sample/map_reuse.c"
    register uint64_t r3 = 0;
#line 45 "sample/map_reuse.c"
    register uint64_t r4 = 0;
#line 45 "sample/map_reuse.c"
    register uint64_t r5 = 0;
#line 45 "sample/map_reuse.c"
    register uint64_t r6 = 0;
#line 45 "sample/map_reuse.c"
    register uint64_t r7 = 0;
#line 45 "sample/map_reuse.c"
    register uint64_t r10 = 0;

#line 45 "sample/map_reuse.c"
    r1 = (uintptr_t)context;
#line 45 "sample/map_reuse.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=0
#line 45 "sample/map_reuse.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r6 offset=-4 imm=0
#line 47 "sample/map_reuse.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2 dst=r2 src=r10 offset=0 imm=0
#line 47 "sample/map_reuse.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=3 dst=r2 src=r0 offset=0 imm=-4
#line 47 "sample/map_reuse.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=4 dst=r1 src=r0 offset=0 imm=0
#line 50 "sample/map_reuse.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=6 dst=r0 src=r0 offset=0 imm=1
#line 50 "sample/map_reuse.c"
    r0 = lookup_update_helpers[0].address
#line 50 "sample/map_reuse.c"
         (r1, r2, r3, r4, r5);
#line 50 "sample/map_reuse.c"
    if ((lookup_update_helpers[0].tail_call) && (r0 == 0))
#line 50 "sample/map_reuse.c"
        return 0;
    // EBPF_OP_JEQ_IMM pc=7 dst=r0 src=r0 offset=21 imm=0
#line 51 "sample/map_reuse.c"
    if (r0 == IMMEDIATE(0))
#line 51 "sample/map_reuse.c"
        goto label_2;
    // EBPF_OP_MOV64_IMM pc=8 dst=r6 src=r0 offset=0 imm=0
#line 51 "sample/map_reuse.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=9 dst=r10 src=r6 offset=-8 imm=0
#line 52 "sample/map_reuse.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=10 dst=r2 src=r10 offset=0 imm=0
#line 52 "sample/map_reuse.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=11 dst=r2 src=r0 offset=0 imm=-8
#line 52 "sample/map_reuse.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=12 dst=r1 src=r0 offset=0 imm=0
#line 53 "sample/map_reuse.c"
    r1 = r0;
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=1
#line 53 "sample/map_reuse.c"
    r0 = lookup_update_helpers[0].address
#line 53 "sample/map_reuse.c"
         (r1, r2, r3, r4, r5);
#line 53 "sample/map_reuse.c"
    if ((lookup_update_helpers[0].tail_call) && (r0 == 0))
#line 53 "sample/map_reuse.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r7 src=r0 offset=0 imm=0
#line 53 "sample/map_reuse.c"
    r7 = r0;
    // EBPF_OP_JNE_IMM pc=15 dst=r7 src=r0 offset=1 imm=0
#line 54 "sample/map_reuse.c"
    if (r7 != IMMEDIATE(0))
#line 54 "sample/map_reuse.c"
        goto label_1;
    // EBPF_OP_JA pc=16 dst=r0 src=r0 offset=12 imm=0
#line 54 "sample/map_reuse.c"
    goto label_2;
label_1:
    // EBPF_OP_STXW pc=17 dst=r10 src=r6 offset=-12 imm=0
#line 56 "sample/map_reuse.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint32_t)r6;
    // EBPF_OP_LDXW pc=18 dst=r1 src=r7 offset=0 imm=0
#line 57 "sample/map_reuse.c"
    r1 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_STXW pc=19 dst=r10 src=r1 offset=-16 imm=0
#line 57 "sample/map_reuse.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=20 dst=r2 src=r10 offset=0 imm=0
#line 57 "sample/map_reuse.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=21 dst=r2 src=r0 offset=0 imm=-12
#line 57 "sample/map_reuse.c"
    r2 += IMMEDIATE(-12);
    // EBPF_OP_MOV64_REG pc=22 dst=r3 src=r10 offset=0 imm=0
#line 57 "sample/map_reuse.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r3 src=r0 offset=0 imm=-16
#line 57 "sample/map_reuse.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=24 dst=r1 src=r0 offset=0 imm=0
#line 58 "sample/map_reuse.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_MOV64_IMM pc=26 dst=r4 src=r0 offset=0 imm=0
#line 58 "sample/map_reuse.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=27 dst=r0 src=r0 offset=0 imm=2
#line 58 "sample/map_reuse.c"
    r0 = lookup_update_helpers[1].address
#line 58 "sample/map_reuse.c"
         (r1, r2, r3, r4, r5);
#line 58 "sample/map_reuse.c"
    if ((lookup_update_helpers[1].tail_call) && (r0 == 0))
#line 58 "sample/map_reuse.c"
        return 0;
    // EBPF_OP_LDXW pc=28 dst=r6 src=r7 offset=0 imm=0
#line 60 "sample/map_reuse.c"
    r6 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
label_2:
    // EBPF_OP_MOV64_REG pc=29 dst=r0 src=r6 offset=0 imm=0
#line 64 "sample/map_reuse.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=30 dst=r0 src=r0 offset=0 imm=0
#line 64 "sample/map_reuse.c"
    return r0;
#line 64 "sample/map_reuse.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        lookup_update,
        "xdp_prog",
        "xdp_prog",
        "lookup_update",
        lookup_update_maps,
        2,
        lookup_update_helpers,
        2,
        31,
        &lookup_update_program_type_guid,
        &lookup_update_attach_type_guid,
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

metadata_table_t map_reuse_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
