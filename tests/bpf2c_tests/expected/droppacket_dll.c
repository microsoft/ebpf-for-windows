// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from droppacket.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table droppacket##_metadata_table
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
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         8,                  // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         PIN_NONE,           // Pinning type for the map.
         0,                  // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "dropped_packet_map"},
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
     "interface_index_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 2;
}

static helper_function_entry_t DropPacket_helpers[] = {
    {NULL, 1, "helper_id_1"},
};

static GUID DropPacket_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID DropPacket_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t DropPacket_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "xdp")
static uint64_t
DropPacket(void* context)
#line 35 "sample/droppacket.c"
{
#line 35 "sample/droppacket.c"
    // Prologue
#line 35 "sample/droppacket.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 35 "sample/droppacket.c"
    register uint64_t r0 = 0;
#line 35 "sample/droppacket.c"
    register uint64_t r1 = 0;
#line 35 "sample/droppacket.c"
    register uint64_t r2 = 0;
#line 35 "sample/droppacket.c"
    register uint64_t r3 = 0;
#line 35 "sample/droppacket.c"
    register uint64_t r4 = 0;
#line 35 "sample/droppacket.c"
    register uint64_t r5 = 0;
#line 35 "sample/droppacket.c"
    register uint64_t r6 = 0;
#line 35 "sample/droppacket.c"
    register uint64_t r10 = 0;

#line 35 "sample/droppacket.c"
    r1 = (uintptr_t)context;
#line 35 "sample/droppacket.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 35 "sample/droppacket.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 35 "sample/droppacket.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 39 "sample/droppacket.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 39 "sample/droppacket.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-8
#line 39 "sample/droppacket.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 48 "sample/droppacket.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 48 "sample/droppacket.c"
    r0 = DropPacket_helpers[0].address
#line 48 "sample/droppacket.c"
         (r1, r2, r3, r4, r5);
#line 48 "sample/droppacket.c"
    if ((DropPacket_helpers[0].tail_call) && (r0 == 0))
#line 48 "sample/droppacket.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=8 dst=r1 src=r0 offset=0 imm=0
#line 48 "sample/droppacket.c"
    r1 = r0;
    // EBPF_OP_JEQ_IMM pc=9 dst=r1 src=r0 offset=4 imm=0
#line 49 "sample/droppacket.c"
    if (r1 == IMMEDIATE(0))
#line 49 "sample/droppacket.c"
        goto label_1;
    // EBPF_OP_MOV64_IMM pc=10 dst=r0 src=r0 offset=0 imm=1
#line 49 "sample/droppacket.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=11 dst=r1 src=r1 offset=0 imm=0
#line 50 "sample/droppacket.c"
    r1 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_LDXW pc=12 dst=r2 src=r6 offset=24 imm=0
#line 50 "sample/droppacket.c"
    r2 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(24));
    // EBPF_OP_JNE_REG pc=13 dst=r2 src=r1 offset=32 imm=0
#line 50 "sample/droppacket.c"
    if (r2 != r1)
#line 50 "sample/droppacket.c"
        goto label_2;
label_1:
    // EBPF_OP_MOV64_IMM pc=14 dst=r0 src=r0 offset=0 imm=1
#line 50 "sample/droppacket.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_LDXDW pc=15 dst=r2 src=r6 offset=8 imm=0
#line 56 "sample/droppacket.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_LDXDW pc=16 dst=r1 src=r6 offset=0 imm=0
#line 56 "sample/droppacket.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=17 dst=r3 src=r1 offset=0 imm=0
#line 56 "sample/droppacket.c"
    r3 = r1;
    // EBPF_OP_ADD64_IMM pc=18 dst=r3 src=r0 offset=0 imm=42
#line 56 "sample/droppacket.c"
    r3 += IMMEDIATE(42);
    // EBPF_OP_JGT_REG pc=19 dst=r3 src=r2 offset=26 imm=0
#line 56 "sample/droppacket.c"
    if (r3 > r2)
#line 56 "sample/droppacket.c"
        goto label_2;
    // EBPF_OP_LDXH pc=20 dst=r3 src=r1 offset=12 imm=0
#line 61 "sample/droppacket.c"
    r3 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(12));
    // EBPF_OP_JNE_IMM pc=21 dst=r3 src=r0 offset=24 imm=8
#line 61 "sample/droppacket.c"
    if (r3 != IMMEDIATE(8))
#line 61 "sample/droppacket.c"
        goto label_2;
    // EBPF_OP_LDXB pc=22 dst=r3 src=r1 offset=23 imm=0
#line 64 "sample/droppacket.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(23));
    // EBPF_OP_JNE_IMM pc=23 dst=r3 src=r0 offset=22 imm=17
#line 64 "sample/droppacket.c"
    if (r3 != IMMEDIATE(17))
#line 64 "sample/droppacket.c"
        goto label_2;
    // EBPF_OP_ADD64_IMM pc=24 dst=r1 src=r0 offset=0 imm=14
#line 64 "sample/droppacket.c"
    r1 += IMMEDIATE(14);
    // EBPF_OP_LDXB pc=25 dst=r3 src=r1 offset=0 imm=0
#line 66 "sample/droppacket.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_LSH64_IMM pc=26 dst=r3 src=r0 offset=0 imm=2
#line 66 "sample/droppacket.c"
    r3 <<= IMMEDIATE(2);
    // EBPF_OP_AND64_IMM pc=27 dst=r3 src=r0 offset=0 imm=60
#line 66 "sample/droppacket.c"
    r3 &= IMMEDIATE(60);
    // EBPF_OP_ADD64_REG pc=28 dst=r1 src=r3 offset=0 imm=0
#line 66 "sample/droppacket.c"
    r1 += r3;
    // EBPF_OP_MOV64_REG pc=29 dst=r3 src=r1 offset=0 imm=0
#line 67 "sample/droppacket.c"
    r3 = r1;
    // EBPF_OP_ADD64_IMM pc=30 dst=r3 src=r0 offset=0 imm=8
#line 67 "sample/droppacket.c"
    r3 += IMMEDIATE(8);
    // EBPF_OP_JGT_REG pc=31 dst=r3 src=r2 offset=14 imm=0
#line 67 "sample/droppacket.c"
    if (r3 > r2)
#line 67 "sample/droppacket.c"
        goto label_2;
    // EBPF_OP_LDXH pc=32 dst=r1 src=r1 offset=4 imm=0
#line 71 "sample/droppacket.c"
    r1 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(4));
    // EBPF_OP_BE pc=33 dst=r1 src=r0 offset=0 imm=16
#line 71 "sample/droppacket.c"
    r1 = htobe16((uint16_t)r1);
#line 71 "sample/droppacket.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_JGT_IMM pc=34 dst=r1 src=r0 offset=11 imm=8
#line 71 "sample/droppacket.c"
    if (r1 > IMMEDIATE(8))
#line 71 "sample/droppacket.c"
        goto label_2;
    // EBPF_OP_MOV64_REG pc=35 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/droppacket.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=36 dst=r2 src=r0 offset=0 imm=-8
#line 71 "sample/droppacket.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=37 dst=r1 src=r0 offset=0 imm=0
#line 72 "sample/droppacket.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=39 dst=r0 src=r0 offset=0 imm=1
#line 72 "sample/droppacket.c"
    r0 = DropPacket_helpers[0].address
#line 72 "sample/droppacket.c"
         (r1, r2, r3, r4, r5);
#line 72 "sample/droppacket.c"
    if ((DropPacket_helpers[0].tail_call) && (r0 == 0))
#line 72 "sample/droppacket.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=40 dst=r1 src=r0 offset=0 imm=0
#line 72 "sample/droppacket.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=41 dst=r0 src=r0 offset=0 imm=2
#line 72 "sample/droppacket.c"
    r0 = IMMEDIATE(2);
    // EBPF_OP_JEQ_IMM pc=42 dst=r1 src=r0 offset=3 imm=0
#line 73 "sample/droppacket.c"
    if (r1 == IMMEDIATE(0))
#line 73 "sample/droppacket.c"
        goto label_2;
    // EBPF_OP_LDXDW pc=43 dst=r2 src=r1 offset=0 imm=0
#line 74 "sample/droppacket.c"
    r2 = *(uint64_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=44 dst=r2 src=r0 offset=0 imm=1
#line 74 "sample/droppacket.c"
    r2 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=45 dst=r1 src=r2 offset=0 imm=0
#line 74 "sample/droppacket.c"
    *(uint64_t*)(uintptr_t)(r1 + OFFSET(0)) = (uint64_t)r2;
label_2:
    // EBPF_OP_EXIT pc=46 dst=r0 src=r0 offset=0 imm=0
#line 82 "sample/droppacket.c"
    return r0;
#line 82 "sample/droppacket.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        DropPacket,
        "xdp",
        "xdp",
        "DropPacket",
        DropPacket_maps,
        2,
        DropPacket_helpers,
        1,
        47,
        &DropPacket_program_type_guid,
        &DropPacket_attach_type_guid,
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

metadata_table_t droppacket_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
