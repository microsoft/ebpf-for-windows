// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from cgroup_sock_addr2.o

#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>

#include <stdio.h>

#include "bpf2c.h"

#define metadata_table cgroup_sock_addr2##_metadata_table
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
         24,                // Size in bytes of a map key.
         24,                // Size in bytes of a map value.
         100,               // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         PIN_NONE,          // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "policy_map"},
    {NULL,
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         8,                 // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         100,               // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         PIN_NONE,          // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "verdict_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 2;
}

static helper_function_entry_t connect_redirect4_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 14, "helper_id_14"},
    {NULL, 2, "helper_id_2"},
};

static GUID connect_redirect4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID connect_redirect4_attach_type_guid = {
    0xa82e37b1, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t connect_redirect4_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "cgroup~1")
static uint64_t
connect_redirect4(void* context)
#line 106 "sample/cgroup_sock_addr2.c"
{
#line 106 "sample/cgroup_sock_addr2.c"
    // Prologue
#line 106 "sample/cgroup_sock_addr2.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 106 "sample/cgroup_sock_addr2.c"
    register uint64_t r0 = 0;
#line 106 "sample/cgroup_sock_addr2.c"
    register uint64_t r1 = 0;
#line 106 "sample/cgroup_sock_addr2.c"
    register uint64_t r2 = 0;
#line 106 "sample/cgroup_sock_addr2.c"
    register uint64_t r3 = 0;
#line 106 "sample/cgroup_sock_addr2.c"
    register uint64_t r4 = 0;
#line 106 "sample/cgroup_sock_addr2.c"
    register uint64_t r5 = 0;
#line 106 "sample/cgroup_sock_addr2.c"
    register uint64_t r6 = 0;
#line 106 "sample/cgroup_sock_addr2.c"
    register uint64_t r7 = 0;
#line 106 "sample/cgroup_sock_addr2.c"
    register uint64_t r10 = 0;

#line 106 "sample/cgroup_sock_addr2.c"
    r1 = (uintptr_t)context;
#line 106 "sample/cgroup_sock_addr2.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 106 "sample/cgroup_sock_addr2.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r0 src=r0 offset=0 imm=0
#line 106 "sample/cgroup_sock_addr2.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r0 offset=-4 imm=0
#line 37 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r0;
    // EBPF_OP_STXW pc=3 dst=r10 src=r0 offset=-16 imm=0
#line 38 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r0;
    // EBPF_OP_STXW pc=4 dst=r10 src=r0 offset=-20 imm=0
#line 38 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint32_t)r0;
    // EBPF_OP_STXW pc=5 dst=r10 src=r0 offset=-24 imm=0
#line 38 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r0;
    // EBPF_OP_STXW pc=6 dst=r10 src=r0 offset=-28 imm=0
#line 38 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint32_t)r0;
    // EBPF_OP_LDXW pc=7 dst=r1 src=r6 offset=24 imm=0
#line 39 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(24));
    // EBPF_OP_STXW pc=8 dst=r10 src=r1 offset=-32 imm=0
#line 39 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r1;
    // EBPF_OP_LDXH pc=9 dst=r1 src=r6 offset=40 imm=0
#line 40 "sample/cgroup_sock_addr2.c"
    r1 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(40));
    // EBPF_OP_STXH pc=10 dst=r10 src=r1 offset=-16 imm=0
#line 40 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r1;
    // EBPF_OP_LDXW pc=11 dst=r1 src=r6 offset=44 imm=0
#line 41 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_STXW pc=12 dst=r10 src=r1 offset=-12 imm=0
#line 41 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint32_t)r1;
    // EBPF_OP_JEQ_IMM pc=13 dst=r1 src=r0 offset=1 imm=17
#line 43 "sample/cgroup_sock_addr2.c"
    if (r1 == IMMEDIATE(17))
#line 43 "sample/cgroup_sock_addr2.c"
        goto label_1;
        // EBPF_OP_JNE_IMM pc=14 dst=r1 src=r0 offset=48 imm=6
#line 43 "sample/cgroup_sock_addr2.c"
    if (r1 != IMMEDIATE(6))
#line 43 "sample/cgroup_sock_addr2.c"
        goto label_3;
label_1:
    // EBPF_OP_LDXW pc=15 dst=r1 src=r6 offset=0 imm=0
#line 47 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=16 dst=r1 src=r0 offset=46 imm=2
#line 47 "sample/cgroup_sock_addr2.c"
    if (r1 != IMMEDIATE(2))
#line 47 "sample/cgroup_sock_addr2.c"
        goto label_3;
        // EBPF_OP_MOV64_REG pc=17 dst=r2 src=r10 offset=0 imm=0
#line 47 "sample/cgroup_sock_addr2.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=18 dst=r2 src=r0 offset=0 imm=-32
#line 52 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-32);
    // EBPF_OP_LDDW pc=19 dst=r1 src=r0 offset=0 imm=0
#line 52 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=21 dst=r0 src=r0 offset=0 imm=1
#line 52 "sample/cgroup_sock_addr2.c"
    r0 = connect_redirect4_helpers[0].address
#line 52 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 52 "sample/cgroup_sock_addr2.c"
    if ((connect_redirect4_helpers[0].tail_call) && (r0 == 0))
#line 52 "sample/cgroup_sock_addr2.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=22 dst=r7 src=r0 offset=0 imm=0
#line 52 "sample/cgroup_sock_addr2.c"
    r7 = r0;
    // EBPF_OP_JEQ_IMM pc=23 dst=r7 src=r0 offset=28 imm=0
#line 53 "sample/cgroup_sock_addr2.c"
    if (r7 == IMMEDIATE(0))
#line 53 "sample/cgroup_sock_addr2.c"
        goto label_2;
        // EBPF_OP_MOV64_IMM pc=24 dst=r1 src=r0 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=25 dst=r10 src=r1 offset=-38 imm=0
#line 54 "sample/cgroup_sock_addr2.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-38)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=26 dst=r1 src=r0 offset=0 imm=29989
#line 54 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(29989);
    // EBPF_OP_STXH pc=27 dst=r10 src=r1 offset=-40 imm=0
#line 54 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=28 dst=r1 src=r0 offset=0 imm=540697973
#line 54 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)2318356710503900533;
    // EBPF_OP_STXDW pc=30 dst=r10 src=r1 offset=-48 imm=0
#line 54 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=31 dst=r1 src=r0 offset=0 imm=2037544046
#line 54 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7809653110685725806;
    // EBPF_OP_STXDW pc=33 dst=r10 src=r1 offset=-56 imm=0
#line 54 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=34 dst=r1 src=r0 offset=0 imm=1869770784
#line 54 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7286957755258269728;
    // EBPF_OP_STXDW pc=36 dst=r10 src=r1 offset=-64 imm=0
#line 54 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=37 dst=r1 src=r0 offset=0 imm=1853189958
#line 54 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)3780244552946118470;
    // EBPF_OP_STXDW pc=39 dst=r10 src=r1 offset=-72 imm=0
#line 54 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDXH pc=40 dst=r4 src=r7 offset=16 imm=0
#line 54 "sample/cgroup_sock_addr2.c"
    r4 = *(uint16_t*)(uintptr_t)(r7 + OFFSET(16));
    // EBPF_OP_LDXW pc=41 dst=r3 src=r7 offset=0 imm=0
#line 54 "sample/cgroup_sock_addr2.c"
    r3 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=42 dst=r1 src=r10 offset=0 imm=0
#line 54 "sample/cgroup_sock_addr2.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=43 dst=r1 src=r0 offset=0 imm=-72
#line 54 "sample/cgroup_sock_addr2.c"
    r1 += IMMEDIATE(-72);
    // EBPF_OP_MOV64_IMM pc=44 dst=r2 src=r0 offset=0 imm=35
#line 54 "sample/cgroup_sock_addr2.c"
    r2 = IMMEDIATE(35);
    // EBPF_OP_CALL pc=45 dst=r0 src=r0 offset=0 imm=14
#line 54 "sample/cgroup_sock_addr2.c"
    r0 = connect_redirect4_helpers[1].address
#line 54 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 54 "sample/cgroup_sock_addr2.c"
    if ((connect_redirect4_helpers[1].tail_call) && (r0 == 0))
#line 54 "sample/cgroup_sock_addr2.c"
        return 0;
        // EBPF_OP_LDXW pc=46 dst=r1 src=r7 offset=0 imm=0
#line 55 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_STXW pc=47 dst=r6 src=r1 offset=24 imm=0
#line 55 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r6 + OFFSET(24)) = (uint32_t)r1;
    // EBPF_OP_LDXH pc=48 dst=r1 src=r7 offset=16 imm=0
#line 56 "sample/cgroup_sock_addr2.c"
    r1 = *(uint16_t*)(uintptr_t)(r7 + OFFSET(16));
    // EBPF_OP_STXH pc=49 dst=r6 src=r1 offset=40 imm=0
#line 56 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(40)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=50 dst=r1 src=r0 offset=0 imm=1
#line 56 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=51 dst=r10 src=r1 offset=-4 imm=0
#line 58 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
label_2:
    // EBPF_OP_LDXDW pc=52 dst=r1 src=r6 offset=64 imm=0
#line 61 "sample/cgroup_sock_addr2.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(64));
    // EBPF_OP_STXDW pc=53 dst=r10 src=r1 offset=-72 imm=0
#line 61 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=54 dst=r2 src=r10 offset=0 imm=0
#line 61 "sample/cgroup_sock_addr2.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=55 dst=r2 src=r0 offset=0 imm=-72
#line 61 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-72);
    // EBPF_OP_MOV64_REG pc=56 dst=r3 src=r10 offset=0 imm=0
#line 61 "sample/cgroup_sock_addr2.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=57 dst=r3 src=r0 offset=0 imm=-4
#line 61 "sample/cgroup_sock_addr2.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=58 dst=r1 src=r0 offset=0 imm=0
#line 62 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_MOV64_IMM pc=60 dst=r4 src=r0 offset=0 imm=0
#line 62 "sample/cgroup_sock_addr2.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=61 dst=r0 src=r0 offset=0 imm=2
#line 62 "sample/cgroup_sock_addr2.c"
    r0 = connect_redirect4_helpers[2].address
#line 62 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 62 "sample/cgroup_sock_addr2.c"
    if ((connect_redirect4_helpers[2].tail_call) && (r0 == 0))
#line 62 "sample/cgroup_sock_addr2.c"
        return 0;
        // EBPF_OP_LDXW pc=62 dst=r0 src=r10 offset=-4 imm=0
#line 64 "sample/cgroup_sock_addr2.c"
    r0 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
label_3:
    // EBPF_OP_EXIT pc=63 dst=r0 src=r0 offset=0 imm=0
#line 108 "sample/cgroup_sock_addr2.c"
    return r0;
#line 108 "sample/cgroup_sock_addr2.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t connect_redirect6_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 12, "helper_id_12"},
    {NULL, 2, "helper_id_2"},
};

static GUID connect_redirect6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID connect_redirect6_attach_type_guid = {
    0xa82e37b2, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t connect_redirect6_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "cgroup~2")
static uint64_t
connect_redirect6(void* context)
#line 113 "sample/cgroup_sock_addr2.c"
{
#line 113 "sample/cgroup_sock_addr2.c"
    // Prologue
#line 113 "sample/cgroup_sock_addr2.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 113 "sample/cgroup_sock_addr2.c"
    register uint64_t r0 = 0;
#line 113 "sample/cgroup_sock_addr2.c"
    register uint64_t r1 = 0;
#line 113 "sample/cgroup_sock_addr2.c"
    register uint64_t r2 = 0;
#line 113 "sample/cgroup_sock_addr2.c"
    register uint64_t r3 = 0;
#line 113 "sample/cgroup_sock_addr2.c"
    register uint64_t r4 = 0;
#line 113 "sample/cgroup_sock_addr2.c"
    register uint64_t r5 = 0;
#line 113 "sample/cgroup_sock_addr2.c"
    register uint64_t r6 = 0;
#line 113 "sample/cgroup_sock_addr2.c"
    register uint64_t r7 = 0;
#line 113 "sample/cgroup_sock_addr2.c"
    register uint64_t r8 = 0;
#line 113 "sample/cgroup_sock_addr2.c"
    register uint64_t r10 = 0;

#line 113 "sample/cgroup_sock_addr2.c"
    r1 = (uintptr_t)context;
#line 113 "sample/cgroup_sock_addr2.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 113 "sample/cgroup_sock_addr2.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r0 src=r0 offset=0 imm=0
#line 113 "sample/cgroup_sock_addr2.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r0 offset=-4 imm=0
#line 70 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r0;
    // EBPF_OP_STXDW pc=3 dst=r10 src=r0 offset=-16 imm=0
#line 71 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r0;
    // EBPF_OP_STXDW pc=4 dst=r10 src=r0 offset=-24 imm=0
#line 71 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r0;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r0 offset=-32 imm=0
#line 71 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r0;
    // EBPF_OP_LDXW pc=6 dst=r1 src=r6 offset=44 imm=0
#line 73 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_JEQ_IMM pc=7 dst=r1 src=r0 offset=1 imm=17
#line 73 "sample/cgroup_sock_addr2.c"
    if (r1 == IMMEDIATE(17))
#line 73 "sample/cgroup_sock_addr2.c"
        goto label_1;
        // EBPF_OP_JNE_IMM pc=8 dst=r1 src=r0 offset=64 imm=6
#line 73 "sample/cgroup_sock_addr2.c"
    if (r1 != IMMEDIATE(6))
#line 73 "sample/cgroup_sock_addr2.c"
        goto label_3;
label_1:
    // EBPF_OP_LDXW pc=9 dst=r2 src=r6 offset=0 imm=0
#line 77 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=10 dst=r2 src=r0 offset=62 imm=23
#line 77 "sample/cgroup_sock_addr2.c"
    if (r2 != IMMEDIATE(23))
#line 77 "sample/cgroup_sock_addr2.c"
        goto label_3;
        // EBPF_OP_LDXW pc=11 dst=r2 src=r6 offset=36 imm=0
#line 84 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(36));
    // EBPF_OP_LSH64_IMM pc=12 dst=r2 src=r0 offset=0 imm=32
#line 84 "sample/cgroup_sock_addr2.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_LDXW pc=13 dst=r3 src=r6 offset=32 imm=0
#line 84 "sample/cgroup_sock_addr2.c"
    r3 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(32));
    // EBPF_OP_OR64_REG pc=14 dst=r2 src=r3 offset=0 imm=0
#line 84 "sample/cgroup_sock_addr2.c"
    r2 |= r3;
    // EBPF_OP_STXDW pc=15 dst=r10 src=r2 offset=-24 imm=0
#line 84 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r2;
    // EBPF_OP_LDXW pc=16 dst=r2 src=r6 offset=28 imm=0
#line 84 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(28));
    // EBPF_OP_LSH64_IMM pc=17 dst=r2 src=r0 offset=0 imm=32
#line 84 "sample/cgroup_sock_addr2.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_LDXW pc=18 dst=r3 src=r6 offset=24 imm=0
#line 84 "sample/cgroup_sock_addr2.c"
    r3 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(24));
    // EBPF_OP_OR64_REG pc=19 dst=r2 src=r3 offset=0 imm=0
#line 84 "sample/cgroup_sock_addr2.c"
    r2 |= r3;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r2 offset=-32 imm=0
#line 84 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r2;
    // EBPF_OP_LDXH pc=21 dst=r2 src=r6 offset=40 imm=0
#line 85 "sample/cgroup_sock_addr2.c"
    r2 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(40));
    // EBPF_OP_STXH pc=22 dst=r10 src=r2 offset=-16 imm=0
#line 85 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r2;
    // EBPF_OP_STXW pc=23 dst=r10 src=r1 offset=-12 imm=0
#line 86 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=24 dst=r2 src=r10 offset=0 imm=0
#line 86 "sample/cgroup_sock_addr2.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=25 dst=r2 src=r0 offset=0 imm=-32
#line 84 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-32);
    // EBPF_OP_LDDW pc=26 dst=r1 src=r0 offset=0 imm=0
#line 89 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=28 dst=r0 src=r0 offset=0 imm=1
#line 89 "sample/cgroup_sock_addr2.c"
    r0 = connect_redirect6_helpers[0].address
#line 89 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 89 "sample/cgroup_sock_addr2.c"
    if ((connect_redirect6_helpers[0].tail_call) && (r0 == 0))
#line 89 "sample/cgroup_sock_addr2.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=29 dst=r7 src=r0 offset=0 imm=0
#line 89 "sample/cgroup_sock_addr2.c"
    r7 = r0;
    // EBPF_OP_JEQ_IMM pc=30 dst=r7 src=r0 offset=31 imm=0
#line 90 "sample/cgroup_sock_addr2.c"
    if (r7 == IMMEDIATE(0))
#line 90 "sample/cgroup_sock_addr2.c"
        goto label_2;
        // EBPF_OP_MOV64_REG pc=31 dst=r8 src=r6 offset=0 imm=0
#line 90 "sample/cgroup_sock_addr2.c"
    r8 = r6;
    // EBPF_OP_ADD64_IMM pc=32 dst=r8 src=r0 offset=0 imm=24
#line 90 "sample/cgroup_sock_addr2.c"
    r8 += IMMEDIATE(24);
    // EBPF_OP_MOV64_IMM pc=33 dst=r1 src=r0 offset=0 imm=0
#line 90 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=34 dst=r10 src=r1 offset=-38 imm=0
#line 91 "sample/cgroup_sock_addr2.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-38)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=35 dst=r1 src=r0 offset=0 imm=25973
#line 91 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(25973);
    // EBPF_OP_STXH pc=36 dst=r10 src=r1 offset=-40 imm=0
#line 91 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=37 dst=r1 src=r0 offset=0 imm=2037544046
#line 91 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7809653110685725806;
    // EBPF_OP_STXDW pc=39 dst=r10 src=r1 offset=-48 imm=0
#line 91 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=40 dst=r1 src=r0 offset=0 imm=1869770784
#line 91 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7286957755258269728;
    // EBPF_OP_STXDW pc=42 dst=r10 src=r1 offset=-56 imm=0
#line 91 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=43 dst=r1 src=r0 offset=0 imm=1853189958
#line 91 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)3924359741021974342;
    // EBPF_OP_STXDW pc=45 dst=r10 src=r1 offset=-64 imm=0
#line 91 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=46 dst=r1 src=r10 offset=0 imm=0
#line 91 "sample/cgroup_sock_addr2.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=47 dst=r1 src=r0 offset=0 imm=-64
#line 91 "sample/cgroup_sock_addr2.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=48 dst=r2 src=r0 offset=0 imm=27
#line 91 "sample/cgroup_sock_addr2.c"
    r2 = IMMEDIATE(27);
    // EBPF_OP_CALL pc=49 dst=r0 src=r0 offset=0 imm=12
#line 91 "sample/cgroup_sock_addr2.c"
    r0 = connect_redirect6_helpers[1].address
#line 91 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 91 "sample/cgroup_sock_addr2.c"
    if ((connect_redirect6_helpers[1].tail_call) && (r0 == 0))
#line 91 "sample/cgroup_sock_addr2.c"
        return 0;
        // EBPF_OP_LDXW pc=50 dst=r1 src=r7 offset=12 imm=0
#line 92 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(12));
    // EBPF_OP_STXW pc=51 dst=r8 src=r1 offset=12 imm=0
#line 92 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(12)) = (uint32_t)r1;
    // EBPF_OP_LDXW pc=52 dst=r1 src=r7 offset=8 imm=0
#line 92 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(8));
    // EBPF_OP_STXW pc=53 dst=r8 src=r1 offset=8 imm=0
#line 92 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(8)) = (uint32_t)r1;
    // EBPF_OP_LDXW pc=54 dst=r1 src=r7 offset=4 imm=0
#line 92 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(4));
    // EBPF_OP_STXW pc=55 dst=r8 src=r1 offset=4 imm=0
#line 92 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(4)) = (uint32_t)r1;
    // EBPF_OP_LDXW pc=56 dst=r1 src=r7 offset=0 imm=0
#line 92 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_STXW pc=57 dst=r8 src=r1 offset=0 imm=0
#line 92 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_LDXH pc=58 dst=r1 src=r7 offset=16 imm=0
#line 93 "sample/cgroup_sock_addr2.c"
    r1 = *(uint16_t*)(uintptr_t)(r7 + OFFSET(16));
    // EBPF_OP_STXH pc=59 dst=r6 src=r1 offset=40 imm=0
#line 93 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(40)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=60 dst=r1 src=r0 offset=0 imm=1
#line 93 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=61 dst=r10 src=r1 offset=-4 imm=0
#line 95 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
label_2:
    // EBPF_OP_LDXDW pc=62 dst=r1 src=r6 offset=64 imm=0
#line 98 "sample/cgroup_sock_addr2.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(64));
    // EBPF_OP_STXDW pc=63 dst=r10 src=r1 offset=-64 imm=0
#line 98 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=64 dst=r2 src=r10 offset=0 imm=0
#line 98 "sample/cgroup_sock_addr2.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=65 dst=r2 src=r0 offset=0 imm=-64
#line 98 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_REG pc=66 dst=r3 src=r10 offset=0 imm=0
#line 98 "sample/cgroup_sock_addr2.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=67 dst=r3 src=r0 offset=0 imm=-4
#line 98 "sample/cgroup_sock_addr2.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=68 dst=r1 src=r0 offset=0 imm=0
#line 99 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_MOV64_IMM pc=70 dst=r4 src=r0 offset=0 imm=0
#line 99 "sample/cgroup_sock_addr2.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=71 dst=r0 src=r0 offset=0 imm=2
#line 99 "sample/cgroup_sock_addr2.c"
    r0 = connect_redirect6_helpers[2].address
#line 99 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 99 "sample/cgroup_sock_addr2.c"
    if ((connect_redirect6_helpers[2].tail_call) && (r0 == 0))
#line 99 "sample/cgroup_sock_addr2.c"
        return 0;
        // EBPF_OP_LDXW pc=72 dst=r0 src=r10 offset=-4 imm=0
#line 101 "sample/cgroup_sock_addr2.c"
    r0 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
label_3:
    // EBPF_OP_EXIT pc=73 dst=r0 src=r0 offset=0 imm=0
#line 115 "sample/cgroup_sock_addr2.c"
    return r0;
#line 115 "sample/cgroup_sock_addr2.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        connect_redirect4,
        "cgroup~1",
        "cgroup/connect4",
        "connect_redirect4",
        connect_redirect4_maps,
        2,
        connect_redirect4_helpers,
        3,
        64,
        &connect_redirect4_program_type_guid,
        &connect_redirect4_attach_type_guid,
    },
    {
        0,
        connect_redirect6,
        "cgroup~2",
        "cgroup/connect6",
        "connect_redirect6",
        connect_redirect6_maps,
        2,
        connect_redirect6_helpers,
        3,
        74,
        &connect_redirect6_program_type_guid,
        &connect_redirect6_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 2;
}

metadata_table_t cgroup_sock_addr2_metadata_table = {_get_programs, _get_maps, _get_hash};
