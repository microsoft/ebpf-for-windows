// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from bindmonitor_mt_tailcall.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table bindmonitor_mt_tailcall##_metadata_table
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
         BPF_MAP_TYPE_PROG_ARRAY, // Type of map.
         4,                       // Size in bytes of a map key.
         4,                       // Size in bytes of a map value.
         32,                      // Maximum number of entries allowed in the map.
         0,                       // Inner map index.
         PIN_NONE,                // Pinning type for the map.
         0,                       // Identifier for a map template.
         0,                       // The id of the inner map template.
     },
     "bind_tail_call_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 1;
}

static helper_function_entry_t BindMonitor_Caller_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Caller_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Caller_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Caller_maps[] = {
    0,
};

#pragma code_seg(push, "bind")
static uint64_t
BindMonitor_Caller(void* context)
#line 31 "sample/bindmonitor_mt_tailcall.c"
{
#line 31 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 31 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 31 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 31 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 31 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 31 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 31 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 31 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 31 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 31 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 31 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 31 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 31 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 31 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 33 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 33 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 33 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 33 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 33 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 33 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 33 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 33 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=0
#line 33 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 33 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Caller_helpers[0].address
#line 33 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 33 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Caller_helpers[0].tail_call) && (r0 == 0))
#line 33 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 34 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 34 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=0
#line 34 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 34 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Caller_helpers[1].address
#line 34 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 34 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Caller_helpers[1].tail_call) && (r0 == 0))
#line 34 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 36 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 36 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 36 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee0_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee0_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee0_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee0_maps[] = {
    0,
};

#pragma code_seg(push, "bind/0")
static uint64_t
BindMonitor_Callee0(void* context)
#line 50 "sample/bindmonitor_mt_tailcall.c"
{
#line 50 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 50 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 50 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 50 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 50 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 50 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 50 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 50 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 50 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 50 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 50 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 50 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 50 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 50 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 50 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 50 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 50 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 50 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 50 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 50 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 50 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 50 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=1
#line 50 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(1);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 50 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee0_helpers[0].address
#line 50 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 50 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee0_helpers[0].tail_call) && (r0 == 0))
#line 50 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 50 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 50 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=1
#line 50 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(1);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 50 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee0_helpers[1].address
#line 50 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 50 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee0_helpers[1].tail_call) && (r0 == 0))
#line 50 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 50 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 50 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 50 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee1_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee1_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee1_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee1_maps[] = {
    0,
};

#pragma code_seg(push, "bind/1")
static uint64_t
BindMonitor_Callee1(void* context)
#line 51 "sample/bindmonitor_mt_tailcall.c"
{
#line 51 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 51 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 51 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 51 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 51 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 51 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 51 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 51 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 51 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 51 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 51 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 51 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 51 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 51 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 51 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 51 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 51 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 51 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 51 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 51 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 51 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 51 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=2
#line 51 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 51 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee1_helpers[0].address
#line 51 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 51 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee1_helpers[0].tail_call) && (r0 == 0))
#line 51 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 51 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 51 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=2
#line 51 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 51 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee1_helpers[1].address
#line 51 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 51 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee1_helpers[1].tail_call) && (r0 == 0))
#line 51 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 51 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 51 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 51 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee10_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee10_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee10_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee10_maps[] = {
    0,
};

#pragma code_seg(push, "bind/10")
static uint64_t
BindMonitor_Callee10(void* context)
#line 60 "sample/bindmonitor_mt_tailcall.c"
{
#line 60 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 60 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 60 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 60 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 60 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 60 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 60 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 60 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 60 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 60 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 60 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 60 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 60 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 60 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 60 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 60 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 60 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 60 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 60 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 60 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 60 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 60 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=11
#line 60 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(11);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 60 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee10_helpers[0].address
#line 60 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 60 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee10_helpers[0].tail_call) && (r0 == 0))
#line 60 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 60 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 60 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=11
#line 60 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(11);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 60 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee10_helpers[1].address
#line 60 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 60 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee10_helpers[1].tail_call) && (r0 == 0))
#line 60 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 60 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 60 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 60 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee11_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee11_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee11_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee11_maps[] = {
    0,
};

#pragma code_seg(push, "bind/11")
static uint64_t
BindMonitor_Callee11(void* context)
#line 61 "sample/bindmonitor_mt_tailcall.c"
{
#line 61 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 61 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 61 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 61 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 61 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 61 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 61 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 61 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 61 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 61 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 61 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 61 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 61 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 61 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 61 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 61 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 61 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 61 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 61 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 61 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 61 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 61 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=12
#line 61 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(12);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 61 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee11_helpers[0].address
#line 61 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 61 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee11_helpers[0].tail_call) && (r0 == 0))
#line 61 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 61 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 61 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=12
#line 61 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(12);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 61 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee11_helpers[1].address
#line 61 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 61 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee11_helpers[1].tail_call) && (r0 == 0))
#line 61 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 61 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 61 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 61 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee12_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee12_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee12_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee12_maps[] = {
    0,
};

#pragma code_seg(push, "bind/12")
static uint64_t
BindMonitor_Callee12(void* context)
#line 62 "sample/bindmonitor_mt_tailcall.c"
{
#line 62 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 62 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 62 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 62 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 62 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 62 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 62 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 62 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 62 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 62 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 62 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 62 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 62 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 62 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 62 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 62 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 62 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 62 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 62 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 62 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 62 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 62 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=13
#line 62 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(13);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 62 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee12_helpers[0].address
#line 62 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 62 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee12_helpers[0].tail_call) && (r0 == 0))
#line 62 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 62 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 62 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=13
#line 62 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(13);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 62 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee12_helpers[1].address
#line 62 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 62 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee12_helpers[1].tail_call) && (r0 == 0))
#line 62 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 62 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 62 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 62 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee13_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee13_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee13_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee13_maps[] = {
    0,
};

#pragma code_seg(push, "bind/13")
static uint64_t
BindMonitor_Callee13(void* context)
#line 63 "sample/bindmonitor_mt_tailcall.c"
{
#line 63 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 63 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 63 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 63 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 63 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 63 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 63 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 63 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 63 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 63 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 63 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 63 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 63 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 63 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 63 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 63 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 63 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 63 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 63 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 63 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 63 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 63 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=14
#line 63 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(14);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 63 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee13_helpers[0].address
#line 63 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 63 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee13_helpers[0].tail_call) && (r0 == 0))
#line 63 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 63 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 63 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=14
#line 63 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(14);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 63 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee13_helpers[1].address
#line 63 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 63 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee13_helpers[1].tail_call) && (r0 == 0))
#line 63 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 63 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 63 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 63 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee14_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee14_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee14_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee14_maps[] = {
    0,
};

#pragma code_seg(push, "bind/14")
static uint64_t
BindMonitor_Callee14(void* context)
#line 64 "sample/bindmonitor_mt_tailcall.c"
{
#line 64 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 64 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 64 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 64 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 64 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 64 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 64 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 64 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 64 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 64 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 64 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 64 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 64 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 64 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 64 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 64 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 64 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 64 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 64 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 64 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 64 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 64 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=15
#line 64 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(15);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 64 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee14_helpers[0].address
#line 64 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 64 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee14_helpers[0].tail_call) && (r0 == 0))
#line 64 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 64 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 64 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=15
#line 64 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(15);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 64 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee14_helpers[1].address
#line 64 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 64 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee14_helpers[1].tail_call) && (r0 == 0))
#line 64 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 64 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 64 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 64 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee15_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee15_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee15_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee15_maps[] = {
    0,
};

#pragma code_seg(push, "bind/15")
static uint64_t
BindMonitor_Callee15(void* context)
#line 65 "sample/bindmonitor_mt_tailcall.c"
{
#line 65 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 65 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 65 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 65 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 65 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 65 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 65 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 65 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 65 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 65 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 65 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 65 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 65 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 65 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 65 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 65 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 65 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 65 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 65 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 65 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 65 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 65 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=16
#line 65 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(16);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 65 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee15_helpers[0].address
#line 65 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 65 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee15_helpers[0].tail_call) && (r0 == 0))
#line 65 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 65 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 65 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=16
#line 65 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(16);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 65 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee15_helpers[1].address
#line 65 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 65 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee15_helpers[1].tail_call) && (r0 == 0))
#line 65 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 65 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 65 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 65 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee16_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee16_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee16_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee16_maps[] = {
    0,
};

#pragma code_seg(push, "bind/16")
static uint64_t
BindMonitor_Callee16(void* context)
#line 66 "sample/bindmonitor_mt_tailcall.c"
{
#line 66 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 66 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 66 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 66 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 66 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 66 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 66 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 66 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 66 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 66 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 66 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 66 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 66 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 66 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 66 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 66 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 66 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 66 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 66 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 66 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 66 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 66 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=17
#line 66 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(17);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 66 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee16_helpers[0].address
#line 66 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 66 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee16_helpers[0].tail_call) && (r0 == 0))
#line 66 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 66 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 66 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=17
#line 66 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(17);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 66 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee16_helpers[1].address
#line 66 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 66 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee16_helpers[1].tail_call) && (r0 == 0))
#line 66 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 66 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 66 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 66 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee17_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee17_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee17_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee17_maps[] = {
    0,
};

#pragma code_seg(push, "bind/17")
static uint64_t
BindMonitor_Callee17(void* context)
#line 67 "sample/bindmonitor_mt_tailcall.c"
{
#line 67 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 67 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 67 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 67 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 67 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 67 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 67 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 67 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 67 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 67 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 67 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 67 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 67 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 67 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 67 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 67 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 67 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 67 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 67 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 67 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 67 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 67 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=18
#line 67 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(18);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 67 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee17_helpers[0].address
#line 67 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 67 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee17_helpers[0].tail_call) && (r0 == 0))
#line 67 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 67 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 67 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=18
#line 67 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(18);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 67 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee17_helpers[1].address
#line 67 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 67 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee17_helpers[1].tail_call) && (r0 == 0))
#line 67 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 67 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 67 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 67 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee18_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee18_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee18_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee18_maps[] = {
    0,
};

#pragma code_seg(push, "bind/18")
static uint64_t
BindMonitor_Callee18(void* context)
#line 68 "sample/bindmonitor_mt_tailcall.c"
{
#line 68 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 68 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 68 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 68 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 68 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 68 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 68 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 68 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 68 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 68 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 68 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 68 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 68 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 68 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 68 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 68 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 68 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 68 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 68 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 68 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 68 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 68 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=19
#line 68 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(19);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 68 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee18_helpers[0].address
#line 68 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 68 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee18_helpers[0].tail_call) && (r0 == 0))
#line 68 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 68 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 68 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=19
#line 68 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(19);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 68 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee18_helpers[1].address
#line 68 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 68 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee18_helpers[1].tail_call) && (r0 == 0))
#line 68 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 68 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 68 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 68 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee19_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee19_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee19_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee19_maps[] = {
    0,
};

#pragma code_seg(push, "bind/19")
static uint64_t
BindMonitor_Callee19(void* context)
#line 69 "sample/bindmonitor_mt_tailcall.c"
{
#line 69 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 69 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 69 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 69 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 69 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 69 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 69 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 69 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 69 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 69 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 69 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 69 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 69 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 69 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 69 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 69 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 69 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 69 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 69 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 69 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 69 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 69 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=20
#line 69 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(20);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 69 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee19_helpers[0].address
#line 69 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 69 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee19_helpers[0].tail_call) && (r0 == 0))
#line 69 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 69 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 69 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=20
#line 69 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(20);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 69 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee19_helpers[1].address
#line 69 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 69 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee19_helpers[1].tail_call) && (r0 == 0))
#line 69 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 69 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 69 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 69 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee2_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee2_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee2_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee2_maps[] = {
    0,
};

#pragma code_seg(push, "bind/2")
static uint64_t
BindMonitor_Callee2(void* context)
#line 52 "sample/bindmonitor_mt_tailcall.c"
{
#line 52 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 52 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 52 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 52 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 52 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 52 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 52 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 52 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 52 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 52 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 52 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 52 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 52 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 52 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 52 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 52 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 52 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 52 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 52 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 52 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 52 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 52 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=3
#line 52 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(3);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 52 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee2_helpers[0].address
#line 52 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 52 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee2_helpers[0].tail_call) && (r0 == 0))
#line 52 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 52 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 52 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=3
#line 52 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(3);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 52 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee2_helpers[1].address
#line 52 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 52 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee2_helpers[1].tail_call) && (r0 == 0))
#line 52 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 52 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 52 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 52 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee20_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee20_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee20_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee20_maps[] = {
    0,
};

#pragma code_seg(push, "bind/20")
static uint64_t
BindMonitor_Callee20(void* context)
#line 70 "sample/bindmonitor_mt_tailcall.c"
{
#line 70 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 70 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 70 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 70 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 70 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 70 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 70 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 70 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 70 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 70 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 70 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 70 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 70 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 70 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 70 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 70 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 70 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 70 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 70 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 70 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 70 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 70 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=21
#line 70 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(21);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 70 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee20_helpers[0].address
#line 70 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee20_helpers[0].tail_call) && (r0 == 0))
#line 70 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 70 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 70 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=21
#line 70 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(21);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 70 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee20_helpers[1].address
#line 70 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee20_helpers[1].tail_call) && (r0 == 0))
#line 70 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 70 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 70 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 70 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee21_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee21_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee21_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee21_maps[] = {
    0,
};

#pragma code_seg(push, "bind/21")
static uint64_t
BindMonitor_Callee21(void* context)
#line 71 "sample/bindmonitor_mt_tailcall.c"
{
#line 71 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 71 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 71 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 71 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 71 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 71 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 71 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 71 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 71 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 71 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 71 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 71 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 71 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 71 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 71 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 71 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 71 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 71 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 71 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 71 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 71 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 71 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=22
#line 71 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(22);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 71 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee21_helpers[0].address
#line 71 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 71 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee21_helpers[0].tail_call) && (r0 == 0))
#line 71 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 71 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 71 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=22
#line 71 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(22);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 71 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee21_helpers[1].address
#line 71 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 71 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee21_helpers[1].tail_call) && (r0 == 0))
#line 71 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 71 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 71 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 71 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee22_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee22_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee22_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee22_maps[] = {
    0,
};

#pragma code_seg(push, "bind/22")
static uint64_t
BindMonitor_Callee22(void* context)
#line 72 "sample/bindmonitor_mt_tailcall.c"
{
#line 72 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 72 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 72 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 72 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 72 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 72 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 72 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 72 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 72 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 72 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 72 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 72 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 72 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 72 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 72 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 72 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 72 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 72 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 72 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 72 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 72 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 72 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=23
#line 72 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(23);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 72 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee22_helpers[0].address
#line 72 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 72 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee22_helpers[0].tail_call) && (r0 == 0))
#line 72 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 72 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 72 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=23
#line 72 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(23);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 72 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee22_helpers[1].address
#line 72 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 72 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee22_helpers[1].tail_call) && (r0 == 0))
#line 72 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 72 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 72 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 72 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee23_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee23_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee23_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee23_maps[] = {
    0,
};

#pragma code_seg(push, "bind/23")
static uint64_t
BindMonitor_Callee23(void* context)
#line 73 "sample/bindmonitor_mt_tailcall.c"
{
#line 73 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 73 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 73 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 73 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 73 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 73 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 73 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 73 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 73 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 73 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 73 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 73 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 73 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 73 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 73 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 73 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 73 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 73 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 73 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 73 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 73 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 73 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=24
#line 73 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 73 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee23_helpers[0].address
#line 73 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 73 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee23_helpers[0].tail_call) && (r0 == 0))
#line 73 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 73 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 73 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=24
#line 73 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 73 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee23_helpers[1].address
#line 73 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 73 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee23_helpers[1].tail_call) && (r0 == 0))
#line 73 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 73 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 73 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 73 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee24_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee24_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee24_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee24_maps[] = {
    0,
};

#pragma code_seg(push, "bind/24")
static uint64_t
BindMonitor_Callee24(void* context)
#line 74 "sample/bindmonitor_mt_tailcall.c"
{
#line 74 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 74 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 74 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 74 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 74 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 74 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 74 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 74 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 74 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 74 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 74 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 74 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 74 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 74 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 74 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 74 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 74 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 74 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 74 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 74 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 74 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 74 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=25
#line 74 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 74 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee24_helpers[0].address
#line 74 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 74 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee24_helpers[0].tail_call) && (r0 == 0))
#line 74 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 74 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 74 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=25
#line 74 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 74 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee24_helpers[1].address
#line 74 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 74 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee24_helpers[1].tail_call) && (r0 == 0))
#line 74 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 74 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 74 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 74 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee25_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee25_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee25_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee25_maps[] = {
    0,
};

#pragma code_seg(push, "bind/25")
static uint64_t
BindMonitor_Callee25(void* context)
#line 75 "sample/bindmonitor_mt_tailcall.c"
{
#line 75 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 75 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 75 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 75 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 75 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 75 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 75 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 75 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 75 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 75 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 75 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 75 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 75 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 75 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 75 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 75 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 75 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 75 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 75 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 75 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 75 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 75 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=26
#line 75 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(26);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 75 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee25_helpers[0].address
#line 75 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 75 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee25_helpers[0].tail_call) && (r0 == 0))
#line 75 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 75 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 75 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=26
#line 75 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(26);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 75 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee25_helpers[1].address
#line 75 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 75 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee25_helpers[1].tail_call) && (r0 == 0))
#line 75 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 75 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 75 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 75 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee26_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee26_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee26_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee26_maps[] = {
    0,
};

#pragma code_seg(push, "bind/26")
static uint64_t
BindMonitor_Callee26(void* context)
#line 76 "sample/bindmonitor_mt_tailcall.c"
{
#line 76 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 76 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 76 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 76 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 76 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 76 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 76 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 76 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 76 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 76 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 76 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 76 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 76 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 76 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 76 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 76 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 76 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 76 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 76 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 76 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 76 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 76 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=27
#line 76 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(27);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 76 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee26_helpers[0].address
#line 76 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee26_helpers[0].tail_call) && (r0 == 0))
#line 76 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 76 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 76 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=27
#line 76 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(27);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 76 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee26_helpers[1].address
#line 76 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee26_helpers[1].tail_call) && (r0 == 0))
#line 76 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 76 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 76 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 76 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee27_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee27_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee27_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee27_maps[] = {
    0,
};

#pragma code_seg(push, "bind/27")
static uint64_t
BindMonitor_Callee27(void* context)
#line 77 "sample/bindmonitor_mt_tailcall.c"
{
#line 77 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 77 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 77 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 77 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 77 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 77 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 77 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 77 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 77 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 77 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 77 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 77 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 77 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 77 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 77 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 77 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 77 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 77 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 77 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 77 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 77 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 77 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=28
#line 77 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(28);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 77 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee27_helpers[0].address
#line 77 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 77 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee27_helpers[0].tail_call) && (r0 == 0))
#line 77 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 77 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 77 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=28
#line 77 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(28);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 77 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee27_helpers[1].address
#line 77 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 77 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee27_helpers[1].tail_call) && (r0 == 0))
#line 77 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 77 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 77 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 77 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee28_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee28_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee28_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee28_maps[] = {
    0,
};

#pragma code_seg(push, "bind/28")
static uint64_t
BindMonitor_Callee28(void* context)
#line 78 "sample/bindmonitor_mt_tailcall.c"
{
#line 78 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 78 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 78 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 78 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 78 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 78 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 78 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 78 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 78 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 78 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 78 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 78 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 78 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 78 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 78 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 78 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 78 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 78 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 78 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 78 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 78 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 78 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=29
#line 78 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(29);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 78 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee28_helpers[0].address
#line 78 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 78 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee28_helpers[0].tail_call) && (r0 == 0))
#line 78 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 78 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 78 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=29
#line 78 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(29);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 78 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee28_helpers[1].address
#line 78 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 78 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee28_helpers[1].tail_call) && (r0 == 0))
#line 78 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 78 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 78 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 78 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee29_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee29_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee29_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee29_maps[] = {
    0,
};

#pragma code_seg(push, "bind/29")
static uint64_t
BindMonitor_Callee29(void* context)
#line 79 "sample/bindmonitor_mt_tailcall.c"
{
#line 79 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 79 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 79 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 79 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 79 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 79 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 79 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 79 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 79 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 79 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 79 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 79 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 79 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 79 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 79 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 79 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 79 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 79 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 79 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 79 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 79 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 79 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=30
#line 79 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(30);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 79 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee29_helpers[0].address
#line 79 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 79 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee29_helpers[0].tail_call) && (r0 == 0))
#line 79 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 79 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 79 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=30
#line 79 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(30);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 79 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee29_helpers[1].address
#line 79 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 79 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee29_helpers[1].tail_call) && (r0 == 0))
#line 79 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 79 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 79 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 79 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee3_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee3_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee3_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee3_maps[] = {
    0,
};

#pragma code_seg(push, "bind/3")
static uint64_t
BindMonitor_Callee3(void* context)
#line 53 "sample/bindmonitor_mt_tailcall.c"
{
#line 53 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 53 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 53 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 53 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 53 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 53 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 53 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 53 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 53 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 53 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 53 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 53 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 53 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 53 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 53 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 53 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 53 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 53 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 53 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 53 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 53 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 53 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=4
#line 53 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 53 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee3_helpers[0].address
#line 53 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 53 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee3_helpers[0].tail_call) && (r0 == 0))
#line 53 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 53 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 53 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=4
#line 53 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 53 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee3_helpers[1].address
#line 53 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 53 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee3_helpers[1].tail_call) && (r0 == 0))
#line 53 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 53 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 53 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 53 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee30_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee30_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee30_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee30_maps[] = {
    0,
};

#pragma code_seg(push, "bind/30")
static uint64_t
BindMonitor_Callee30(void* context)
#line 80 "sample/bindmonitor_mt_tailcall.c"
{
#line 80 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 80 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 80 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 80 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 80 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 80 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 80 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 80 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 80 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 80 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 80 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 80 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 80 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 80 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 80 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 80 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 80 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 80 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 80 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 80 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 80 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 80 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=31
#line 80 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(31);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 80 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee30_helpers[0].address
#line 80 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 80 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee30_helpers[0].tail_call) && (r0 == 0))
#line 80 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 80 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 80 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=31
#line 80 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(31);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 80 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee30_helpers[1].address
#line 80 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 80 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee30_helpers[1].tail_call) && (r0 == 0))
#line 80 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 80 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 80 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 80 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static GUID BindMonitor_Callee31_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee31_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
#pragma code_seg(push, "bind/31")
static uint64_t
BindMonitor_Callee31(void* context)
#line 93 "sample/bindmonitor_mt_tailcall.c"
{
#line 93 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 93 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 93 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 93 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 93 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 93 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 93 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r0 src=r0 offset=0 imm=0
#line 93 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=1 dst=r0 src=r0 offset=0 imm=0
#line 93 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 93 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee4_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee4_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee4_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee4_maps[] = {
    0,
};

#pragma code_seg(push, "bind/4")
static uint64_t
BindMonitor_Callee4(void* context)
#line 54 "sample/bindmonitor_mt_tailcall.c"
{
#line 54 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 54 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 54 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 54 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 54 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 54 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 54 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 54 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 54 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 54 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 54 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 54 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 54 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 54 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 54 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 54 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 54 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 54 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 54 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 54 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 54 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 54 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=5
#line 54 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(5);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 54 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee4_helpers[0].address
#line 54 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 54 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee4_helpers[0].tail_call) && (r0 == 0))
#line 54 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 54 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 54 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=5
#line 54 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(5);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 54 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee4_helpers[1].address
#line 54 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 54 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee4_helpers[1].tail_call) && (r0 == 0))
#line 54 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 54 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 54 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 54 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee5_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee5_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee5_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee5_maps[] = {
    0,
};

#pragma code_seg(push, "bind/5")
static uint64_t
BindMonitor_Callee5(void* context)
#line 55 "sample/bindmonitor_mt_tailcall.c"
{
#line 55 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 55 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 55 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 55 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 55 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 55 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 55 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 55 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 55 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 55 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 55 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 55 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 55 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 55 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 55 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 55 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 55 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 55 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 55 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 55 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 55 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 55 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=6
#line 55 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(6);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 55 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee5_helpers[0].address
#line 55 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 55 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee5_helpers[0].tail_call) && (r0 == 0))
#line 55 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 55 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 55 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=6
#line 55 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(6);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 55 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee5_helpers[1].address
#line 55 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 55 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee5_helpers[1].tail_call) && (r0 == 0))
#line 55 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 55 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 55 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 55 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee6_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee6_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee6_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee6_maps[] = {
    0,
};

#pragma code_seg(push, "bind/6")
static uint64_t
BindMonitor_Callee6(void* context)
#line 56 "sample/bindmonitor_mt_tailcall.c"
{
#line 56 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 56 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 56 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 56 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 56 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 56 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 56 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 56 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 56 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 56 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 56 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 56 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 56 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 56 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 56 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 56 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 56 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 56 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 56 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 56 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 56 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 56 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=7
#line 56 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(7);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 56 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee6_helpers[0].address
#line 56 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 56 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee6_helpers[0].tail_call) && (r0 == 0))
#line 56 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 56 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 56 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=7
#line 56 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(7);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 56 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee6_helpers[1].address
#line 56 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 56 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee6_helpers[1].tail_call) && (r0 == 0))
#line 56 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 56 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 56 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 56 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee7_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee7_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee7_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee7_maps[] = {
    0,
};

#pragma code_seg(push, "bind/7")
static uint64_t
BindMonitor_Callee7(void* context)
#line 57 "sample/bindmonitor_mt_tailcall.c"
{
#line 57 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 57 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 57 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 57 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 57 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 57 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 57 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 57 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 57 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 57 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 57 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 57 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 57 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 57 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 57 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 57 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 57 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 57 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 57 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 57 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 57 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 57 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=8
#line 57 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(8);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 57 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee7_helpers[0].address
#line 57 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 57 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee7_helpers[0].tail_call) && (r0 == 0))
#line 57 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 57 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 57 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=8
#line 57 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(8);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 57 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee7_helpers[1].address
#line 57 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 57 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee7_helpers[1].tail_call) && (r0 == 0))
#line 57 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 57 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 57 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 57 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee8_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee8_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee8_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee8_maps[] = {
    0,
};

#pragma code_seg(push, "bind/8")
static uint64_t
BindMonitor_Callee8(void* context)
#line 58 "sample/bindmonitor_mt_tailcall.c"
{
#line 58 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 58 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 58 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 58 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 58 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 58 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 58 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 58 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 58 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 58 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 58 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 58 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 58 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 58 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 58 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 58 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 58 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 58 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 58 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 58 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 58 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 58 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=9
#line 58 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(9);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 58 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee8_helpers[0].address
#line 58 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 58 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee8_helpers[0].tail_call) && (r0 == 0))
#line 58 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 58 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 58 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=9
#line 58 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(9);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 58 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee8_helpers[1].address
#line 58 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 58 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee8_helpers[1].tail_call) && (r0 == 0))
#line 58 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 58 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 58 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 58 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee9_helpers[] = {
    {NULL, 13, "helper_id_13"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee9_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee9_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee9_maps[] = {
    0,
};

#pragma code_seg(push, "bind/9")
static uint64_t
BindMonitor_Callee9(void* context)
#line 59 "sample/bindmonitor_mt_tailcall.c"
{
#line 59 "sample/bindmonitor_mt_tailcall.c"
    // Prologue
#line 59 "sample/bindmonitor_mt_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 59 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r0 = 0;
#line 59 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r1 = 0;
#line 59 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r2 = 0;
#line 59 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r3 = 0;
#line 59 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r4 = 0;
#line 59 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r5 = 0;
#line 59 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r6 = 0;
#line 59 "sample/bindmonitor_mt_tailcall.c"
    register uint64_t r10 = 0;

#line 59 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uintptr_t)context;
#line 59 "sample/bindmonitor_mt_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 59 "sample/bindmonitor_mt_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=680997
#line 59 "sample/bindmonitor_mt_tailcall.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 59 "sample/bindmonitor_mt_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=3 dst=r1 src=r0 offset=0 imm=1852383340
#line 59 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)2339731488442490988;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-16 imm=0
#line 59 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=1818845524
#line 59 "sample/bindmonitor_mt_tailcall.c"
    r1 = (uint64_t)7809632219746099540;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 59 "sample/bindmonitor_mt_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r10 offset=0 imm=0
#line 59 "sample/bindmonitor_mt_tailcall.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r1 src=r0 offset=0 imm=-24
#line 59 "sample/bindmonitor_mt_tailcall.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=20
#line 59 "sample/bindmonitor_mt_tailcall.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=10
#line 59 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(10);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=13
#line 59 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee9_helpers[0].address
#line 59 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 59 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee9_helpers[0].tail_call) && (r0 == 0))
#line 59 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=14 dst=r1 src=r6 offset=0 imm=0
#line 59 "sample/bindmonitor_mt_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=15 dst=r2 src=r0 offset=0 imm=0
#line 59 "sample/bindmonitor_mt_tailcall.c"
    r2 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=10
#line 59 "sample/bindmonitor_mt_tailcall.c"
    r3 = IMMEDIATE(10);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=5
#line 59 "sample/bindmonitor_mt_tailcall.c"
    r0 = BindMonitor_Callee9_helpers[1].address
#line 59 "sample/bindmonitor_mt_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 59 "sample/bindmonitor_mt_tailcall.c"
    if ((BindMonitor_Callee9_helpers[1].tail_call) && (r0 == 0))
#line 59 "sample/bindmonitor_mt_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=1
#line 59 "sample/bindmonitor_mt_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 59 "sample/bindmonitor_mt_tailcall.c"
    return r0;
#line 59 "sample/bindmonitor_mt_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        BindMonitor_Caller,
        "bind",
        "bind",
        "BindMonitor_Caller",
        BindMonitor_Caller_maps,
        1,
        BindMonitor_Caller_helpers,
        2,
        21,
        &BindMonitor_Caller_program_type_guid,
        &BindMonitor_Caller_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee0,
        "bind/0",
        "bind/0",
        "BindMonitor_Callee0",
        BindMonitor_Callee0_maps,
        1,
        BindMonitor_Callee0_helpers,
        2,
        21,
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
        1,
        BindMonitor_Callee1_helpers,
        2,
        21,
        &BindMonitor_Callee1_program_type_guid,
        &BindMonitor_Callee1_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee10,
        "bind/10",
        "bind/10",
        "BindMonitor_Callee10",
        BindMonitor_Callee10_maps,
        1,
        BindMonitor_Callee10_helpers,
        2,
        21,
        &BindMonitor_Callee10_program_type_guid,
        &BindMonitor_Callee10_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee11,
        "bind/11",
        "bind/11",
        "BindMonitor_Callee11",
        BindMonitor_Callee11_maps,
        1,
        BindMonitor_Callee11_helpers,
        2,
        21,
        &BindMonitor_Callee11_program_type_guid,
        &BindMonitor_Callee11_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee12,
        "bind/12",
        "bind/12",
        "BindMonitor_Callee12",
        BindMonitor_Callee12_maps,
        1,
        BindMonitor_Callee12_helpers,
        2,
        21,
        &BindMonitor_Callee12_program_type_guid,
        &BindMonitor_Callee12_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee13,
        "bind/13",
        "bind/13",
        "BindMonitor_Callee13",
        BindMonitor_Callee13_maps,
        1,
        BindMonitor_Callee13_helpers,
        2,
        21,
        &BindMonitor_Callee13_program_type_guid,
        &BindMonitor_Callee13_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee14,
        "bind/14",
        "bind/14",
        "BindMonitor_Callee14",
        BindMonitor_Callee14_maps,
        1,
        BindMonitor_Callee14_helpers,
        2,
        21,
        &BindMonitor_Callee14_program_type_guid,
        &BindMonitor_Callee14_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee15,
        "bind/15",
        "bind/15",
        "BindMonitor_Callee15",
        BindMonitor_Callee15_maps,
        1,
        BindMonitor_Callee15_helpers,
        2,
        21,
        &BindMonitor_Callee15_program_type_guid,
        &BindMonitor_Callee15_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee16,
        "bind/16",
        "bind/16",
        "BindMonitor_Callee16",
        BindMonitor_Callee16_maps,
        1,
        BindMonitor_Callee16_helpers,
        2,
        21,
        &BindMonitor_Callee16_program_type_guid,
        &BindMonitor_Callee16_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee17,
        "bind/17",
        "bind/17",
        "BindMonitor_Callee17",
        BindMonitor_Callee17_maps,
        1,
        BindMonitor_Callee17_helpers,
        2,
        21,
        &BindMonitor_Callee17_program_type_guid,
        &BindMonitor_Callee17_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee18,
        "bind/18",
        "bind/18",
        "BindMonitor_Callee18",
        BindMonitor_Callee18_maps,
        1,
        BindMonitor_Callee18_helpers,
        2,
        21,
        &BindMonitor_Callee18_program_type_guid,
        &BindMonitor_Callee18_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee19,
        "bind/19",
        "bind/19",
        "BindMonitor_Callee19",
        BindMonitor_Callee19_maps,
        1,
        BindMonitor_Callee19_helpers,
        2,
        21,
        &BindMonitor_Callee19_program_type_guid,
        &BindMonitor_Callee19_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee2,
        "bind/2",
        "bind/2",
        "BindMonitor_Callee2",
        BindMonitor_Callee2_maps,
        1,
        BindMonitor_Callee2_helpers,
        2,
        21,
        &BindMonitor_Callee2_program_type_guid,
        &BindMonitor_Callee2_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee20,
        "bind/20",
        "bind/20",
        "BindMonitor_Callee20",
        BindMonitor_Callee20_maps,
        1,
        BindMonitor_Callee20_helpers,
        2,
        21,
        &BindMonitor_Callee20_program_type_guid,
        &BindMonitor_Callee20_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee21,
        "bind/21",
        "bind/21",
        "BindMonitor_Callee21",
        BindMonitor_Callee21_maps,
        1,
        BindMonitor_Callee21_helpers,
        2,
        21,
        &BindMonitor_Callee21_program_type_guid,
        &BindMonitor_Callee21_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee22,
        "bind/22",
        "bind/22",
        "BindMonitor_Callee22",
        BindMonitor_Callee22_maps,
        1,
        BindMonitor_Callee22_helpers,
        2,
        21,
        &BindMonitor_Callee22_program_type_guid,
        &BindMonitor_Callee22_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee23,
        "bind/23",
        "bind/23",
        "BindMonitor_Callee23",
        BindMonitor_Callee23_maps,
        1,
        BindMonitor_Callee23_helpers,
        2,
        21,
        &BindMonitor_Callee23_program_type_guid,
        &BindMonitor_Callee23_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee24,
        "bind/24",
        "bind/24",
        "BindMonitor_Callee24",
        BindMonitor_Callee24_maps,
        1,
        BindMonitor_Callee24_helpers,
        2,
        21,
        &BindMonitor_Callee24_program_type_guid,
        &BindMonitor_Callee24_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee25,
        "bind/25",
        "bind/25",
        "BindMonitor_Callee25",
        BindMonitor_Callee25_maps,
        1,
        BindMonitor_Callee25_helpers,
        2,
        21,
        &BindMonitor_Callee25_program_type_guid,
        &BindMonitor_Callee25_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee26,
        "bind/26",
        "bind/26",
        "BindMonitor_Callee26",
        BindMonitor_Callee26_maps,
        1,
        BindMonitor_Callee26_helpers,
        2,
        21,
        &BindMonitor_Callee26_program_type_guid,
        &BindMonitor_Callee26_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee27,
        "bind/27",
        "bind/27",
        "BindMonitor_Callee27",
        BindMonitor_Callee27_maps,
        1,
        BindMonitor_Callee27_helpers,
        2,
        21,
        &BindMonitor_Callee27_program_type_guid,
        &BindMonitor_Callee27_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee28,
        "bind/28",
        "bind/28",
        "BindMonitor_Callee28",
        BindMonitor_Callee28_maps,
        1,
        BindMonitor_Callee28_helpers,
        2,
        21,
        &BindMonitor_Callee28_program_type_guid,
        &BindMonitor_Callee28_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee29,
        "bind/29",
        "bind/29",
        "BindMonitor_Callee29",
        BindMonitor_Callee29_maps,
        1,
        BindMonitor_Callee29_helpers,
        2,
        21,
        &BindMonitor_Callee29_program_type_guid,
        &BindMonitor_Callee29_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee3,
        "bind/3",
        "bind/3",
        "BindMonitor_Callee3",
        BindMonitor_Callee3_maps,
        1,
        BindMonitor_Callee3_helpers,
        2,
        21,
        &BindMonitor_Callee3_program_type_guid,
        &BindMonitor_Callee3_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee30,
        "bind/30",
        "bind/30",
        "BindMonitor_Callee30",
        BindMonitor_Callee30_maps,
        1,
        BindMonitor_Callee30_helpers,
        2,
        21,
        &BindMonitor_Callee30_program_type_guid,
        &BindMonitor_Callee30_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee31,
        "bind/31",
        "bind/31",
        "BindMonitor_Callee31",
        NULL,
        0,
        NULL,
        0,
        2,
        &BindMonitor_Callee31_program_type_guid,
        &BindMonitor_Callee31_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee4,
        "bind/4",
        "bind/4",
        "BindMonitor_Callee4",
        BindMonitor_Callee4_maps,
        1,
        BindMonitor_Callee4_helpers,
        2,
        21,
        &BindMonitor_Callee4_program_type_guid,
        &BindMonitor_Callee4_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee5,
        "bind/5",
        "bind/5",
        "BindMonitor_Callee5",
        BindMonitor_Callee5_maps,
        1,
        BindMonitor_Callee5_helpers,
        2,
        21,
        &BindMonitor_Callee5_program_type_guid,
        &BindMonitor_Callee5_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee6,
        "bind/6",
        "bind/6",
        "BindMonitor_Callee6",
        BindMonitor_Callee6_maps,
        1,
        BindMonitor_Callee6_helpers,
        2,
        21,
        &BindMonitor_Callee6_program_type_guid,
        &BindMonitor_Callee6_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee7,
        "bind/7",
        "bind/7",
        "BindMonitor_Callee7",
        BindMonitor_Callee7_maps,
        1,
        BindMonitor_Callee7_helpers,
        2,
        21,
        &BindMonitor_Callee7_program_type_guid,
        &BindMonitor_Callee7_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee8,
        "bind/8",
        "bind/8",
        "BindMonitor_Callee8",
        BindMonitor_Callee8_maps,
        1,
        BindMonitor_Callee8_helpers,
        2,
        21,
        &BindMonitor_Callee8_program_type_guid,
        &BindMonitor_Callee8_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee9,
        "bind/9",
        "bind/9",
        "BindMonitor_Callee9",
        BindMonitor_Callee9_maps,
        1,
        BindMonitor_Callee9_helpers,
        2,
        21,
        &BindMonitor_Callee9_program_type_guid,
        &BindMonitor_Callee9_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 33;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = 0;
    version->minor = 9;
    version->revision = 0;
}

metadata_table_t bindmonitor_mt_tailcall_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
