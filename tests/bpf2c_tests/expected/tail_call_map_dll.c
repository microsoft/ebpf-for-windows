// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from tail_call_map.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table tail_call_map##_metadata_table
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
         1,                       // Maximum number of entries allowed in the map.
         0,                       // Inner map index.
         LIBBPF_PIN_NONE,         // Pinning type for the map.
         21,                      // Identifier for a map template.
         0,                       // The id of the inner map template.
     },
     "inner_map"},
    {NULL,
     {
         BPF_MAP_TYPE_ARRAY_OF_MAPS, // Type of map.
         4,                          // Size in bytes of a map key.
         4,                          // Size in bytes of a map value.
         1,                          // Maximum number of entries allowed in the map.
         0,                          // Inner map index.
         LIBBPF_PIN_NONE,            // Pinning type for the map.
         27,                         // Identifier for a map template.
         21,                         // The id of the inner map template.
     },
     "outer_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 2;
}

static helper_function_entry_t caller_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 5, "helper_id_5"},
};

static GUID caller_program_type_guid = {0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID caller_attach_type_guid = {0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t caller_maps[] = {
    1,
};

#pragma code_seg(push, "sample~2")
static uint64_t
caller(void* context)
#line 40 "sample/undocked/tail_call_map.c"
{
#line 40 "sample/undocked/tail_call_map.c"
    // Prologue
#line 40 "sample/undocked/tail_call_map.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 40 "sample/undocked/tail_call_map.c"
    register uint64_t r0 = 0;
#line 40 "sample/undocked/tail_call_map.c"
    register uint64_t r1 = 0;
#line 40 "sample/undocked/tail_call_map.c"
    register uint64_t r2 = 0;
#line 40 "sample/undocked/tail_call_map.c"
    register uint64_t r3 = 0;
#line 40 "sample/undocked/tail_call_map.c"
    register uint64_t r4 = 0;
#line 40 "sample/undocked/tail_call_map.c"
    register uint64_t r5 = 0;
#line 40 "sample/undocked/tail_call_map.c"
    register uint64_t r6 = 0;
#line 40 "sample/undocked/tail_call_map.c"
    register uint64_t r10 = 0;

#line 40 "sample/undocked/tail_call_map.c"
    r1 = (uintptr_t)context;
#line 40 "sample/undocked/tail_call_map.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 40 "sample/undocked/tail_call_map.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 40 "sample/undocked/tail_call_map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 42 "sample/undocked/tail_call_map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 42 "sample/undocked/tail_call_map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 42 "sample/undocked/tail_call_map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 43 "sample/undocked/tail_call_map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 43 "sample/undocked/tail_call_map.c"
    r0 = caller_helpers[0].address
#line 43 "sample/undocked/tail_call_map.c"
         (r1, r2, r3, r4, r5);
#line 43 "sample/undocked/tail_call_map.c"
    if ((caller_helpers[0].tail_call) && (r0 == 0))
#line 43 "sample/undocked/tail_call_map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r1 src=r6 offset=0 imm=0
#line 45 "sample/undocked/tail_call_map.c"
    r1 = r6;
    // EBPF_OP_MOV64_REG pc=9 dst=r2 src=r0 offset=0 imm=0
#line 45 "sample/undocked/tail_call_map.c"
    r2 = r0;
    // EBPF_OP_MOV64_IMM pc=10 dst=r3 src=r0 offset=0 imm=0
#line 45 "sample/undocked/tail_call_map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=11 dst=r0 src=r0 offset=0 imm=5
#line 45 "sample/undocked/tail_call_map.c"
    r0 = caller_helpers[1].address
#line 45 "sample/undocked/tail_call_map.c"
         (r1, r2, r3, r4, r5);
#line 45 "sample/undocked/tail_call_map.c"
    if ((caller_helpers[1].tail_call) && (r0 == 0))
#line 45 "sample/undocked/tail_call_map.c"
        return 0;
        // EBPF_OP_MOV64_IMM pc=12 dst=r0 src=r0 offset=0 imm=6
#line 48 "sample/undocked/tail_call_map.c"
    r0 = IMMEDIATE(6);
    // EBPF_OP_EXIT pc=13 dst=r0 src=r0 offset=0 imm=0
#line 48 "sample/undocked/tail_call_map.c"
    return r0;
#line 48 "sample/undocked/tail_call_map.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static GUID callee_program_type_guid = {0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID callee_attach_type_guid = {0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
#pragma code_seg(push, "sample~1")
static uint64_t
callee(void* context)
#line 17 "sample/undocked/tail_call_map.c"
{
#line 17 "sample/undocked/tail_call_map.c"
    // Prologue
#line 17 "sample/undocked/tail_call_map.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 17 "sample/undocked/tail_call_map.c"
    register uint64_t r0 = 0;
#line 17 "sample/undocked/tail_call_map.c"
    register uint64_t r1 = 0;
#line 17 "sample/undocked/tail_call_map.c"
    register uint64_t r10 = 0;

#line 17 "sample/undocked/tail_call_map.c"
    r1 = (uintptr_t)context;
#line 17 "sample/undocked/tail_call_map.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r0 src=r0 offset=0 imm=42
#line 17 "sample/undocked/tail_call_map.c"
    r0 = IMMEDIATE(42);
    // EBPF_OP_EXIT pc=1 dst=r0 src=r0 offset=0 imm=0
#line 17 "sample/undocked/tail_call_map.c"
    return r0;
#line 17 "sample/undocked/tail_call_map.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        caller,
        "sample~2",
        "sample_ext",
        "caller",
        caller_maps,
        1,
        caller_helpers,
        2,
        14,
        &caller_program_type_guid,
        &caller_attach_type_guid,
    },
    {
        0,
        callee,
        "sample~1",
        "sample_ext/0",
        "callee",
        NULL,
        0,
        NULL,
        0,
        2,
        &callee_program_type_guid,
        &callee_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 2;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = 0;
    version->minor = 16;
    version->revision = 0;
}

#pragma data_seg(push, "map_initial_values")
static const char* _inner_map_initial_string_table[] = {
    "callee",
};

static const char* _outer_map_initial_string_table[] = {
    "inner_map",
};

static map_initial_values_t _map_initial_values_array[] = {
    {
        .name = "inner_map",
        .count = 1,
        .values = _inner_map_initial_string_table,
    },
    {
        .name = "outer_map",
        .count = 1,
        .values = _outer_map_initial_string_table,
    },
};
#pragma data_seg(pop)

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = _map_initial_values_array;
    *count = 2;
}

metadata_table_t tail_call_map_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};
