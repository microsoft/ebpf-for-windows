// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from tail_call.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table tail_call##_metadata_table
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
    {0,
     {
         BPF_MAP_TYPE_PROG_ARRAY, // Type of map.
         4,                       // Size in bytes of a map key.
         4,                       // Size in bytes of a map value.
         10,                      // Maximum number of entries allowed in the map.
         0,                       // Inner map index.
         LIBBPF_PIN_NONE,         // Pinning type for the map.
         10,                      // Identifier for a map template.
         0,                       // The id of the inner map template.
     },
     "map"},
    {0,
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         16,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "canary"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 2;
}

static helper_function_entry_t caller_helpers[] = {
    {5, "helper_id_5"},
    {1, "helper_id_1"},
};

static GUID caller_program_type_guid = {0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID caller_attach_type_guid = {0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t caller_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sample~1")
static uint64_t
caller(void* context, const program_runtime_context_t* runtime_context)
#line 33 "sample/undocked/tail_call.c"
{
#line 33 "sample/undocked/tail_call.c"
    // Prologue
#line 33 "sample/undocked/tail_call.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 33 "sample/undocked/tail_call.c"
    register uint64_t r0 = 0;
#line 33 "sample/undocked/tail_call.c"
    register uint64_t r1 = 0;
#line 33 "sample/undocked/tail_call.c"
    register uint64_t r2 = 0;
#line 33 "sample/undocked/tail_call.c"
    register uint64_t r3 = 0;
#line 33 "sample/undocked/tail_call.c"
    register uint64_t r4 = 0;
#line 33 "sample/undocked/tail_call.c"
    register uint64_t r5 = 0;
#line 33 "sample/undocked/tail_call.c"
    register uint64_t r10 = 0;

#line 33 "sample/undocked/tail_call.c"
    r1 = (uintptr_t)context;
#line 33 "sample/undocked/tail_call.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r2 src=r0 offset=0 imm=0
#line 33 "sample/undocked/tail_call.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r2 offset=-4 imm=0
#line 35 "sample/undocked/tail_call.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r2;
    // EBPF_OP_LDDW pc=2 dst=r2 src=r0 offset=0 imm=0
#line 38 "sample/undocked/tail_call.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=4 dst=r3 src=r0 offset=0 imm=9
#line 38 "sample/undocked/tail_call.c"
    r3 = IMMEDIATE(9);
    // EBPF_OP_CALL pc=5 dst=r0 src=r0 offset=0 imm=5
#line 38 "sample/undocked/tail_call.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5);
#line 38 "sample/undocked/tail_call.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 38 "sample/undocked/tail_call.c"
        return 0;
#line 38 "sample/undocked/tail_call.c"
    }
    // EBPF_OP_MOV64_REG pc=6 dst=r2 src=r10 offset=0 imm=0
#line 38 "sample/undocked/tail_call.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r2 src=r0 offset=0 imm=-4
#line 38 "sample/undocked/tail_call.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=8 dst=r1 src=r0 offset=0 imm=0
#line 41 "sample/undocked/tail_call.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=10 dst=r0 src=r0 offset=0 imm=1
#line 41 "sample/undocked/tail_call.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5);
#line 41 "sample/undocked/tail_call.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 41 "sample/undocked/tail_call.c"
        return 0;
#line 41 "sample/undocked/tail_call.c"
    }
    // EBPF_OP_JEQ_IMM pc=11 dst=r0 src=r0 offset=2 imm=0
#line 42 "sample/undocked/tail_call.c"
    if (r0 == IMMEDIATE(0)) {
#line 42 "sample/undocked/tail_call.c"
        goto label_1;
#line 42 "sample/undocked/tail_call.c"
    }
    // EBPF_OP_MOV64_IMM pc=12 dst=r1 src=r0 offset=0 imm=1
#line 42 "sample/undocked/tail_call.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=13 dst=r0 src=r1 offset=0 imm=0
#line 43 "sample/undocked/tail_call.c"
    *(uint32_t*)(uintptr_t)(r0 + OFFSET(0)) = (uint32_t)r1;
label_1:
    // EBPF_OP_MOV64_IMM pc=14 dst=r0 src=r0 offset=0 imm=6
#line 46 "sample/undocked/tail_call.c"
    r0 = IMMEDIATE(6);
    // EBPF_OP_EXIT pc=15 dst=r0 src=r0 offset=0 imm=0
#line 46 "sample/undocked/tail_call.c"
    return r0;
#line 46 "sample/undocked/tail_call.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static GUID callee_program_type_guid = {0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID callee_attach_type_guid = {0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
#pragma code_seg(push, "sample~2")
static uint64_t
callee(void* context, const program_runtime_context_t* runtime_context)
#line 49 "sample/undocked/tail_call.c"
{
#line 49 "sample/undocked/tail_call.c"
    // Prologue
#line 49 "sample/undocked/tail_call.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 49 "sample/undocked/tail_call.c"
    register uint64_t r0 = 0;
#line 49 "sample/undocked/tail_call.c"
    register uint64_t r1 = 0;
#line 49 "sample/undocked/tail_call.c"
    register uint64_t r10 = 0;

#line 49 "sample/undocked/tail_call.c"
    r1 = (uintptr_t)context;
#line 49 "sample/undocked/tail_call.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));
#line 49 "sample/undocked/tail_call.c"
    UNREFERENCED_PARAMETER(runtime_context);

    // EBPF_OP_MOV64_IMM pc=0 dst=r0 src=r0 offset=0 imm=42
#line 49 "sample/undocked/tail_call.c"
    r0 = IMMEDIATE(42);
    // EBPF_OP_EXIT pc=1 dst=r0 src=r0 offset=0 imm=0
#line 49 "sample/undocked/tail_call.c"
    return r0;
#line 49 "sample/undocked/tail_call.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        caller,
        "sample~1",
        "sample_ext",
        "caller",
        caller_maps,
        2,
        caller_helpers,
        2,
        16,
        &caller_program_type_guid,
        &caller_attach_type_guid,
    },
    {
        0,
        callee,
        "sample~2",
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
    version->minor = 17;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t tail_call_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};
