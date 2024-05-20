// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from test_sample_ebpf_2.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table test_sample_ebpf_2##_metadata_table
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
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         2,                  // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_BY_NAME, // Pinning type for the map.
         10,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "output_map1"},
    {0,
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         14,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "output_map2"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 2;
}

static helper_function_entry_t test_program_entry_helpers[] = {
    {2, "helper_id_2"},
};

static GUID test_program_entry_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID test_program_entry_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t test_program_entry_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sample~1")
static uint64_t
test_program_entry(void* context, const program_runtime_context_t* runtime_context)
#line 58 "sample/undocked/test_sample_ebpf_2.c"
{
#line 58 "sample/undocked/test_sample_ebpf_2.c"
    // Prologue
#line 58 "sample/undocked/test_sample_ebpf_2.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 58 "sample/undocked/test_sample_ebpf_2.c"
    register uint64_t r0 = 0;
#line 58 "sample/undocked/test_sample_ebpf_2.c"
    register uint64_t r1 = 0;
#line 58 "sample/undocked/test_sample_ebpf_2.c"
    register uint64_t r2 = 0;
#line 58 "sample/undocked/test_sample_ebpf_2.c"
    register uint64_t r3 = 0;
#line 58 "sample/undocked/test_sample_ebpf_2.c"
    register uint64_t r4 = 0;
#line 58 "sample/undocked/test_sample_ebpf_2.c"
    register uint64_t r5 = 0;
#line 58 "sample/undocked/test_sample_ebpf_2.c"
    register uint64_t r6 = 0;
#line 58 "sample/undocked/test_sample_ebpf_2.c"
    register uint64_t r10 = 0;

#line 58 "sample/undocked/test_sample_ebpf_2.c"
    r1 = (uintptr_t)context;
#line 58 "sample/undocked/test_sample_ebpf_2.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=0
#line 58 "sample/undocked/test_sample_ebpf_2.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r6 offset=-4 imm=0
#line 42 "sample/undocked/test_sample_ebpf_2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_LDXH pc=2 dst=r2 src=r1 offset=20 imm=0
#line 43 "sample/undocked/test_sample_ebpf_2.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(20));
    // EBPF_OP_STXW pc=3 dst=r10 src=r2 offset=-8 imm=0
#line 43 "sample/undocked/test_sample_ebpf_2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=4 dst=r1 src=r1 offset=16 imm=0
#line 44 "sample/undocked/test_sample_ebpf_2.c"
    r1 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(16));
    // EBPF_OP_STXW pc=5 dst=r10 src=r1 offset=-12 imm=0
#line 44 "sample/undocked/test_sample_ebpf_2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=6 dst=r2 src=r10 offset=0 imm=0
#line 44 "sample/undocked/test_sample_ebpf_2.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r2 src=r0 offset=0 imm=-4
#line 44 "sample/undocked/test_sample_ebpf_2.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=8 dst=r3 src=r10 offset=0 imm=0
#line 44 "sample/undocked/test_sample_ebpf_2.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=9 dst=r3 src=r0 offset=0 imm=-8
#line 44 "sample/undocked/test_sample_ebpf_2.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=10 dst=r1 src=r0 offset=0 imm=0
#line 46 "sample/undocked/test_sample_ebpf_2.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=12 dst=r4 src=r0 offset=0 imm=0
#line 46 "sample/undocked/test_sample_ebpf_2.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=2
#line 46 "sample/undocked/test_sample_ebpf_2.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5);
#line 46 "sample/undocked/test_sample_ebpf_2.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 46 "sample/undocked/test_sample_ebpf_2.c"
        return 0;
#line 46 "sample/undocked/test_sample_ebpf_2.c"
    }
    // EBPF_OP_LSH64_IMM pc=14 dst=r0 src=r0 offset=0 imm=32
#line 46 "sample/undocked/test_sample_ebpf_2.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=15 dst=r0 src=r0 offset=0 imm=32
#line 46 "sample/undocked/test_sample_ebpf_2.c"
    r0 = (int64_t)r0 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=16 dst=r6 src=r0 offset=8 imm=0
#line 47 "sample/undocked/test_sample_ebpf_2.c"
    if ((int64_t)r6 > (int64_t)r0) {
#line 47 "sample/undocked/test_sample_ebpf_2.c"
        goto label_1;
#line 47 "sample/undocked/test_sample_ebpf_2.c"
    }
    // EBPF_OP_MOV64_REG pc=17 dst=r2 src=r10 offset=0 imm=0
#line 47 "sample/undocked/test_sample_ebpf_2.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=18 dst=r2 src=r0 offset=0 imm=-4
#line 47 "sample/undocked/test_sample_ebpf_2.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=19 dst=r3 src=r10 offset=0 imm=0
#line 47 "sample/undocked/test_sample_ebpf_2.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=20 dst=r3 src=r0 offset=0 imm=-12
#line 47 "sample/undocked/test_sample_ebpf_2.c"
    r3 += IMMEDIATE(-12);
    // EBPF_OP_LDDW pc=21 dst=r1 src=r0 offset=0 imm=0
#line 50 "sample/undocked/test_sample_ebpf_2.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=23 dst=r4 src=r0 offset=0 imm=0
#line 50 "sample/undocked/test_sample_ebpf_2.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=2
#line 50 "sample/undocked/test_sample_ebpf_2.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5);
#line 50 "sample/undocked/test_sample_ebpf_2.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 50 "sample/undocked/test_sample_ebpf_2.c"
        return 0;
#line 50 "sample/undocked/test_sample_ebpf_2.c"
    }
label_1:
    // EBPF_OP_EXIT pc=25 dst=r0 src=r0 offset=0 imm=0
#line 64 "sample/undocked/test_sample_ebpf_2.c"
    return r0;
#line 64 "sample/undocked/test_sample_ebpf_2.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        test_program_entry,
        "sample~1",
        "sample_ext",
        "test_program_entry",
        test_program_entry_maps,
        2,
        test_program_entry_helpers,
        1,
        26,
        &test_program_entry_program_type_guid,
        &test_program_entry_attach_type_guid,
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
    version->minor = 17;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t test_sample_ebpf_2_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};