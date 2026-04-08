// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from ambiguous_array_map.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers.
#include <windows.h>

#define metadata_table ambiguous_array_map##_metadata_table
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

__declspec(dllexport) metadata_table_t*
get_metadata_table()
{
    return &metadata_table;
}

#include "bpf2c.h"

static void
_get_hash(_Outptr_result_buffer_maybenull_(*size) const uint8_t** hash, _Out_ size_t* size)
{
    *hash = NULL;
    *size = 0;
}

#pragma data_seg(push, "maps")
static map_entry_t _maps[] = {
    {
     {0, 0},
     {
         1,                  // Current Version.
         80,                 // Struct size up to the last field.
         80,                 // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         8,                  // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         13,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "map_a"},
    {
     {0, 0},
     {
         1,                  // Current Version.
         80,                 // Struct size up to the last field.
         80,                 // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         8,                  // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         15,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "map_b"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 2;
}

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static helper_function_entry_t ambiguous_map_lookup_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID ambiguous_map_lookup_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID ambiguous_map_lookup_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t ambiguous_map_lookup_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "bind")
static uint64_t
ambiguous_map_lookup(void* context, const program_runtime_context_t* runtime_context)
#line 30 "sample/ambiguous_array_map.c"
{
#line 30 "sample/ambiguous_array_map.c"
    // Prologue.
#line 30 "sample/ambiguous_array_map.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 30 "sample/ambiguous_array_map.c"
    register uint64_t r0 = 0;
#line 30 "sample/ambiguous_array_map.c"
    register uint64_t r1 = 0;
#line 30 "sample/ambiguous_array_map.c"
    register uint64_t r2 = 0;
#line 30 "sample/ambiguous_array_map.c"
    register uint64_t r3 = 0;
#line 30 "sample/ambiguous_array_map.c"
    register uint64_t r4 = 0;
#line 30 "sample/ambiguous_array_map.c"
    register uint64_t r5 = 0;
#line 30 "sample/ambiguous_array_map.c"
    register uint64_t r6 = 0;
#line 30 "sample/ambiguous_array_map.c"
    register uint64_t r10 = 0;

#line 30 "sample/ambiguous_array_map.c"
    r1 = (uintptr_t)context;
#line 30 "sample/ambiguous_array_map.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=0
#line 30 "sample/ambiguous_array_map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r6 offset=-4 imm=0
#line 32 "sample/ambiguous_array_map.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_LDXDW pc=2 dst=r2 src=r1 offset=16 imm=0
#line 38 "sample/ambiguous_array_map.c"
    READ_ONCE_64(r2, r1, OFFSET(16));
    // EBPF_OP_AND64_IMM pc=3 dst=r2 src=r0 offset=0 imm=1
#line 38 "sample/ambiguous_array_map.c"
    r2 &= IMMEDIATE(1);
    // EBPF_OP_LDDW pc=4 dst=r1 src=r1 offset=0 imm=2
#line 38 "sample/ambiguous_array_map.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_JEQ_IMM pc=6 dst=r2 src=r0 offset=2 imm=0
#line 38 "sample/ambiguous_array_map.c"
    if (r2 == IMMEDIATE(0)) {
#line 38 "sample/ambiguous_array_map.c"
        goto label_1;
#line 38 "sample/ambiguous_array_map.c"
    }
    // EBPF_OP_LDDW pc=7 dst=r1 src=r1 offset=0 imm=1
#line 38 "sample/ambiguous_array_map.c"
    r1 = POINTER(runtime_context->map_data[0].address);
label_1:
    // EBPF_OP_MOV64_REG pc=9 dst=r2 src=r10 offset=0 imm=0
#line 38 "sample/ambiguous_array_map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r2 src=r0 offset=0 imm=-4
#line 38 "sample/ambiguous_array_map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_CALL pc=11 dst=r0 src=r0 offset=0 imm=1
#line 44 "sample/ambiguous_array_map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=12 dst=r0 src=r0 offset=1 imm=0
#line 45 "sample/ambiguous_array_map.c"
    if (r0 == IMMEDIATE(0)) {
#line 45 "sample/ambiguous_array_map.c"
        goto label_2;
#line 45 "sample/ambiguous_array_map.c"
    }
    // EBPF_OP_LDXDW pc=13 dst=r6 src=r0 offset=0 imm=0
#line 46 "sample/ambiguous_array_map.c"
    READ_ONCE_64(r6, r0, OFFSET(0));
label_2:
    // EBPF_OP_MOV64_REG pc=14 dst=r0 src=r6 offset=0 imm=0
#line 49 "sample/ambiguous_array_map.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=15 dst=r0 src=r0 offset=0 imm=0
#line 49 "sample/ambiguous_array_map.c"
    return r0;
#line 30 "sample/ambiguous_array_map.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        ambiguous_map_lookup,
        "bind",
        "bind",
        "ambiguous_map_lookup",
        ambiguous_map_lookup_maps,
        2,
        ambiguous_map_lookup_helpers,
        1,
        16,
        &ambiguous_map_lookup_program_type_guid,
        &ambiguous_map_lookup_attach_type_guid,
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
    version->major = 1;
    version->minor = 2;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t ambiguous_array_map_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
