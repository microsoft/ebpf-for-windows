// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from global_vars.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table global_vars##_metadata_table
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
         4,                  // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         26,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "global_.rodata"},
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
         24,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "global_.data"},
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
         4,                  // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         23,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "global_.bss"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 3;
}

const char global__rodata_initial_data[] = {10, 0, 0, 0};

const char global__data_initial_data[] = {20, 0, 0, 0, 40, 0, 0, 0};

const char global__bss_initial_data[] = {0, 0, 0, 0};

#pragma data_seg(push, "global_variables")
static global_variable_section_info_t _global_variable_sections[] = {
    {
        .header = {1, 48, 48},
        .name = "global_.rodata",
        .size = 4,
        .initial_data = &global__rodata_initial_data,
    },
    {
        .header = {1, 48, 48},
        .name = "global_.data",
        .size = 8,
        .initial_data = &global__data_initial_data,
    },
    {
        .header = {1, 48, 48},
        .name = "global_.bss",
        .size = 4,
        .initial_data = &global__bss_initial_data,
    },
};
#pragma data_seg(pop)

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = _global_variable_sections;
    *count = 3;
}

static GUID GlobalVariableTest_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID GlobalVariableTest_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t GlobalVariableTest_maps[] = {
    0,
    1,
    2,
};

#pragma code_seg(push, "sample~1")
static uint64_t
GlobalVariableTest(void* context, const program_runtime_context_t* runtime_context)
#line 30 "sample/undocked/global_vars.c"
{
#line 30 "sample/undocked/global_vars.c"
    // Prologue.
#line 30 "sample/undocked/global_vars.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 30 "sample/undocked/global_vars.c"
    register uint64_t r0 = 0;
#line 30 "sample/undocked/global_vars.c"
    register uint64_t r1 = 0;
#line 30 "sample/undocked/global_vars.c"
    register uint64_t r2 = 0;
#line 30 "sample/undocked/global_vars.c"
    register uint64_t r3 = 0;
#line 30 "sample/undocked/global_vars.c"
    register uint64_t r10 = 0;

#line 30 "sample/undocked/global_vars.c"
    r1 = (uintptr_t)context;
#line 30 "sample/undocked/global_vars.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDDW pc=0 dst=r1 src=r2 offset=0 imm=3
#line 30 "sample/undocked/global_vars.c"
    r1 = POINTER(runtime_context->global_variable_section_data[0].address_of_map_value + 0);
    // EBPF_OP_LDXW pc=2 dst=r1 src=r1 offset=0 imm=0
#line 30 "sample/undocked/global_vars.c"
    r1 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_LDDW pc=3 dst=r2 src=r2 offset=0 imm=2
#line 30 "sample/undocked/global_vars.c"
    r2 = POINTER(runtime_context->global_variable_section_data[1].address_of_map_value + 0);
    // EBPF_OP_LDXW pc=5 dst=r2 src=r2 offset=0 imm=0
#line 30 "sample/undocked/global_vars.c"
    r2 = *(uint32_t*)(uintptr_t)(r2 + OFFSET(0));
    // EBPF_OP_ADD64_REG pc=6 dst=r2 src=r1 offset=0 imm=0
#line 30 "sample/undocked/global_vars.c"
    r2 += r1;
    // EBPF_OP_LDDW pc=7 dst=r1 src=r2 offset=0 imm=1
#line 30 "sample/undocked/global_vars.c"
    r1 = POINTER(runtime_context->global_variable_section_data[2].address_of_map_value + 0);
    // EBPF_OP_STXW pc=9 dst=r1 src=r2 offset=0 imm=0
#line 30 "sample/undocked/global_vars.c"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(0)) = (uint32_t)r2;
    // EBPF_OP_LDDW pc=10 dst=r2 src=r2 offset=0 imm=2
#line 31 "sample/undocked/global_vars.c"
    r2 = POINTER(runtime_context->global_variable_section_data[1].address_of_map_value + 4);
    // EBPF_OP_LDXW pc=12 dst=r2 src=r2 offset=0 imm=0
#line 31 "sample/undocked/global_vars.c"
    r2 = *(uint32_t*)(uintptr_t)(r2 + OFFSET(0));
    // EBPF_OP_LDXW pc=13 dst=r3 src=r1 offset=0 imm=0
#line 31 "sample/undocked/global_vars.c"
    r3 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_ADD64_REG pc=14 dst=r3 src=r2 offset=0 imm=0
#line 31 "sample/undocked/global_vars.c"
    r3 += r2;
    // EBPF_OP_STXW pc=15 dst=r1 src=r3 offset=0 imm=0
#line 31 "sample/undocked/global_vars.c"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(0)) = (uint32_t)r3;
    // EBPF_OP_MOV64_IMM pc=16 dst=r0 src=r0 offset=0 imm=0
#line 32 "sample/undocked/global_vars.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=17 dst=r0 src=r0 offset=0 imm=0
#line 32 "sample/undocked/global_vars.c"
    return r0;
#line 30 "sample/undocked/global_vars.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        GlobalVariableTest,
        "sample~1",
        "sample_ext",
        "GlobalVariableTest",
        GlobalVariableTest_maps,
        3,
        NULL,
        0,
        18,
        &GlobalVariableTest_program_type_guid,
        &GlobalVariableTest_attach_type_guid,
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
    version->minor = 21;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t global_vars_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
