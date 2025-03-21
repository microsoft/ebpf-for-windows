// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from global_vars_and_map.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table global_vars_and_map##_metadata_table
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
         1,                 // Current Version.
         80,                // Struct size up to the last field.
         80,                // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         4,                 // Size in bytes of a map key.
         24,                // Size in bytes of a map value.
         1,                 // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         13,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "some_config_map"},
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
         24,                 // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         29,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "global_.bss"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 2;
}

const char global__bss_initial_data[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

#pragma data_seg(push, "global_variables")
static global_variable_section_info_t _global_variable_sections[] = {
    {
        .header = {1, 48, 48},
        .name = "global_.bss",
        .size = 24,
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
    *count = 1;
}

static helper_function_entry_t GlobalVariableAndMapTest_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     22,
     "helper_id_22",
    },
};

static GUID GlobalVariableAndMapTest_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID GlobalVariableAndMapTest_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t GlobalVariableAndMapTest_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sample~1")
static uint64_t
GlobalVariableAndMapTest(void* context, const program_runtime_context_t* runtime_context)
#line 40 "sample/undocked/global_vars_and_map.c"
{
#line 40 "sample/undocked/global_vars_and_map.c"
    // Prologue.
#line 40 "sample/undocked/global_vars_and_map.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 40 "sample/undocked/global_vars_and_map.c"
    register uint64_t r0 = 0;
#line 40 "sample/undocked/global_vars_and_map.c"
    register uint64_t r1 = 0;
#line 40 "sample/undocked/global_vars_and_map.c"
    register uint64_t r2 = 0;
#line 40 "sample/undocked/global_vars_and_map.c"
    register uint64_t r3 = 0;
#line 40 "sample/undocked/global_vars_and_map.c"
    register uint64_t r4 = 0;
#line 40 "sample/undocked/global_vars_and_map.c"
    register uint64_t r5 = 0;
#line 40 "sample/undocked/global_vars_and_map.c"
    register uint64_t r10 = 0;

#line 40 "sample/undocked/global_vars_and_map.c"
    r1 = (uintptr_t)context;
#line 40 "sample/undocked/global_vars_and_map.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r1 src=r0 offset=0 imm=0
#line 40 "sample/undocked/global_vars_and_map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r1 offset=-4 imm=0
#line 43 "sample/undocked/global_vars_and_map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2 dst=r2 src=r10 offset=0 imm=0
#line 43 "sample/undocked/global_vars_and_map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=3 dst=r2 src=r0 offset=0 imm=-4
#line 43 "sample/undocked/global_vars_and_map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=4 dst=r1 src=r1 offset=0 imm=1
#line 44 "sample/undocked/global_vars_and_map.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=6 dst=r0 src=r0 offset=0 imm=1
#line 44 "sample/undocked/global_vars_and_map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 44 "sample/undocked/global_vars_and_map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 44 "sample/undocked/global_vars_and_map.c"
        return 0;
#line 44 "sample/undocked/global_vars_and_map.c"
    }
    // EBPF_OP_MOV64_IMM pc=7 dst=r1 src=r0 offset=0 imm=1
#line 44 "sample/undocked/global_vars_and_map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=8 dst=r0 src=r0 offset=7 imm=0
#line 45 "sample/undocked/global_vars_and_map.c"
    if (r0 == IMMEDIATE(0)) {
#line 45 "sample/undocked/global_vars_and_map.c"
        goto label_1;
#line 45 "sample/undocked/global_vars_and_map.c"
    }
    // EBPF_OP_LDDW pc=9 dst=r1 src=r2 offset=0 imm=2
#line 50 "sample/undocked/global_vars_and_map.c"
    r1 = POINTER(runtime_context->global_variable_section_data[0].address_of_map_value + 0);
    // EBPF_OP_MOV64_IMM pc=11 dst=r2 src=r0 offset=0 imm=24
#line 50 "sample/undocked/global_vars_and_map.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_MOV64_REG pc=12 dst=r3 src=r0 offset=0 imm=0
#line 50 "sample/undocked/global_vars_and_map.c"
    r3 = r0;
    // EBPF_OP_MOV64_IMM pc=13 dst=r4 src=r0 offset=0 imm=24
#line 50 "sample/undocked/global_vars_and_map.c"
    r4 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=14 dst=r0 src=r0 offset=0 imm=22
#line 50 "sample/undocked/global_vars_and_map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 50 "sample/undocked/global_vars_and_map.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 50 "sample/undocked/global_vars_and_map.c"
        return 0;
#line 50 "sample/undocked/global_vars_and_map.c"
    }
    // EBPF_OP_MOV64_IMM pc=15 dst=r1 src=r0 offset=0 imm=0
#line 50 "sample/undocked/global_vars_and_map.c"
    r1 = IMMEDIATE(0);
label_1:
    // EBPF_OP_MOV64_REG pc=16 dst=r0 src=r1 offset=0 imm=0
#line 53 "sample/undocked/global_vars_and_map.c"
    r0 = r1;
    // EBPF_OP_EXIT pc=17 dst=r0 src=r0 offset=0 imm=0
#line 53 "sample/undocked/global_vars_and_map.c"
    return r0;
#line 40 "sample/undocked/global_vars_and_map.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        GlobalVariableAndMapTest,
        "sample~1",
        "sample_ext",
        "GlobalVariableAndMapTest",
        GlobalVariableAndMapTest_maps,
        2,
        GlobalVariableAndMapTest_helpers,
        2,
        18,
        &GlobalVariableAndMapTest_program_type_guid,
        &GlobalVariableAndMapTest_attach_type_guid,
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

metadata_table_t global_vars_and_map_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
