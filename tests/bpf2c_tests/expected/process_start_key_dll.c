// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from process_start_key.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table process_start_key##_metadata_table
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
         16,                 // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         15,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "process_start_key_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 1;
}

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static helper_function_entry_t function_v4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     19,
     "helper_id_19",
    },
    {
     {1, 40, 40}, // Version header.
     33,
     "helper_id_33",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID function_v4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID function_v4_attach_type_guid = {
    0xa82e37b1, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t function_v4_maps[] = {
    0,
};

#pragma code_seg(push, "cgroup~2")
static uint64_t
function_v4(void* context, const program_runtime_context_t* runtime_context)
#line 37 "sample/process_start_key.c"
{
#line 37 "sample/process_start_key.c"
    // Prologue.
#line 37 "sample/process_start_key.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 37 "sample/process_start_key.c"
    register uint64_t r0 = 0;
#line 37 "sample/process_start_key.c"
    register uint64_t r1 = 0;
#line 37 "sample/process_start_key.c"
    register uint64_t r2 = 0;
#line 37 "sample/process_start_key.c"
    register uint64_t r3 = 0;
#line 37 "sample/process_start_key.c"
    register uint64_t r4 = 0;
#line 37 "sample/process_start_key.c"
    register uint64_t r5 = 0;
#line 37 "sample/process_start_key.c"
    register uint64_t r6 = 0;
#line 37 "sample/process_start_key.c"
    register uint64_t r7 = 0;
#line 37 "sample/process_start_key.c"
    register uint64_t r10 = 0;

#line 37 "sample/process_start_key.c"
    r1 = (uintptr_t)context;
#line 37 "sample/process_start_key.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r7 src=r0 offset=0 imm=0
#line 37 "sample/process_start_key.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=1 dst=r10 src=r7 offset=-16 imm=0
#line 24 "sample/process_start_key.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-16));
    // EBPF_OP_CALL pc=2 dst=r0 src=r0 offset=0 imm=19
#line 26 "sample/process_start_key.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 26 "sample/process_start_key.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 26 "sample/process_start_key.c"
        return 0;
#line 26 "sample/process_start_key.c"
    }
    // EBPF_OP_MOV64_REG pc=3 dst=r6 src=r0 offset=0 imm=0
#line 26 "sample/process_start_key.c"
    r6 = r0;
    // EBPF_OP_CALL pc=4 dst=r0 src=r0 offset=0 imm=33
#line 27 "sample/process_start_key.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 27 "sample/process_start_key.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 27 "sample/process_start_key.c"
        return 0;
#line 27 "sample/process_start_key.c"
    }
    // EBPF_OP_STXDW pc=5 dst=r10 src=r0 offset=-8 imm=0
#line 27 "sample/process_start_key.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-8));
    // EBPF_OP_RSH64_IMM pc=6 dst=r6 src=r0 offset=0 imm=32
#line 28 "sample/process_start_key.c"
    r6 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_STXW pc=7 dst=r10 src=r6 offset=-16 imm=0
#line 28 "sample/process_start_key.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-16));
    // EBPF_OP_STXW pc=8 dst=r10 src=r7 offset=-20 imm=0
#line 29 "sample/process_start_key.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-20));
    // EBPF_OP_MOV64_REG pc=9 dst=r2 src=r10 offset=0 imm=0
#line 29 "sample/process_start_key.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r2 src=r0 offset=0 imm=-20
#line 29 "sample/process_start_key.c"
    r2 += IMMEDIATE(-20);
    // EBPF_OP_MOV64_REG pc=11 dst=r3 src=r10 offset=0 imm=0
#line 29 "sample/process_start_key.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=12 dst=r3 src=r0 offset=0 imm=-16
#line 29 "sample/process_start_key.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=13 dst=r1 src=r1 offset=0 imm=1
#line 30 "sample/process_start_key.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=15 dst=r4 src=r0 offset=0 imm=0
#line 30 "sample/process_start_key.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=16 dst=r0 src=r0 offset=0 imm=2
#line 30 "sample/process_start_key.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 30 "sample/process_start_key.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 30 "sample/process_start_key.c"
        return 0;
#line 30 "sample/process_start_key.c"
    }
    // EBPF_OP_MOV64_IMM pc=17 dst=r0 src=r0 offset=0 imm=1
#line 39 "sample/process_start_key.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=18 dst=r0 src=r0 offset=0 imm=0
#line 39 "sample/process_start_key.c"
    return r0;
#line 37 "sample/process_start_key.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t function_v6_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     19,
     "helper_id_19",
    },
    {
     {1, 40, 40}, // Version header.
     33,
     "helper_id_33",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID function_v6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID function_v6_attach_type_guid = {
    0xa82e37b2, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t function_v6_maps[] = {
    0,
};

#pragma code_seg(push, "cgroup~1")
static uint64_t
function_v6(void* context, const program_runtime_context_t* runtime_context)
#line 44 "sample/process_start_key.c"
{
#line 44 "sample/process_start_key.c"
    // Prologue.
#line 44 "sample/process_start_key.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 44 "sample/process_start_key.c"
    register uint64_t r0 = 0;
#line 44 "sample/process_start_key.c"
    register uint64_t r1 = 0;
#line 44 "sample/process_start_key.c"
    register uint64_t r2 = 0;
#line 44 "sample/process_start_key.c"
    register uint64_t r3 = 0;
#line 44 "sample/process_start_key.c"
    register uint64_t r4 = 0;
#line 44 "sample/process_start_key.c"
    register uint64_t r5 = 0;
#line 44 "sample/process_start_key.c"
    register uint64_t r6 = 0;
#line 44 "sample/process_start_key.c"
    register uint64_t r7 = 0;
#line 44 "sample/process_start_key.c"
    register uint64_t r10 = 0;

#line 44 "sample/process_start_key.c"
    r1 = (uintptr_t)context;
#line 44 "sample/process_start_key.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r7 src=r0 offset=0 imm=0
#line 44 "sample/process_start_key.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=1 dst=r10 src=r7 offset=-16 imm=0
#line 24 "sample/process_start_key.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-16));
    // EBPF_OP_CALL pc=2 dst=r0 src=r0 offset=0 imm=19
#line 26 "sample/process_start_key.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 26 "sample/process_start_key.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 26 "sample/process_start_key.c"
        return 0;
#line 26 "sample/process_start_key.c"
    }
    // EBPF_OP_MOV64_REG pc=3 dst=r6 src=r0 offset=0 imm=0
#line 26 "sample/process_start_key.c"
    r6 = r0;
    // EBPF_OP_CALL pc=4 dst=r0 src=r0 offset=0 imm=33
#line 27 "sample/process_start_key.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 27 "sample/process_start_key.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 27 "sample/process_start_key.c"
        return 0;
#line 27 "sample/process_start_key.c"
    }
    // EBPF_OP_STXDW pc=5 dst=r10 src=r0 offset=-8 imm=0
#line 27 "sample/process_start_key.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-8));
    // EBPF_OP_RSH64_IMM pc=6 dst=r6 src=r0 offset=0 imm=32
#line 28 "sample/process_start_key.c"
    r6 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_STXW pc=7 dst=r10 src=r6 offset=-16 imm=0
#line 28 "sample/process_start_key.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-16));
    // EBPF_OP_STXW pc=8 dst=r10 src=r7 offset=-20 imm=0
#line 29 "sample/process_start_key.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-20));
    // EBPF_OP_MOV64_REG pc=9 dst=r2 src=r10 offset=0 imm=0
#line 29 "sample/process_start_key.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r2 src=r0 offset=0 imm=-20
#line 29 "sample/process_start_key.c"
    r2 += IMMEDIATE(-20);
    // EBPF_OP_MOV64_REG pc=11 dst=r3 src=r10 offset=0 imm=0
#line 29 "sample/process_start_key.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=12 dst=r3 src=r0 offset=0 imm=-16
#line 29 "sample/process_start_key.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=13 dst=r1 src=r1 offset=0 imm=1
#line 30 "sample/process_start_key.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=15 dst=r4 src=r0 offset=0 imm=0
#line 30 "sample/process_start_key.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=16 dst=r0 src=r0 offset=0 imm=2
#line 30 "sample/process_start_key.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 30 "sample/process_start_key.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 30 "sample/process_start_key.c"
        return 0;
#line 30 "sample/process_start_key.c"
    }
    // EBPF_OP_MOV64_IMM pc=17 dst=r0 src=r0 offset=0 imm=1
#line 46 "sample/process_start_key.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=18 dst=r0 src=r0 offset=0 imm=0
#line 46 "sample/process_start_key.c"
    return r0;
#line 44 "sample/process_start_key.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        function_v4,
        "cgroup~2",
        "cgroup/connect4",
        "function_v4",
        function_v4_maps,
        1,
        function_v4_helpers,
        3,
        19,
        &function_v4_program_type_guid,
        &function_v4_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        function_v6,
        "cgroup~1",
        "cgroup/connect6",
        "function_v6",
        function_v6_maps,
        1,
        function_v6_helpers,
        3,
        19,
        &function_v6_program_type_guid,
        &function_v6_attach_type_guid,
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
    version->major = 1;
    version->minor = 0;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t process_start_key_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
