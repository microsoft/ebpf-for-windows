// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from callgraph_bpf2bpf.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers.
#include <windows.h>

#define metadata_table callgraph_bpf2bpf##_metadata_table
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
         8,                 // Size in bytes of a map key.
         8,                 // Size in bytes of a map value.
         128,               // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         10,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "bind_count_map"},
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

static helper_function_entry_t entry_program1_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     0,
     "",
    },
    {
     {1, 40, 40}, // Version header.
     0,
     "",
    },
    {
     {1, 40, 40}, // Version header.
     9,
     "helper_id_9",
    },
    {
     {1, 40, 40}, // Version header.
     19,
     "helper_id_19",
    },
};

// Forward references for local functions.
static uint64_t
ScenarioS1(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context);
static uint64_t
ScenarioS2(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context);
static uint64_t
ScenarioS3(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context);
static uint64_t
ScenarioS4(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context);
static uint64_t
update_map(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context);

static GUID entry_program1_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID entry_program1_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
#pragma code_seg(push, "bind/1")
static uint64_t
entry_program1(void* context, const program_runtime_context_t* runtime_context)
#line 124 "sample/callgraph_bpf2bpf.c"
{
#line 124 "sample/callgraph_bpf2bpf.c"
    // Prologue.
#line 124 "sample/callgraph_bpf2bpf.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 124 "sample/callgraph_bpf2bpf.c"
    register uint64_t r0 = 0;
#line 124 "sample/callgraph_bpf2bpf.c"
    register uint64_t r1 = 0;
#line 124 "sample/callgraph_bpf2bpf.c"
    register uint64_t r2 = 0;
#line 124 "sample/callgraph_bpf2bpf.c"
    register uint64_t r3 = 0;
#line 124 "sample/callgraph_bpf2bpf.c"
    register uint64_t r4 = 0;
#line 124 "sample/callgraph_bpf2bpf.c"
    register uint64_t r5 = 0;
#line 124 "sample/callgraph_bpf2bpf.c"
    register uint64_t r6 = 0;
#line 124 "sample/callgraph_bpf2bpf.c"
    register uint64_t r7 = 0;
#line 124 "sample/callgraph_bpf2bpf.c"
    register uint64_t r10 = 0;

#line 124 "sample/callgraph_bpf2bpf.c"
    r1 = (uintptr_t)context;
#line 124 "sample/callgraph_bpf2bpf.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXDW pc=0 dst=r1 src=r1 offset=16 imm=0
#line 124 "sample/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r1, OFFSET(16));
    // EBPF_OP_STXDW pc=1 dst=r10 src=r1 offset=-8 imm=0
#line 124 "sample/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-8));
    // EBPF_OP_CALL pc=2 dst=r0 src=r0 offset=0 imm=19
#line 129 "sample/callgraph_bpf2bpf.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_CALL pc=3 dst=r0 src=r0 offset=0 imm=9
#line 130 "sample/callgraph_bpf2bpf.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=4 dst=r6 src=r10 offset=0 imm=0
#line 130 "sample/callgraph_bpf2bpf.c"
    r6 = r10;
    // EBPF_OP_ADD64_IMM pc=5 dst=r6 src=r0 offset=0 imm=-8
#line 130 "sample/callgraph_bpf2bpf.c"
    r6 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=6 dst=r1 src=r6 offset=0 imm=0
#line 132 "sample/callgraph_bpf2bpf.c"
    r1 = r6;
    // EBPF_OP_CALL pc=7 dst=r0 src=r1 offset=0 imm=9
#line 132 "sample/callgraph_bpf2bpf.c"
    r0 = ScenarioS1(r1, r2, r3, r4, r5, r10, context, runtime_context);
    // EBPF_OP_MOV64_REG pc=8 dst=r7 src=r0 offset=0 imm=0
#line 132 "sample/callgraph_bpf2bpf.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r6 offset=0 imm=0
#line 133 "sample/callgraph_bpf2bpf.c"
    r1 = r6;
    // EBPF_OP_CALL pc=10 dst=r0 src=r1 offset=0 imm=29
#line 133 "sample/callgraph_bpf2bpf.c"
    r0 = ScenarioS4(r1, r2, r3, r4, r5, r10, context, runtime_context);
    // EBPF_OP_LSH64_IMM pc=11 dst=r7 src=r0 offset=0 imm=32
#line 132 "sample/callgraph_bpf2bpf.c"
    r7 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=12 dst=r7 src=r0 offset=0 imm=32
#line 132 "sample/callgraph_bpf2bpf.c"
    r7 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_IMM pc=13 dst=r0 src=r0 offset=0 imm=2
#line 132 "sample/callgraph_bpf2bpf.c"
    r0 = IMMEDIATE(2);
    // EBPF_OP_JEQ_IMM pc=14 dst=r7 src=r0 offset=1 imm=2
#line 139 "sample/callgraph_bpf2bpf.c"
    if (r7 == IMMEDIATE(2)) {
#line 139 "sample/callgraph_bpf2bpf.c"
        goto label_1;
#line 139 "sample/callgraph_bpf2bpf.c"
    }
    // EBPF_OP_MOV64_IMM pc=15 dst=r0 src=r0 offset=0 imm=1
#line 139 "sample/callgraph_bpf2bpf.c"
    r0 = IMMEDIATE(1);
label_1:
    // EBPF_OP_EXIT pc=16 dst=r0 src=r0 offset=0 imm=0
#line 139 "sample/callgraph_bpf2bpf.c"
    return r0;
#line 124 "sample/callgraph_bpf2bpf.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static uint64_t
ScenarioS1(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context)
{
    register uint64_t r0 = 0;

    // EBPF_OP_STXDW pc=0 dst=r10 src=r1 offset=-8 imm=0
#line 56 "sample/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-8));
    // EBPF_OP_CALL pc=1 dst=r0 src=r0 offset=0 imm=19
#line 59 "sample/callgraph_bpf2bpf.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXDW pc=2 dst=r1 src=r10 offset=-8 imm=0
#line 62 "sample/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r10, OFFSET(-8));
    // EBPF_OP_CALL pc=3 dst=r0 src=r1 offset=0 imm=1
#line 62 "sample/callgraph_bpf2bpf.c"
    r0 = ScenarioS2(r1, r2, r3, r4, r5, r10, context, runtime_context);
    // EBPF_OP_EXIT pc=4 dst=r0 src=r0 offset=0 imm=0
#line 62 "sample/callgraph_bpf2bpf.c"
    return r0;
}
static uint64_t
ScenarioS2(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context)
{
    register uint64_t r0 = 0;
    (void)context;
    UNREFERENCED_PARAMETER(runtime_context);

    // EBPF_OP_STXDW pc=0 dst=r10 src=r1 offset=-8 imm=0
#line 56 "sample/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-8));
    // EBPF_OP_LDXDW pc=1 dst=r1 src=r10 offset=-8 imm=0
#line 59 "sample/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r10, OFFSET(-8));
    // EBPF_OP_CALL pc=2 dst=r0 src=r1 offset=0 imm=1
#line 62 "sample/callgraph_bpf2bpf.c"
    r0 = ScenarioS3(r1, r2, r3, r4, r5, r10, context, runtime_context);
    // EBPF_OP_EXIT pc=3 dst=r0 src=r0 offset=0 imm=0
#line 62 "sample/callgraph_bpf2bpf.c"
    return r0;
}
static uint64_t
ScenarioS3(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context)
{
    register uint64_t r0 = 0;

    // EBPF_OP_STXDW pc=0 dst=r10 src=r1 offset=-16 imm=0
#line 56 "sample/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_CALL pc=1 dst=r0 src=r0 offset=0 imm=19
#line 59 "sample/callgraph_bpf2bpf.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXDW pc=2 dst=r1 src=r10 offset=-16 imm=0
#line 62 "sample/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r10, OFFSET(-16));
    // EBPF_OP_LDXDW pc=3 dst=r1 src=r1 offset=0 imm=0
#line 62 "sample/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r1, OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=4 dst=r1 src=r0 offset=4 imm=0
#line 62 "sample/callgraph_bpf2bpf.c"
    if (r1 == IMMEDIATE(0)) {
#line 62 "sample/callgraph_bpf2bpf.c"
        goto label_2;
#line 62 "sample/callgraph_bpf2bpf.c"
    }
    // EBPF_OP_JA pc=5 dst=r0 src=r0 offset=0 imm=0
#line 62 "sample/callgraph_bpf2bpf.c"
    goto label_1;
label_1:
    // EBPF_OP_MOV64_IMM pc=6 dst=r1 src=r0 offset=0 imm=2
#line 62 "sample/callgraph_bpf2bpf.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=7 dst=r10 src=r1 offset=-4 imm=0
#line 63 "sample/callgraph_bpf2bpf.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_JA pc=8 dst=r0 src=r0 offset=3 imm=0
#line 63 "sample/callgraph_bpf2bpf.c"
    goto label_3;
label_2:
    // EBPF_OP_MOV64_IMM pc=9 dst=r1 src=r0 offset=0 imm=0
#line 63 "sample/callgraph_bpf2bpf.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=10 dst=r10 src=r1 offset=-4 imm=0
#line 65 "sample/callgraph_bpf2bpf.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_JA pc=11 dst=r0 src=r0 offset=0 imm=0
#line 65 "sample/callgraph_bpf2bpf.c"
    goto label_3;
label_3:
    // EBPF_OP_LDXW pc=12 dst=r0 src=r10 offset=-4 imm=0
#line 66 "sample/callgraph_bpf2bpf.c"
    READ_ONCE_32(r0, r10, OFFSET(-4));
    // EBPF_OP_EXIT pc=13 dst=r0 src=r0 offset=0 imm=0
#line 66 "sample/callgraph_bpf2bpf.c"
    return r0;
}
static uint64_t
ScenarioS4(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context)
{
    register uint64_t r0 = 0;

    // EBPF_OP_STXDW pc=0 dst=r10 src=r1 offset=-8 imm=0
#line 56 "sample/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-8));
    // EBPF_OP_CALL pc=1 dst=r0 src=r0 offset=0 imm=9
#line 59 "sample/callgraph_bpf2bpf.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_IMM pc=2 dst=r0 src=r0 offset=0 imm=0
#line 62 "sample/callgraph_bpf2bpf.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=3 dst=r0 src=r0 offset=0 imm=0
#line 62 "sample/callgraph_bpf2bpf.c"
    return r0;
}
static uint64_t
update_map(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context)
{
    register uint64_t r0 = 0;
    register uint64_t r6 = 0;

    // EBPF_OP_STXDW pc=0 dst=r10 src=r1 offset=-16 imm=0
#line 56 "sample/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDXDW pc=1 dst=r1 src=r10 offset=-16 imm=0
#line 59 "sample/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r10, OFFSET(-16));
    // EBPF_OP_LDXDW pc=2 dst=r1 src=r1 offset=0 imm=0
#line 62 "sample/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r1, OFFSET(0));
    // EBPF_OP_STXDW pc=3 dst=r10 src=r1 offset=-24 imm=0
#line 62 "sample/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_CALL pc=4 dst=r0 src=r0 offset=0 imm=19
#line 62 "sample/callgraph_bpf2bpf.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXDW pc=5 dst=r10 src=r0 offset=-32 imm=0
#line 62 "sample/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-32));
    // EBPF_OP_LDXDW pc=6 dst=r1 src=r10 offset=-32 imm=0
#line 62 "sample/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r10, OFFSET(-32));
    // EBPF_OP_JNE_IMM pc=7 dst=r1 src=r0 offset=7 imm=0
#line 63 "sample/callgraph_bpf2bpf.c"
    if (r1 != IMMEDIATE(0)) {
#line 63 "sample/callgraph_bpf2bpf.c"
        goto label_2;
#line 63 "sample/callgraph_bpf2bpf.c"
    }
    // EBPF_OP_JA pc=8 dst=r0 src=r0 offset=0 imm=0
#line 63 "sample/callgraph_bpf2bpf.c"
    goto label_1;
label_1:
    // EBPF_OP_LDDW pc=9 dst=r1 src=r0 offset=0 imm=-1
#line 63 "sample/callgraph_bpf2bpf.c"
    r1 = (uint64_t)4294967295;
    // EBPF_OP_STXW pc=11 dst=r10 src=r1 offset=-4 imm=0
#line 63 "sample/callgraph_bpf2bpf.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MOV64_IMM pc=12 dst=r1 src=r0 offset=0 imm=1
#line 66 "sample/callgraph_bpf2bpf.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=13 dst=r10 src=r1 offset=-36 imm=0
#line 66 "sample/callgraph_bpf2bpf.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-36));
    // EBPF_OP_JA pc=14 dst=r0 src=r0 offset=39 imm=0
#line 69 "sample/callgraph_bpf2bpf.c"
    goto label_6;
label_2:
    // EBPF_OP_MOV64_REG pc=15 dst=r2 src=r10 offset=0 imm=0
#line 72 "sample/callgraph_bpf2bpf.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=16 dst=r2 src=r0 offset=0 imm=-24
#line 72 "sample/callgraph_bpf2bpf.c"
    r2 += IMMEDIATE(-24);
    // EBPF_OP_LDDW pc=17 dst=r1 src=r1 offset=0 imm=1
#line 72 "sample/callgraph_bpf2bpf.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=19 dst=r0 src=r0 offset=0 imm=1
#line 79 "sample/callgraph_bpf2bpf.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXDW pc=20 dst=r10 src=r0 offset=-48 imm=0
#line 80 "sample/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-48));
    // EBPF_OP_LDXDW pc=21 dst=r1 src=r10 offset=-48 imm=0
#line 80 "sample/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r10, OFFSET(-48));
    // EBPF_OP_JEQ_IMM pc=22 dst=r1 src=r0 offset=17 imm=0
#line 80 "sample/callgraph_bpf2bpf.c"
    if (r1 == IMMEDIATE(0)) {
#line 80 "sample/callgraph_bpf2bpf.c"
        goto label_4;
#line 80 "sample/callgraph_bpf2bpf.c"
    }
    // EBPF_OP_JA pc=23 dst=r0 src=r0 offset=0 imm=0
#line 84 "sample/callgraph_bpf2bpf.c"
    goto label_3;
label_3:
    // EBPF_OP_LDXDW pc=24 dst=r1 src=r10 offset=-48 imm=0
#line 89 "sample/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r10, OFFSET(-48));
    // EBPF_OP_LDXDW pc=25 dst=r1 src=r1 offset=0 imm=0
#line 90 "sample/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r1, OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=26 dst=r1 src=r0 offset=0 imm=1
#line 90 "sample/callgraph_bpf2bpf.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=27 dst=r10 src=r1 offset=-56 imm=0
#line 97 "sample/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-56));
    // EBPF_OP_MOV64_REG pc=28 dst=r2 src=r10 offset=0 imm=0
#line 99 "sample/callgraph_bpf2bpf.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=29 dst=r2 src=r0 offset=0 imm=-24
#line 99 "sample/callgraph_bpf2bpf.c"
    r2 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_REG pc=30 dst=r3 src=r10 offset=0 imm=0
#line 99 "sample/callgraph_bpf2bpf.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=31 dst=r3 src=r0 offset=0 imm=-56
#line 102 "sample/callgraph_bpf2bpf.c"
    r3 += IMMEDIATE(-56);
    // EBPF_OP_LDDW pc=32 dst=r1 src=r1 offset=0 imm=1
#line 102 "sample/callgraph_bpf2bpf.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=34 dst=r4 src=r0 offset=0 imm=0
#line 105 "sample/callgraph_bpf2bpf.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=35 dst=r0 src=r0 offset=0 imm=2
#line 105 "sample/callgraph_bpf2bpf.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXW pc=36 dst=r10 src=r0 offset=-4 imm=0
#line 105 "sample/callgraph_bpf2bpf.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-4));
    // EBPF_OP_MOV64_IMM pc=37 dst=r1 src=r0 offset=0 imm=1
#line 105 "sample/callgraph_bpf2bpf.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=38 dst=r10 src=r1 offset=-36 imm=0
#line 106 "sample/callgraph_bpf2bpf.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-36));
    // EBPF_OP_JA pc=39 dst=r0 src=r0 offset=13 imm=0
#line 106 "sample/callgraph_bpf2bpf.c"
    goto label_5;
label_4:
    // EBPF_OP_MOV64_IMM pc=40 dst=r6 src=r0 offset=0 imm=1
#line 106 "sample/callgraph_bpf2bpf.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_STXDW pc=41 dst=r10 src=r6 offset=-64 imm=0
#line 106 "sample/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-64));
    // EBPF_OP_MOV64_REG pc=42 dst=r2 src=r10 offset=0 imm=0
#line 106 "sample/callgraph_bpf2bpf.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=43 dst=r2 src=r0 offset=0 imm=-24
#line 110 "sample/callgraph_bpf2bpf.c"
    r2 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_REG pc=44 dst=r3 src=r10 offset=0 imm=0
#line 110 "sample/callgraph_bpf2bpf.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=45 dst=r3 src=r0 offset=0 imm=-64
#line 110 "sample/callgraph_bpf2bpf.c"
    r3 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=46 dst=r1 src=r1 offset=0 imm=1
#line 110 "sample/callgraph_bpf2bpf.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=48 dst=r4 src=r0 offset=0 imm=0
#line 111 "sample/callgraph_bpf2bpf.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=49 dst=r0 src=r0 offset=0 imm=2
#line 111 "sample/callgraph_bpf2bpf.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXW pc=50 dst=r10 src=r0 offset=-4 imm=0
#line 111 "sample/callgraph_bpf2bpf.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-4));
    // EBPF_OP_STXW pc=51 dst=r10 src=r6 offset=-36 imm=0
#line 112 "sample/callgraph_bpf2bpf.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-36));
    // EBPF_OP_JA pc=52 dst=r0 src=r0 offset=0 imm=0
#line 112 "sample/callgraph_bpf2bpf.c"
    goto label_5;
label_5:
    // EBPF_OP_JA pc=53 dst=r0 src=r0 offset=0 imm=0
#line 112 "sample/callgraph_bpf2bpf.c"
    goto label_6;
label_6:
    // EBPF_OP_LDXW pc=54 dst=r0 src=r10 offset=-4 imm=0
#line 112 "sample/callgraph_bpf2bpf.c"
    READ_ONCE_32(r0, r10, OFFSET(-4));
    // EBPF_OP_EXIT pc=55 dst=r0 src=r0 offset=0 imm=0
#line 112 "sample/callgraph_bpf2bpf.c"
    return r0;
}
static helper_function_entry_t entry_program2_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     0,
     "",
    },
    {
     {1, 40, 40}, // Version header.
     0,
     "",
    },
    {
     {1, 40, 40}, // Version header.
     0,
     "",
    },
    {
     {1, 40, 40}, // Version header.
     19,
     "helper_id_19",
    },
};

// Forward references for local functions.
static uint64_t
ScenarioS1(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context);
static uint64_t
ScenarioS2(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context);
static uint64_t
ScenarioS3(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context);
static uint64_t
ScenarioS4(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context);
static uint64_t
update_map(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context);

static GUID entry_program2_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID entry_program2_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
#pragma code_seg(push, "bind/2")
static uint64_t
entry_program2(void* context, const program_runtime_context_t* runtime_context)
#line 145 "sample/callgraph_bpf2bpf.c"
{
#line 145 "sample/callgraph_bpf2bpf.c"
    // Prologue.
#line 145 "sample/callgraph_bpf2bpf.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 145 "sample/callgraph_bpf2bpf.c"
    register uint64_t r0 = 0;
#line 145 "sample/callgraph_bpf2bpf.c"
    register uint64_t r1 = 0;
#line 145 "sample/callgraph_bpf2bpf.c"
    register uint64_t r2 = 0;
#line 145 "sample/callgraph_bpf2bpf.c"
    register uint64_t r3 = 0;
#line 145 "sample/callgraph_bpf2bpf.c"
    register uint64_t r4 = 0;
#line 145 "sample/callgraph_bpf2bpf.c"
    register uint64_t r5 = 0;
#line 145 "sample/callgraph_bpf2bpf.c"
    register uint64_t r10 = 0;

#line 145 "sample/callgraph_bpf2bpf.c"
    r1 = (uintptr_t)context;
#line 145 "sample/callgraph_bpf2bpf.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXDW pc=0 dst=r1 src=r1 offset=16 imm=0
#line 145 "sample/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r1, OFFSET(16));
    // EBPF_OP_STXDW pc=1 dst=r10 src=r1 offset=-8 imm=0
#line 145 "sample/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-8));
    // EBPF_OP_CALL pc=2 dst=r0 src=r0 offset=0 imm=19
#line 149 "sample/callgraph_bpf2bpf.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=3 dst=r1 src=r10 offset=0 imm=0
#line 149 "sample/callgraph_bpf2bpf.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r1 src=r0 offset=0 imm=-8
#line 149 "sample/callgraph_bpf2bpf.c"
    r1 += IMMEDIATE(-8);
    // EBPF_OP_CALL pc=5 dst=r0 src=r1 offset=0 imm=7
#line 151 "sample/callgraph_bpf2bpf.c"
    r0 = ScenarioS2(r1, r2, r3, r4, r5, r10, context, runtime_context);
    // EBPF_OP_MOV64_REG pc=6 dst=r1 src=r0 offset=0 imm=0
#line 151 "sample/callgraph_bpf2bpf.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=7 dst=r1 src=r0 offset=0 imm=32
#line 151 "sample/callgraph_bpf2bpf.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=8 dst=r1 src=r0 offset=0 imm=32
#line 151 "sample/callgraph_bpf2bpf.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_IMM pc=9 dst=r0 src=r0 offset=0 imm=1
#line 151 "sample/callgraph_bpf2bpf.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JNE_IMM pc=10 dst=r1 src=r0 offset=1 imm=2
#line 153 "sample/callgraph_bpf2bpf.c"
    if (r1 != IMMEDIATE(2)) {
#line 153 "sample/callgraph_bpf2bpf.c"
        goto label_1;
#line 153 "sample/callgraph_bpf2bpf.c"
    }
    // EBPF_OP_MOV64_IMM pc=11 dst=r0 src=r0 offset=0 imm=0
#line 153 "sample/callgraph_bpf2bpf.c"
    r0 = IMMEDIATE(0);
label_1:
    // EBPF_OP_EXIT pc=12 dst=r0 src=r0 offset=0 imm=0
#line 157 "sample/callgraph_bpf2bpf.c"
    return r0;
#line 145 "sample/callgraph_bpf2bpf.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t entry_program3_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
    {
     {1, 40, 40}, // Version header.
     0,
     "",
    },
    {
     {1, 40, 40}, // Version header.
     19,
     "helper_id_19",
    },
};

// Forward references for local functions.
static uint64_t
ScenarioS1(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context);
static uint64_t
ScenarioS2(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context);
static uint64_t
ScenarioS3(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context);
static uint64_t
ScenarioS4(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context);
static uint64_t
update_map(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context);

static GUID entry_program3_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID entry_program3_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t entry_program3_maps[] = {
    0,
};

#pragma code_seg(push, "bind/3")
static uint64_t
entry_program3(void* context, const program_runtime_context_t* runtime_context)
#line 163 "sample/callgraph_bpf2bpf.c"
{
#line 163 "sample/callgraph_bpf2bpf.c"
    // Prologue.
#line 163 "sample/callgraph_bpf2bpf.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 163 "sample/callgraph_bpf2bpf.c"
    register uint64_t r0 = 0;
#line 163 "sample/callgraph_bpf2bpf.c"
    register uint64_t r1 = 0;
#line 163 "sample/callgraph_bpf2bpf.c"
    register uint64_t r2 = 0;
#line 163 "sample/callgraph_bpf2bpf.c"
    register uint64_t r3 = 0;
#line 163 "sample/callgraph_bpf2bpf.c"
    register uint64_t r4 = 0;
#line 163 "sample/callgraph_bpf2bpf.c"
    register uint64_t r5 = 0;
#line 163 "sample/callgraph_bpf2bpf.c"
    register uint64_t r10 = 0;

#line 163 "sample/callgraph_bpf2bpf.c"
    r1 = (uintptr_t)context;
#line 163 "sample/callgraph_bpf2bpf.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXDW pc=0 dst=r1 src=r1 offset=16 imm=0
#line 163 "sample/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r1, OFFSET(16));
    // EBPF_OP_STXDW pc=1 dst=r10 src=r1 offset=-8 imm=0
#line 163 "sample/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=2 dst=r1 src=r10 offset=0 imm=0
#line 163 "sample/callgraph_bpf2bpf.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=3 dst=r1 src=r0 offset=0 imm=-8
#line 163 "sample/callgraph_bpf2bpf.c"
    r1 += IMMEDIATE(-8);
    // EBPF_OP_CALL pc=4 dst=r0 src=r1 offset=0 imm=7
#line 166 "sample/callgraph_bpf2bpf.c"
    r0 = update_map(r1, r2, r3, r4, r5, r10, context, runtime_context);
    // EBPF_OP_MOV64_REG pc=5 dst=r1 src=r0 offset=0 imm=0
#line 166 "sample/callgraph_bpf2bpf.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=6 dst=r1 src=r0 offset=0 imm=32
#line 166 "sample/callgraph_bpf2bpf.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=7 dst=r1 src=r0 offset=0 imm=32
#line 166 "sample/callgraph_bpf2bpf.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_IMM pc=8 dst=r0 src=r0 offset=0 imm=1
#line 166 "sample/callgraph_bpf2bpf.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JNE_IMM pc=9 dst=r1 src=r0 offset=1 imm=0
#line 168 "sample/callgraph_bpf2bpf.c"
    if (r1 != IMMEDIATE(0)) {
#line 168 "sample/callgraph_bpf2bpf.c"
        goto label_1;
#line 168 "sample/callgraph_bpf2bpf.c"
    }
    // EBPF_OP_MOV64_IMM pc=10 dst=r0 src=r0 offset=0 imm=0
#line 168 "sample/callgraph_bpf2bpf.c"
    r0 = IMMEDIATE(0);
label_1:
    // EBPF_OP_EXIT pc=11 dst=r0 src=r0 offset=0 imm=0
#line 173 "sample/callgraph_bpf2bpf.c"
    return r0;
#line 163 "sample/callgraph_bpf2bpf.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {2, 160, 160}, // Version header.
        entry_program1,
        "bind/1",
        "bind/1",
        "entry_program1",
        NULL,
        0,
        entry_program1_helpers,
        4,
        NULL,
        0,
        17,
        &entry_program1_program_type_guid,
        &entry_program1_attach_type_guid,
    },
    {
        0,
        {2, 160, 160}, // Version header.
        entry_program2,
        "bind/2",
        "bind/2",
        "entry_program2",
        NULL,
        0,
        entry_program2_helpers,
        4,
        NULL,
        0,
        13,
        &entry_program2_program_type_guid,
        &entry_program2_attach_type_guid,
    },
    {
        0,
        {2, 160, 160}, // Version header.
        entry_program3,
        "bind/3",
        "bind/3",
        "entry_program3",
        entry_program3_maps,
        1,
        entry_program3_helpers,
        4,
        NULL,
        0,
        12,
        &entry_program3_program_type_guid,
        &entry_program3_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 3;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = 1;
    version->minor = 5;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t callgraph_bpf2bpf_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
