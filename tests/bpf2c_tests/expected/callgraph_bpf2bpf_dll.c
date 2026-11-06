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
#include "ebpf_version.h"

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
     "call_count_map"},
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
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID entry_program1_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
#pragma code_seg(push, "sample~3")
static uint64_t
entry_program1(void* context, const program_runtime_context_t* runtime_context)
#line 120 "sample/undocked/callgraph_bpf2bpf.c"
{
#line 120 "sample/undocked/callgraph_bpf2bpf.c"
    // Prologue.
#line 120 "sample/undocked/callgraph_bpf2bpf.c"
    uint64_t stack[((UBPF_STACK_SIZE * 4) + 7) / 8];
#line 120 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r0 = 0;
#line 120 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r1 = 0;
#line 120 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r2 = 0;
#line 120 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r3 = 0;
#line 120 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r4 = 0;
#line 120 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r5 = 0;
#line 120 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r6 = 0;
#line 120 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r7 = 0;
#line 120 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r8 = 0;
#line 120 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r10 = 0;

#line 120 "sample/undocked/callgraph_bpf2bpf.c"
    r1 = (uintptr_t)context;
#line 120 "sample/undocked/callgraph_bpf2bpf.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXW pc=0 dst=r1 src=r1 offset=16 imm=0
#line 120 "sample/undocked/callgraph_bpf2bpf.c"
    READ_ONCE_32(r1, r1, OFFSET(16));
    // EBPF_OP_MOV64_IMM pc=1 dst=r6 src=r0 offset=0 imm=1
#line 120 "sample/undocked/callgraph_bpf2bpf.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_JGT_IMM pc=2 dst=r1 src=r0 offset=1 imm=1
#line 121 "sample/undocked/callgraph_bpf2bpf.c"
    if (r1 > IMMEDIATE(1)) {
#line 121 "sample/undocked/callgraph_bpf2bpf.c"
        goto label_1;
#line 121 "sample/undocked/callgraph_bpf2bpf.c"
    }
    // EBPF_OP_MOV64_IMM pc=3 dst=r1 src=r0 offset=0 imm=1
#line 121 "sample/undocked/callgraph_bpf2bpf.c"
    r1 = IMMEDIATE(1);
label_1:
    // EBPF_OP_STXDW pc=4 dst=r10 src=r1 offset=-8 imm=0
#line 121 "sample/undocked/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-8));
    // EBPF_OP_CALL pc=5 dst=r0 src=r0 offset=0 imm=19
#line 126 "sample/undocked/callgraph_bpf2bpf.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_CALL pc=6 dst=r0 src=r0 offset=0 imm=9
#line 127 "sample/undocked/callgraph_bpf2bpf.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=7 dst=r7 src=r10 offset=0 imm=0
#line 127 "sample/undocked/callgraph_bpf2bpf.c"
    r7 = r10;
    // EBPF_OP_ADD64_IMM pc=8 dst=r7 src=r0 offset=0 imm=-8
#line 127 "sample/undocked/callgraph_bpf2bpf.c"
    r7 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r7 offset=0 imm=0
#line 129 "sample/undocked/callgraph_bpf2bpf.c"
    r1 = r7;
    // EBPF_OP_CALL pc=10 dst=r0 src=r1 offset=0 imm=10
#line 129 "sample/undocked/callgraph_bpf2bpf.c"
    r0 = ScenarioS1(r1, r2, r3, r4, r5, r10 - UBPF_STACK_SIZE, context, runtime_context);
    // EBPF_OP_MOV64_REG pc=11 dst=r8 src=r0 offset=0 imm=0
#line 129 "sample/undocked/callgraph_bpf2bpf.c"
    r8 = r0;
    // EBPF_OP_MOV64_REG pc=12 dst=r1 src=r7 offset=0 imm=0
#line 130 "sample/undocked/callgraph_bpf2bpf.c"
    r1 = r7;
    // EBPF_OP_CALL pc=13 dst=r0 src=r1 offset=0 imm=30
#line 130 "sample/undocked/callgraph_bpf2bpf.c"
    r0 = ScenarioS4(r1, r2, r3, r4, r5, r10 - UBPF_STACK_SIZE, context, runtime_context);
    // EBPF_OP_LSH64_IMM pc=14 dst=r8 src=r0 offset=0 imm=32
#line 129 "sample/undocked/callgraph_bpf2bpf.c"
    r8 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=15 dst=r8 src=r0 offset=0 imm=32
#line 129 "sample/undocked/callgraph_bpf2bpf.c"
    r8 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=16 dst=r8 src=r0 offset=1 imm=2
#line 129 "sample/undocked/callgraph_bpf2bpf.c"
    if (r8 == IMMEDIATE(2)) {
#line 129 "sample/undocked/callgraph_bpf2bpf.c"
        goto label_2;
#line 129 "sample/undocked/callgraph_bpf2bpf.c"
    }
    // EBPF_OP_MOV64_IMM pc=17 dst=r6 src=r0 offset=0 imm=0
#line 129 "sample/undocked/callgraph_bpf2bpf.c"
    r6 = IMMEDIATE(0);
label_2:
    // EBPF_OP_LSH64_IMM pc=18 dst=r6 src=r0 offset=0 imm=1
#line 136 "sample/undocked/callgraph_bpf2bpf.c"
    r6 <<= (IMMEDIATE(1) & 63);
    // EBPF_OP_MOV64_REG pc=19 dst=r0 src=r6 offset=0 imm=0
#line 136 "sample/undocked/callgraph_bpf2bpf.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 136 "sample/undocked/callgraph_bpf2bpf.c"
    return r0;
#line 120 "sample/undocked/callgraph_bpf2bpf.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static uint64_t
ScenarioS1(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context)
{
    register uint64_t r0 = 0;

    // EBPF_OP_STXDW pc=0 dst=r10 src=r1 offset=-8 imm=0
#line 48 "sample/undocked/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-8));
    // EBPF_OP_CALL pc=1 dst=r0 src=r0 offset=0 imm=19
#line 51 "sample/undocked/callgraph_bpf2bpf.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXDW pc=2 dst=r1 src=r10 offset=-8 imm=0
#line 54 "sample/undocked/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r10, OFFSET(-8));
    // EBPF_OP_CALL pc=3 dst=r0 src=r1 offset=0 imm=1
#line 54 "sample/undocked/callgraph_bpf2bpf.c"
    r0 = ScenarioS2(r1, r2, r3, r4, r5, r10 - UBPF_STACK_SIZE, context, runtime_context);
    // EBPF_OP_EXIT pc=4 dst=r0 src=r0 offset=0 imm=0
#line 54 "sample/undocked/callgraph_bpf2bpf.c"
    return r0;
}
static uint64_t
ScenarioS2(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context)
{
    register uint64_t r0 = 0;
    (void)context;
    UNREFERENCED_PARAMETER(runtime_context);

    // EBPF_OP_STXDW pc=0 dst=r10 src=r1 offset=-8 imm=0
#line 48 "sample/undocked/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-8));
    // EBPF_OP_LDXDW pc=1 dst=r1 src=r10 offset=-8 imm=0
#line 51 "sample/undocked/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r10, OFFSET(-8));
    // EBPF_OP_CALL pc=2 dst=r0 src=r1 offset=0 imm=1
#line 54 "sample/undocked/callgraph_bpf2bpf.c"
    r0 = ScenarioS3(r1, r2, r3, r4, r5, r10 - UBPF_STACK_SIZE, context, runtime_context);
    // EBPF_OP_EXIT pc=3 dst=r0 src=r0 offset=0 imm=0
#line 54 "sample/undocked/callgraph_bpf2bpf.c"
    return r0;
}
static uint64_t
ScenarioS3(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context)
{
    register uint64_t r0 = 0;

    // EBPF_OP_STXDW pc=0 dst=r10 src=r1 offset=-16 imm=0
#line 48 "sample/undocked/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_CALL pc=1 dst=r0 src=r0 offset=0 imm=19
#line 51 "sample/undocked/callgraph_bpf2bpf.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXDW pc=2 dst=r1 src=r10 offset=-16 imm=0
#line 54 "sample/undocked/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r10, OFFSET(-16));
    // EBPF_OP_LDXDW pc=3 dst=r1 src=r1 offset=0 imm=0
#line 54 "sample/undocked/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r1, OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=4 dst=r1 src=r0 offset=4 imm=0
#line 54 "sample/undocked/callgraph_bpf2bpf.c"
    if (r1 == IMMEDIATE(0)) {
#line 54 "sample/undocked/callgraph_bpf2bpf.c"
        goto label_2;
#line 54 "sample/undocked/callgraph_bpf2bpf.c"
    }
    // EBPF_OP_JA pc=5 dst=r0 src=r0 offset=0 imm=0
#line 54 "sample/undocked/callgraph_bpf2bpf.c"
    goto label_1;
label_1:
    // EBPF_OP_MOV64_IMM pc=6 dst=r1 src=r0 offset=0 imm=2
#line 54 "sample/undocked/callgraph_bpf2bpf.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=7 dst=r10 src=r1 offset=-4 imm=0
#line 55 "sample/undocked/callgraph_bpf2bpf.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_JA pc=8 dst=r0 src=r0 offset=3 imm=0
#line 55 "sample/undocked/callgraph_bpf2bpf.c"
    goto label_3;
label_2:
    // EBPF_OP_MOV64_IMM pc=9 dst=r1 src=r0 offset=0 imm=1
#line 55 "sample/undocked/callgraph_bpf2bpf.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=10 dst=r10 src=r1 offset=-4 imm=0
#line 57 "sample/undocked/callgraph_bpf2bpf.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_JA pc=11 dst=r0 src=r0 offset=0 imm=0
#line 57 "sample/undocked/callgraph_bpf2bpf.c"
    goto label_3;
label_3:
    // EBPF_OP_LDXW pc=12 dst=r0 src=r10 offset=-4 imm=0
#line 58 "sample/undocked/callgraph_bpf2bpf.c"
    READ_ONCE_32(r0, r10, OFFSET(-4));
    // EBPF_OP_EXIT pc=13 dst=r0 src=r0 offset=0 imm=0
#line 58 "sample/undocked/callgraph_bpf2bpf.c"
    return r0;
}
static uint64_t
ScenarioS4(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context)
{
    register uint64_t r0 = 0;

    // EBPF_OP_STXDW pc=0 dst=r10 src=r1 offset=-8 imm=0
#line 48 "sample/undocked/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-8));
    // EBPF_OP_CALL pc=1 dst=r0 src=r0 offset=0 imm=9
#line 51 "sample/undocked/callgraph_bpf2bpf.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_IMM pc=2 dst=r0 src=r0 offset=0 imm=1
#line 54 "sample/undocked/callgraph_bpf2bpf.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=3 dst=r0 src=r0 offset=0 imm=0
#line 54 "sample/undocked/callgraph_bpf2bpf.c"
    return r0;
}
static uint64_t
update_map(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context)
{
    register uint64_t r0 = 0;
    register uint64_t r6 = 0;

    // EBPF_OP_STXDW pc=0 dst=r10 src=r1 offset=-16 imm=0
#line 48 "sample/undocked/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDXDW pc=1 dst=r1 src=r10 offset=-16 imm=0
#line 51 "sample/undocked/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r10, OFFSET(-16));
    // EBPF_OP_LDXDW pc=2 dst=r1 src=r1 offset=0 imm=0
#line 54 "sample/undocked/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r1, OFFSET(0));
    // EBPF_OP_STXDW pc=3 dst=r10 src=r1 offset=-24 imm=0
#line 54 "sample/undocked/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_CALL pc=4 dst=r0 src=r0 offset=0 imm=19
#line 54 "sample/undocked/callgraph_bpf2bpf.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXDW pc=5 dst=r10 src=r0 offset=-32 imm=0
#line 54 "sample/undocked/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-32));
    // EBPF_OP_LDXDW pc=6 dst=r1 src=r10 offset=-32 imm=0
#line 54 "sample/undocked/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r10, OFFSET(-32));
    // EBPF_OP_JNE_IMM pc=7 dst=r1 src=r0 offset=7 imm=0
#line 55 "sample/undocked/callgraph_bpf2bpf.c"
    if (r1 != IMMEDIATE(0)) {
#line 55 "sample/undocked/callgraph_bpf2bpf.c"
        goto label_2;
#line 55 "sample/undocked/callgraph_bpf2bpf.c"
    }
    // EBPF_OP_JA pc=8 dst=r0 src=r0 offset=0 imm=0
#line 55 "sample/undocked/callgraph_bpf2bpf.c"
    goto label_1;
label_1:
    // EBPF_OP_LDDW pc=9 dst=r1 src=r0 offset=0 imm=-1
#line 55 "sample/undocked/callgraph_bpf2bpf.c"
    r1 = (uint64_t)4294967295;
    // EBPF_OP_STXW pc=11 dst=r10 src=r1 offset=-4 imm=0
#line 55 "sample/undocked/callgraph_bpf2bpf.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MOV64_IMM pc=12 dst=r1 src=r0 offset=0 imm=1
#line 58 "sample/undocked/callgraph_bpf2bpf.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=13 dst=r10 src=r1 offset=-36 imm=0
#line 58 "sample/undocked/callgraph_bpf2bpf.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-36));
    // EBPF_OP_JA pc=14 dst=r0 src=r0 offset=39 imm=0
#line 61 "sample/undocked/callgraph_bpf2bpf.c"
    goto label_6;
label_2:
    // EBPF_OP_MOV64_REG pc=15 dst=r2 src=r10 offset=0 imm=0
#line 64 "sample/undocked/callgraph_bpf2bpf.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=16 dst=r2 src=r0 offset=0 imm=-24
#line 64 "sample/undocked/callgraph_bpf2bpf.c"
    r2 += IMMEDIATE(-24);
    // EBPF_OP_LDDW pc=17 dst=r1 src=r1 offset=0 imm=1
#line 64 "sample/undocked/callgraph_bpf2bpf.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=19 dst=r0 src=r0 offset=0 imm=1
#line 71 "sample/undocked/callgraph_bpf2bpf.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXDW pc=20 dst=r10 src=r0 offset=-48 imm=0
#line 72 "sample/undocked/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-48));
    // EBPF_OP_LDXDW pc=21 dst=r1 src=r10 offset=-48 imm=0
#line 72 "sample/undocked/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r10, OFFSET(-48));
    // EBPF_OP_JEQ_IMM pc=22 dst=r1 src=r0 offset=17 imm=0
#line 72 "sample/undocked/callgraph_bpf2bpf.c"
    if (r1 == IMMEDIATE(0)) {
#line 72 "sample/undocked/callgraph_bpf2bpf.c"
        goto label_4;
#line 72 "sample/undocked/callgraph_bpf2bpf.c"
    }
    // EBPF_OP_JA pc=23 dst=r0 src=r0 offset=0 imm=0
#line 76 "sample/undocked/callgraph_bpf2bpf.c"
    goto label_3;
label_3:
    // EBPF_OP_LDXDW pc=24 dst=r1 src=r10 offset=-48 imm=0
#line 81 "sample/undocked/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r10, OFFSET(-48));
    // EBPF_OP_LDXDW pc=25 dst=r1 src=r1 offset=0 imm=0
#line 82 "sample/undocked/callgraph_bpf2bpf.c"
    READ_ONCE_64(r1, r1, OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=26 dst=r1 src=r0 offset=0 imm=1
#line 82 "sample/undocked/callgraph_bpf2bpf.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=27 dst=r10 src=r1 offset=-56 imm=0
#line 89 "sample/undocked/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-56));
    // EBPF_OP_MOV64_REG pc=28 dst=r2 src=r10 offset=0 imm=0
#line 91 "sample/undocked/callgraph_bpf2bpf.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=29 dst=r2 src=r0 offset=0 imm=-24
#line 91 "sample/undocked/callgraph_bpf2bpf.c"
    r2 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_REG pc=30 dst=r3 src=r10 offset=0 imm=0
#line 91 "sample/undocked/callgraph_bpf2bpf.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=31 dst=r3 src=r0 offset=0 imm=-56
#line 94 "sample/undocked/callgraph_bpf2bpf.c"
    r3 += IMMEDIATE(-56);
    // EBPF_OP_LDDW pc=32 dst=r1 src=r1 offset=0 imm=1
#line 94 "sample/undocked/callgraph_bpf2bpf.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=34 dst=r4 src=r0 offset=0 imm=0
#line 97 "sample/undocked/callgraph_bpf2bpf.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=35 dst=r0 src=r0 offset=0 imm=2
#line 97 "sample/undocked/callgraph_bpf2bpf.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXW pc=36 dst=r10 src=r0 offset=-4 imm=0
#line 97 "sample/undocked/callgraph_bpf2bpf.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-4));
    // EBPF_OP_MOV64_IMM pc=37 dst=r1 src=r0 offset=0 imm=1
#line 97 "sample/undocked/callgraph_bpf2bpf.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=38 dst=r10 src=r1 offset=-36 imm=0
#line 98 "sample/undocked/callgraph_bpf2bpf.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-36));
    // EBPF_OP_JA pc=39 dst=r0 src=r0 offset=13 imm=0
#line 98 "sample/undocked/callgraph_bpf2bpf.c"
    goto label_5;
label_4:
    // EBPF_OP_MOV64_IMM pc=40 dst=r6 src=r0 offset=0 imm=1
#line 98 "sample/undocked/callgraph_bpf2bpf.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_STXDW pc=41 dst=r10 src=r6 offset=-64 imm=0
#line 98 "sample/undocked/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-64));
    // EBPF_OP_MOV64_REG pc=42 dst=r2 src=r10 offset=0 imm=0
#line 98 "sample/undocked/callgraph_bpf2bpf.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=43 dst=r2 src=r0 offset=0 imm=-24
#line 102 "sample/undocked/callgraph_bpf2bpf.c"
    r2 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_REG pc=44 dst=r3 src=r10 offset=0 imm=0
#line 102 "sample/undocked/callgraph_bpf2bpf.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=45 dst=r3 src=r0 offset=0 imm=-64
#line 102 "sample/undocked/callgraph_bpf2bpf.c"
    r3 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=46 dst=r1 src=r1 offset=0 imm=1
#line 102 "sample/undocked/callgraph_bpf2bpf.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=48 dst=r4 src=r0 offset=0 imm=0
#line 103 "sample/undocked/callgraph_bpf2bpf.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=49 dst=r0 src=r0 offset=0 imm=2
#line 103 "sample/undocked/callgraph_bpf2bpf.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXW pc=50 dst=r10 src=r0 offset=-4 imm=0
#line 103 "sample/undocked/callgraph_bpf2bpf.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-4));
    // EBPF_OP_STXW pc=51 dst=r10 src=r6 offset=-36 imm=0
#line 104 "sample/undocked/callgraph_bpf2bpf.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-36));
    // EBPF_OP_JA pc=52 dst=r0 src=r0 offset=0 imm=0
#line 104 "sample/undocked/callgraph_bpf2bpf.c"
    goto label_5;
label_5:
    // EBPF_OP_JA pc=53 dst=r0 src=r0 offset=0 imm=0
#line 104 "sample/undocked/callgraph_bpf2bpf.c"
    goto label_6;
label_6:
    // EBPF_OP_LDXW pc=54 dst=r0 src=r10 offset=-4 imm=0
#line 104 "sample/undocked/callgraph_bpf2bpf.c"
    READ_ONCE_32(r0, r10, OFFSET(-4));
    // EBPF_OP_EXIT pc=55 dst=r0 src=r0 offset=0 imm=0
#line 104 "sample/undocked/callgraph_bpf2bpf.c"
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
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID entry_program2_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
#pragma code_seg(push, "sample~2")
static uint64_t
entry_program2(void* context, const program_runtime_context_t* runtime_context)
#line 145 "sample/undocked/callgraph_bpf2bpf.c"
{
#line 145 "sample/undocked/callgraph_bpf2bpf.c"
    // Prologue.
#line 145 "sample/undocked/callgraph_bpf2bpf.c"
    uint64_t stack[((UBPF_STACK_SIZE * 3) + 7) / 8];
#line 145 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r0 = 0;
#line 145 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r1 = 0;
#line 145 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r2 = 0;
#line 145 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r3 = 0;
#line 145 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r4 = 0;
#line 145 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r5 = 0;
#line 145 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r6 = 0;
#line 145 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r10 = 0;

#line 145 "sample/undocked/callgraph_bpf2bpf.c"
    r1 = (uintptr_t)context;
#line 145 "sample/undocked/callgraph_bpf2bpf.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXW pc=0 dst=r1 src=r1 offset=16 imm=0
#line 145 "sample/undocked/callgraph_bpf2bpf.c"
    READ_ONCE_32(r1, r1, OFFSET(16));
    // EBPF_OP_MOV64_IMM pc=1 dst=r6 src=r0 offset=0 imm=1
#line 145 "sample/undocked/callgraph_bpf2bpf.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_JGT_IMM pc=2 dst=r1 src=r0 offset=1 imm=1
#line 146 "sample/undocked/callgraph_bpf2bpf.c"
    if (r1 > IMMEDIATE(1)) {
#line 146 "sample/undocked/callgraph_bpf2bpf.c"
        goto label_1;
#line 146 "sample/undocked/callgraph_bpf2bpf.c"
    }
    // EBPF_OP_MOV64_IMM pc=3 dst=r1 src=r0 offset=0 imm=1
#line 146 "sample/undocked/callgraph_bpf2bpf.c"
    r1 = IMMEDIATE(1);
label_1:
    // EBPF_OP_STXDW pc=4 dst=r10 src=r1 offset=-8 imm=0
#line 146 "sample/undocked/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-8));
    // EBPF_OP_CALL pc=5 dst=r0 src=r0 offset=0 imm=19
#line 151 "sample/undocked/callgraph_bpf2bpf.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=6 dst=r1 src=r10 offset=0 imm=0
#line 151 "sample/undocked/callgraph_bpf2bpf.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r1 src=r0 offset=0 imm=-8
#line 151 "sample/undocked/callgraph_bpf2bpf.c"
    r1 += IMMEDIATE(-8);
    // EBPF_OP_CALL pc=8 dst=r0 src=r1 offset=0 imm=6
#line 153 "sample/undocked/callgraph_bpf2bpf.c"
    r0 = ScenarioS2(r1, r2, r3, r4, r5, r10 - UBPF_STACK_SIZE, context, runtime_context);
    // EBPF_OP_LSH64_IMM pc=9 dst=r0 src=r0 offset=0 imm=32
#line 153 "sample/undocked/callgraph_bpf2bpf.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=10 dst=r0 src=r0 offset=0 imm=32
#line 153 "sample/undocked/callgraph_bpf2bpf.c"
    r0 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=11 dst=r0 src=r0 offset=1 imm=2
#line 155 "sample/undocked/callgraph_bpf2bpf.c"
    if (r0 == IMMEDIATE(2)) {
#line 155 "sample/undocked/callgraph_bpf2bpf.c"
        goto label_2;
#line 155 "sample/undocked/callgraph_bpf2bpf.c"
    }
    // EBPF_OP_MOV64_IMM pc=12 dst=r6 src=r0 offset=0 imm=0
#line 155 "sample/undocked/callgraph_bpf2bpf.c"
    r6 = IMMEDIATE(0);
label_2:
    // EBPF_OP_MOV64_REG pc=13 dst=r0 src=r6 offset=0 imm=0
#line 159 "sample/undocked/callgraph_bpf2bpf.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=14 dst=r0 src=r0 offset=0 imm=0
#line 159 "sample/undocked/callgraph_bpf2bpf.c"
    return r0;
#line 145 "sample/undocked/callgraph_bpf2bpf.c"
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
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID entry_program3_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t entry_program3_maps[] = {
    0,
};

#pragma code_seg(push, "sample~1")
static uint64_t
entry_program3(void* context, const program_runtime_context_t* runtime_context)
#line 167 "sample/undocked/callgraph_bpf2bpf.c"
{
#line 167 "sample/undocked/callgraph_bpf2bpf.c"
    // Prologue.
#line 167 "sample/undocked/callgraph_bpf2bpf.c"
    uint64_t stack[((UBPF_STACK_SIZE * 2) + 7) / 8];
#line 167 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r0 = 0;
#line 167 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r1 = 0;
#line 167 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r2 = 0;
#line 167 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r3 = 0;
#line 167 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r4 = 0;
#line 167 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r5 = 0;
#line 167 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r6 = 0;
#line 167 "sample/undocked/callgraph_bpf2bpf.c"
    register uint64_t r10 = 0;

#line 167 "sample/undocked/callgraph_bpf2bpf.c"
    r1 = (uintptr_t)context;
#line 167 "sample/undocked/callgraph_bpf2bpf.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXW pc=0 dst=r1 src=r1 offset=16 imm=0
#line 167 "sample/undocked/callgraph_bpf2bpf.c"
    READ_ONCE_32(r1, r1, OFFSET(16));
    // EBPF_OP_MOV64_IMM pc=1 dst=r6 src=r0 offset=0 imm=1
#line 167 "sample/undocked/callgraph_bpf2bpf.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_JGT_IMM pc=2 dst=r1 src=r0 offset=1 imm=1
#line 168 "sample/undocked/callgraph_bpf2bpf.c"
    if (r1 > IMMEDIATE(1)) {
#line 168 "sample/undocked/callgraph_bpf2bpf.c"
        goto label_1;
#line 168 "sample/undocked/callgraph_bpf2bpf.c"
    }
    // EBPF_OP_MOV64_IMM pc=3 dst=r1 src=r0 offset=0 imm=1
#line 168 "sample/undocked/callgraph_bpf2bpf.c"
    r1 = IMMEDIATE(1);
label_1:
    // EBPF_OP_STXDW pc=4 dst=r10 src=r1 offset=-8 imm=0
#line 168 "sample/undocked/callgraph_bpf2bpf.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=5 dst=r1 src=r10 offset=0 imm=0
#line 168 "sample/undocked/callgraph_bpf2bpf.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=6 dst=r1 src=r0 offset=0 imm=-8
#line 168 "sample/undocked/callgraph_bpf2bpf.c"
    r1 += IMMEDIATE(-8);
    // EBPF_OP_CALL pc=7 dst=r0 src=r1 offset=0 imm=6
#line 173 "sample/undocked/callgraph_bpf2bpf.c"
    r0 = update_map(r1, r2, r3, r4, r5, r10 - UBPF_STACK_SIZE, context, runtime_context);
    // EBPF_OP_LSH64_IMM pc=8 dst=r0 src=r0 offset=0 imm=32
#line 173 "sample/undocked/callgraph_bpf2bpf.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=9 dst=r0 src=r0 offset=0 imm=32
#line 173 "sample/undocked/callgraph_bpf2bpf.c"
    r0 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=10 dst=r0 src=r0 offset=1 imm=0
#line 175 "sample/undocked/callgraph_bpf2bpf.c"
    if (r0 == IMMEDIATE(0)) {
#line 175 "sample/undocked/callgraph_bpf2bpf.c"
        goto label_2;
#line 175 "sample/undocked/callgraph_bpf2bpf.c"
    }
    // EBPF_OP_MOV64_IMM pc=11 dst=r6 src=r0 offset=0 imm=0
#line 175 "sample/undocked/callgraph_bpf2bpf.c"
    r6 = IMMEDIATE(0);
label_2:
    // EBPF_OP_MOV64_REG pc=12 dst=r0 src=r6 offset=0 imm=0
#line 180 "sample/undocked/callgraph_bpf2bpf.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=13 dst=r0 src=r0 offset=0 imm=0
#line 180 "sample/undocked/callgraph_bpf2bpf.c"
    return r0;
#line 167 "sample/undocked/callgraph_bpf2bpf.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 154, 160}, // Version header.
        entry_program1,
        "sample~3",
        "sample_ext/1",
        "entry_program1",
        NULL,
        0,
        entry_program1_helpers,
        4,
        21,
        &entry_program1_program_type_guid,
        &entry_program1_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        entry_program2,
        "sample~2",
        "sample_ext/2",
        "entry_program2",
        NULL,
        0,
        entry_program2_helpers,
        4,
        15,
        &entry_program2_program_type_guid,
        &entry_program2_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        entry_program3,
        "sample~1",
        "sample_ext/3",
        "entry_program3",
        entry_program3_maps,
        1,
        entry_program3_helpers,
        4,
        14,
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
    version->major = EBPF_VERSION_MAJOR;
    version->minor = EBPF_VERSION_MINOR;
    version->revision = EBPF_VERSION_REVISION;
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
