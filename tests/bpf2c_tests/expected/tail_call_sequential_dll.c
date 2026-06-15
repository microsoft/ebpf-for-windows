// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from tail_call_sequential.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers.
#include <windows.h>

#define metadata_table tail_call_sequential##_metadata_table
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
         1,                       // Current Version.
         80,                      // Struct size up to the last field.
         80,                      // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_PROG_ARRAY, // Type of map.
         4,                       // Size in bytes of a map key.
         4,                       // Size in bytes of a map value.
         35,                      // Maximum number of entries allowed in the map.
         0,                       // Inner map index.
         LIBBPF_PIN_NONE,         // Pinning type for the map.
         22,                      // Identifier for a map template.
         0,                       // The id of the inner map template.
     },
     "map"},
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
         28,                 // Identifier for a map template.
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

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static helper_function_entry_t sequential0_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential0_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential0_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential0_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~35")
static uint64_t
sequential0(void* context, const program_runtime_context_t* runtime_context)
#line 133 "sample/undocked/tail_call_sequential.c"
{
#line 133 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 133 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 133 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 133 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 133 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 133 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 133 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 133 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 133 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 133 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 133 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 133 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 133 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 133 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 133 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 133 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 133 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 133 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 133 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 133 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 133 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 133 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 133 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 133 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 133 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 133 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 133 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 133 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976252001
#line 133 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834439265;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 133 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 133 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 133 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 133 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 133 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 133 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 133 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 133 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 133 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=0
#line 133 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(0)) {
#line 133 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 133 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=1
#line 133 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 133 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 133 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r1 offset=0 imm=1
#line 133 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=1
#line 133 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(1);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 133 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 133 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 133 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 133 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 133 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 133 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 133 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 133 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential1_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential1_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential1_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential1_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~34")
static uint64_t
sequential1(void* context, const program_runtime_context_t* runtime_context)
#line 134 "sample/undocked/tail_call_sequential.c"
{
#line 134 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 134 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 134 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 134 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 134 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 134 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 134 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 134 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 134 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 134 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 134 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 134 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 134 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 134 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 134 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 134 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 134 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 134 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 134 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 134 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 134 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 134 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 134 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 134 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 134 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 134 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 134 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 134 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976317537
#line 134 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834504801;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 134 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 134 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 134 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 134 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 134 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 134 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 134 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 134 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 134 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=1
#line 134 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(1)) {
#line 134 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 134 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=2
#line 134 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 134 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 134 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r1 offset=0 imm=1
#line 134 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=2
#line 134 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 134 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 134 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 134 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 134 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 134 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 134 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 134 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 134 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential10_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential10_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential10_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential10_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~25")
static uint64_t
sequential10(void* context, const program_runtime_context_t* runtime_context)
#line 143 "sample/undocked/tail_call_sequential.c"
{
#line 143 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 143 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 143 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 143 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 143 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 143 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 143 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 143 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 143 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 143 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 143 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 143 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 143 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 143 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 143 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 143 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 143 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 143 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 143 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 143 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 143 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 143 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 143 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 143 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 143 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 143 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 143 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 143 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 143 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 143 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=808545377
#line 143 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479786081377;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 143 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 143 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 143 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 143 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 143 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 143 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 143 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 143 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 143 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=10
#line 143 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(10)) {
#line 143 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 143 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=11
#line 143 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(11);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 143 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 143 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 143 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=11
#line 143 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(11);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 143 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 143 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 143 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 143 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 143 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 143 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 143 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 143 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential11_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential11_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential11_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential11_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~24")
static uint64_t
sequential11(void* context, const program_runtime_context_t* runtime_context)
#line 144 "sample/undocked/tail_call_sequential.c"
{
#line 144 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 144 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 144 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 144 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 144 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 144 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 144 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 144 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 144 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 144 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 144 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 144 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 144 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 144 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 144 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 144 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 144 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 144 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 144 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 144 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 144 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 144 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 144 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 144 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 144 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 144 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 144 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 144 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 144 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 144 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=825322593
#line 144 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479802858593;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 144 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 144 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 144 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 144 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 144 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 144 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 144 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 144 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 144 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=11
#line 144 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(11)) {
#line 144 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 144 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=12
#line 144 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(12);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 144 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 144 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 144 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=12
#line 144 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(12);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 144 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 144 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 144 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 144 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 144 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 144 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 144 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 144 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential12_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential12_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential12_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential12_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~23")
static uint64_t
sequential12(void* context, const program_runtime_context_t* runtime_context)
#line 145 "sample/undocked/tail_call_sequential.c"
{
#line 145 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 145 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 145 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 145 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 145 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 145 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 145 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 145 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 145 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 145 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 145 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 145 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 145 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 145 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 145 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 145 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 145 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 145 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 145 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 145 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 145 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 145 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 145 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 145 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 145 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 145 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 145 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 145 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 145 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 145 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=842099809
#line 145 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479819635809;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 145 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 145 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 145 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 145 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 145 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 145 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 145 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 145 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 145 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=12
#line 145 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(12)) {
#line 145 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 145 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=13
#line 145 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(13);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 145 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 145 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 145 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=13
#line 145 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(13);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 145 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 145 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 145 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 145 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 145 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 145 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 145 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 145 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential13_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential13_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential13_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential13_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~22")
static uint64_t
sequential13(void* context, const program_runtime_context_t* runtime_context)
#line 146 "sample/undocked/tail_call_sequential.c"
{
#line 146 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 146 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 146 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 146 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 146 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 146 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 146 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 146 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 146 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 146 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 146 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 146 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 146 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 146 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 146 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 146 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 146 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 146 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 146 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 146 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 146 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 146 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 146 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 146 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 146 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 146 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 146 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 146 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 146 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 146 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=858877025
#line 146 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479836413025;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 146 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 146 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 146 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 146 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 146 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 146 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 146 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 146 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 146 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=13
#line 146 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(13)) {
#line 146 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 146 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=14
#line 146 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(14);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 146 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 146 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 146 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=14
#line 146 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(14);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 146 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 146 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 146 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 146 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 146 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 146 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 146 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 146 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential14_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential14_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential14_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential14_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~21")
static uint64_t
sequential14(void* context, const program_runtime_context_t* runtime_context)
#line 147 "sample/undocked/tail_call_sequential.c"
{
#line 147 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 147 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 147 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 147 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 147 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 147 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 147 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 147 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 147 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 147 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 147 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 147 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 147 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 147 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 147 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 147 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 147 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 147 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 147 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 147 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 147 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 147 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 147 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 147 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 147 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 147 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 147 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 147 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 147 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 147 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=875654241
#line 147 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479853190241;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 147 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 147 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 147 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 147 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 147 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 147 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 147 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 147 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 147 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=14
#line 147 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(14)) {
#line 147 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 147 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=15
#line 147 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(15);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 147 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 147 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 147 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=15
#line 147 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(15);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 147 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 147 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 147 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 147 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 147 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 147 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 147 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 147 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential15_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential15_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential15_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential15_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~20")
static uint64_t
sequential15(void* context, const program_runtime_context_t* runtime_context)
#line 148 "sample/undocked/tail_call_sequential.c"
{
#line 148 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 148 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 148 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 148 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 148 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 148 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 148 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 148 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 148 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 148 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 148 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 148 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 148 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 148 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 148 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 148 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 148 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 148 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 148 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 148 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 148 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 148 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 148 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 148 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 148 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 148 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 148 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 148 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 148 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 148 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=892431457
#line 148 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479869967457;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 148 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 148 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 148 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 148 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 148 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 148 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 148 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 148 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 148 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=15
#line 148 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(15)) {
#line 148 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 148 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=16
#line 148 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(16);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 148 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 148 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 148 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=16
#line 148 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(16);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 148 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 148 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 148 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 148 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 148 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 148 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 148 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 148 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential16_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential16_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential16_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential16_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~19")
static uint64_t
sequential16(void* context, const program_runtime_context_t* runtime_context)
#line 149 "sample/undocked/tail_call_sequential.c"
{
#line 149 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 149 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 149 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 149 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 149 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 149 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 149 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 149 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 149 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 149 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 149 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 149 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 149 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 149 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 149 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 149 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 149 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 149 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 149 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 149 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 149 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 149 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 149 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 149 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 149 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 149 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 149 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 149 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 149 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 149 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=909208673
#line 149 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479886744673;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 149 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 149 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 149 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 149 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 149 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 149 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 149 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 149 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 149 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=16
#line 149 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(16)) {
#line 149 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 149 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=17
#line 149 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(17);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 149 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 149 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 149 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=17
#line 149 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(17);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 149 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 149 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 149 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 149 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 149 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 149 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 149 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 149 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential17_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential17_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential17_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential17_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~18")
static uint64_t
sequential17(void* context, const program_runtime_context_t* runtime_context)
#line 150 "sample/undocked/tail_call_sequential.c"
{
#line 150 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 150 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 150 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 150 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 150 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 150 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 150 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 150 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 150 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 150 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 150 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 150 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 150 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 150 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 150 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 150 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 150 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 150 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 150 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 150 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 150 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 150 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 150 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 150 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 150 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 150 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 150 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 150 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 150 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 150 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=925985889
#line 150 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479903521889;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 150 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 150 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 150 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 150 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 150 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 150 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 150 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 150 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 150 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=17
#line 150 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(17)) {
#line 150 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 150 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=18
#line 150 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(18);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 150 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 150 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 150 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=18
#line 150 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(18);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 150 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 150 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 150 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 150 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 150 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 150 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 150 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 150 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential18_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential18_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential18_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential18_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~17")
static uint64_t
sequential18(void* context, const program_runtime_context_t* runtime_context)
#line 151 "sample/undocked/tail_call_sequential.c"
{
#line 151 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 151 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 151 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 151 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 151 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 151 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 151 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 151 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 151 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 151 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 151 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 151 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 151 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 151 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 151 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 151 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 151 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 151 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 151 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 151 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 151 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 151 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 151 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 151 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 151 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 151 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 151 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 151 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 151 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=942763105
#line 151 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479920299105;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 151 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 151 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 151 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 151 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 151 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 151 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 151 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 151 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 151 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=18
#line 151 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(18)) {
#line 151 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 151 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=19
#line 151 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(19);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 151 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 151 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 151 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=19
#line 151 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(19);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 151 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 151 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 151 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 151 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 151 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 151 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 151 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 151 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential19_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential19_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential19_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential19_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~16")
static uint64_t
sequential19(void* context, const program_runtime_context_t* runtime_context)
#line 152 "sample/undocked/tail_call_sequential.c"
{
#line 152 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 152 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 152 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 152 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 152 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 152 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 152 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 152 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 152 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 152 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 152 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 152 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 152 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 152 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 152 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 152 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 152 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 152 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 152 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 152 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 152 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 152 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 152 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 152 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 152 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 152 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 152 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 152 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 152 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 152 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=959540321
#line 152 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479937076321;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 152 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 152 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 152 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 152 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 152 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 152 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 152 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 152 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 152 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=19
#line 152 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(19)) {
#line 152 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 152 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=20
#line 152 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(20);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 152 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 152 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 152 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=20
#line 152 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(20);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 152 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 152 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 152 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 152 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 152 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 152 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 152 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 152 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential2_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential2_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential2_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential2_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~33")
static uint64_t
sequential2(void* context, const program_runtime_context_t* runtime_context)
#line 135 "sample/undocked/tail_call_sequential.c"
{
#line 135 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 135 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 135 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 135 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 135 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 135 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 135 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 135 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 135 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 135 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 135 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 135 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 135 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 135 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 135 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 135 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 135 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 135 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 135 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 135 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 135 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 135 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 135 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 135 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 135 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 135 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 135 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 135 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976383073
#line 135 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834570337;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 135 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 135 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 135 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 135 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 135 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 135 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 135 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 135 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 135 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=2
#line 135 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(2)) {
#line 135 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 135 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=3
#line 135 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 135 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 135 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r1 offset=0 imm=1
#line 135 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=3
#line 135 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(3);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 135 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 135 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 135 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 135 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 135 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 135 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 135 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 135 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential20_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential20_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential20_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential20_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~15")
static uint64_t
sequential20(void* context, const program_runtime_context_t* runtime_context)
#line 153 "sample/undocked/tail_call_sequential.c"
{
#line 153 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 153 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 153 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 153 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 153 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 153 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 153 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 153 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 153 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 153 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 153 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 153 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 153 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 153 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 153 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 153 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 153 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 153 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 153 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 153 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 153 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 153 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 153 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 153 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 153 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 153 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 153 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 153 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 153 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 153 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=808610913
#line 153 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479786146913;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 153 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 153 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 153 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 153 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 153 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 153 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 153 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 153 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 153 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=20
#line 153 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(20)) {
#line 153 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 153 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=21
#line 153 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(21);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 153 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 153 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 153 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=21
#line 153 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(21);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 153 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 153 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 153 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 153 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 153 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 153 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 153 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 153 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential21_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential21_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential21_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential21_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~14")
static uint64_t
sequential21(void* context, const program_runtime_context_t* runtime_context)
#line 154 "sample/undocked/tail_call_sequential.c"
{
#line 154 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 154 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 154 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 154 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 154 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 154 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 154 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 154 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 154 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 154 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 154 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 154 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 154 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 154 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 154 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 154 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 154 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 154 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 154 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 154 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 154 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 154 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 154 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 154 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 154 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 154 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 154 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 154 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 154 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 154 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=825388129
#line 154 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479802924129;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 154 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 154 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 154 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 154 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 154 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 154 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 154 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 154 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 154 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=21
#line 154 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(21)) {
#line 154 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 154 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=22
#line 154 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(22);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 154 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 154 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 154 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=22
#line 154 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(22);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 154 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 154 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 154 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 154 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 154 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 154 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 154 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 154 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential22_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential22_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential22_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential22_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~13")
static uint64_t
sequential22(void* context, const program_runtime_context_t* runtime_context)
#line 155 "sample/undocked/tail_call_sequential.c"
{
#line 155 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 155 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 155 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 155 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 155 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 155 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 155 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 155 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 155 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 155 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 155 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 155 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 155 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 155 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 155 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 155 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 155 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 155 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 155 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 155 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 155 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 155 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 155 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 155 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 155 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 155 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 155 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 155 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 155 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 155 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=842165345
#line 155 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479819701345;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 155 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 155 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 155 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 155 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 155 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 155 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 155 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 155 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 155 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=22
#line 155 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(22)) {
#line 155 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 155 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=23
#line 155 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(23);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 155 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 155 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 155 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=23
#line 155 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(23);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 155 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 155 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 155 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 155 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 155 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 155 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 155 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 155 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential23_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential23_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential23_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential23_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~12")
static uint64_t
sequential23(void* context, const program_runtime_context_t* runtime_context)
#line 156 "sample/undocked/tail_call_sequential.c"
{
#line 156 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 156 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 156 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 156 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 156 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 156 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 156 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 156 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 156 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 156 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 156 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 156 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 156 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 156 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 156 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 156 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 156 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 156 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 156 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 156 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 156 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 156 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 156 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 156 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 156 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 156 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 156 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 156 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 156 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 156 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=858942561
#line 156 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479836478561;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 156 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 156 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 156 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 156 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 156 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 156 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 156 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 156 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 156 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=23
#line 156 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(23)) {
#line 156 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 156 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=24
#line 156 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(24);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 156 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 156 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 156 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=24
#line 156 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 156 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 156 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 156 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 156 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 156 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 156 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 156 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 156 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential24_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential24_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential24_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential24_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~11")
static uint64_t
sequential24(void* context, const program_runtime_context_t* runtime_context)
#line 157 "sample/undocked/tail_call_sequential.c"
{
#line 157 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 157 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 157 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 157 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 157 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 157 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 157 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 157 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 157 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 157 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 157 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 157 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 157 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 157 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 157 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 157 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 157 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 157 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 157 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 157 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 157 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 157 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 157 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 157 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 157 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 157 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 157 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 157 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 157 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 157 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=875719777
#line 157 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479853255777;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 157 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 157 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 157 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 157 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 157 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 157 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r9 src=r0 offset=0 imm=25
#line 157 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(25);
    // EBPF_OP_MOV64_IMM pc=25 dst=r2 src=r0 offset=0 imm=25
#line 157 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=26 dst=r0 src=r0 offset=0 imm=13
#line 157 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=27 dst=r1 src=r8 offset=0 imm=0
#line 157 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=28 dst=r1 src=r0 offset=7 imm=24
#line 157 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(24)) {
#line 157 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 157 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXW pc=29 dst=r8 src=r9 offset=0 imm=0
#line 157 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r9, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 157 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 157 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=25
#line 157 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 157 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 157 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 157 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 157 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 157 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 157 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 157 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 157 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential25_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential25_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential25_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential25_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~10")
static uint64_t
sequential25(void* context, const program_runtime_context_t* runtime_context)
#line 158 "sample/undocked/tail_call_sequential.c"
{
#line 158 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 158 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 158 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 158 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 158 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 158 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 158 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 158 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 158 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 158 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 158 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 158 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 158 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 158 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 158 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 158 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 158 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 158 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 158 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 158 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 158 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 158 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 158 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 158 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 158 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 158 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 158 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 158 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 158 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 158 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=892496993
#line 158 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479870032993;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 158 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 158 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 158 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 158 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 158 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 158 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 158 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 158 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 158 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=25
#line 158 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(25)) {
#line 158 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 158 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=26
#line 158 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(26);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 158 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 158 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 158 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=26
#line 158 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(26);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 158 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 158 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 158 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 158 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 158 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 158 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 158 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 158 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential26_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential26_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential26_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential26_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sample~9")
static uint64_t
sequential26(void* context, const program_runtime_context_t* runtime_context)
#line 159 "sample/undocked/tail_call_sequential.c"
{
#line 159 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 159 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 159 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 159 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 159 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 159 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 159 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 159 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 159 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 159 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 159 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 159 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 159 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 159 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 159 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 159 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 159 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 159 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 159 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 159 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 159 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 159 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 159 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 159 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 159 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 159 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 159 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 159 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 159 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 159 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=909274209
#line 159 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479886810209;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 159 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 159 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 159 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 159 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 159 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 159 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 159 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 159 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 159 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=26
#line 159 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(26)) {
#line 159 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 159 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=27
#line 159 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(27);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 159 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 159 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 159 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=27
#line 159 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(27);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 159 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 159 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 159 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 159 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 159 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 159 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 159 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 159 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential27_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential27_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential27_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential27_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sample~8")
static uint64_t
sequential27(void* context, const program_runtime_context_t* runtime_context)
#line 160 "sample/undocked/tail_call_sequential.c"
{
#line 160 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 160 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 160 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 160 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 160 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 160 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 160 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 160 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 160 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 160 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 160 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 160 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 160 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 160 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 160 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 160 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 160 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 160 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 160 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 160 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 160 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 160 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 160 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 160 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 160 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 160 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 160 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 160 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 160 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 160 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=926051425
#line 160 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479903587425;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 160 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 160 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 160 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 160 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 160 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 160 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 160 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 160 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 160 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=27
#line 160 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(27)) {
#line 160 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 160 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=28
#line 160 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(28);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 160 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 160 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 160 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=28
#line 160 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(28);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 160 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 160 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 160 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 160 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 160 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 160 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 160 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 160 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential28_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential28_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential28_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential28_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sample~7")
static uint64_t
sequential28(void* context, const program_runtime_context_t* runtime_context)
#line 161 "sample/undocked/tail_call_sequential.c"
{
#line 161 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 161 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 161 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 161 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 161 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 161 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 161 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 161 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 161 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 161 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 161 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 161 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 161 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 161 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 161 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 161 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 161 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 161 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 161 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 161 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 161 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 161 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 161 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 161 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 161 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 161 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 161 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 161 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 161 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 161 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=942828641
#line 161 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479920364641;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 161 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 161 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 161 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 161 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 161 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 161 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 161 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 161 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 161 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=28
#line 161 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(28)) {
#line 161 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 161 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=29
#line 161 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(29);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 161 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 161 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 161 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=29
#line 161 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(29);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 161 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 161 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 161 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 161 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 161 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 161 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 161 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 161 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential29_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential29_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential29_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential29_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sample~6")
static uint64_t
sequential29(void* context, const program_runtime_context_t* runtime_context)
#line 162 "sample/undocked/tail_call_sequential.c"
{
#line 162 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 162 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 162 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 162 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 162 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 162 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 162 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 162 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 162 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 162 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 162 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 162 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 162 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 162 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 162 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 162 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 162 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 162 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 162 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 162 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 162 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 162 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 162 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 162 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 162 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 162 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 162 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 162 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 162 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 162 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=959605857
#line 162 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479937141857;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 162 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 162 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 162 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 162 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 162 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 162 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 162 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 162 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 162 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=29
#line 162 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(29)) {
#line 162 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 162 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=30
#line 162 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(30);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 162 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 162 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 162 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=30
#line 162 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(30);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 162 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 162 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 162 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 162 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 162 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 162 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 162 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 162 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential3_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential3_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential3_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential3_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~32")
static uint64_t
sequential3(void* context, const program_runtime_context_t* runtime_context)
#line 136 "sample/undocked/tail_call_sequential.c"
{
#line 136 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 136 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 136 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 136 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 136 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 136 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 136 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 136 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 136 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 136 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 136 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 136 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 136 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 136 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 136 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 136 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 136 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 136 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 136 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 136 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 136 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 136 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 136 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 136 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 136 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 136 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 136 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 136 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976448609
#line 136 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834635873;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 136 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 136 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 136 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 136 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 136 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 136 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 136 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 136 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 136 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=3
#line 136 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(3)) {
#line 136 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 136 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=4
#line 136 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 136 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 136 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r1 offset=0 imm=1
#line 136 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=4
#line 136 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 136 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 136 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 136 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 136 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 136 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 136 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 136 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 136 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential30_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential30_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential30_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential30_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sample~5")
static uint64_t
sequential30(void* context, const program_runtime_context_t* runtime_context)
#line 163 "sample/undocked/tail_call_sequential.c"
{
#line 163 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 163 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 163 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 163 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 163 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 163 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 163 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 163 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 163 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 163 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 163 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 163 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 163 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 163 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 163 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 163 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 163 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 163 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 163 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 163 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 163 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 163 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 163 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 163 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 163 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 163 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 163 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 163 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 163 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 163 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=808676449
#line 163 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479786212449;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 163 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 163 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 163 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 163 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 163 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 163 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 163 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 163 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 163 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=30
#line 163 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(30)) {
#line 163 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 163 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=31
#line 163 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(31);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 163 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 163 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 163 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=31
#line 163 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(31);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 163 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 163 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 163 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 163 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 163 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 163 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 163 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 163 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential31_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential31_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential31_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential31_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sample~4")
static uint64_t
sequential31(void* context, const program_runtime_context_t* runtime_context)
#line 164 "sample/undocked/tail_call_sequential.c"
{
#line 164 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 164 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 164 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 164 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 164 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 164 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 164 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 164 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 164 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 164 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 164 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 164 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 164 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 164 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 164 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 164 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 164 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 164 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 164 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 164 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 164 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 164 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 164 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 164 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 164 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 164 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 164 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 164 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 164 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 164 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=825453665
#line 164 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479802989665;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 164 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 164 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 164 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 164 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 164 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 164 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 164 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 164 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 164 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=31
#line 164 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(31)) {
#line 164 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 164 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=32
#line 164 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(32);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 164 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 164 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 164 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=32
#line 164 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 164 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 164 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 164 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 164 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 164 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 164 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 164 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 164 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential32_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential32_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential32_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential32_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sample~3")
static uint64_t
sequential32(void* context, const program_runtime_context_t* runtime_context)
#line 165 "sample/undocked/tail_call_sequential.c"
{
#line 165 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 165 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 165 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 165 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 165 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 165 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 165 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 165 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 165 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 165 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 165 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 165 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 165 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 165 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 165 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 165 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 165 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 165 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 165 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 165 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 165 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 165 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 165 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 165 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 165 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 165 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 165 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 165 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 165 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 165 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=842230881
#line 165 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479819766881;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 165 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 165 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 165 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 165 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 165 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 165 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 165 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 165 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 165 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=32
#line 165 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(32)) {
#line 165 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 165 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=33
#line 165 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(33);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 165 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 165 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 165 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=33
#line 165 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(33);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 165 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 165 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 165 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 165 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 165 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 165 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 165 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 165 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential33_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential33_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential33_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential33_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sample~2")
static uint64_t
sequential33(void* context, const program_runtime_context_t* runtime_context)
#line 166 "sample/undocked/tail_call_sequential.c"
{
#line 166 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 166 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 166 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 166 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 166 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 166 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 166 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 166 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 166 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 166 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 166 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 166 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 166 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 166 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 166 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 166 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 166 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 166 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 166 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 166 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 166 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 166 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 166 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 166 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 166 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 166 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 166 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 166 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 166 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 166 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=859008097
#line 166 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479836544097;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 166 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 166 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 166 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 166 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 166 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 166 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 166 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 166 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 166 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=33
#line 166 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(33)) {
#line 166 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 166 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=34
#line 166 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(34);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 166 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 166 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 166 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=34
#line 166 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(34);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 166 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 166 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 166 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 166 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 166 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 166 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 166 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 166 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential34_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential34_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential34_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential34_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sample~1")
static uint64_t
sequential34(void* context, const program_runtime_context_t* runtime_context)
#line 167 "sample/undocked/tail_call_sequential.c"
{
#line 167 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 167 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 167 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 167 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 167 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 167 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 167 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 167 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 167 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 167 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 167 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 167 "sample/undocked/tail_call_sequential.c"
    register uint64_t r9 = 0;
#line 167 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 167 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 167 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 167 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 167 "sample/undocked/tail_call_sequential.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-4 imm=0
#line 167 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 167 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 167 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 167 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 167 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 167 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 167 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=25 imm=0
#line 167 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 167 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 167 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_STXB pc=11 dst=r10 src=r9 offset=-8 imm=0
#line 167 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_8(r10, (uint8_t)r9, OFFSET(-8));
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1702194273
#line 167 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)748764383675772001;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 167 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=875785313
#line 167 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)8514653479853321313;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 167 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=1970365811
#line 167 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-32 imm=0
#line 167 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=21 dst=r3 src=r8 offset=0 imm=0
#line 167 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=22 dst=r1 src=r10 offset=0 imm=0
#line 167 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r1 src=r0 offset=0 imm=-32
#line 167 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=24 dst=r2 src=r0 offset=0 imm=25
#line 167 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(25);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=13
#line 167 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r1 src=r8 offset=0 imm=0
#line 167 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=8 imm=34
#line 167 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(34)) {
#line 167 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 167 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=35
#line 167 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(35);
    // EBPF_OP_STXW pc=29 dst=r8 src=r1 offset=0 imm=0
#line 167 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 167 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=31 dst=r2 src=r1 offset=0 imm=1
#line 167 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r3 src=r0 offset=0 imm=35
#line 167 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(35);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=5
#line 167 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 167 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 167 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 167 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r7 src=r0 offset=0 imm=0
#line 167 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=36 dst=r0 src=r7 offset=0 imm=0
#line 167 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 167 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 167 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential4_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential4_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential4_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~31")
static uint64_t
sequential4(void* context, const program_runtime_context_t* runtime_context)
#line 137 "sample/undocked/tail_call_sequential.c"
{
#line 137 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 137 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 137 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 137 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 137 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 137 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 137 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 137 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 137 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 137 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 137 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 137 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 137 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 137 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 137 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 137 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 137 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 137 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 137 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 137 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 137 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 137 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 137 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 137 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 137 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 137 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 137 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 137 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976514145
#line 137 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834701409;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 137 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 137 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 137 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 137 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 137 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 137 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 137 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 137 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 137 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=4
#line 137 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(4)) {
#line 137 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 137 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=5
#line 137 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 137 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 137 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r1 offset=0 imm=1
#line 137 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=5
#line 137 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(5);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 137 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 137 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 137 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 137 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 137 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 137 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 137 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 137 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential5_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential5_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential5_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential5_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~30")
static uint64_t
sequential5(void* context, const program_runtime_context_t* runtime_context)
#line 138 "sample/undocked/tail_call_sequential.c"
{
#line 138 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 138 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 138 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 138 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 138 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 138 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 138 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 138 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 138 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 138 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 138 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 138 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 138 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 138 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 138 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 138 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 138 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 138 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 138 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 138 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 138 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 138 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 138 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 138 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 138 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 138 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 138 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 138 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976579681
#line 138 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834766945;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 138 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 138 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 138 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 138 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 138 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 138 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 138 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 138 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 138 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=5
#line 138 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(5)) {
#line 138 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 138 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=6
#line 138 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 138 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 138 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r1 offset=0 imm=1
#line 138 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=6
#line 138 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(6);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 138 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 138 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 138 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 138 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 138 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 138 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 138 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 138 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential6_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential6_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential6_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential6_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~29")
static uint64_t
sequential6(void* context, const program_runtime_context_t* runtime_context)
#line 139 "sample/undocked/tail_call_sequential.c"
{
#line 139 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 139 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 139 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 139 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 139 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 139 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 139 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 139 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 139 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 139 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 139 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 139 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 139 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 139 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 139 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 139 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 139 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 139 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 139 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 139 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 139 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 139 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 139 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 139 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 139 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 139 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 139 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 139 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976645217
#line 139 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834832481;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 139 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 139 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 139 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 139 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 139 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 139 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 139 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 139 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 139 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=6
#line 139 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(6)) {
#line 139 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 139 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=7
#line 139 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 139 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 139 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r1 offset=0 imm=1
#line 139 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=7
#line 139 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(7);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 139 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 139 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 139 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 139 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 139 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 139 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 139 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 139 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential7_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential7_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential7_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential7_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~28")
static uint64_t
sequential7(void* context, const program_runtime_context_t* runtime_context)
#line 140 "sample/undocked/tail_call_sequential.c"
{
#line 140 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 140 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 140 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 140 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 140 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 140 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 140 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 140 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 140 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 140 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 140 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 140 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 140 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 140 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 140 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 140 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 140 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 140 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 140 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 140 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 140 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 140 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 140 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 140 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 140 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 140 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 140 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 140 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976710753
#line 140 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834898017;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 140 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 140 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 140 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 140 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 140 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 140 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 140 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 140 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 140 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=7
#line 140 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(7)) {
#line 140 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 140 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=8
#line 140 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 140 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 140 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r1 offset=0 imm=1
#line 140 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=8
#line 140 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(8);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 140 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 140 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 140 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 140 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 140 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 140 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 140 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 140 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential8_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential8_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential8_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential8_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~27")
static uint64_t
sequential8(void* context, const program_runtime_context_t* runtime_context)
#line 141 "sample/undocked/tail_call_sequential.c"
{
#line 141 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 141 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 141 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 141 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 141 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 141 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 141 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 141 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 141 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 141 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 141 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 141 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 141 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 141 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 141 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 141 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 141 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 141 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 141 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 141 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 141 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 141 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 141 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 141 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 141 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 141 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 141 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976776289
#line 141 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7022846986834963553;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 141 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 141 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 141 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 141 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 141 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 141 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 141 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 141 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 141 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=8
#line 141 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(8)) {
#line 141 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 141 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=9
#line 141 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 141 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 141 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r1 offset=0 imm=1
#line 141 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=9
#line 141 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(9);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 141 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 141 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 141 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 141 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 141 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 141 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 141 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 141 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sequential9_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
};

static GUID sequential9_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sequential9_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sequential9_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sampl~26")
static uint64_t
sequential9(void* context, const program_runtime_context_t* runtime_context)
#line 142 "sample/undocked/tail_call_sequential.c"
{
#line 142 "sample/undocked/tail_call_sequential.c"
    // Prologue.
#line 142 "sample/undocked/tail_call_sequential.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 142 "sample/undocked/tail_call_sequential.c"
    register uint64_t r0 = 0;
#line 142 "sample/undocked/tail_call_sequential.c"
    register uint64_t r1 = 0;
#line 142 "sample/undocked/tail_call_sequential.c"
    register uint64_t r2 = 0;
#line 142 "sample/undocked/tail_call_sequential.c"
    register uint64_t r3 = 0;
#line 142 "sample/undocked/tail_call_sequential.c"
    register uint64_t r4 = 0;
#line 142 "sample/undocked/tail_call_sequential.c"
    register uint64_t r5 = 0;
#line 142 "sample/undocked/tail_call_sequential.c"
    register uint64_t r6 = 0;
#line 142 "sample/undocked/tail_call_sequential.c"
    register uint64_t r7 = 0;
#line 142 "sample/undocked/tail_call_sequential.c"
    register uint64_t r8 = 0;
#line 142 "sample/undocked/tail_call_sequential.c"
    register uint64_t r10 = 0;

#line 142 "sample/undocked/tail_call_sequential.c"
    r1 = (uintptr_t)context;
#line 142 "sample/undocked/tail_call_sequential.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 142 "sample/undocked/tail_call_sequential.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 142 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 142 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 142 "sample/undocked/tail_call_sequential.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 142 "sample/undocked/tail_call_sequential.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 142 "sample/undocked/tail_call_sequential.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 142 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=8 dst=r8 src=r0 offset=0 imm=0
#line 142 "sample/undocked/tail_call_sequential.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=9 dst=r7 src=r0 offset=0 imm=1
#line 142 "sample/undocked/tail_call_sequential.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=10 dst=r8 src=r0 offset=24 imm=0
#line 142 "sample/undocked/tail_call_sequential.c"
    if (r8 == IMMEDIATE(0)) {
#line 142 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 142 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1030059372
#line 142 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)2924860873733484;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 142 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=976841825
#line 142 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7022846986835029089;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 142 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1970365811
#line 142 "sample/undocked/tail_call_sequential.c"
    r1 = (uint64_t)7598819853321987443;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-32 imm=0
#line 142 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
    // EBPF_OP_LDXW pc=20 dst=r3 src=r8 offset=0 imm=0
#line 142 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 142 "sample/undocked/tail_call_sequential.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-32
#line 142 "sample/undocked/tail_call_sequential.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=24
#line 142 "sample/undocked/tail_call_sequential.c"
    r2 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=13
#line 142 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=25 dst=r1 src=r8 offset=0 imm=0
#line 142 "sample/undocked/tail_call_sequential.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=26 dst=r1 src=r0 offset=8 imm=9
#line 142 "sample/undocked/tail_call_sequential.c"
    if (r1 != IMMEDIATE(9)) {
#line 142 "sample/undocked/tail_call_sequential.c"
        goto label_1;
#line 142 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=10
#line 142 "sample/undocked/tail_call_sequential.c"
    r1 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=28 dst=r8 src=r1 offset=0 imm=0
#line 142 "sample/undocked/tail_call_sequential.c"
    WRITE_ONCE_32(r8, (uint32_t)r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r6 offset=0 imm=0
#line 142 "sample/undocked/tail_call_sequential.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=30 dst=r2 src=r1 offset=0 imm=1
#line 142 "sample/undocked/tail_call_sequential.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=10
#line 142 "sample/undocked/tail_call_sequential.c"
    r3 = IMMEDIATE(10);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=5
#line 142 "sample/undocked/tail_call_sequential.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 142 "sample/undocked/tail_call_sequential.c"
    if (r0 == 0) {
#line 142 "sample/undocked/tail_call_sequential.c"
        return 0;
#line 142 "sample/undocked/tail_call_sequential.c"
    }
    // EBPF_OP_MOV64_REG pc=34 dst=r7 src=r0 offset=0 imm=0
#line 142 "sample/undocked/tail_call_sequential.c"
    r7 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=35 dst=r0 src=r7 offset=0 imm=0
#line 142 "sample/undocked/tail_call_sequential.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 142 "sample/undocked/tail_call_sequential.c"
    return r0;
#line 142 "sample/undocked/tail_call_sequential.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential0,
        .pe_section_name = "sampl~35",
        .section_name = "sample_ext0",
        .program_name = "sequential0",
        .referenced_map_indices = sequential0_maps,
        .referenced_map_count = 2,
        .helpers = sequential0_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 37,
        .program_type = &sequential0_program_type_guid,
        .expected_attach_type = &sequential0_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential1,
        .pe_section_name = "sampl~34",
        .section_name = "sample_ext1",
        .program_name = "sequential1",
        .referenced_map_indices = sequential1_maps,
        .referenced_map_count = 2,
        .helpers = sequential1_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 37,
        .program_type = &sequential1_program_type_guid,
        .expected_attach_type = &sequential1_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential10,
        .pe_section_name = "sampl~25",
        .section_name = "sample_ext10",
        .program_name = "sequential10",
        .referenced_map_indices = sequential10_maps,
        .referenced_map_count = 2,
        .helpers = sequential10_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential10_program_type_guid,
        .expected_attach_type = &sequential10_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential11,
        .pe_section_name = "sampl~24",
        .section_name = "sample_ext11",
        .program_name = "sequential11",
        .referenced_map_indices = sequential11_maps,
        .referenced_map_count = 2,
        .helpers = sequential11_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential11_program_type_guid,
        .expected_attach_type = &sequential11_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential12,
        .pe_section_name = "sampl~23",
        .section_name = "sample_ext12",
        .program_name = "sequential12",
        .referenced_map_indices = sequential12_maps,
        .referenced_map_count = 2,
        .helpers = sequential12_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential12_program_type_guid,
        .expected_attach_type = &sequential12_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential13,
        .pe_section_name = "sampl~22",
        .section_name = "sample_ext13",
        .program_name = "sequential13",
        .referenced_map_indices = sequential13_maps,
        .referenced_map_count = 2,
        .helpers = sequential13_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential13_program_type_guid,
        .expected_attach_type = &sequential13_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential14,
        .pe_section_name = "sampl~21",
        .section_name = "sample_ext14",
        .program_name = "sequential14",
        .referenced_map_indices = sequential14_maps,
        .referenced_map_count = 2,
        .helpers = sequential14_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential14_program_type_guid,
        .expected_attach_type = &sequential14_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential15,
        .pe_section_name = "sampl~20",
        .section_name = "sample_ext15",
        .program_name = "sequential15",
        .referenced_map_indices = sequential15_maps,
        .referenced_map_count = 2,
        .helpers = sequential15_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential15_program_type_guid,
        .expected_attach_type = &sequential15_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential16,
        .pe_section_name = "sampl~19",
        .section_name = "sample_ext16",
        .program_name = "sequential16",
        .referenced_map_indices = sequential16_maps,
        .referenced_map_count = 2,
        .helpers = sequential16_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential16_program_type_guid,
        .expected_attach_type = &sequential16_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential17,
        .pe_section_name = "sampl~18",
        .section_name = "sample_ext17",
        .program_name = "sequential17",
        .referenced_map_indices = sequential17_maps,
        .referenced_map_count = 2,
        .helpers = sequential17_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential17_program_type_guid,
        .expected_attach_type = &sequential17_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential18,
        .pe_section_name = "sampl~17",
        .section_name = "sample_ext18",
        .program_name = "sequential18",
        .referenced_map_indices = sequential18_maps,
        .referenced_map_count = 2,
        .helpers = sequential18_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential18_program_type_guid,
        .expected_attach_type = &sequential18_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential19,
        .pe_section_name = "sampl~16",
        .section_name = "sample_ext19",
        .program_name = "sequential19",
        .referenced_map_indices = sequential19_maps,
        .referenced_map_count = 2,
        .helpers = sequential19_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential19_program_type_guid,
        .expected_attach_type = &sequential19_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential2,
        .pe_section_name = "sampl~33",
        .section_name = "sample_ext2",
        .program_name = "sequential2",
        .referenced_map_indices = sequential2_maps,
        .referenced_map_count = 2,
        .helpers = sequential2_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 37,
        .program_type = &sequential2_program_type_guid,
        .expected_attach_type = &sequential2_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential20,
        .pe_section_name = "sampl~15",
        .section_name = "sample_ext20",
        .program_name = "sequential20",
        .referenced_map_indices = sequential20_maps,
        .referenced_map_count = 2,
        .helpers = sequential20_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential20_program_type_guid,
        .expected_attach_type = &sequential20_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential21,
        .pe_section_name = "sampl~14",
        .section_name = "sample_ext21",
        .program_name = "sequential21",
        .referenced_map_indices = sequential21_maps,
        .referenced_map_count = 2,
        .helpers = sequential21_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential21_program_type_guid,
        .expected_attach_type = &sequential21_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential22,
        .pe_section_name = "sampl~13",
        .section_name = "sample_ext22",
        .program_name = "sequential22",
        .referenced_map_indices = sequential22_maps,
        .referenced_map_count = 2,
        .helpers = sequential22_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential22_program_type_guid,
        .expected_attach_type = &sequential22_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential23,
        .pe_section_name = "sampl~12",
        .section_name = "sample_ext23",
        .program_name = "sequential23",
        .referenced_map_indices = sequential23_maps,
        .referenced_map_count = 2,
        .helpers = sequential23_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential23_program_type_guid,
        .expected_attach_type = &sequential23_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential24,
        .pe_section_name = "sampl~11",
        .section_name = "sample_ext24",
        .program_name = "sequential24",
        .referenced_map_indices = sequential24_maps,
        .referenced_map_count = 2,
        .helpers = sequential24_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential24_program_type_guid,
        .expected_attach_type = &sequential24_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential25,
        .pe_section_name = "sampl~10",
        .section_name = "sample_ext25",
        .program_name = "sequential25",
        .referenced_map_indices = sequential25_maps,
        .referenced_map_count = 2,
        .helpers = sequential25_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential25_program_type_guid,
        .expected_attach_type = &sequential25_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential26,
        .pe_section_name = "sample~9",
        .section_name = "sample_ext26",
        .program_name = "sequential26",
        .referenced_map_indices = sequential26_maps,
        .referenced_map_count = 2,
        .helpers = sequential26_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential26_program_type_guid,
        .expected_attach_type = &sequential26_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential27,
        .pe_section_name = "sample~8",
        .section_name = "sample_ext27",
        .program_name = "sequential27",
        .referenced_map_indices = sequential27_maps,
        .referenced_map_count = 2,
        .helpers = sequential27_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential27_program_type_guid,
        .expected_attach_type = &sequential27_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential28,
        .pe_section_name = "sample~7",
        .section_name = "sample_ext28",
        .program_name = "sequential28",
        .referenced_map_indices = sequential28_maps,
        .referenced_map_count = 2,
        .helpers = sequential28_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential28_program_type_guid,
        .expected_attach_type = &sequential28_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential29,
        .pe_section_name = "sample~6",
        .section_name = "sample_ext29",
        .program_name = "sequential29",
        .referenced_map_indices = sequential29_maps,
        .referenced_map_count = 2,
        .helpers = sequential29_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential29_program_type_guid,
        .expected_attach_type = &sequential29_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential3,
        .pe_section_name = "sampl~32",
        .section_name = "sample_ext3",
        .program_name = "sequential3",
        .referenced_map_indices = sequential3_maps,
        .referenced_map_count = 2,
        .helpers = sequential3_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 37,
        .program_type = &sequential3_program_type_guid,
        .expected_attach_type = &sequential3_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential30,
        .pe_section_name = "sample~5",
        .section_name = "sample_ext30",
        .program_name = "sequential30",
        .referenced_map_indices = sequential30_maps,
        .referenced_map_count = 2,
        .helpers = sequential30_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential30_program_type_guid,
        .expected_attach_type = &sequential30_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential31,
        .pe_section_name = "sample~4",
        .section_name = "sample_ext31",
        .program_name = "sequential31",
        .referenced_map_indices = sequential31_maps,
        .referenced_map_count = 2,
        .helpers = sequential31_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential31_program_type_guid,
        .expected_attach_type = &sequential31_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential32,
        .pe_section_name = "sample~3",
        .section_name = "sample_ext32",
        .program_name = "sequential32",
        .referenced_map_indices = sequential32_maps,
        .referenced_map_count = 2,
        .helpers = sequential32_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential32_program_type_guid,
        .expected_attach_type = &sequential32_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential33,
        .pe_section_name = "sample~2",
        .section_name = "sample_ext33",
        .program_name = "sequential33",
        .referenced_map_indices = sequential33_maps,
        .referenced_map_count = 2,
        .helpers = sequential33_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential33_program_type_guid,
        .expected_attach_type = &sequential33_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential34,
        .pe_section_name = "sample~1",
        .section_name = "sample_ext34",
        .program_name = "sequential34",
        .referenced_map_indices = sequential34_maps,
        .referenced_map_count = 2,
        .helpers = sequential34_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 38,
        .program_type = &sequential34_program_type_guid,
        .expected_attach_type = &sequential34_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential4,
        .pe_section_name = "sampl~31",
        .section_name = "sample_ext4",
        .program_name = "sequential4",
        .referenced_map_indices = sequential4_maps,
        .referenced_map_count = 2,
        .helpers = sequential4_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 37,
        .program_type = &sequential4_program_type_guid,
        .expected_attach_type = &sequential4_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential5,
        .pe_section_name = "sampl~30",
        .section_name = "sample_ext5",
        .program_name = "sequential5",
        .referenced_map_indices = sequential5_maps,
        .referenced_map_count = 2,
        .helpers = sequential5_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 37,
        .program_type = &sequential5_program_type_guid,
        .expected_attach_type = &sequential5_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential6,
        .pe_section_name = "sampl~29",
        .section_name = "sample_ext6",
        .program_name = "sequential6",
        .referenced_map_indices = sequential6_maps,
        .referenced_map_count = 2,
        .helpers = sequential6_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 37,
        .program_type = &sequential6_program_type_guid,
        .expected_attach_type = &sequential6_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential7,
        .pe_section_name = "sampl~28",
        .section_name = "sample_ext7",
        .program_name = "sequential7",
        .referenced_map_indices = sequential7_maps,
        .referenced_map_count = 2,
        .helpers = sequential7_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 37,
        .program_type = &sequential7_program_type_guid,
        .expected_attach_type = &sequential7_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential8,
        .pe_section_name = "sampl~27",
        .section_name = "sample_ext8",
        .program_name = "sequential8",
        .referenced_map_indices = sequential8_maps,
        .referenced_map_count = 2,
        .helpers = sequential8_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 37,
        .program_type = &sequential8_program_type_guid,
        .expected_attach_type = &sequential8_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = sequential9,
        .pe_section_name = "sampl~26",
        .section_name = "sample_ext9",
        .program_name = "sequential9",
        .referenced_map_indices = sequential9_maps,
        .referenced_map_count = 2,
        .helpers = sequential9_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 37,
        .program_type = &sequential9_program_type_guid,
        .expected_attach_type = &sequential9_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 35;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = 1;
    version->minor = 4;
    version->revision = 0;
}

#pragma data_seg(push, "map_initial_values")
// clang-format off
static const char* _map_initial_string_table[] = {
    "sequential0",
    "sequential1",
    "sequential2",
    "sequential3",
    "sequential4",
    "sequential5",
    "sequential6",
    "sequential7",
    "sequential8",
    "sequential9",
    "sequential10",
    "sequential11",
    "sequential12",
    "sequential13",
    "sequential14",
    "sequential15",
    "sequential16",
    "sequential17",
    "sequential18",
    "sequential19",
    "sequential20",
    "sequential21",
    "sequential22",
    "sequential23",
    "sequential24",
    "sequential25",
    "sequential26",
    "sequential27",
    "sequential28",
    "sequential29",
    "sequential30",
    "sequential31",
    "sequential32",
    "sequential33",
    "sequential34",
};
// clang-format on

static map_initial_values_t _map_initial_values_array[] = {
    {
        .header = {1, 48, 48},
        .name = "map",
        .count = 35,
        .values = _map_initial_string_table,
    },
};
#pragma data_seg(pop)

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = _map_initial_values_array;
    *count = 1;
}

metadata_table_t tail_call_sequential_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
