// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from tail_call_recursive.o

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
         3,                       // Maximum number of entries allowed in the map.
         0,                       // Inner map index.
         LIBBPF_PIN_NONE,         // Pinning type for the map.
         20,                      // Identifier for a map template.
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
         26,                 // Identifier for a map template.
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

static helper_function_entry_t recurse_helpers[] = {
    {1, "helper_id_1"},
    {13, "helper_id_13"},
    {5, "helper_id_5"},
};

static GUID recurse_program_type_guid = {0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID recurse_attach_type_guid = {0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t recurse_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sample~1")
static uint64_t
recurse(void* context, const program_runtime_context_t* runtime_context)
#line 45 "sample/undocked/tail_call_recursive.c"
{
#line 45 "sample/undocked/tail_call_recursive.c"
    // Prologue
#line 45 "sample/undocked/tail_call_recursive.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 45 "sample/undocked/tail_call_recursive.c"
    register uint64_t r0 = 0;
#line 45 "sample/undocked/tail_call_recursive.c"
    register uint64_t r1 = 0;
#line 45 "sample/undocked/tail_call_recursive.c"
    register uint64_t r2 = 0;
#line 45 "sample/undocked/tail_call_recursive.c"
    register uint64_t r3 = 0;
#line 45 "sample/undocked/tail_call_recursive.c"
    register uint64_t r4 = 0;
#line 45 "sample/undocked/tail_call_recursive.c"
    register uint64_t r5 = 0;
#line 45 "sample/undocked/tail_call_recursive.c"
    register uint64_t r6 = 0;
#line 45 "sample/undocked/tail_call_recursive.c"
    register uint64_t r7 = 0;
#line 45 "sample/undocked/tail_call_recursive.c"
    register uint64_t r8 = 0;
#line 45 "sample/undocked/tail_call_recursive.c"
    register uint64_t r10 = 0;

#line 45 "sample/undocked/tail_call_recursive.c"
    r1 = (uintptr_t)context;
#line 45 "sample/undocked/tail_call_recursive.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 45 "sample/undocked/tail_call_recursive.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r8 src=r0 offset=0 imm=0
#line 45 "sample/undocked/tail_call_recursive.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r8 offset=-4 imm=0
#line 47 "sample/undocked/tail_call_recursive.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r8;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 47 "sample/undocked/tail_call_recursive.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 47 "sample/undocked/tail_call_recursive.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 51 "sample/undocked/tail_call_recursive.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 51 "sample/undocked/tail_call_recursive.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5);
#line 51 "sample/undocked/tail_call_recursive.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 51 "sample/undocked/tail_call_recursive.c"
        return 0;
#line 51 "sample/undocked/tail_call_recursive.c"
    }
    // EBPF_OP_MOV64_REG pc=8 dst=r7 src=r0 offset=0 imm=0
#line 51 "sample/undocked/tail_call_recursive.c"
    r7 = r0;
    // EBPF_OP_JEQ_IMM pc=9 dst=r7 src=r0 offset=22 imm=0
#line 52 "sample/undocked/tail_call_recursive.c"
    if (r7 == IMMEDIATE(0)) {
#line 52 "sample/undocked/tail_call_recursive.c"
        goto label_1;
#line 52 "sample/undocked/tail_call_recursive.c"
    }
    // EBPF_OP_MOV64_IMM pc=10 dst=r1 src=r0 offset=0 imm=680997
#line 52 "sample/undocked/tail_call_recursive.c"
    r1 = IMMEDIATE(680997);
    // EBPF_OP_STXW pc=11 dst=r10 src=r1 offset=-8 imm=0
#line 56 "sample/undocked/tail_call_recursive.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=1635133984
#line 56 "sample/undocked/tail_call_recursive.c"
    r1 = (uint64_t)4424071317313432096;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 56 "sample/undocked/tail_call_recursive.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=1969448306
#line 56 "sample/undocked/tail_call_recursive.c"
    r1 = (uint64_t)4207896362280510834;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-24 imm=0
#line 56 "sample/undocked/tail_call_recursive.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=18 dst=r3 src=r7 offset=0 imm=0
#line 56 "sample/undocked/tail_call_recursive.c"
    r3 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=19 dst=r1 src=r10 offset=0 imm=0
#line 56 "sample/undocked/tail_call_recursive.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=20 dst=r1 src=r0 offset=0 imm=-24
#line 56 "sample/undocked/tail_call_recursive.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=21 dst=r2 src=r0 offset=0 imm=20
#line 56 "sample/undocked/tail_call_recursive.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_CALL pc=22 dst=r0 src=r0 offset=0 imm=13
#line 56 "sample/undocked/tail_call_recursive.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5);
#line 56 "sample/undocked/tail_call_recursive.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 56 "sample/undocked/tail_call_recursive.c"
        return 0;
#line 56 "sample/undocked/tail_call_recursive.c"
    }
    // EBPF_OP_LDXW pc=23 dst=r1 src=r7 offset=0 imm=0
#line 59 "sample/undocked/tail_call_recursive.c"
    r1 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=24 dst=r1 src=r0 offset=0 imm=1
#line 59 "sample/undocked/tail_call_recursive.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=25 dst=r7 src=r1 offset=0 imm=0
#line 59 "sample/undocked/tail_call_recursive.c"
    *(uint32_t*)(uintptr_t)(r7 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=26 dst=r1 src=r6 offset=0 imm=0
#line 62 "sample/undocked/tail_call_recursive.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=27 dst=r2 src=r0 offset=0 imm=0
#line 62 "sample/undocked/tail_call_recursive.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=29 dst=r3 src=r0 offset=0 imm=1
#line 62 "sample/undocked/tail_call_recursive.c"
    r3 = IMMEDIATE(1);
    // EBPF_OP_CALL pc=30 dst=r0 src=r0 offset=0 imm=5
#line 62 "sample/undocked/tail_call_recursive.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5);
#line 62 "sample/undocked/tail_call_recursive.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 62 "sample/undocked/tail_call_recursive.c"
        return 0;
#line 62 "sample/undocked/tail_call_recursive.c"
    }
    // EBPF_OP_MOV64_REG pc=31 dst=r8 src=r0 offset=0 imm=0
#line 62 "sample/undocked/tail_call_recursive.c"
    r8 = r0;
label_1:
    // EBPF_OP_MOV64_REG pc=32 dst=r0 src=r8 offset=0 imm=0
#line 63 "sample/undocked/tail_call_recursive.c"
    r0 = r8;
    // EBPF_OP_EXIT pc=33 dst=r0 src=r0 offset=0 imm=0
#line 63 "sample/undocked/tail_call_recursive.c"
    return r0;
#line 63 "sample/undocked/tail_call_recursive.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        recurse,
        "sample~1",
        "sample_ext",
        "recurse",
        recurse_maps,
        2,
        recurse_helpers,
        3,
        34,
        &recurse_program_type_guid,
        &recurse_attach_type_guid,
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

#pragma data_seg(push, "map_initial_values")
// clang-format off
static const char* _map_initial_string_table[] = {
    NULL,
    "recurse",
    NULL,
};
// clang-format on

static map_initial_values_t _map_initial_values_array[] = {
    {
        .name = "map",
        .count = 3,
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

metadata_table_t tail_call_recursive_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};
