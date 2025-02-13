// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from test_sample_ebpf.o

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
         32,                 // Size in bytes of a map value.
         2,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         10,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "test_map"},
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
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_t** global_variable_sections, _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static helper_function_entry_t test_program_entry_helpers[] = {
    {1, "helper_id_1"},
    {65537, "helper_id_65537"},
    {65538, "helper_id_65538"},
    {65536, "helper_id_65536"},
};

static GUID test_program_entry_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID test_program_entry_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t test_program_entry_maps[] = {
    0,
};

#pragma code_seg(push, "sample~1")
static uint64_t
test_program_entry(void* context, const program_runtime_context_t* runtime_context)
#line 33 "sample/undocked/test_sample_ebpf.c"
{
#line 33 "sample/undocked/test_sample_ebpf.c"
    // Prologue.
#line 33 "sample/undocked/test_sample_ebpf.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 33 "sample/undocked/test_sample_ebpf.c"
    register uint64_t r0 = 0;
#line 33 "sample/undocked/test_sample_ebpf.c"
    register uint64_t r1 = 0;
#line 33 "sample/undocked/test_sample_ebpf.c"
    register uint64_t r2 = 0;
#line 33 "sample/undocked/test_sample_ebpf.c"
    register uint64_t r3 = 0;
#line 33 "sample/undocked/test_sample_ebpf.c"
    register uint64_t r4 = 0;
#line 33 "sample/undocked/test_sample_ebpf.c"
    register uint64_t r5 = 0;
#line 33 "sample/undocked/test_sample_ebpf.c"
    register uint64_t r6 = 0;
#line 33 "sample/undocked/test_sample_ebpf.c"
    register uint64_t r7 = 0;
#line 33 "sample/undocked/test_sample_ebpf.c"
    register uint64_t r8 = 0;
#line 33 "sample/undocked/test_sample_ebpf.c"
    register uint64_t r10 = 0;

#line 33 "sample/undocked/test_sample_ebpf.c"
    r1 = (uintptr_t)context;
#line 33 "sample/undocked/test_sample_ebpf.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 33 "sample/undocked/test_sample_ebpf.c"
    r6 = r1;
    // EBPF_OP_LDDW pc=1 dst=r1 src=r0 offset=0 imm=0
#line 33 "sample/undocked/test_sample_ebpf.c"
    r1 = (uint64_t)4294967296;
    // EBPF_OP_STXDW pc=3 dst=r10 src=r1 offset=-8 imm=0
#line 36 "sample/undocked/test_sample_ebpf.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=4 dst=r2 src=r10 offset=0 imm=0
#line 36 "sample/undocked/test_sample_ebpf.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=5 dst=r2 src=r0 offset=0 imm=-8
#line 36 "sample/undocked/test_sample_ebpf.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=6 dst=r1 src=r1 offset=0 imm=1
#line 39 "sample/undocked/test_sample_ebpf.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=8 dst=r0 src=r0 offset=0 imm=1
#line 39 "sample/undocked/test_sample_ebpf.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 39 "sample/undocked/test_sample_ebpf.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 39 "sample/undocked/test_sample_ebpf.c"
        return 0;
#line 39 "sample/undocked/test_sample_ebpf.c"
    }
    // EBPF_OP_MOV64_REG pc=9 dst=r8 src=r0 offset=0 imm=0
#line 39 "sample/undocked/test_sample_ebpf.c"
    r8 = r0;
    // EBPF_OP_MOV64_REG pc=10 dst=r2 src=r10 offset=0 imm=0
#line 40 "sample/undocked/test_sample_ebpf.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=11 dst=r2 src=r0 offset=0 imm=-4
#line 40 "sample/undocked/test_sample_ebpf.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=12 dst=r1 src=r1 offset=0 imm=1
#line 40 "sample/undocked/test_sample_ebpf.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=14 dst=r0 src=r0 offset=0 imm=1
#line 40 "sample/undocked/test_sample_ebpf.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 40 "sample/undocked/test_sample_ebpf.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 40 "sample/undocked/test_sample_ebpf.c"
        return 0;
#line 40 "sample/undocked/test_sample_ebpf.c"
    }
    // EBPF_OP_MOV64_REG pc=15 dst=r7 src=r0 offset=0 imm=0
#line 40 "sample/undocked/test_sample_ebpf.c"
    r7 = r0;
    // EBPF_OP_LDXDW pc=16 dst=r1 src=r6 offset=0 imm=0
#line 42 "sample/undocked/test_sample_ebpf.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=17 dst=r2 src=r6 offset=8 imm=0
#line 42 "sample/undocked/test_sample_ebpf.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_JGE_REG pc=18 dst=r1 src=r2 offset=15 imm=0
#line 42 "sample/undocked/test_sample_ebpf.c"
    if (r1 >= r2) {
#line 42 "sample/undocked/test_sample_ebpf.c"
        goto label_1;
#line 42 "sample/undocked/test_sample_ebpf.c"
    }
    // EBPF_OP_JEQ_IMM pc=19 dst=r8 src=r0 offset=14 imm=0
#line 42 "sample/undocked/test_sample_ebpf.c"
    if (r8 == IMMEDIATE(0)) {
#line 42 "sample/undocked/test_sample_ebpf.c"
        goto label_1;
#line 42 "sample/undocked/test_sample_ebpf.c"
    }
    // EBPF_OP_SUB64_REG pc=20 dst=r2 src=r1 offset=0 imm=0
#line 47 "sample/undocked/test_sample_ebpf.c"
    r2 -= r1;
    // EBPF_OP_MOV64_REG pc=21 dst=r3 src=r8 offset=0 imm=0
#line 46 "sample/undocked/test_sample_ebpf.c"
    r3 = r8;
    // EBPF_OP_MOV64_IMM pc=22 dst=r4 src=r0 offset=0 imm=32
#line 46 "sample/undocked/test_sample_ebpf.c"
    r4 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=23 dst=r0 src=r0 offset=0 imm=65537
#line 46 "sample/undocked/test_sample_ebpf.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 46 "sample/undocked/test_sample_ebpf.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 46 "sample/undocked/test_sample_ebpf.c"
        return 0;
#line 46 "sample/undocked/test_sample_ebpf.c"
    }
    // EBPF_OP_JEQ_IMM pc=24 dst=r7 src=r0 offset=9 imm=0
#line 48 "sample/undocked/test_sample_ebpf.c"
    if (r7 == IMMEDIATE(0)) {
#line 48 "sample/undocked/test_sample_ebpf.c"
        goto label_1;
#line 48 "sample/undocked/test_sample_ebpf.c"
    }
    // EBPF_OP_LDXDW pc=25 dst=r1 src=r6 offset=0 imm=0
#line 50 "sample/undocked/test_sample_ebpf.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=26 dst=r2 src=r6 offset=8 imm=0
#line 50 "sample/undocked/test_sample_ebpf.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=27 dst=r2 src=r1 offset=0 imm=0
#line 50 "sample/undocked/test_sample_ebpf.c"
    r2 -= r1;
    // EBPF_OP_MOV64_REG pc=28 dst=r3 src=r0 offset=0 imm=0
#line 49 "sample/undocked/test_sample_ebpf.c"
    r3 = r0;
    // EBPF_OP_MOV64_REG pc=29 dst=r4 src=r7 offset=0 imm=0
#line 49 "sample/undocked/test_sample_ebpf.c"
    r4 = r7;
    // EBPF_OP_MOV64_IMM pc=30 dst=r5 src=r0 offset=0 imm=32
#line 49 "sample/undocked/test_sample_ebpf.c"
    r5 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=31 dst=r0 src=r0 offset=0 imm=65538
#line 49 "sample/undocked/test_sample_ebpf.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 49 "sample/undocked/test_sample_ebpf.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 49 "sample/undocked/test_sample_ebpf.c"
        return 0;
#line 49 "sample/undocked/test_sample_ebpf.c"
    }
    // EBPF_OP_MOV64_IMM pc=32 dst=r1 src=r0 offset=0 imm=0
#line 49 "sample/undocked/test_sample_ebpf.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=33 dst=r1 src=r0 offset=5 imm=0
#line 51 "sample/undocked/test_sample_ebpf.c"
    if ((int64_t)r1 > (int64_t)r0) {
#line 51 "sample/undocked/test_sample_ebpf.c"
        goto label_2;
#line 51 "sample/undocked/test_sample_ebpf.c"
    }
label_1:
    // EBPF_OP_MOV64_REG pc=34 dst=r1 src=r6 offset=0 imm=0
#line 58 "sample/undocked/test_sample_ebpf.c"
    r1 = r6;
    // EBPF_OP_CALL pc=35 dst=r0 src=r0 offset=0 imm=65536
#line 58 "sample/undocked/test_sample_ebpf.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 58 "sample/undocked/test_sample_ebpf.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 58 "sample/undocked/test_sample_ebpf.c"
        return 0;
#line 58 "sample/undocked/test_sample_ebpf.c"
    }
    // EBPF_OP_MOV64_IMM pc=36 dst=r1 src=r0 offset=0 imm=0
#line 58 "sample/undocked/test_sample_ebpf.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=37 dst=r1 src=r0 offset=1 imm=0
#line 59 "sample/undocked/test_sample_ebpf.c"
    if ((int64_t)r1 > (int64_t)r0) {
#line 59 "sample/undocked/test_sample_ebpf.c"
        goto label_2;
#line 59 "sample/undocked/test_sample_ebpf.c"
    }
    // EBPF_OP_MOV64_IMM pc=38 dst=r0 src=r0 offset=0 imm=42
#line 59 "sample/undocked/test_sample_ebpf.c"
    r0 = IMMEDIATE(42);
label_2:
    // EBPF_OP_EXIT pc=39 dst=r0 src=r0 offset=0 imm=0
#line 68 "sample/undocked/test_sample_ebpf.c"
    return r0;
#line 33 "sample/undocked/test_sample_ebpf.c"
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
        1,
        test_program_entry_helpers,
        4,
        40,
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
    version->minor = 21;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t test_sample_ebpf_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
