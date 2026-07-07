// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from bpf2bpf_loop.o

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
         10,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "bpf2bpf_loop_map"},
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

static helper_function_entry_t caller_with_loop_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

// Forward references for local functions.
static uint64_t
increment(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context);

static GUID caller_with_loop_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID caller_with_loop_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t caller_with_loop_maps[] = {
    0,
};

#pragma code_seg(push, "sample~1")
static uint64_t
caller_with_loop(void* context, const program_runtime_context_t* runtime_context)
#line 28 "sample/undocked/bpf2bpf_loop.c"
{
#line 28 "sample/undocked/bpf2bpf_loop.c"
    // Prologue.
#line 28 "sample/undocked/bpf2bpf_loop.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 28 "sample/undocked/bpf2bpf_loop.c"
    register uint64_t r0 = 0;
#line 28 "sample/undocked/bpf2bpf_loop.c"
    register uint64_t r1 = 0;
#line 28 "sample/undocked/bpf2bpf_loop.c"
    register uint64_t r2 = 0;
#line 28 "sample/undocked/bpf2bpf_loop.c"
    register uint64_t r3 = 0;
#line 28 "sample/undocked/bpf2bpf_loop.c"
    register uint64_t r4 = 0;
#line 28 "sample/undocked/bpf2bpf_loop.c"
    register uint64_t r5 = 0;
#line 28 "sample/undocked/bpf2bpf_loop.c"
    register uint64_t r6 = 0;
#line 28 "sample/undocked/bpf2bpf_loop.c"
    register uint64_t r10 = 0;

#line 28 "sample/undocked/bpf2bpf_loop.c"
    r1 = (uintptr_t)context;
#line 28 "sample/undocked/bpf2bpf_loop.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r0 src=r0 offset=0 imm=0
#line 28 "sample/undocked/bpf2bpf_loop.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r0 offset=-4 imm=0
#line 30 "sample/undocked/bpf2bpf_loop.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-4));
    // EBPF_OP_STXW pc=2 dst=r10 src=r0 offset=-12 imm=0
#line 33 "sample/undocked/bpf2bpf_loop.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-12));
    // EBPF_OP_LDXW pc=3 dst=r1 src=r10 offset=-12 imm=0
#line 33 "sample/undocked/bpf2bpf_loop.c"
    READ_ONCE_32(r1, r10, OFFSET(-12));
    // EBPF_OP_LSH64_IMM pc=4 dst=r1 src=r0 offset=0 imm=32
#line 33 "sample/undocked/bpf2bpf_loop.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=5 dst=r1 src=r0 offset=0 imm=32
#line 33 "sample/undocked/bpf2bpf_loop.c"
    r1 = (int64_t)r1 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=6 dst=r1 src=r0 offset=10 imm=9
#line 33 "sample/undocked/bpf2bpf_loop.c"
    if ((int64_t)r1 > IMMEDIATE(9)) {
#line 33 "sample/undocked/bpf2bpf_loop.c"
        goto label_2;
#line 33 "sample/undocked/bpf2bpf_loop.c"
    }
    // EBPF_OP_MOV64_IMM pc=7 dst=r6 src=r0 offset=0 imm=10
#line 33 "sample/undocked/bpf2bpf_loop.c"
    r6 = IMMEDIATE(10);
label_1:
    // EBPF_OP_MOV64_REG pc=8 dst=r1 src=r0 offset=0 imm=0
#line 34 "sample/undocked/bpf2bpf_loop.c"
    r1 = r0;
    // EBPF_OP_CALL pc=9 dst=r0 src=r1 offset=0 imm=18
#line 34 "sample/undocked/bpf2bpf_loop.c"
    r0 = increment(r1, r2, r3, r4, r5, r10, context, runtime_context);
    // EBPF_OP_LDXW pc=10 dst=r1 src=r10 offset=-12 imm=0
#line 33 "sample/undocked/bpf2bpf_loop.c"
    READ_ONCE_32(r1, r10, OFFSET(-12));
    // EBPF_OP_ADD64_IMM pc=11 dst=r1 src=r0 offset=0 imm=1
#line 33 "sample/undocked/bpf2bpf_loop.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=12 dst=r10 src=r1 offset=-12 imm=0
#line 33 "sample/undocked/bpf2bpf_loop.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-12));
    // EBPF_OP_LDXW pc=13 dst=r1 src=r10 offset=-12 imm=0
#line 33 "sample/undocked/bpf2bpf_loop.c"
    READ_ONCE_32(r1, r10, OFFSET(-12));
    // EBPF_OP_LSH64_IMM pc=14 dst=r1 src=r0 offset=0 imm=32
#line 33 "sample/undocked/bpf2bpf_loop.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=15 dst=r1 src=r0 offset=0 imm=32
#line 33 "sample/undocked/bpf2bpf_loop.c"
    r1 = (int64_t)r1 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=16 dst=r6 src=r1 offset=-9 imm=0
#line 33 "sample/undocked/bpf2bpf_loop.c"
    if ((int64_t)r6 > (int64_t)r1) {
#line 33 "sample/undocked/bpf2bpf_loop.c"
        goto label_1;
#line 33 "sample/undocked/bpf2bpf_loop.c"
    }
label_2:
    // EBPF_OP_STXW pc=17 dst=r10 src=r0 offset=-8 imm=0
#line 34 "sample/undocked/bpf2bpf_loop.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=18 dst=r2 src=r10 offset=0 imm=0
#line 34 "sample/undocked/bpf2bpf_loop.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=19 dst=r2 src=r0 offset=0 imm=-4
#line 34 "sample/undocked/bpf2bpf_loop.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=20 dst=r3 src=r10 offset=0 imm=0
#line 34 "sample/undocked/bpf2bpf_loop.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=21 dst=r3 src=r0 offset=0 imm=-8
#line 34 "sample/undocked/bpf2bpf_loop.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=22 dst=r1 src=r1 offset=0 imm=1
#line 37 "sample/undocked/bpf2bpf_loop.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=24 dst=r4 src=r0 offset=0 imm=0
#line 37 "sample/undocked/bpf2bpf_loop.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=2
#line 37 "sample/undocked/bpf2bpf_loop.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDXW pc=26 dst=r0 src=r10 offset=-8 imm=0
#line 38 "sample/undocked/bpf2bpf_loop.c"
    READ_ONCE_32(r0, r10, OFFSET(-8));
    // EBPF_OP_EXIT pc=27 dst=r0 src=r0 offset=0 imm=0
#line 38 "sample/undocked/bpf2bpf_loop.c"
    return r0;
#line 28 "sample/undocked/bpf2bpf_loop.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static uint64_t
increment(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context, const program_runtime_context_t* runtime_context)
{
    register uint64_t r0 = 0;
    (void)r2;
    (void)r3;
    (void)r4;
    (void)r5;
    (void)r10;
    (void)context;
    UNREFERENCED_PARAMETER(runtime_context);

    // EBPF_OP_MOV64_REG pc=0 dst=r0 src=r1 offset=0 imm=0
#line 20 "sample/undocked/bpf2bpf_loop.c"
    r0 = r1;
    // EBPF_OP_ADD64_IMM pc=1 dst=r0 src=r0 offset=0 imm=1
#line 22 "sample/undocked/bpf2bpf_loop.c"
    r0 += IMMEDIATE(1);
    // EBPF_OP_EXIT pc=2 dst=r0 src=r0 offset=0 imm=0
#line 22 "sample/undocked/bpf2bpf_loop.c"
    return r0;
}
#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = caller_with_loop,
        .pe_section_name = "sample~1",
        .section_name = "sample_ext",
        .program_name = "caller_with_loop",
        .referenced_map_indices = caller_with_loop_maps,
        .referenced_map_count = 1,
        .helpers = caller_with_loop_helpers,
        .helper_count = 1,
        .bpf_instruction_count = 28,
        .program_type = &caller_with_loop_program_type_guid,
        .expected_attach_type = &caller_with_loop_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
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
    version->minor = 5;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t bpf2bpf_loop_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
