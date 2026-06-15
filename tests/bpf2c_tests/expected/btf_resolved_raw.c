// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from btf_resolved.o

#include "bpf2c.h"

static void
_get_hash(_Outptr_result_buffer_maybenull_(*size) const uint8_t** hash, _Out_ size_t* size)
{
    *hash = NULL;
    *size = 0;
}

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = NULL;
    *count = 0;
}

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static btf_resolved_function_entry_t func_btf_resolved_functions[] = {
    {
     0,
     {2, 84, 88}, // Version header.
     "sample_ebpf_extension_btf_lookup",
     {0x8f6c1f83, 0xce4c, 0x4b58, {0x8b, 0x91, 0x65, 0x4a, 0x29, 0xe2, 0x3b, 0x7c}},
     0,
     {
         1,
         9,
         2,
         0,
         0,
     },
     0,
    },
};

static GUID func_program_type_guid = {0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID func_attach_type_guid = {0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
#pragma code_seg(push, "bind")
static uint64_t
func(void* context, const program_runtime_context_t* runtime_context)
#line 9 "sample/undocked/btf_resolved.c"
{
#line 9 "sample/undocked/btf_resolved.c"
    // Prologue.
#line 9 "sample/undocked/btf_resolved.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 9 "sample/undocked/btf_resolved.c"
    register uint64_t r0 = 0;
#line 9 "sample/undocked/btf_resolved.c"
    register uint64_t r1 = 0;
#line 9 "sample/undocked/btf_resolved.c"
    register uint64_t r2 = 0;
#line 9 "sample/undocked/btf_resolved.c"
    register uint64_t r3 = 0;
#line 9 "sample/undocked/btf_resolved.c"
    register uint64_t r4 = 0;
#line 9 "sample/undocked/btf_resolved.c"
    register uint64_t r5 = 0;
#line 9 "sample/undocked/btf_resolved.c"
    register uint64_t r10 = 0;

#line 9 "sample/undocked/btf_resolved.c"
    r1 = (uintptr_t)context;
#line 9 "sample/undocked/btf_resolved.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r2 src=r0 offset=0 imm=0
#line 9 "sample/undocked/btf_resolved.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=1 dst=r10 src=r2 offset=-8 imm=0
#line 11 "sample/undocked/btf_resolved.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-8));
    // EBPF_OP_LDXDW pc=2 dst=r1 src=r1 offset=16 imm=0
#line 12 "sample/undocked/btf_resolved.c"
    READ_ONCE_64(r1, r1, OFFSET(16));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 12 "sample/undocked/btf_resolved.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-8
#line 12 "sample/undocked/btf_resolved.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=5 dst=r3 src=r0 offset=0 imm=8
#line 12 "sample/undocked/btf_resolved.c"
    r3 = IMMEDIATE(8);
    // EBPF_OP_CALL pc=6 dst=r0 src=r2 offset=0 imm=1
#line 12 "sample/undocked/btf_resolved.c"
    r0 = ((helper_function_t)runtime_context->btf_resolved_function_data[0].address)(r1, r2, r3, r4, r5, context);
    // EBPF_OP_EXIT pc=7 dst=r0 src=r0 offset=0 imm=0
#line 12 "sample/undocked/btf_resolved.c"
    return r0;
#line 9 "sample/undocked/btf_resolved.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = func,
        .pe_section_name = "bind",
        .section_name = "bind",
        .program_name = "func",
        .referenced_map_indices = NULL,
        .referenced_map_count = 0,
        .helpers = NULL,
        .helper_count = 0,
        .bpf_instruction_count = 8,
        .program_type = &func_program_type_guid,
        .expected_attach_type = &func_attach_type_guid,
        .btf_resolved_functions = func_btf_resolved_functions,
        .btf_resolved_function_count = 1,
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
    version->minor = 4;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t btf_resolved_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
