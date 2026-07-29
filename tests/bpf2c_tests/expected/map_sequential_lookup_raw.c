// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from map_sequential_lookup.o

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
         2,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         8,                  // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "stats_map"},
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

static helper_function_entry_t map_sequential_lookup_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID map_sequential_lookup_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID map_sequential_lookup_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t map_sequential_lookup_maps[] = {
    0,
};

#pragma code_seg(push, "sample~1")
static uint64_t
map_sequential_lookup(void* context, const program_runtime_context_t* runtime_context)
#line 45 "sample/undocked/map_sequential_lookup.c"
{
#line 45 "sample/undocked/map_sequential_lookup.c"
    // Prologue.
#line 45 "sample/undocked/map_sequential_lookup.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 45 "sample/undocked/map_sequential_lookup.c"
    register uint64_t r0 = 0;
#line 45 "sample/undocked/map_sequential_lookup.c"
    register uint64_t r1 = 0;
#line 45 "sample/undocked/map_sequential_lookup.c"
    register uint64_t r2 = 0;
#line 45 "sample/undocked/map_sequential_lookup.c"
    register uint64_t r6 = 0;
#line 45 "sample/undocked/map_sequential_lookup.c"
    register uint64_t r10 = 0;

#line 45 "sample/undocked/map_sequential_lookup.c"
    r1 = (uintptr_t)context;
#line 45 "sample/undocked/map_sequential_lookup.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r1 src=r0 offset=0 imm=0
#line 45 "sample/undocked/map_sequential_lookup.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r1 offset=-4 imm=0
#line 48 "sample/undocked/map_sequential_lookup.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MOV64_IMM pc=2 dst=r1 src=r0 offset=0 imm=1
#line 48 "sample/undocked/map_sequential_lookup.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=3 dst=r10 src=r1 offset=-8 imm=0
#line 49 "sample/undocked/map_sequential_lookup.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=4 dst=r2 src=r10 offset=0 imm=0
#line 49 "sample/undocked/map_sequential_lookup.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=5 dst=r2 src=r0 offset=0 imm=-4
#line 49 "sample/undocked/map_sequential_lookup.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=6 dst=r1 src=r1 offset=0 imm=1
#line 52 "sample/undocked/map_sequential_lookup.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=8 dst=r0 src=r0 offset=0 imm=1
#line 52 "sample/undocked/map_sequential_lookup.c"
    {
#line 52 "sample/undocked/map_sequential_lookup.c"
        uint32_t _array_key = *(uint32_t*)(uintptr_t)r2;
#line 52 "sample/undocked/map_sequential_lookup.c"
        if (_array_key < 2) {
#line 52 "sample/undocked/map_sequential_lookup.c"
            r0 = (uint64_t)(uintptr_t)(runtime_context->map_data[0].array_data + (uint64_t)_array_key * 4);
#line 52 "sample/undocked/map_sequential_lookup.c"
        } else {
#line 52 "sample/undocked/map_sequential_lookup.c"
            r0 = 0;
#line 52 "sample/undocked/map_sequential_lookup.c"
        }
#line 52 "sample/undocked/map_sequential_lookup.c"
    }
    // EBPF_OP_MOV64_REG pc=9 dst=r6 src=r0 offset=0 imm=0
#line 52 "sample/undocked/map_sequential_lookup.c"
    r6 = r0;
    // EBPF_OP_LDDW pc=10 dst=r0 src=r0 offset=0 imm=-1
#line 52 "sample/undocked/map_sequential_lookup.c"
    r0 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=12 dst=r6 src=r0 offset=12 imm=0
#line 53 "sample/undocked/map_sequential_lookup.c"
    if (r6 == IMMEDIATE(0)) {
#line 53 "sample/undocked/map_sequential_lookup.c"
        goto label_1;
#line 53 "sample/undocked/map_sequential_lookup.c"
    }
    // EBPF_OP_MOV64_REG pc=13 dst=r2 src=r10 offset=0 imm=0
#line 53 "sample/undocked/map_sequential_lookup.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=14 dst=r2 src=r0 offset=0 imm=-8
#line 60 "sample/undocked/map_sequential_lookup.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=15 dst=r1 src=r1 offset=0 imm=1
#line 60 "sample/undocked/map_sequential_lookup.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=17 dst=r0 src=r0 offset=0 imm=1
#line 60 "sample/undocked/map_sequential_lookup.c"
    {
#line 60 "sample/undocked/map_sequential_lookup.c"
        uint32_t _array_key = *(uint32_t*)(uintptr_t)r2;
#line 60 "sample/undocked/map_sequential_lookup.c"
        if (_array_key < 2) {
#line 60 "sample/undocked/map_sequential_lookup.c"
            r0 = (uint64_t)(uintptr_t)(runtime_context->map_data[0].array_data + (uint64_t)_array_key * 4);
#line 60 "sample/undocked/map_sequential_lookup.c"
        } else {
#line 60 "sample/undocked/map_sequential_lookup.c"
            r0 = 0;
#line 60 "sample/undocked/map_sequential_lookup.c"
        }
#line 60 "sample/undocked/map_sequential_lookup.c"
    }
    // EBPF_OP_MOV64_REG pc=18 dst=r1 src=r0 offset=0 imm=0
#line 60 "sample/undocked/map_sequential_lookup.c"
    r1 = r0;
    // EBPF_OP_LDDW pc=19 dst=r0 src=r0 offset=0 imm=-2
#line 60 "sample/undocked/map_sequential_lookup.c"
    r0 = (uint64_t)4294967294;
    // EBPF_OP_JEQ_IMM pc=21 dst=r1 src=r0 offset=3 imm=0
#line 61 "sample/undocked/map_sequential_lookup.c"
    if (r1 == IMMEDIATE(0)) {
#line 61 "sample/undocked/map_sequential_lookup.c"
        goto label_1;
#line 61 "sample/undocked/map_sequential_lookup.c"
    }
    // EBPF_OP_LDXW pc=22 dst=r2 src=r6 offset=0 imm=0
#line 65 "sample/undocked/map_sequential_lookup.c"
    READ_ONCE_32(r2, r6, OFFSET(0));
    // EBPF_OP_LDXW pc=23 dst=r0 src=r1 offset=0 imm=0
#line 65 "sample/undocked/map_sequential_lookup.c"
    READ_ONCE_32(r0, r1, OFFSET(0));
    // EBPF_OP_ADD64_REG pc=24 dst=r0 src=r2 offset=0 imm=0
#line 65 "sample/undocked/map_sequential_lookup.c"
    r0 += r2;
label_1:
    // EBPF_OP_EXIT pc=25 dst=r0 src=r0 offset=0 imm=0
#line 66 "sample/undocked/map_sequential_lookup.c"
    return r0;
#line 45 "sample/undocked/map_sequential_lookup.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        map_sequential_lookup,
        "sample~1",
        "sample_ext",
        "map_sequential_lookup",
        map_sequential_lookup_maps,
        1,
        map_sequential_lookup_helpers,
        1,
        26,
        &map_sequential_lookup_program_type_guid,
        &map_sequential_lookup_attach_type_guid,
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

metadata_table_t map_sequential_lookup_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
