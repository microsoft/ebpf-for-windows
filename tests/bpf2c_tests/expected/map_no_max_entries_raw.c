// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from map_no_max_entries.o

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
         1,                     // Current Version.
         84,                    // Struct size up to the last field.
         88,                    // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH,     // Type of map.
         4,                     // Size in bytes of a map key.
         8,                     // Size in bytes of a map value.
         2,                     // Maximum number of entries allowed in the map.
         0,                     // Inner map index.
         LIBBPF_PIN_NONE,       // Pinning type for the map.
         0,                     // Identifier for a map template.
         0,                     // The id of the inner map template.
     },
     "no_max_entries_map",  // Map name.
     8192,                  // Map creation flags.
    },
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

static helper_function_entry_t map_no_max_entries_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID map_no_max_entries_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID map_no_max_entries_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t map_no_max_entries_maps[] = {
    0,
};

#pragma code_seg(push, "sample~1")
static uint64_t
map_no_max_entries(void* context, const program_runtime_context_t* runtime_context)
#line 19 "sample/undocked/map_no_max_entries.c"
{
#line 19 "sample/undocked/map_no_max_entries.c"
    // Prologue.
#line 19 "sample/undocked/map_no_max_entries.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 19 "sample/undocked/map_no_max_entries.c"
    register uint64_t r0 = 0;
#line 19 "sample/undocked/map_no_max_entries.c"
    register uint64_t r1 = 0;
#line 19 "sample/undocked/map_no_max_entries.c"
    register uint64_t r2 = 0;
#line 19 "sample/undocked/map_no_max_entries.c"
    register uint64_t r3 = 0;
#line 19 "sample/undocked/map_no_max_entries.c"
    register uint64_t r4 = 0;
#line 19 "sample/undocked/map_no_max_entries.c"
    register uint64_t r5 = 0;
#line 19 "sample/undocked/map_no_max_entries.c"
    register uint64_t r10 = 0;

#line 19 "sample/undocked/map_no_max_entries.c"
    r1 = (uintptr_t)context;
#line 19 "sample/undocked/map_no_max_entries.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDDW pc=0 dst=r0 src=r0 offset=0 imm=-1
#line 19 "sample/undocked/map_no_max_entries.c"
    r0 = (uint64_t)4294967295;
    // EBPF_OP_LDXDW pc=2 dst=r2 src=r1 offset=8 imm=0
#line 21 "sample/undocked/map_no_max_entries.c"
    READ_ONCE_64(r2, r1, OFFSET(8));
    // EBPF_OP_LDXDW pc=3 dst=r1 src=r1 offset=0 imm=0
#line 21 "sample/undocked/map_no_max_entries.c"
    READ_ONCE_64(r1, r1, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=4 dst=r3 src=r1 offset=0 imm=0
#line 21 "sample/undocked/map_no_max_entries.c"
    r3 = r1;
    // EBPF_OP_ADD64_IMM pc=5 dst=r3 src=r0 offset=0 imm=4
#line 21 "sample/undocked/map_no_max_entries.c"
    r3 += IMMEDIATE(4);
    // EBPF_OP_JGT_REG pc=6 dst=r3 src=r2 offset=12 imm=0
#line 21 "sample/undocked/map_no_max_entries.c"
    if (r3 > r2) {
#line 21 "sample/undocked/map_no_max_entries.c"
        goto label_1;
#line 21 "sample/undocked/map_no_max_entries.c"
    }
    // EBPF_OP_LDXW pc=7 dst=r1 src=r1 offset=0 imm=0
#line 25 "sample/undocked/map_no_max_entries.c"
    READ_ONCE_32(r1, r1, OFFSET(0));
    // EBPF_OP_STXW pc=8 dst=r10 src=r1 offset=-4 imm=0
#line 25 "sample/undocked/map_no_max_entries.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MUL64_REG pc=9 dst=r1 src=r1 offset=0 imm=0
#line 26 "sample/undocked/map_no_max_entries.c"
    r1 *= r1;
    // EBPF_OP_STXDW pc=10 dst=r10 src=r1 offset=-16 imm=0
#line 26 "sample/undocked/map_no_max_entries.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=11 dst=r2 src=r10 offset=0 imm=0
#line 26 "sample/undocked/map_no_max_entries.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=12 dst=r2 src=r0 offset=0 imm=-4
#line 25 "sample/undocked/map_no_max_entries.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=13 dst=r3 src=r10 offset=0 imm=0
#line 25 "sample/undocked/map_no_max_entries.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=14 dst=r3 src=r0 offset=0 imm=-16
#line 25 "sample/undocked/map_no_max_entries.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=15 dst=r1 src=r1 offset=0 imm=1
#line 28 "sample/undocked/map_no_max_entries.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=17 dst=r4 src=r0 offset=0 imm=0
#line 28 "sample/undocked/map_no_max_entries.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=2
#line 28 "sample/undocked/map_no_max_entries.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
label_1:
    // EBPF_OP_EXIT pc=19 dst=r0 src=r0 offset=0 imm=0
#line 29 "sample/undocked/map_no_max_entries.c"
    return r0;
#line 19 "sample/undocked/map_no_max_entries.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 154, 160}, // Version header.
        map_no_max_entries,
        "sample~1",
        "sample_ext",
        "map_no_max_entries",
        map_no_max_entries_maps,
        1,
        map_no_max_entries_helpers,
        1,
        20,
        &map_no_max_entries_program_type_guid,
        &map_no_max_entries_attach_type_guid,
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
    version->minor = 6;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t map_no_max_entries_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
