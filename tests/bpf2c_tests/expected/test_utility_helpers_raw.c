// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from test_utility_helpers.o

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
         40,                 // Size in bytes of a map value.
         2,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         13,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "utility_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 1;
}

static helper_function_entry_t test_utility_helpers_helpers[] = {
    {6, "helper_id_6"},
    {7, "helper_id_7"},
    {9, "helper_id_9"},
    {8, "helper_id_8"},
    {19, "helper_id_19"},
    {2, "helper_id_2"},
};

static GUID test_utility_helpers_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID test_utility_helpers_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t test_utility_helpers_maps[] = {
    0,
};

#pragma code_seg(push, "sample~1")
static uint64_t
test_utility_helpers(void* context, const program_runtime_context_t* runtime_context)
#line 33 "sample/undocked/test_utility_helpers.c"
{
#line 33 "sample/undocked/test_utility_helpers.c"
    // Prologue
#line 33 "sample/undocked/test_utility_helpers.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 33 "sample/undocked/test_utility_helpers.c"
    register uint64_t r0 = 0;
#line 33 "sample/undocked/test_utility_helpers.c"
    register uint64_t r1 = 0;
#line 33 "sample/undocked/test_utility_helpers.c"
    register uint64_t r2 = 0;
#line 33 "sample/undocked/test_utility_helpers.c"
    register uint64_t r3 = 0;
#line 33 "sample/undocked/test_utility_helpers.c"
    register uint64_t r4 = 0;
#line 33 "sample/undocked/test_utility_helpers.c"
    register uint64_t r5 = 0;
#line 33 "sample/undocked/test_utility_helpers.c"
    register uint64_t r6 = 0;
#line 33 "sample/undocked/test_utility_helpers.c"
    register uint64_t r10 = 0;

#line 33 "sample/undocked/test_utility_helpers.c"
    r1 = (uintptr_t)context;
#line 33 "sample/undocked/test_utility_helpers.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDDW pc=0 dst=r1 src=r0 offset=0 imm=0
#line 33 "sample/undocked/test_utility_helpers.c"
    r1 = (uint64_t)4294967296;
    // EBPF_OP_STXDW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 12 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=3 dst=r1 src=r0 offset=0 imm=0
#line 12 "sample/./sample_common_routines.h"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=4 dst=r10 src=r1 offset=-24 imm=0
#line 13 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-32 imm=0
#line 13 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=6 dst=r10 src=r1 offset=-40 imm=0
#line 13 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=7 dst=r10 src=r1 offset=-48 imm=0
#line 13 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_CALL pc=8 dst=r0 src=r0 offset=0 imm=6
#line 16 "sample/./sample_common_routines.h"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5);
#line 16 "sample/./sample_common_routines.h"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 16 "sample/./sample_common_routines.h"
        return 0;
#line 16 "sample/./sample_common_routines.h"
    }
    // EBPF_OP_STXW pc=9 dst=r10 src=r0 offset=-48 imm=0
#line 16 "sample/./sample_common_routines.h"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint32_t)r0;
    // EBPF_OP_CALL pc=10 dst=r0 src=r0 offset=0 imm=7
#line 24 "sample/./sample_common_routines.h"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5);
#line 24 "sample/./sample_common_routines.h"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 24 "sample/./sample_common_routines.h"
        return 0;
#line 24 "sample/./sample_common_routines.h"
    }
    // EBPF_OP_STXDW pc=11 dst=r10 src=r0 offset=-32 imm=0
#line 24 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r0;
    // EBPF_OP_CALL pc=12 dst=r0 src=r0 offset=0 imm=9
#line 27 "sample/./sample_common_routines.h"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5);
#line 27 "sample/./sample_common_routines.h"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 27 "sample/./sample_common_routines.h"
        return 0;
#line 27 "sample/./sample_common_routines.h"
    }
    // EBPF_OP_STXDW pc=13 dst=r10 src=r0 offset=-40 imm=0
#line 27 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r0;
    // EBPF_OP_CALL pc=14 dst=r0 src=r0 offset=0 imm=8
#line 30 "sample/./sample_common_routines.h"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5);
#line 30 "sample/./sample_common_routines.h"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 30 "sample/./sample_common_routines.h"
        return 0;
#line 30 "sample/./sample_common_routines.h"
    }
    // EBPF_OP_STXW pc=15 dst=r10 src=r0 offset=-24 imm=0
#line 30 "sample/./sample_common_routines.h"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r0;
    // EBPF_OP_CALL pc=16 dst=r0 src=r0 offset=0 imm=19
#line 33 "sample/./sample_common_routines.h"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5);
#line 33 "sample/./sample_common_routines.h"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 33 "sample/./sample_common_routines.h"
        return 0;
#line 33 "sample/./sample_common_routines.h"
    }
    // EBPF_OP_STXDW pc=17 dst=r10 src=r0 offset=-16 imm=0
#line 33 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r0;
    // EBPF_OP_MOV64_REG pc=18 dst=r2 src=r10 offset=0 imm=0
#line 33 "sample/./sample_common_routines.h"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=19 dst=r2 src=r0 offset=0 imm=-8
#line 33 "sample/./sample_common_routines.h"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=20 dst=r6 src=r10 offset=0 imm=0
#line 33 "sample/./sample_common_routines.h"
    r6 = r10;
    // EBPF_OP_ADD64_IMM pc=21 dst=r6 src=r0 offset=0 imm=-48
#line 33 "sample/./sample_common_routines.h"
    r6 += IMMEDIATE(-48);
    // EBPF_OP_LDDW pc=22 dst=r1 src=r0 offset=0 imm=0
#line 36 "sample/./sample_common_routines.h"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_REG pc=24 dst=r3 src=r6 offset=0 imm=0
#line 36 "sample/./sample_common_routines.h"
    r3 = r6;
    // EBPF_OP_MOV64_IMM pc=25 dst=r4 src=r0 offset=0 imm=0
#line 36 "sample/./sample_common_routines.h"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=26 dst=r0 src=r0 offset=0 imm=2
#line 36 "sample/./sample_common_routines.h"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5);
#line 36 "sample/./sample_common_routines.h"
    if ((runtime_context->helper_data[5].tail_call) && (r0 == 0)) {
#line 36 "sample/./sample_common_routines.h"
        return 0;
#line 36 "sample/./sample_common_routines.h"
    }
    // EBPF_OP_CALL pc=27 dst=r0 src=r0 offset=0 imm=6
#line 39 "sample/./sample_common_routines.h"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5);
#line 39 "sample/./sample_common_routines.h"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 39 "sample/./sample_common_routines.h"
        return 0;
#line 39 "sample/./sample_common_routines.h"
    }
    // EBPF_OP_STXW pc=28 dst=r10 src=r0 offset=-48 imm=0
#line 39 "sample/./sample_common_routines.h"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint32_t)r0;
    // EBPF_OP_CALL pc=29 dst=r0 src=r0 offset=0 imm=9
#line 42 "sample/./sample_common_routines.h"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5);
#line 42 "sample/./sample_common_routines.h"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 42 "sample/./sample_common_routines.h"
        return 0;
#line 42 "sample/./sample_common_routines.h"
    }
    // EBPF_OP_STXDW pc=30 dst=r10 src=r0 offset=-40 imm=0
#line 42 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r0;
    // EBPF_OP_CALL pc=31 dst=r0 src=r0 offset=0 imm=7
#line 45 "sample/./sample_common_routines.h"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5);
#line 45 "sample/./sample_common_routines.h"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 45 "sample/./sample_common_routines.h"
        return 0;
#line 45 "sample/./sample_common_routines.h"
    }
    // EBPF_OP_STXDW pc=32 dst=r10 src=r0 offset=-32 imm=0
#line 45 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r0;
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=19
#line 48 "sample/./sample_common_routines.h"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5);
#line 48 "sample/./sample_common_routines.h"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 48 "sample/./sample_common_routines.h"
        return 0;
#line 48 "sample/./sample_common_routines.h"
    }
    // EBPF_OP_STXDW pc=34 dst=r10 src=r0 offset=-16 imm=0
#line 48 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r0;
    // EBPF_OP_MOV64_REG pc=35 dst=r2 src=r10 offset=0 imm=0
#line 51 "sample/./sample_common_routines.h"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=36 dst=r2 src=r0 offset=0 imm=-4
#line 51 "sample/./sample_common_routines.h"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=37 dst=r1 src=r0 offset=0 imm=0
#line 51 "sample/./sample_common_routines.h"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_REG pc=39 dst=r3 src=r6 offset=0 imm=0
#line 51 "sample/./sample_common_routines.h"
    r3 = r6;
    // EBPF_OP_MOV64_IMM pc=40 dst=r4 src=r0 offset=0 imm=0
#line 51 "sample/./sample_common_routines.h"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=41 dst=r0 src=r0 offset=0 imm=2
#line 51 "sample/./sample_common_routines.h"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5);
#line 51 "sample/./sample_common_routines.h"
    if ((runtime_context->helper_data[5].tail_call) && (r0 == 0)) {
#line 51 "sample/./sample_common_routines.h"
        return 0;
#line 51 "sample/./sample_common_routines.h"
    }
    // EBPF_OP_MOV64_IMM pc=42 dst=r0 src=r0 offset=0 imm=0
#line 35 "sample/undocked/test_utility_helpers.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=43 dst=r0 src=r0 offset=0 imm=0
#line 35 "sample/undocked/test_utility_helpers.c"
    return r0;
#line 35 "sample/undocked/test_utility_helpers.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        test_utility_helpers,
        "sample~1",
        "sample_ext",
        "test_utility_helpers",
        test_utility_helpers_maps,
        1,
        test_utility_helpers_helpers,
        6,
        44,
        &test_utility_helpers_program_type_guid,
        &test_utility_helpers_attach_type_guid,
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

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t test_utility_helpers_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};
