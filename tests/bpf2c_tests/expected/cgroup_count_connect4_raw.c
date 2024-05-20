// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from cgroup_count_connect4.o

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
         BPF_MAP_TYPE_HASH, // Type of map.
         2,                 // Size in bytes of a map key.
         8,                 // Size in bytes of a map value.
         1,                 // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         11,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "connect4_count_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 1;
}

static helper_function_entry_t count_tcp_connect4_helpers[] = {
    {1, "helper_id_1"},
    {2, "helper_id_2"},
};

static GUID count_tcp_connect4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID count_tcp_connect4_attach_type_guid = {
    0xa82e37b1, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t count_tcp_connect4_maps[] = {
    0,
};

#pragma code_seg(push, "cgroup~1")
static uint64_t
count_tcp_connect4(void* context, const program_runtime_context_t* runtime_context)
#line 31 "sample/cgroup_count_connect4.c"
{
#line 31 "sample/cgroup_count_connect4.c"
    // Prologue
#line 31 "sample/cgroup_count_connect4.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 31 "sample/cgroup_count_connect4.c"
    register uint64_t r0 = 0;
#line 31 "sample/cgroup_count_connect4.c"
    register uint64_t r1 = 0;
#line 31 "sample/cgroup_count_connect4.c"
    register uint64_t r2 = 0;
#line 31 "sample/cgroup_count_connect4.c"
    register uint64_t r3 = 0;
#line 31 "sample/cgroup_count_connect4.c"
    register uint64_t r4 = 0;
#line 31 "sample/cgroup_count_connect4.c"
    register uint64_t r5 = 0;
#line 31 "sample/cgroup_count_connect4.c"
    register uint64_t r6 = 0;
#line 31 "sample/cgroup_count_connect4.c"
    register uint64_t r10 = 0;

#line 31 "sample/cgroup_count_connect4.c"
    r1 = (uintptr_t)context;
#line 31 "sample/cgroup_count_connect4.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=1
#line 31 "sample/cgroup_count_connect4.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=1 dst=r2 src=r1 offset=44 imm=0
#line 34 "sample/cgroup_count_connect4.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_JNE_IMM pc=2 dst=r2 src=r0 offset=27 imm=6
#line 34 "sample/cgroup_count_connect4.c"
    if (r2 != IMMEDIATE(6)) {
#line 34 "sample/cgroup_count_connect4.c"
        goto label_2;
#line 34 "sample/cgroup_count_connect4.c"
    }
    // EBPF_OP_LDXH pc=3 dst=r1 src=r1 offset=40 imm=0
#line 40 "sample/cgroup_count_connect4.c"
    r1 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_JNE_IMM pc=4 dst=r1 src=r0 offset=25 imm=7459
#line 40 "sample/cgroup_count_connect4.c"
    if (r1 != IMMEDIATE(7459)) {
#line 40 "sample/cgroup_count_connect4.c"
        goto label_2;
#line 40 "sample/cgroup_count_connect4.c"
    }
    // EBPF_OP_MOV64_IMM pc=5 dst=r6 src=r0 offset=0 imm=0
#line 40 "sample/cgroup_count_connect4.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=6 dst=r10 src=r6 offset=-16 imm=0
#line 47 "sample/cgroup_count_connect4.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r6;
    // EBPF_OP_MOV64_IMM pc=7 dst=r1 src=r0 offset=0 imm=8989
#line 47 "sample/cgroup_count_connect4.c"
    r1 = IMMEDIATE(8989);
    // EBPF_OP_STXH pc=8 dst=r10 src=r1 offset=-2 imm=0
#line 46 "sample/cgroup_count_connect4.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-2)) = (uint16_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r2 src=r10 offset=0 imm=0
#line 46 "sample/cgroup_count_connect4.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r2 src=r0 offset=0 imm=-2
#line 46 "sample/cgroup_count_connect4.c"
    r2 += IMMEDIATE(-2);
    // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=0
#line 48 "sample/cgroup_count_connect4.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=1
#line 48 "sample/cgroup_count_connect4.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5);
#line 48 "sample/cgroup_count_connect4.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 48 "sample/cgroup_count_connect4.c"
        return 0;
#line 48 "sample/cgroup_count_connect4.c"
    }
    // EBPF_OP_JNE_IMM pc=14 dst=r0 src=r0 offset=12 imm=0
#line 49 "sample/cgroup_count_connect4.c"
    if (r0 != IMMEDIATE(0)) {
#line 49 "sample/cgroup_count_connect4.c"
        goto label_1;
#line 49 "sample/cgroup_count_connect4.c"
    }
    // EBPF_OP_MOV64_IMM pc=15 dst=r1 src=r0 offset=0 imm=1
#line 49 "sample/cgroup_count_connect4.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-16 imm=0
#line 50 "sample/cgroup_count_connect4.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=17 dst=r2 src=r10 offset=0 imm=0
#line 50 "sample/cgroup_count_connect4.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=18 dst=r2 src=r0 offset=0 imm=-2
#line 50 "sample/cgroup_count_connect4.c"
    r2 += IMMEDIATE(-2);
    // EBPF_OP_MOV64_REG pc=19 dst=r3 src=r10 offset=0 imm=0
#line 50 "sample/cgroup_count_connect4.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=20 dst=r3 src=r0 offset=0 imm=-16
#line 50 "sample/cgroup_count_connect4.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_IMM pc=21 dst=r6 src=r0 offset=0 imm=0
#line 50 "sample/cgroup_count_connect4.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=22 dst=r1 src=r0 offset=0 imm=0
#line 51 "sample/cgroup_count_connect4.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=24 dst=r4 src=r0 offset=0 imm=0
#line 51 "sample/cgroup_count_connect4.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=2
#line 51 "sample/cgroup_count_connect4.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5);
#line 51 "sample/cgroup_count_connect4.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 51 "sample/cgroup_count_connect4.c"
        return 0;
#line 51 "sample/cgroup_count_connect4.c"
    }
    // EBPF_OP_JA pc=26 dst=r0 src=r0 offset=3 imm=0
#line 51 "sample/cgroup_count_connect4.c"
    goto label_2;
label_1:
    // EBPF_OP_LDXDW pc=27 dst=r1 src=r0 offset=0 imm=0
#line 53 "sample/cgroup_count_connect4.c"
    r1 = *(uint64_t*)(uintptr_t)(r0 + OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=28 dst=r1 src=r0 offset=0 imm=1
#line 53 "sample/cgroup_count_connect4.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=29 dst=r0 src=r1 offset=0 imm=0
#line 53 "sample/cgroup_count_connect4.c"
    *(uint64_t*)(uintptr_t)(r0 + OFFSET(0)) = (uint64_t)r1;
label_2:
    // EBPF_OP_MOV64_REG pc=30 dst=r0 src=r6 offset=0 imm=0
#line 62 "sample/cgroup_count_connect4.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=31 dst=r0 src=r0 offset=0 imm=0
#line 62 "sample/cgroup_count_connect4.c"
    return r0;
#line 62 "sample/cgroup_count_connect4.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        count_tcp_connect4,
        "cgroup~1",
        "cgroup/connect4",
        "count_tcp_connect4",
        count_tcp_connect4_maps,
        1,
        count_tcp_connect4_helpers,
        2,
        32,
        &count_tcp_connect4_program_type_guid,
        &count_tcp_connect4_attach_type_guid,
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

metadata_table_t cgroup_count_connect4_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};
