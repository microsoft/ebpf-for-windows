// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from pidtgid.o

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
         12,                 // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         12,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "pidtgid_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 1;
}

static helper_function_entry_t func_helpers[] = {
    {19, "helper_id_19"},
    {2, "helper_id_2"},
};

static GUID func_program_type_guid = {0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID func_attach_type_guid = {0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t func_maps[] = {
    0,
};

#pragma code_seg(push, "bind")
static uint64_t
func(void* context, const program_runtime_context_t* runtime_context)
#line 34 "sample/pidtgid.c"
{
#line 34 "sample/pidtgid.c"
    // Prologue
#line 34 "sample/pidtgid.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 34 "sample/pidtgid.c"
    register uint64_t r0 = 0;
#line 34 "sample/pidtgid.c"
    register uint64_t r1 = 0;
#line 34 "sample/pidtgid.c"
    register uint64_t r2 = 0;
#line 34 "sample/pidtgid.c"
    register uint64_t r3 = 0;
#line 34 "sample/pidtgid.c"
    register uint64_t r4 = 0;
#line 34 "sample/pidtgid.c"
    register uint64_t r5 = 0;
#line 34 "sample/pidtgid.c"
    register uint64_t r6 = 0;
#line 34 "sample/pidtgid.c"
    register uint64_t r10 = 0;

#line 34 "sample/pidtgid.c"
    r1 = (uintptr_t)context;
#line 34 "sample/pidtgid.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 34 "sample/pidtgid.c"
    r6 = r1;
    // EBPF_OP_LDXB pc=1 dst=r1 src=r6 offset=40 imm=0
#line 46 "sample/pidtgid.c"
    r1 = *(uint8_t*)(uintptr_t)(r6 + OFFSET(40));
    // EBPF_OP_MOV64_IMM pc=2 dst=r2 src=r0 offset=0 imm=16
#line 46 "sample/pidtgid.c"
    r2 = IMMEDIATE(16);
    // EBPF_OP_JGT_REG pc=3 dst=r2 src=r1 offset=18 imm=0
#line 46 "sample/pidtgid.c"
    if (r2 > r1) {
#line 46 "sample/pidtgid.c"
        goto label_1;
#line 46 "sample/pidtgid.c"
    }
    // EBPF_OP_LDXH pc=4 dst=r1 src=r6 offset=26 imm=0
#line 46 "sample/pidtgid.c"
    r1 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(26));
    // EBPF_OP_JNE_IMM pc=5 dst=r1 src=r0 offset=16 imm=15295
#line 46 "sample/pidtgid.c"
    if (r1 != IMMEDIATE(15295)) {
#line 46 "sample/pidtgid.c"
        goto label_1;
#line 46 "sample/pidtgid.c"
    }
    // EBPF_OP_CALL pc=6 dst=r0 src=r0 offset=0 imm=19
#line 47 "sample/pidtgid.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5);
#line 47 "sample/pidtgid.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 47 "sample/pidtgid.c"
        return 0;
#line 47 "sample/pidtgid.c"
    }
    // EBPF_OP_LDXDW pc=7 dst=r1 src=r6 offset=16 imm=0
#line 49 "sample/pidtgid.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(16));
    // EBPF_OP_STXW pc=8 dst=r10 src=r0 offset=-8 imm=0
#line 48 "sample/pidtgid.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r0;
    // EBPF_OP_RSH64_IMM pc=9 dst=r0 src=r0 offset=0 imm=32
#line 49 "sample/pidtgid.c"
    r0 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_STXW pc=10 dst=r10 src=r0 offset=-12 imm=0
#line 48 "sample/pidtgid.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint32_t)r0;
    // EBPF_OP_STXW pc=11 dst=r10 src=r1 offset=-16 imm=0
#line 48 "sample/pidtgid.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=12 dst=r1 src=r0 offset=0 imm=0
#line 48 "sample/pidtgid.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=13 dst=r10 src=r1 offset=-20 imm=0
#line 50 "sample/pidtgid.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=14 dst=r2 src=r10 offset=0 imm=0
#line 50 "sample/pidtgid.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=15 dst=r2 src=r0 offset=0 imm=-20
#line 47 "sample/pidtgid.c"
    r2 += IMMEDIATE(-20);
    // EBPF_OP_MOV64_REG pc=16 dst=r3 src=r10 offset=0 imm=0
#line 47 "sample/pidtgid.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=17 dst=r3 src=r0 offset=0 imm=-16
#line 47 "sample/pidtgid.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=0
#line 51 "sample/pidtgid.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=20 dst=r4 src=r0 offset=0 imm=0
#line 51 "sample/pidtgid.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=21 dst=r0 src=r0 offset=0 imm=2
#line 51 "sample/pidtgid.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5);
#line 51 "sample/pidtgid.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 51 "sample/pidtgid.c"
        return 0;
#line 51 "sample/pidtgid.c"
    }
label_1:
    // EBPF_OP_MOV64_IMM pc=22 dst=r0 src=r0 offset=0 imm=0
#line 54 "sample/pidtgid.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=23 dst=r0 src=r0 offset=0 imm=0
#line 54 "sample/pidtgid.c"
    return r0;
#line 54 "sample/pidtgid.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        func,
        "bind",
        "bind",
        "func",
        func_maps,
        1,
        func_helpers,
        2,
        24,
        &func_program_type_guid,
        &func_attach_type_guid,
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

metadata_table_t pidtgid_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};
