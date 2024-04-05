// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from bindmonitor_tailcall.o

#include "bpf2c.h"

static void
_get_hash(_Outptr_result_buffer_maybenull_(*size) const uint8_t** hash, _Out_ size_t* size)
{
    *hash = NULL;
    *size = 0;
}
#pragma data_seg(push, "maps")
static map_entry_t _maps[] = {
    {NULL,
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         8,                 // Size in bytes of a map key.
         68,                // Size in bytes of a map value.
         1024,              // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "process_map"},
    {NULL,
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         0,                  // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "limits_map"},
    {NULL,
     {
         BPF_MAP_TYPE_PROG_ARRAY, // Type of map.
         4,                       // Size in bytes of a map key.
         4,                       // Size in bytes of a map value.
         8,                       // Maximum number of entries allowed in the map.
         0,                       // Inner map index.
         LIBBPF_PIN_NONE,         // Pinning type for the map.
         0,                       // Identifier for a map template.
         0,                       // The id of the inner map template.
     },
     "prog_array_map"},
    {NULL,
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         4,                 // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         1000,              // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "dummy_map"},
    {NULL,
     {
         BPF_MAP_TYPE_ARRAY_OF_MAPS, // Type of map.
         4,                          // Size in bytes of a map key.
         4,                          // Size in bytes of a map value.
         1,                          // Maximum number of entries allowed in the map.
         0,                          // Inner map index.
         LIBBPF_PIN_NONE,            // Pinning type for the map.
         0,                          // Identifier for a map template.
         10,                         // The id of the inner map template.
     },
     "dummy_outer_map"},
    {NULL,
     {
         BPF_MAP_TYPE_HASH_OF_MAPS, // Type of map.
         4,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         10,                        // Maximum number of entries allowed in the map.
         6,                         // Inner map index.
         LIBBPF_PIN_NONE,           // Pinning type for the map.
         0,                         // Identifier for a map template.
         0,                         // The id of the inner map template.
     },
     "dummy_outer_idx_map"},
    {NULL,
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         4,                 // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         1,                 // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         10,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "dummy_inner_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 7;
}

static helper_function_entry_t BindMonitor_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_maps[] = {
    2,
    3,
};

#pragma code_seg(push, "bind")
static uint64_t
BindMonitor(void* context)
#line 120 "sample/bindmonitor_tailcall.c"
{
#line 120 "sample/bindmonitor_tailcall.c"
    // Prologue
#line 120 "sample/bindmonitor_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 120 "sample/bindmonitor_tailcall.c"
    register uint64_t r0 = 0;
#line 120 "sample/bindmonitor_tailcall.c"
    register uint64_t r1 = 0;
#line 120 "sample/bindmonitor_tailcall.c"
    register uint64_t r2 = 0;
#line 120 "sample/bindmonitor_tailcall.c"
    register uint64_t r3 = 0;
#line 120 "sample/bindmonitor_tailcall.c"
    register uint64_t r4 = 0;
#line 120 "sample/bindmonitor_tailcall.c"
    register uint64_t r5 = 0;
#line 120 "sample/bindmonitor_tailcall.c"
    register uint64_t r6 = 0;
#line 120 "sample/bindmonitor_tailcall.c"
    register uint64_t r10 = 0;

#line 120 "sample/bindmonitor_tailcall.c"
    r1 = (uintptr_t)context;
#line 120 "sample/bindmonitor_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 120 "sample/bindmonitor_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 120 "sample/bindmonitor_tailcall.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 122 "sample/bindmonitor_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 122 "sample/bindmonitor_tailcall.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 122 "sample/bindmonitor_tailcall.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 123 "sample/bindmonitor_tailcall.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 123 "sample/bindmonitor_tailcall.c"
    r0 = BindMonitor_helpers[0].address
#line 123 "sample/bindmonitor_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 123 "sample/bindmonitor_tailcall.c"
    if ((BindMonitor_helpers[0].tail_call) && (r0 == 0))
#line 123 "sample/bindmonitor_tailcall.c"
        return 0;
    // EBPF_OP_JNE_IMM pc=8 dst=r0 src=r0 offset=5 imm=0
#line 125 "sample/bindmonitor_tailcall.c"
    if (r0 != IMMEDIATE(0))
#line 125 "sample/bindmonitor_tailcall.c"
        goto label_1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r6 offset=0 imm=0
#line 128 "sample/bindmonitor_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=10 dst=r2 src=r0 offset=0 imm=0
#line 128 "sample/bindmonitor_tailcall.c"
    r2 = POINTER(_maps[2].address);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=0
#line 128 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=5
#line 128 "sample/bindmonitor_tailcall.c"
    r0 = BindMonitor_helpers[1].address
#line 128 "sample/bindmonitor_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 128 "sample/bindmonitor_tailcall.c"
    if ((BindMonitor_helpers[1].tail_call) && (r0 == 0))
#line 128 "sample/bindmonitor_tailcall.c"
        return 0;
label_1:
    // EBPF_OP_MOV64_IMM pc=14 dst=r0 src=r0 offset=0 imm=1
#line 131 "sample/bindmonitor_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=15 dst=r0 src=r0 offset=0 imm=0
#line 131 "sample/bindmonitor_tailcall.c"
    return r0;
#line 131 "sample/bindmonitor_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee0_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 5, "helper_id_5"},
};

static GUID BindMonitor_Callee0_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee0_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee0_maps[] = {
    2,
    3,
};

#pragma code_seg(push, "bind/0")
static uint64_t
BindMonitor_Callee0(void* context)
#line 136 "sample/bindmonitor_tailcall.c"
{
#line 136 "sample/bindmonitor_tailcall.c"
    // Prologue
#line 136 "sample/bindmonitor_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 136 "sample/bindmonitor_tailcall.c"
    register uint64_t r0 = 0;
#line 136 "sample/bindmonitor_tailcall.c"
    register uint64_t r1 = 0;
#line 136 "sample/bindmonitor_tailcall.c"
    register uint64_t r2 = 0;
#line 136 "sample/bindmonitor_tailcall.c"
    register uint64_t r3 = 0;
#line 136 "sample/bindmonitor_tailcall.c"
    register uint64_t r4 = 0;
#line 136 "sample/bindmonitor_tailcall.c"
    register uint64_t r5 = 0;
#line 136 "sample/bindmonitor_tailcall.c"
    register uint64_t r6 = 0;
#line 136 "sample/bindmonitor_tailcall.c"
    register uint64_t r10 = 0;

#line 136 "sample/bindmonitor_tailcall.c"
    r1 = (uintptr_t)context;
#line 136 "sample/bindmonitor_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 136 "sample/bindmonitor_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 136 "sample/bindmonitor_tailcall.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 138 "sample/bindmonitor_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 138 "sample/bindmonitor_tailcall.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 138 "sample/bindmonitor_tailcall.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 139 "sample/bindmonitor_tailcall.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 139 "sample/bindmonitor_tailcall.c"
    r0 = BindMonitor_Callee0_helpers[0].address
#line 139 "sample/bindmonitor_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 139 "sample/bindmonitor_tailcall.c"
    if ((BindMonitor_Callee0_helpers[0].tail_call) && (r0 == 0))
#line 139 "sample/bindmonitor_tailcall.c"
        return 0;
    // EBPF_OP_JNE_IMM pc=8 dst=r0 src=r0 offset=5 imm=0
#line 141 "sample/bindmonitor_tailcall.c"
    if (r0 != IMMEDIATE(0))
#line 141 "sample/bindmonitor_tailcall.c"
        goto label_1;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r6 offset=0 imm=0
#line 144 "sample/bindmonitor_tailcall.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=10 dst=r2 src=r0 offset=0 imm=0
#line 144 "sample/bindmonitor_tailcall.c"
    r2 = POINTER(_maps[2].address);
    // EBPF_OP_MOV64_IMM pc=12 dst=r3 src=r0 offset=0 imm=1
#line 144 "sample/bindmonitor_tailcall.c"
    r3 = IMMEDIATE(1);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=5
#line 144 "sample/bindmonitor_tailcall.c"
    r0 = BindMonitor_Callee0_helpers[1].address
#line 144 "sample/bindmonitor_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 144 "sample/bindmonitor_tailcall.c"
    if ((BindMonitor_Callee0_helpers[1].tail_call) && (r0 == 0))
#line 144 "sample/bindmonitor_tailcall.c"
        return 0;
label_1:
    // EBPF_OP_MOV64_IMM pc=14 dst=r0 src=r0 offset=0 imm=1
#line 147 "sample/bindmonitor_tailcall.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=15 dst=r0 src=r0 offset=0 imm=0
#line 147 "sample/bindmonitor_tailcall.c"
    return r0;
#line 147 "sample/bindmonitor_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t BindMonitor_Callee1_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 2, "helper_id_2"},
    {NULL, 22, "helper_id_22"},
    {NULL, 3, "helper_id_3"},
};

static GUID BindMonitor_Callee1_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Callee1_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t BindMonitor_Callee1_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "bind/1")
static uint64_t
BindMonitor_Callee1(void* context)
#line 152 "sample/bindmonitor_tailcall.c"
{
#line 152 "sample/bindmonitor_tailcall.c"
    // Prologue
#line 152 "sample/bindmonitor_tailcall.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 152 "sample/bindmonitor_tailcall.c"
    register uint64_t r0 = 0;
#line 152 "sample/bindmonitor_tailcall.c"
    register uint64_t r1 = 0;
#line 152 "sample/bindmonitor_tailcall.c"
    register uint64_t r2 = 0;
#line 152 "sample/bindmonitor_tailcall.c"
    register uint64_t r3 = 0;
#line 152 "sample/bindmonitor_tailcall.c"
    register uint64_t r4 = 0;
#line 152 "sample/bindmonitor_tailcall.c"
    register uint64_t r5 = 0;
#line 152 "sample/bindmonitor_tailcall.c"
    register uint64_t r6 = 0;
#line 152 "sample/bindmonitor_tailcall.c"
    register uint64_t r7 = 0;
#line 152 "sample/bindmonitor_tailcall.c"
    register uint64_t r8 = 0;
#line 152 "sample/bindmonitor_tailcall.c"
    register uint64_t r9 = 0;
#line 152 "sample/bindmonitor_tailcall.c"
    register uint64_t r10 = 0;

#line 152 "sample/bindmonitor_tailcall.c"
    r1 = (uintptr_t)context;
#line 152 "sample/bindmonitor_tailcall.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 152 "sample/bindmonitor_tailcall.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r9 src=r0 offset=0 imm=0
#line 152 "sample/bindmonitor_tailcall.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r9 offset=-84 imm=0
#line 154 "sample/bindmonitor_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-84)) = (uint32_t)r9;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 154 "sample/bindmonitor_tailcall.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-84
#line 154 "sample/bindmonitor_tailcall.c"
    r2 += IMMEDIATE(-84);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 156 "sample/bindmonitor_tailcall.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 156 "sample/bindmonitor_tailcall.c"
    r0 = BindMonitor_Callee1_helpers[0].address
#line 156 "sample/bindmonitor_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 156 "sample/bindmonitor_tailcall.c"
    if ((BindMonitor_Callee1_helpers[0].tail_call) && (r0 == 0))
#line 156 "sample/bindmonitor_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=8 dst=r7 src=r0 offset=0 imm=0
#line 156 "sample/bindmonitor_tailcall.c"
    r7 = r0;
    // EBPF_OP_JEQ_IMM pc=9 dst=r7 src=r0 offset=77 imm=0
#line 157 "sample/bindmonitor_tailcall.c"
    if (r7 == IMMEDIATE(0))
#line 157 "sample/bindmonitor_tailcall.c"
        goto label_7;
    // EBPF_OP_LDXW pc=10 dst=r1 src=r7 offset=0 imm=0
#line 157 "sample/bindmonitor_tailcall.c"
    r1 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=11 dst=r1 src=r0 offset=75 imm=0
#line 157 "sample/bindmonitor_tailcall.c"
    if (r1 == IMMEDIATE(0))
#line 157 "sample/bindmonitor_tailcall.c"
        goto label_7;
    // EBPF_OP_LDXDW pc=12 dst=r1 src=r6 offset=16 imm=0
#line 81 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(16));
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-8 imm=0
#line 81 "sample/bindmonitor_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=14 dst=r1 src=r0 offset=0 imm=0
#line 81 "sample/bindmonitor_tailcall.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=15 dst=r10 src=r1 offset=-16 imm=0
#line 83 "sample/bindmonitor_tailcall.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-24 imm=0
#line 83 "sample/bindmonitor_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r1 offset=-32 imm=0
#line 83 "sample/bindmonitor_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=18 dst=r10 src=r1 offset=-40 imm=0
#line 83 "sample/bindmonitor_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-48 imm=0
#line 83 "sample/bindmonitor_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-56 imm=0
#line 83 "sample/bindmonitor_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=21 dst=r10 src=r1 offset=-64 imm=0
#line 83 "sample/bindmonitor_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=22 dst=r10 src=r1 offset=-72 imm=0
#line 83 "sample/bindmonitor_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=23 dst=r10 src=r1 offset=-80 imm=0
#line 83 "sample/bindmonitor_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=24 dst=r2 src=r10 offset=0 imm=0
#line 83 "sample/bindmonitor_tailcall.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=25 dst=r2 src=r0 offset=0 imm=-8
#line 83 "sample/bindmonitor_tailcall.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=26 dst=r1 src=r0 offset=0 imm=0
#line 86 "sample/bindmonitor_tailcall.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=28 dst=r0 src=r0 offset=0 imm=1
#line 86 "sample/bindmonitor_tailcall.c"
    r0 = BindMonitor_Callee1_helpers[0].address
#line 86 "sample/bindmonitor_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 86 "sample/bindmonitor_tailcall.c"
    if ((BindMonitor_Callee1_helpers[0].tail_call) && (r0 == 0))
#line 86 "sample/bindmonitor_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=29 dst=r8 src=r0 offset=0 imm=0
#line 86 "sample/bindmonitor_tailcall.c"
    r8 = r0;
    // EBPF_OP_JNE_IMM pc=30 dst=r8 src=r0 offset=28 imm=0
#line 87 "sample/bindmonitor_tailcall.c"
    if (r8 != IMMEDIATE(0))
#line 87 "sample/bindmonitor_tailcall.c"
        goto label_1;
    // EBPF_OP_LDXW pc=31 dst=r1 src=r6 offset=44 imm=0
#line 91 "sample/bindmonitor_tailcall.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_JNE_IMM pc=32 dst=r1 src=r0 offset=53 imm=0
#line 91 "sample/bindmonitor_tailcall.c"
    if (r1 != IMMEDIATE(0))
#line 91 "sample/bindmonitor_tailcall.c"
        goto label_6;
    // EBPF_OP_LDXDW pc=33 dst=r1 src=r6 offset=0 imm=0
#line 95 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=34 dst=r1 src=r0 offset=51 imm=0
#line 95 "sample/bindmonitor_tailcall.c"
    if (r1 == IMMEDIATE(0))
#line 95 "sample/bindmonitor_tailcall.c"
        goto label_6;
    // EBPF_OP_LDXDW pc=35 dst=r1 src=r6 offset=8 imm=0
#line 95 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_JEQ_IMM pc=36 dst=r1 src=r0 offset=49 imm=0
#line 95 "sample/bindmonitor_tailcall.c"
    if (r1 == IMMEDIATE(0))
#line 95 "sample/bindmonitor_tailcall.c"
        goto label_6;
    // EBPF_OP_MOV64_REG pc=37 dst=r8 src=r10 offset=0 imm=0
#line 95 "sample/bindmonitor_tailcall.c"
    r8 = r10;
    // EBPF_OP_ADD64_IMM pc=38 dst=r8 src=r0 offset=0 imm=-8
#line 95 "sample/bindmonitor_tailcall.c"
    r8 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=39 dst=r3 src=r10 offset=0 imm=0
#line 95 "sample/bindmonitor_tailcall.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=40 dst=r3 src=r0 offset=0 imm=-80
#line 95 "sample/bindmonitor_tailcall.c"
    r3 += IMMEDIATE(-80);
    // EBPF_OP_LDDW pc=41 dst=r1 src=r0 offset=0 imm=0
#line 99 "sample/bindmonitor_tailcall.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_REG pc=43 dst=r2 src=r8 offset=0 imm=0
#line 99 "sample/bindmonitor_tailcall.c"
    r2 = r8;
    // EBPF_OP_MOV64_IMM pc=44 dst=r4 src=r0 offset=0 imm=0
#line 99 "sample/bindmonitor_tailcall.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=45 dst=r0 src=r0 offset=0 imm=2
#line 99 "sample/bindmonitor_tailcall.c"
    r0 = BindMonitor_Callee1_helpers[1].address
#line 99 "sample/bindmonitor_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 99 "sample/bindmonitor_tailcall.c"
    if ((BindMonitor_Callee1_helpers[1].tail_call) && (r0 == 0))
#line 99 "sample/bindmonitor_tailcall.c"
        return 0;
    // EBPF_OP_LDDW pc=46 dst=r1 src=r0 offset=0 imm=0
#line 100 "sample/bindmonitor_tailcall.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_REG pc=48 dst=r2 src=r8 offset=0 imm=0
#line 100 "sample/bindmonitor_tailcall.c"
    r2 = r8;
    // EBPF_OP_CALL pc=49 dst=r0 src=r0 offset=0 imm=1
#line 100 "sample/bindmonitor_tailcall.c"
    r0 = BindMonitor_Callee1_helpers[0].address
#line 100 "sample/bindmonitor_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 100 "sample/bindmonitor_tailcall.c"
    if ((BindMonitor_Callee1_helpers[0].tail_call) && (r0 == 0))
#line 100 "sample/bindmonitor_tailcall.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=50 dst=r8 src=r0 offset=0 imm=0
#line 100 "sample/bindmonitor_tailcall.c"
    r8 = r0;
    // EBPF_OP_JEQ_IMM pc=51 dst=r8 src=r0 offset=34 imm=0
#line 101 "sample/bindmonitor_tailcall.c"
    if (r8 == IMMEDIATE(0))
#line 101 "sample/bindmonitor_tailcall.c"
        goto label_6;
    // EBPF_OP_LDXDW pc=52 dst=r3 src=r6 offset=0 imm=0
#line 105 "sample/bindmonitor_tailcall.c"
    r3 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=53 dst=r4 src=r6 offset=8 imm=0
#line 105 "sample/bindmonitor_tailcall.c"
    r4 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_SUB64_REG pc=54 dst=r4 src=r3 offset=0 imm=0
#line 105 "sample/bindmonitor_tailcall.c"
    r4 -= r3;
    // EBPF_OP_MOV64_REG pc=55 dst=r1 src=r8 offset=0 imm=0
#line 105 "sample/bindmonitor_tailcall.c"
    r1 = r8;
    // EBPF_OP_ADD64_IMM pc=56 dst=r1 src=r0 offset=0 imm=4
#line 105 "sample/bindmonitor_tailcall.c"
    r1 += IMMEDIATE(4);
    // EBPF_OP_MOV64_IMM pc=57 dst=r2 src=r0 offset=0 imm=64
#line 105 "sample/bindmonitor_tailcall.c"
    r2 = IMMEDIATE(64);
    // EBPF_OP_CALL pc=58 dst=r0 src=r0 offset=0 imm=22
#line 105 "sample/bindmonitor_tailcall.c"
    r0 = BindMonitor_Callee1_helpers[2].address
#line 105 "sample/bindmonitor_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 105 "sample/bindmonitor_tailcall.c"
    if ((BindMonitor_Callee1_helpers[2].tail_call) && (r0 == 0))
#line 105 "sample/bindmonitor_tailcall.c"
        return 0;
label_1:
    // EBPF_OP_LDXW pc=59 dst=r1 src=r6 offset=44 imm=0
#line 167 "sample/bindmonitor_tailcall.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_JEQ_IMM pc=60 dst=r1 src=r0 offset=3 imm=0
#line 167 "sample/bindmonitor_tailcall.c"
    if (r1 == IMMEDIATE(0))
#line 167 "sample/bindmonitor_tailcall.c"
        goto label_2;
    // EBPF_OP_JEQ_IMM pc=61 dst=r1 src=r0 offset=9 imm=2
#line 167 "sample/bindmonitor_tailcall.c"
    if (r1 == IMMEDIATE(2))
#line 167 "sample/bindmonitor_tailcall.c"
        goto label_3;
    // EBPF_OP_LDXW pc=62 dst=r1 src=r8 offset=0 imm=0
#line 184 "sample/bindmonitor_tailcall.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JA pc=63 dst=r0 src=r0 offset=11 imm=0
#line 184 "sample/bindmonitor_tailcall.c"
    goto label_4;
label_2:
    // EBPF_OP_MOV64_IMM pc=64 dst=r9 src=r0 offset=0 imm=1
#line 184 "sample/bindmonitor_tailcall.c"
    r9 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=65 dst=r1 src=r8 offset=0 imm=0
#line 169 "sample/bindmonitor_tailcall.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_LDXW pc=66 dst=r2 src=r7 offset=0 imm=0
#line 169 "sample/bindmonitor_tailcall.c"
    r2 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_JGE_REG pc=67 dst=r1 src=r2 offset=19 imm=0
#line 169 "sample/bindmonitor_tailcall.c"
    if (r1 >= r2)
#line 169 "sample/bindmonitor_tailcall.c"
        goto label_7;
    // EBPF_OP_ADD64_IMM pc=68 dst=r1 src=r0 offset=0 imm=1
#line 173 "sample/bindmonitor_tailcall.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=69 dst=r8 src=r1 offset=0 imm=0
#line 173 "sample/bindmonitor_tailcall.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_JA pc=70 dst=r0 src=r0 offset=15 imm=0
#line 173 "sample/bindmonitor_tailcall.c"
    goto label_6;
label_3:
    // EBPF_OP_LDXW pc=71 dst=r1 src=r8 offset=0 imm=0
#line 176 "sample/bindmonitor_tailcall.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=72 dst=r1 src=r0 offset=6 imm=0
#line 176 "sample/bindmonitor_tailcall.c"
    if (r1 == IMMEDIATE(0))
#line 176 "sample/bindmonitor_tailcall.c"
        goto label_5;
    // EBPF_OP_ADD64_IMM pc=73 dst=r1 src=r0 offset=0 imm=-1
#line 177 "sample/bindmonitor_tailcall.c"
    r1 += IMMEDIATE(-1);
    // EBPF_OP_STXW pc=74 dst=r8 src=r1 offset=0 imm=0
#line 177 "sample/bindmonitor_tailcall.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
label_4:
    // EBPF_OP_MOV64_IMM pc=75 dst=r9 src=r0 offset=0 imm=0
#line 177 "sample/bindmonitor_tailcall.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_LSH64_IMM pc=76 dst=r1 src=r0 offset=0 imm=32
#line 184 "sample/bindmonitor_tailcall.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=77 dst=r1 src=r0 offset=0 imm=32
#line 184 "sample/bindmonitor_tailcall.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JNE_IMM pc=78 dst=r1 src=r0 offset=8 imm=0
#line 184 "sample/bindmonitor_tailcall.c"
    if (r1 != IMMEDIATE(0))
#line 184 "sample/bindmonitor_tailcall.c"
        goto label_7;
label_5:
    // EBPF_OP_LDXDW pc=79 dst=r1 src=r6 offset=16 imm=0
#line 185 "sample/bindmonitor_tailcall.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(16));
    // EBPF_OP_STXDW pc=80 dst=r10 src=r1 offset=-80 imm=0
#line 185 "sample/bindmonitor_tailcall.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=81 dst=r2 src=r10 offset=0 imm=0
#line 185 "sample/bindmonitor_tailcall.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=82 dst=r2 src=r0 offset=0 imm=-80
#line 185 "sample/bindmonitor_tailcall.c"
    r2 += IMMEDIATE(-80);
    // EBPF_OP_LDDW pc=83 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/bindmonitor_tailcall.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=85 dst=r0 src=r0 offset=0 imm=3
#line 186 "sample/bindmonitor_tailcall.c"
    r0 = BindMonitor_Callee1_helpers[3].address
#line 186 "sample/bindmonitor_tailcall.c"
         (r1, r2, r3, r4, r5);
#line 186 "sample/bindmonitor_tailcall.c"
    if ((BindMonitor_Callee1_helpers[3].tail_call) && (r0 == 0))
#line 186 "sample/bindmonitor_tailcall.c"
        return 0;
label_6:
    // EBPF_OP_MOV64_IMM pc=86 dst=r9 src=r0 offset=0 imm=0
#line 186 "sample/bindmonitor_tailcall.c"
    r9 = IMMEDIATE(0);
label_7:
    // EBPF_OP_MOV64_REG pc=87 dst=r0 src=r9 offset=0 imm=0
#line 190 "sample/bindmonitor_tailcall.c"
    r0 = r9;
    // EBPF_OP_EXIT pc=88 dst=r0 src=r0 offset=0 imm=0
#line 190 "sample/bindmonitor_tailcall.c"
    return r0;
#line 190 "sample/bindmonitor_tailcall.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        BindMonitor,
        "bind",
        "bind",
        "BindMonitor",
        BindMonitor_maps,
        2,
        BindMonitor_helpers,
        2,
        16,
        &BindMonitor_program_type_guid,
        &BindMonitor_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee0,
        "bind/0",
        "bind/0",
        "BindMonitor_Callee0",
        BindMonitor_Callee0_maps,
        2,
        BindMonitor_Callee0_helpers,
        2,
        16,
        &BindMonitor_Callee0_program_type_guid,
        &BindMonitor_Callee0_attach_type_guid,
    },
    {
        0,
        BindMonitor_Callee1,
        "bind/1",
        "bind/1",
        "BindMonitor_Callee1",
        BindMonitor_Callee1_maps,
        2,
        BindMonitor_Callee1_helpers,
        4,
        89,
        &BindMonitor_Callee1_program_type_guid,
        &BindMonitor_Callee1_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 3;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = 0;
    version->minor = 15;
    version->revision = 1;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t bindmonitor_tailcall_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};
