// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from cgroup_sock_addr.o

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
         1,                 // Current Version.
         80,                // Struct size up to the last field.
         80,                // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         56,                // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         1,                 // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         19,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "egress_connection_policy_map"},
    {
     {0, 0},
     {
         1,                 // Current Version.
         80,                // Struct size up to the last field.
         80,                // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         56,                // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         1,                 // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         21,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "ingress_connection_policy_map"},
    {
     {0, 0},
     {
         1,                 // Current Version.
         80,                // Struct size up to the last field.
         80,                // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         56,                // Size in bytes of a map key.
         8,                 // Size in bytes of a map value.
         1000,              // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         26,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "socket_cookie_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 3;
}

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static helper_function_entry_t authorize_connect4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     26,
     "helper_id_26",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID authorize_connect4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID authorize_connect4_attach_type_guid = {
    0xa82e37b1, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t authorize_connect4_maps[] = {
    0,
    2,
};

#pragma code_seg(push, "cgroup~4")
static uint64_t
authorize_connect4(void* context, const program_runtime_context_t* runtime_context)
#line 83 "sample/cgroup_sock_addr.c"
{
#line 83 "sample/cgroup_sock_addr.c"
    // Prologue.
#line 83 "sample/cgroup_sock_addr.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 83 "sample/cgroup_sock_addr.c"
    register uint64_t r0 = 0;
#line 83 "sample/cgroup_sock_addr.c"
    register uint64_t r1 = 0;
#line 83 "sample/cgroup_sock_addr.c"
    register uint64_t r2 = 0;
#line 83 "sample/cgroup_sock_addr.c"
    register uint64_t r3 = 0;
#line 83 "sample/cgroup_sock_addr.c"
    register uint64_t r4 = 0;
#line 83 "sample/cgroup_sock_addr.c"
    register uint64_t r5 = 0;
#line 83 "sample/cgroup_sock_addr.c"
    register uint64_t r6 = 0;
#line 83 "sample/cgroup_sock_addr.c"
    register uint64_t r10 = 0;

#line 83 "sample/cgroup_sock_addr.c"
    r1 = (uintptr_t)context;
#line 83 "sample/cgroup_sock_addr.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r2 src=r0 offset=0 imm=0
#line 83 "sample/cgroup_sock_addr.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=1 dst=r10 src=r2 offset=-16 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=2 dst=r10 src=r2 offset=-24 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=3 dst=r10 src=r2 offset=-32 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=4 dst=r10 src=r2 offset=-40 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r2 offset=-48 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=6 dst=r10 src=r2 offset=-56 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=7 dst=r10 src=r2 offset=-64 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r2;
    // EBPF_OP_LDXW pc=8 dst=r2 src=r1 offset=24 imm=0
#line 54 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_STXW pc=9 dst=r10 src=r2 offset=-44 imm=0
#line 54 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-44)) = (uint32_t)r2;
    // EBPF_OP_LDXH pc=10 dst=r2 src=r1 offset=40 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_STXH pc=11 dst=r10 src=r2 offset=-28 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint16_t)r2;
    // EBPF_OP_LDXW pc=12 dst=r2 src=r1 offset=44 imm=0
#line 56 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_STXW pc=13 dst=r10 src=r2 offset=-24 imm=0
#line 56 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r2;
    // EBPF_OP_CALL pc=14 dst=r0 src=r0 offset=0 imm=26
#line 44 "sample/cgroup_sock_addr.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 44 "sample/cgroup_sock_addr.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 44 "sample/cgroup_sock_addr.c"
        return 0;
#line 44 "sample/cgroup_sock_addr.c"
    }
    // EBPF_OP_STXDW pc=15 dst=r10 src=r0 offset=-8 imm=0
#line 44 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r0;
    // EBPF_OP_MOV64_REG pc=16 dst=r6 src=r10 offset=0 imm=0
#line 44 "sample/cgroup_sock_addr.c"
    r6 = r10;
    // EBPF_OP_ADD64_IMM pc=17 dst=r6 src=r0 offset=0 imm=-64
#line 44 "sample/cgroup_sock_addr.c"
    r6 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_REG pc=18 dst=r3 src=r10 offset=0 imm=0
#line 44 "sample/cgroup_sock_addr.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=19 dst=r3 src=r0 offset=0 imm=-8
#line 44 "sample/cgroup_sock_addr.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=20 dst=r1 src=r1 offset=0 imm=3
#line 45 "sample/cgroup_sock_addr.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_MOV64_REG pc=22 dst=r2 src=r6 offset=0 imm=0
#line 45 "sample/cgroup_sock_addr.c"
    r2 = r6;
    // EBPF_OP_MOV64_IMM pc=23 dst=r4 src=r0 offset=0 imm=0
#line 45 "sample/cgroup_sock_addr.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=2
#line 45 "sample/cgroup_sock_addr.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 45 "sample/cgroup_sock_addr.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 45 "sample/cgroup_sock_addr.c"
        return 0;
#line 45 "sample/cgroup_sock_addr.c"
    }
    // EBPF_OP_LDDW pc=25 dst=r1 src=r1 offset=0 imm=1
#line 60 "sample/cgroup_sock_addr.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_REG pc=27 dst=r2 src=r6 offset=0 imm=0
#line 60 "sample/cgroup_sock_addr.c"
    r2 = r6;
    // EBPF_OP_CALL pc=28 dst=r0 src=r0 offset=0 imm=1
#line 60 "sample/cgroup_sock_addr.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 60 "sample/cgroup_sock_addr.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 60 "sample/cgroup_sock_addr.c"
        return 0;
#line 60 "sample/cgroup_sock_addr.c"
    }
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r0 offset=0 imm=0
#line 60 "sample/cgroup_sock_addr.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=30 dst=r0 src=r0 offset=0 imm=1
#line 60 "sample/cgroup_sock_addr.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=31 dst=r1 src=r0 offset=1 imm=0
#line 62 "sample/cgroup_sock_addr.c"
    if (r1 == IMMEDIATE(0)) {
#line 62 "sample/cgroup_sock_addr.c"
        goto label_1;
#line 62 "sample/cgroup_sock_addr.c"
    }
    // EBPF_OP_LDXW pc=32 dst=r0 src=r1 offset=0 imm=0
#line 62 "sample/cgroup_sock_addr.c"
    r0 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
label_1:
    // EBPF_OP_EXIT pc=33 dst=r0 src=r0 offset=0 imm=0
#line 85 "sample/cgroup_sock_addr.c"
    return r0;
#line 83 "sample/cgroup_sock_addr.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t authorize_connect6_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     26,
     "helper_id_26",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID authorize_connect6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID authorize_connect6_attach_type_guid = {
    0xa82e37b2, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t authorize_connect6_maps[] = {
    0,
    2,
};

#pragma code_seg(push, "cgroup~3")
static uint64_t
authorize_connect6(void* context, const program_runtime_context_t* runtime_context)
#line 90 "sample/cgroup_sock_addr.c"
{
#line 90 "sample/cgroup_sock_addr.c"
    // Prologue.
#line 90 "sample/cgroup_sock_addr.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 90 "sample/cgroup_sock_addr.c"
    register uint64_t r0 = 0;
#line 90 "sample/cgroup_sock_addr.c"
    register uint64_t r1 = 0;
#line 90 "sample/cgroup_sock_addr.c"
    register uint64_t r2 = 0;
#line 90 "sample/cgroup_sock_addr.c"
    register uint64_t r3 = 0;
#line 90 "sample/cgroup_sock_addr.c"
    register uint64_t r4 = 0;
#line 90 "sample/cgroup_sock_addr.c"
    register uint64_t r5 = 0;
#line 90 "sample/cgroup_sock_addr.c"
    register uint64_t r6 = 0;
#line 90 "sample/cgroup_sock_addr.c"
    register uint64_t r10 = 0;

#line 90 "sample/cgroup_sock_addr.c"
    r1 = (uintptr_t)context;
#line 90 "sample/cgroup_sock_addr.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r2 src=r0 offset=0 imm=0
#line 90 "sample/cgroup_sock_addr.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=1 dst=r10 src=r2 offset=-16 imm=0
#line 68 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=2 dst=r10 src=r2 offset=-24 imm=0
#line 68 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=3 dst=r10 src=r2 offset=-32 imm=0
#line 68 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=4 dst=r10 src=r2 offset=-40 imm=0
#line 68 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r2 offset=-48 imm=0
#line 68 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=6 dst=r10 src=r2 offset=-56 imm=0
#line 68 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=7 dst=r10 src=r2 offset=-64 imm=0
#line 68 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r2;
    // EBPF_OP_LDXW pc=8 dst=r2 src=r1 offset=24 imm=0
#line 70 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_STXW pc=9 dst=r10 src=r2 offset=-44 imm=0
#line 70 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-44)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=10 dst=r2 src=r1 offset=28 imm=0
#line 70 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(28));
    // EBPF_OP_STXW pc=11 dst=r10 src=r2 offset=-40 imm=0
#line 70 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=12 dst=r2 src=r1 offset=32 imm=0
#line 70 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(32));
    // EBPF_OP_STXW pc=13 dst=r10 src=r2 offset=-36 imm=0
#line 70 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-36)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=14 dst=r2 src=r1 offset=36 imm=0
#line 70 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(36));
    // EBPF_OP_STXW pc=15 dst=r10 src=r2 offset=-32 imm=0
#line 70 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r2;
    // EBPF_OP_LDXH pc=16 dst=r2 src=r1 offset=40 imm=0
#line 71 "sample/cgroup_sock_addr.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_STXH pc=17 dst=r10 src=r2 offset=-28 imm=0
#line 71 "sample/cgroup_sock_addr.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint16_t)r2;
    // EBPF_OP_LDXW pc=18 dst=r2 src=r1 offset=44 imm=0
#line 72 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_STXW pc=19 dst=r10 src=r2 offset=-24 imm=0
#line 72 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r2;
    // EBPF_OP_CALL pc=20 dst=r0 src=r0 offset=0 imm=26
#line 44 "sample/cgroup_sock_addr.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 44 "sample/cgroup_sock_addr.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 44 "sample/cgroup_sock_addr.c"
        return 0;
#line 44 "sample/cgroup_sock_addr.c"
    }
    // EBPF_OP_STXDW pc=21 dst=r10 src=r0 offset=-8 imm=0
#line 44 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r0;
    // EBPF_OP_MOV64_REG pc=22 dst=r6 src=r10 offset=0 imm=0
#line 44 "sample/cgroup_sock_addr.c"
    r6 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r6 src=r0 offset=0 imm=-64
#line 44 "sample/cgroup_sock_addr.c"
    r6 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_REG pc=24 dst=r3 src=r10 offset=0 imm=0
#line 44 "sample/cgroup_sock_addr.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=25 dst=r3 src=r0 offset=0 imm=-8
#line 44 "sample/cgroup_sock_addr.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=26 dst=r1 src=r1 offset=0 imm=3
#line 45 "sample/cgroup_sock_addr.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_MOV64_REG pc=28 dst=r2 src=r6 offset=0 imm=0
#line 45 "sample/cgroup_sock_addr.c"
    r2 = r6;
    // EBPF_OP_MOV64_IMM pc=29 dst=r4 src=r0 offset=0 imm=0
#line 45 "sample/cgroup_sock_addr.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=30 dst=r0 src=r0 offset=0 imm=2
#line 45 "sample/cgroup_sock_addr.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 45 "sample/cgroup_sock_addr.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 45 "sample/cgroup_sock_addr.c"
        return 0;
#line 45 "sample/cgroup_sock_addr.c"
    }
    // EBPF_OP_LDDW pc=31 dst=r1 src=r1 offset=0 imm=1
#line 76 "sample/cgroup_sock_addr.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_REG pc=33 dst=r2 src=r6 offset=0 imm=0
#line 76 "sample/cgroup_sock_addr.c"
    r2 = r6;
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=1
#line 76 "sample/cgroup_sock_addr.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 76 "sample/cgroup_sock_addr.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 76 "sample/cgroup_sock_addr.c"
        return 0;
#line 76 "sample/cgroup_sock_addr.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/cgroup_sock_addr.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=36 dst=r0 src=r0 offset=0 imm=1
#line 76 "sample/cgroup_sock_addr.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=37 dst=r1 src=r0 offset=1 imm=0
#line 78 "sample/cgroup_sock_addr.c"
    if (r1 == IMMEDIATE(0)) {
#line 78 "sample/cgroup_sock_addr.c"
        goto label_1;
#line 78 "sample/cgroup_sock_addr.c"
    }
    // EBPF_OP_LDXW pc=38 dst=r0 src=r1 offset=0 imm=0
#line 78 "sample/cgroup_sock_addr.c"
    r0 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
label_1:
    // EBPF_OP_EXIT pc=39 dst=r0 src=r0 offset=0 imm=0
#line 92 "sample/cgroup_sock_addr.c"
    return r0;
#line 90 "sample/cgroup_sock_addr.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t authorize_recv_accept4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     26,
     "helper_id_26",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID authorize_recv_accept4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID authorize_recv_accept4_attach_type_guid = {
    0xa82e37b3, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t authorize_recv_accept4_maps[] = {
    1,
    2,
};

#pragma code_seg(push, "cgroup~2")
static uint64_t
authorize_recv_accept4(void* context, const program_runtime_context_t* runtime_context)
#line 97 "sample/cgroup_sock_addr.c"
{
#line 97 "sample/cgroup_sock_addr.c"
    // Prologue.
#line 97 "sample/cgroup_sock_addr.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 97 "sample/cgroup_sock_addr.c"
    register uint64_t r0 = 0;
#line 97 "sample/cgroup_sock_addr.c"
    register uint64_t r1 = 0;
#line 97 "sample/cgroup_sock_addr.c"
    register uint64_t r2 = 0;
#line 97 "sample/cgroup_sock_addr.c"
    register uint64_t r3 = 0;
#line 97 "sample/cgroup_sock_addr.c"
    register uint64_t r4 = 0;
#line 97 "sample/cgroup_sock_addr.c"
    register uint64_t r5 = 0;
#line 97 "sample/cgroup_sock_addr.c"
    register uint64_t r6 = 0;
#line 97 "sample/cgroup_sock_addr.c"
    register uint64_t r10 = 0;

#line 97 "sample/cgroup_sock_addr.c"
    r1 = (uintptr_t)context;
#line 97 "sample/cgroup_sock_addr.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r2 src=r0 offset=0 imm=0
#line 97 "sample/cgroup_sock_addr.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=1 dst=r10 src=r2 offset=-16 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=2 dst=r10 src=r2 offset=-24 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=3 dst=r10 src=r2 offset=-32 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=4 dst=r10 src=r2 offset=-40 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r2 offset=-48 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=6 dst=r10 src=r2 offset=-56 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=7 dst=r10 src=r2 offset=-64 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r2;
    // EBPF_OP_LDXW pc=8 dst=r2 src=r1 offset=24 imm=0
#line 54 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_STXW pc=9 dst=r10 src=r2 offset=-44 imm=0
#line 54 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-44)) = (uint32_t)r2;
    // EBPF_OP_LDXH pc=10 dst=r2 src=r1 offset=40 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_STXH pc=11 dst=r10 src=r2 offset=-28 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint16_t)r2;
    // EBPF_OP_LDXW pc=12 dst=r2 src=r1 offset=44 imm=0
#line 56 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_STXW pc=13 dst=r10 src=r2 offset=-24 imm=0
#line 56 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r2;
    // EBPF_OP_CALL pc=14 dst=r0 src=r0 offset=0 imm=26
#line 44 "sample/cgroup_sock_addr.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 44 "sample/cgroup_sock_addr.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 44 "sample/cgroup_sock_addr.c"
        return 0;
#line 44 "sample/cgroup_sock_addr.c"
    }
    // EBPF_OP_STXDW pc=15 dst=r10 src=r0 offset=-8 imm=0
#line 44 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r0;
    // EBPF_OP_MOV64_REG pc=16 dst=r6 src=r10 offset=0 imm=0
#line 44 "sample/cgroup_sock_addr.c"
    r6 = r10;
    // EBPF_OP_ADD64_IMM pc=17 dst=r6 src=r0 offset=0 imm=-64
#line 44 "sample/cgroup_sock_addr.c"
    r6 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_REG pc=18 dst=r3 src=r10 offset=0 imm=0
#line 44 "sample/cgroup_sock_addr.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=19 dst=r3 src=r0 offset=0 imm=-8
#line 44 "sample/cgroup_sock_addr.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=20 dst=r1 src=r1 offset=0 imm=3
#line 45 "sample/cgroup_sock_addr.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_MOV64_REG pc=22 dst=r2 src=r6 offset=0 imm=0
#line 45 "sample/cgroup_sock_addr.c"
    r2 = r6;
    // EBPF_OP_MOV64_IMM pc=23 dst=r4 src=r0 offset=0 imm=0
#line 45 "sample/cgroup_sock_addr.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=2
#line 45 "sample/cgroup_sock_addr.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 45 "sample/cgroup_sock_addr.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 45 "sample/cgroup_sock_addr.c"
        return 0;
#line 45 "sample/cgroup_sock_addr.c"
    }
    // EBPF_OP_LDDW pc=25 dst=r1 src=r1 offset=0 imm=2
#line 60 "sample/cgroup_sock_addr.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_REG pc=27 dst=r2 src=r6 offset=0 imm=0
#line 60 "sample/cgroup_sock_addr.c"
    r2 = r6;
    // EBPF_OP_CALL pc=28 dst=r0 src=r0 offset=0 imm=1
#line 60 "sample/cgroup_sock_addr.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 60 "sample/cgroup_sock_addr.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 60 "sample/cgroup_sock_addr.c"
        return 0;
#line 60 "sample/cgroup_sock_addr.c"
    }
    // EBPF_OP_MOV64_REG pc=29 dst=r1 src=r0 offset=0 imm=0
#line 60 "sample/cgroup_sock_addr.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=30 dst=r0 src=r0 offset=0 imm=1
#line 60 "sample/cgroup_sock_addr.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=31 dst=r1 src=r0 offset=1 imm=0
#line 62 "sample/cgroup_sock_addr.c"
    if (r1 == IMMEDIATE(0)) {
#line 62 "sample/cgroup_sock_addr.c"
        goto label_1;
#line 62 "sample/cgroup_sock_addr.c"
    }
    // EBPF_OP_LDXW pc=32 dst=r0 src=r1 offset=0 imm=0
#line 62 "sample/cgroup_sock_addr.c"
    r0 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
label_1:
    // EBPF_OP_EXIT pc=33 dst=r0 src=r0 offset=0 imm=0
#line 99 "sample/cgroup_sock_addr.c"
    return r0;
#line 97 "sample/cgroup_sock_addr.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t authorize_recv_accept6_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     26,
     "helper_id_26",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID authorize_recv_accept6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID authorize_recv_accept6_attach_type_guid = {
    0xa82e37b4, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t authorize_recv_accept6_maps[] = {
    1,
    2,
};

#pragma code_seg(push, "cgroup~1")
static uint64_t
authorize_recv_accept6(void* context, const program_runtime_context_t* runtime_context)
#line 104 "sample/cgroup_sock_addr.c"
{
#line 104 "sample/cgroup_sock_addr.c"
    // Prologue.
#line 104 "sample/cgroup_sock_addr.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 104 "sample/cgroup_sock_addr.c"
    register uint64_t r0 = 0;
#line 104 "sample/cgroup_sock_addr.c"
    register uint64_t r1 = 0;
#line 104 "sample/cgroup_sock_addr.c"
    register uint64_t r2 = 0;
#line 104 "sample/cgroup_sock_addr.c"
    register uint64_t r3 = 0;
#line 104 "sample/cgroup_sock_addr.c"
    register uint64_t r4 = 0;
#line 104 "sample/cgroup_sock_addr.c"
    register uint64_t r5 = 0;
#line 104 "sample/cgroup_sock_addr.c"
    register uint64_t r6 = 0;
#line 104 "sample/cgroup_sock_addr.c"
    register uint64_t r10 = 0;

#line 104 "sample/cgroup_sock_addr.c"
    r1 = (uintptr_t)context;
#line 104 "sample/cgroup_sock_addr.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r2 src=r0 offset=0 imm=0
#line 104 "sample/cgroup_sock_addr.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=1 dst=r10 src=r2 offset=-16 imm=0
#line 68 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=2 dst=r10 src=r2 offset=-24 imm=0
#line 68 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=3 dst=r10 src=r2 offset=-32 imm=0
#line 68 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=4 dst=r10 src=r2 offset=-40 imm=0
#line 68 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r2 offset=-48 imm=0
#line 68 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=6 dst=r10 src=r2 offset=-56 imm=0
#line 68 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=7 dst=r10 src=r2 offset=-64 imm=0
#line 68 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r2;
    // EBPF_OP_LDXW pc=8 dst=r2 src=r1 offset=24 imm=0
#line 70 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_STXW pc=9 dst=r10 src=r2 offset=-44 imm=0
#line 70 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-44)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=10 dst=r2 src=r1 offset=28 imm=0
#line 70 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(28));
    // EBPF_OP_STXW pc=11 dst=r10 src=r2 offset=-40 imm=0
#line 70 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=12 dst=r2 src=r1 offset=32 imm=0
#line 70 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(32));
    // EBPF_OP_STXW pc=13 dst=r10 src=r2 offset=-36 imm=0
#line 70 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-36)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=14 dst=r2 src=r1 offset=36 imm=0
#line 70 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(36));
    // EBPF_OP_STXW pc=15 dst=r10 src=r2 offset=-32 imm=0
#line 70 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r2;
    // EBPF_OP_LDXH pc=16 dst=r2 src=r1 offset=40 imm=0
#line 71 "sample/cgroup_sock_addr.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_STXH pc=17 dst=r10 src=r2 offset=-28 imm=0
#line 71 "sample/cgroup_sock_addr.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint16_t)r2;
    // EBPF_OP_LDXW pc=18 dst=r2 src=r1 offset=44 imm=0
#line 72 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_STXW pc=19 dst=r10 src=r2 offset=-24 imm=0
#line 72 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r2;
    // EBPF_OP_CALL pc=20 dst=r0 src=r0 offset=0 imm=26
#line 44 "sample/cgroup_sock_addr.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 44 "sample/cgroup_sock_addr.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 44 "sample/cgroup_sock_addr.c"
        return 0;
#line 44 "sample/cgroup_sock_addr.c"
    }
    // EBPF_OP_STXDW pc=21 dst=r10 src=r0 offset=-8 imm=0
#line 44 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r0;
    // EBPF_OP_MOV64_REG pc=22 dst=r6 src=r10 offset=0 imm=0
#line 44 "sample/cgroup_sock_addr.c"
    r6 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r6 src=r0 offset=0 imm=-64
#line 44 "sample/cgroup_sock_addr.c"
    r6 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_REG pc=24 dst=r3 src=r10 offset=0 imm=0
#line 44 "sample/cgroup_sock_addr.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=25 dst=r3 src=r0 offset=0 imm=-8
#line 44 "sample/cgroup_sock_addr.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=26 dst=r1 src=r1 offset=0 imm=3
#line 45 "sample/cgroup_sock_addr.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_MOV64_REG pc=28 dst=r2 src=r6 offset=0 imm=0
#line 45 "sample/cgroup_sock_addr.c"
    r2 = r6;
    // EBPF_OP_MOV64_IMM pc=29 dst=r4 src=r0 offset=0 imm=0
#line 45 "sample/cgroup_sock_addr.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=30 dst=r0 src=r0 offset=0 imm=2
#line 45 "sample/cgroup_sock_addr.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 45 "sample/cgroup_sock_addr.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 45 "sample/cgroup_sock_addr.c"
        return 0;
#line 45 "sample/cgroup_sock_addr.c"
    }
    // EBPF_OP_LDDW pc=31 dst=r1 src=r1 offset=0 imm=2
#line 76 "sample/cgroup_sock_addr.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_REG pc=33 dst=r2 src=r6 offset=0 imm=0
#line 76 "sample/cgroup_sock_addr.c"
    r2 = r6;
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=1
#line 76 "sample/cgroup_sock_addr.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 76 "sample/cgroup_sock_addr.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 76 "sample/cgroup_sock_addr.c"
        return 0;
#line 76 "sample/cgroup_sock_addr.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/cgroup_sock_addr.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=36 dst=r0 src=r0 offset=0 imm=1
#line 76 "sample/cgroup_sock_addr.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=37 dst=r1 src=r0 offset=1 imm=0
#line 78 "sample/cgroup_sock_addr.c"
    if (r1 == IMMEDIATE(0)) {
#line 78 "sample/cgroup_sock_addr.c"
        goto label_1;
#line 78 "sample/cgroup_sock_addr.c"
    }
    // EBPF_OP_LDXW pc=38 dst=r0 src=r1 offset=0 imm=0
#line 78 "sample/cgroup_sock_addr.c"
    r0 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
label_1:
    // EBPF_OP_EXIT pc=39 dst=r0 src=r0 offset=0 imm=0
#line 106 "sample/cgroup_sock_addr.c"
    return r0;
#line 104 "sample/cgroup_sock_addr.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        authorize_connect4,
        "cgroup~4",
        "cgroup/connect4",
        "authorize_connect4",
        authorize_connect4_maps,
        2,
        authorize_connect4_helpers,
        3,
        34,
        &authorize_connect4_program_type_guid,
        &authorize_connect4_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        authorize_connect6,
        "cgroup~3",
        "cgroup/connect6",
        "authorize_connect6",
        authorize_connect6_maps,
        2,
        authorize_connect6_helpers,
        3,
        40,
        &authorize_connect6_program_type_guid,
        &authorize_connect6_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        authorize_recv_accept4,
        "cgroup~2",
        "cgroup/recv_accept4",
        "authorize_recv_accept4",
        authorize_recv_accept4_maps,
        2,
        authorize_recv_accept4_helpers,
        3,
        34,
        &authorize_recv_accept4_program_type_guid,
        &authorize_recv_accept4_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        authorize_recv_accept6,
        "cgroup~1",
        "cgroup/recv_accept6",
        "authorize_recv_accept6",
        authorize_recv_accept6_maps,
        2,
        authorize_recv_accept6_helpers,
        3,
        40,
        &authorize_recv_accept6_program_type_guid,
        &authorize_recv_accept6_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 4;
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

metadata_table_t cgroup_sock_addr_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
