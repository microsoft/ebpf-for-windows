// Copyright (c) Microsoft Corporation
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
    {NULL,
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         56,                // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         1,                 // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         PIN_NONE,          // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "ingress_connection_policy_map"},
    {NULL,
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         56,                // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         1,                 // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         PIN_NONE,          // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "egress_connection_policy_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 2;
}

static helper_function_entry_t authorize_connect4_helpers[] = {
    {NULL, 1, "helper_id_1"},
};

static GUID authorize_connect4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID authorize_connect4_attach_type_guid = {
    0xa82e37b1, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t authorize_connect4_maps[] = {
    1,
};

#pragma code_seg(push, "cgroup~1")
static uint64_t
authorize_connect4(void* context)
#line 62 "sample/cgroup_sock_addr.c"
{
#line 62 "sample/cgroup_sock_addr.c"
    // Prologue
#line 62 "sample/cgroup_sock_addr.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 62 "sample/cgroup_sock_addr.c"
    register uint64_t r0 = 0;
#line 62 "sample/cgroup_sock_addr.c"
    register uint64_t r1 = 0;
#line 62 "sample/cgroup_sock_addr.c"
    register uint64_t r2 = 0;
#line 62 "sample/cgroup_sock_addr.c"
    register uint64_t r3 = 0;
#line 62 "sample/cgroup_sock_addr.c"
    register uint64_t r4 = 0;
#line 62 "sample/cgroup_sock_addr.c"
    register uint64_t r5 = 0;
#line 62 "sample/cgroup_sock_addr.c"
    register uint64_t r10 = 0;

#line 62 "sample/cgroup_sock_addr.c"
    r1 = (uintptr_t)context;
#line 62 "sample/cgroup_sock_addr.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r2 src=r0 offset=0 imm=0
#line 62 "sample/cgroup_sock_addr.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=1 dst=r10 src=r2 offset=-8 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=2 dst=r10 src=r2 offset=-16 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=3 dst=r10 src=r2 offset=-24 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=4 dst=r10 src=r2 offset=-32 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r2 offset=-40 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=6 dst=r10 src=r2 offset=-48 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=7 dst=r10 src=r2 offset=-56 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r2;
    // EBPF_OP_LDXW pc=8 dst=r2 src=r1 offset=24 imm=0
#line 37 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_STXW pc=9 dst=r10 src=r2 offset=-36 imm=0
#line 37 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-36)) = (uint32_t)r2;
    // EBPF_OP_LDXH pc=10 dst=r2 src=r1 offset=40 imm=0
#line 38 "sample/cgroup_sock_addr.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_STXH pc=11 dst=r10 src=r2 offset=-20 imm=0
#line 38 "sample/cgroup_sock_addr.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint16_t)r2;
    // EBPF_OP_LDXW pc=12 dst=r1 src=r1 offset=44 imm=0
#line 39 "sample/cgroup_sock_addr.c"
    r1 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_STXW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 39 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=14 dst=r2 src=r10 offset=0 imm=0
#line 39 "sample/cgroup_sock_addr.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=15 dst=r2 src=r0 offset=0 imm=-56
#line 39 "sample/cgroup_sock_addr.c"
    r2 += IMMEDIATE(-56);
    // EBPF_OP_LDDW pc=16 dst=r1 src=r0 offset=0 imm=0
#line 41 "sample/cgroup_sock_addr.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=1
#line 41 "sample/cgroup_sock_addr.c"
    r0 = authorize_connect4_helpers[0].address
#line 41 "sample/cgroup_sock_addr.c"
         (r1, r2, r3, r4, r5);
#line 41 "sample/cgroup_sock_addr.c"
    if ((authorize_connect4_helpers[0].tail_call) && (r0 == 0))
#line 41 "sample/cgroup_sock_addr.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=19 dst=r1 src=r0 offset=0 imm=0
#line 41 "sample/cgroup_sock_addr.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=20 dst=r0 src=r0 offset=0 imm=1
#line 41 "sample/cgroup_sock_addr.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=21 dst=r1 src=r0 offset=1 imm=0
#line 43 "sample/cgroup_sock_addr.c"
    if (r1 == IMMEDIATE(0))
#line 43 "sample/cgroup_sock_addr.c"
        goto label_1;
    // EBPF_OP_LDXW pc=22 dst=r0 src=r1 offset=0 imm=0
#line 43 "sample/cgroup_sock_addr.c"
    r0 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
label_1:
    // EBPF_OP_EXIT pc=23 dst=r0 src=r0 offset=0 imm=0
#line 64 "sample/cgroup_sock_addr.c"
    return r0;
#line 64 "sample/cgroup_sock_addr.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t authorize_connect6_helpers[] = {
    {NULL, 1, "helper_id_1"},
};

static GUID authorize_connect6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID authorize_connect6_attach_type_guid = {
    0xa82e37b2, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t authorize_connect6_maps[] = {
    1,
};

#pragma code_seg(push, "cgroup~2")
static uint64_t
authorize_connect6(void* context)
#line 69 "sample/cgroup_sock_addr.c"
{
#line 69 "sample/cgroup_sock_addr.c"
    // Prologue
#line 69 "sample/cgroup_sock_addr.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 69 "sample/cgroup_sock_addr.c"
    register uint64_t r0 = 0;
#line 69 "sample/cgroup_sock_addr.c"
    register uint64_t r1 = 0;
#line 69 "sample/cgroup_sock_addr.c"
    register uint64_t r2 = 0;
#line 69 "sample/cgroup_sock_addr.c"
    register uint64_t r3 = 0;
#line 69 "sample/cgroup_sock_addr.c"
    register uint64_t r4 = 0;
#line 69 "sample/cgroup_sock_addr.c"
    register uint64_t r5 = 0;
#line 69 "sample/cgroup_sock_addr.c"
    register uint64_t r10 = 0;

#line 69 "sample/cgroup_sock_addr.c"
    r1 = (uintptr_t)context;
#line 69 "sample/cgroup_sock_addr.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r2 src=r0 offset=0 imm=0
#line 69 "sample/cgroup_sock_addr.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=1 dst=r10 src=r2 offset=-8 imm=0
#line 49 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=2 dst=r10 src=r2 offset=-16 imm=0
#line 49 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=3 dst=r10 src=r2 offset=-24 imm=0
#line 49 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=4 dst=r10 src=r2 offset=-32 imm=0
#line 49 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r2 offset=-40 imm=0
#line 49 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=6 dst=r10 src=r2 offset=-48 imm=0
#line 49 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=7 dst=r10 src=r2 offset=-56 imm=0
#line 49 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r2;
    // EBPF_OP_LDXW pc=8 dst=r2 src=r1 offset=24 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_STXW pc=9 dst=r10 src=r2 offset=-36 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-36)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=10 dst=r2 src=r1 offset=28 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(28));
    // EBPF_OP_STXW pc=11 dst=r10 src=r2 offset=-32 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=12 dst=r2 src=r1 offset=32 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(32));
    // EBPF_OP_STXW pc=13 dst=r10 src=r2 offset=-28 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=14 dst=r2 src=r1 offset=36 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(36));
    // EBPF_OP_STXW pc=15 dst=r10 src=r2 offset=-24 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r2;
    // EBPF_OP_LDXH pc=16 dst=r2 src=r1 offset=40 imm=0
#line 52 "sample/cgroup_sock_addr.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_STXH pc=17 dst=r10 src=r2 offset=-20 imm=0
#line 52 "sample/cgroup_sock_addr.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint16_t)r2;
    // EBPF_OP_LDXW pc=18 dst=r1 src=r1 offset=44 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    r1 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_STXW pc=19 dst=r10 src=r1 offset=-16 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=20 dst=r2 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=21 dst=r2 src=r0 offset=0 imm=-56
#line 53 "sample/cgroup_sock_addr.c"
    r2 += IMMEDIATE(-56);
    // EBPF_OP_LDDW pc=22 dst=r1 src=r0 offset=0 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=1
#line 55 "sample/cgroup_sock_addr.c"
    r0 = authorize_connect6_helpers[0].address
#line 55 "sample/cgroup_sock_addr.c"
         (r1, r2, r3, r4, r5);
#line 55 "sample/cgroup_sock_addr.c"
    if ((authorize_connect6_helpers[0].tail_call) && (r0 == 0))
#line 55 "sample/cgroup_sock_addr.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=25 dst=r1 src=r0 offset=0 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=26 dst=r0 src=r0 offset=0 imm=1
#line 55 "sample/cgroup_sock_addr.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=27 dst=r1 src=r0 offset=1 imm=0
#line 57 "sample/cgroup_sock_addr.c"
    if (r1 == IMMEDIATE(0))
#line 57 "sample/cgroup_sock_addr.c"
        goto label_1;
    // EBPF_OP_LDXW pc=28 dst=r0 src=r1 offset=0 imm=0
#line 57 "sample/cgroup_sock_addr.c"
    r0 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
label_1:
    // EBPF_OP_EXIT pc=29 dst=r0 src=r0 offset=0 imm=0
#line 71 "sample/cgroup_sock_addr.c"
    return r0;
#line 71 "sample/cgroup_sock_addr.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t authorize_recv_accept4_helpers[] = {
    {NULL, 1, "helper_id_1"},
};

static GUID authorize_recv_accept4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID authorize_recv_accept4_attach_type_guid = {
    0xa82e37b3, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t authorize_recv_accept4_maps[] = {
    0,
};

#pragma code_seg(push, "cgroup~3")
static uint64_t
authorize_recv_accept4(void* context)
#line 76 "sample/cgroup_sock_addr.c"
{
#line 76 "sample/cgroup_sock_addr.c"
    // Prologue
#line 76 "sample/cgroup_sock_addr.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 76 "sample/cgroup_sock_addr.c"
    register uint64_t r0 = 0;
#line 76 "sample/cgroup_sock_addr.c"
    register uint64_t r1 = 0;
#line 76 "sample/cgroup_sock_addr.c"
    register uint64_t r2 = 0;
#line 76 "sample/cgroup_sock_addr.c"
    register uint64_t r3 = 0;
#line 76 "sample/cgroup_sock_addr.c"
    register uint64_t r4 = 0;
#line 76 "sample/cgroup_sock_addr.c"
    register uint64_t r5 = 0;
#line 76 "sample/cgroup_sock_addr.c"
    register uint64_t r10 = 0;

#line 76 "sample/cgroup_sock_addr.c"
    r1 = (uintptr_t)context;
#line 76 "sample/cgroup_sock_addr.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r2 src=r0 offset=0 imm=0
#line 76 "sample/cgroup_sock_addr.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=1 dst=r10 src=r2 offset=-8 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=2 dst=r10 src=r2 offset=-16 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=3 dst=r10 src=r2 offset=-24 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=4 dst=r10 src=r2 offset=-32 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r2 offset=-40 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=6 dst=r10 src=r2 offset=-48 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=7 dst=r10 src=r2 offset=-56 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r2;
    // EBPF_OP_LDXW pc=8 dst=r2 src=r1 offset=24 imm=0
#line 37 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_STXW pc=9 dst=r10 src=r2 offset=-36 imm=0
#line 37 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-36)) = (uint32_t)r2;
    // EBPF_OP_LDXH pc=10 dst=r2 src=r1 offset=40 imm=0
#line 38 "sample/cgroup_sock_addr.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_STXH pc=11 dst=r10 src=r2 offset=-20 imm=0
#line 38 "sample/cgroup_sock_addr.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint16_t)r2;
    // EBPF_OP_LDXW pc=12 dst=r1 src=r1 offset=44 imm=0
#line 39 "sample/cgroup_sock_addr.c"
    r1 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_STXW pc=13 dst=r10 src=r1 offset=-16 imm=0
#line 39 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=14 dst=r2 src=r10 offset=0 imm=0
#line 39 "sample/cgroup_sock_addr.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=15 dst=r2 src=r0 offset=0 imm=-56
#line 39 "sample/cgroup_sock_addr.c"
    r2 += IMMEDIATE(-56);
    // EBPF_OP_LDDW pc=16 dst=r1 src=r0 offset=0 imm=0
#line 41 "sample/cgroup_sock_addr.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=1
#line 41 "sample/cgroup_sock_addr.c"
    r0 = authorize_recv_accept4_helpers[0].address
#line 41 "sample/cgroup_sock_addr.c"
         (r1, r2, r3, r4, r5);
#line 41 "sample/cgroup_sock_addr.c"
    if ((authorize_recv_accept4_helpers[0].tail_call) && (r0 == 0))
#line 41 "sample/cgroup_sock_addr.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=19 dst=r1 src=r0 offset=0 imm=0
#line 41 "sample/cgroup_sock_addr.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=20 dst=r0 src=r0 offset=0 imm=1
#line 41 "sample/cgroup_sock_addr.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=21 dst=r1 src=r0 offset=1 imm=0
#line 43 "sample/cgroup_sock_addr.c"
    if (r1 == IMMEDIATE(0))
#line 43 "sample/cgroup_sock_addr.c"
        goto label_1;
    // EBPF_OP_LDXW pc=22 dst=r0 src=r1 offset=0 imm=0
#line 43 "sample/cgroup_sock_addr.c"
    r0 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
label_1:
    // EBPF_OP_EXIT pc=23 dst=r0 src=r0 offset=0 imm=0
#line 78 "sample/cgroup_sock_addr.c"
    return r0;
#line 78 "sample/cgroup_sock_addr.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t authorize_recv_accept6_helpers[] = {
    {NULL, 1, "helper_id_1"},
};

static GUID authorize_recv_accept6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID authorize_recv_accept6_attach_type_guid = {
    0xa82e37b4, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t authorize_recv_accept6_maps[] = {
    0,
};

#pragma code_seg(push, "cgroup~4")
static uint64_t
authorize_recv_accept6(void* context)
#line 83 "sample/cgroup_sock_addr.c"
{
#line 83 "sample/cgroup_sock_addr.c"
    // Prologue
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
    register uint64_t r10 = 0;

#line 83 "sample/cgroup_sock_addr.c"
    r1 = (uintptr_t)context;
#line 83 "sample/cgroup_sock_addr.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r2 src=r0 offset=0 imm=0
#line 83 "sample/cgroup_sock_addr.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=1 dst=r10 src=r2 offset=-8 imm=0
#line 49 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=2 dst=r10 src=r2 offset=-16 imm=0
#line 49 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=3 dst=r10 src=r2 offset=-24 imm=0
#line 49 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=4 dst=r10 src=r2 offset=-32 imm=0
#line 49 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r2 offset=-40 imm=0
#line 49 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=6 dst=r10 src=r2 offset=-48 imm=0
#line 49 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=7 dst=r10 src=r2 offset=-56 imm=0
#line 49 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r2;
    // EBPF_OP_LDXW pc=8 dst=r2 src=r1 offset=24 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_STXW pc=9 dst=r10 src=r2 offset=-36 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-36)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=10 dst=r2 src=r1 offset=28 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(28));
    // EBPF_OP_STXW pc=11 dst=r10 src=r2 offset=-32 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=12 dst=r2 src=r1 offset=32 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(32));
    // EBPF_OP_STXW pc=13 dst=r10 src=r2 offset=-28 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=14 dst=r2 src=r1 offset=36 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(36));
    // EBPF_OP_STXW pc=15 dst=r10 src=r2 offset=-24 imm=0
#line 51 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r2;
    // EBPF_OP_LDXH pc=16 dst=r2 src=r1 offset=40 imm=0
#line 52 "sample/cgroup_sock_addr.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_STXH pc=17 dst=r10 src=r2 offset=-20 imm=0
#line 52 "sample/cgroup_sock_addr.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint16_t)r2;
    // EBPF_OP_LDXW pc=18 dst=r1 src=r1 offset=44 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    r1 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_STXW pc=19 dst=r10 src=r1 offset=-16 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=20 dst=r2 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=21 dst=r2 src=r0 offset=0 imm=-56
#line 53 "sample/cgroup_sock_addr.c"
    r2 += IMMEDIATE(-56);
    // EBPF_OP_LDDW pc=22 dst=r1 src=r0 offset=0 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=1
#line 55 "sample/cgroup_sock_addr.c"
    r0 = authorize_recv_accept6_helpers[0].address
#line 55 "sample/cgroup_sock_addr.c"
         (r1, r2, r3, r4, r5);
#line 55 "sample/cgroup_sock_addr.c"
    if ((authorize_recv_accept6_helpers[0].tail_call) && (r0 == 0))
#line 55 "sample/cgroup_sock_addr.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=25 dst=r1 src=r0 offset=0 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=26 dst=r0 src=r0 offset=0 imm=1
#line 55 "sample/cgroup_sock_addr.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=27 dst=r1 src=r0 offset=1 imm=0
#line 57 "sample/cgroup_sock_addr.c"
    if (r1 == IMMEDIATE(0))
#line 57 "sample/cgroup_sock_addr.c"
        goto label_1;
    // EBPF_OP_LDXW pc=28 dst=r0 src=r1 offset=0 imm=0
#line 57 "sample/cgroup_sock_addr.c"
    r0 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
label_1:
    // EBPF_OP_EXIT pc=29 dst=r0 src=r0 offset=0 imm=0
#line 85 "sample/cgroup_sock_addr.c"
    return r0;
#line 85 "sample/cgroup_sock_addr.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        authorize_connect4,
        "cgroup~1",
        "cgroup/connect4",
        "authorize_connect4",
        authorize_connect4_maps,
        1,
        authorize_connect4_helpers,
        1,
        24,
        &authorize_connect4_program_type_guid,
        &authorize_connect4_attach_type_guid,
    },
    {
        0,
        authorize_connect6,
        "cgroup~2",
        "cgroup/connect6",
        "authorize_connect6",
        authorize_connect6_maps,
        1,
        authorize_connect6_helpers,
        1,
        30,
        &authorize_connect6_program_type_guid,
        &authorize_connect6_attach_type_guid,
    },
    {
        0,
        authorize_recv_accept4,
        "cgroup~3",
        "cgroup/recv_accept4",
        "authorize_recv_accept4",
        authorize_recv_accept4_maps,
        1,
        authorize_recv_accept4_helpers,
        1,
        24,
        &authorize_recv_accept4_program_type_guid,
        &authorize_recv_accept4_attach_type_guid,
    },
    {
        0,
        authorize_recv_accept6,
        "cgroup~4",
        "cgroup/recv_accept6",
        "authorize_recv_accept6",
        authorize_recv_accept6_maps,
        1,
        authorize_recv_accept6_helpers,
        1,
        30,
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
    version->minor = 9;
    version->revision = 0;
}

metadata_table_t cgroup_sock_addr_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
