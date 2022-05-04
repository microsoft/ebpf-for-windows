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
static map_entry_t _maps[] = {
    {NULL,
     {
         1,
         44,
         4,
         1,
         0,
         0,
         0,
         0,
     },
     "ingress_connection_policy_map"},
    {NULL,
     {
         1,
         44,
         4,
         1,
         0,
         0,
         0,
         0,
     },
     "egress_connection_policy_map"},
};

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

static uint64_t
authorize_connect4(void* context)
{
#line 66 "sample/cgroup_sock_addr.c"
    // Prologue
#line 66 "sample/cgroup_sock_addr.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 66 "sample/cgroup_sock_addr.c"
    register uint64_t r0 = 0;
#line 66 "sample/cgroup_sock_addr.c"
    register uint64_t r1 = 0;
#line 66 "sample/cgroup_sock_addr.c"
    register uint64_t r2 = 0;
#line 66 "sample/cgroup_sock_addr.c"
    register uint64_t r3 = 0;
#line 66 "sample/cgroup_sock_addr.c"
    register uint64_t r4 = 0;
#line 66 "sample/cgroup_sock_addr.c"
    register uint64_t r5 = 0;
#line 66 "sample/cgroup_sock_addr.c"
    register uint64_t r10 = 0;

#line 66 "sample/cgroup_sock_addr.c"
    r1 = (uintptr_t)context;
#line 66 "sample/cgroup_sock_addr.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r2 src=r0 offset=0 imm=0
#line 66 "sample/cgroup_sock_addr.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r2 offset=-12 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=2 dst=r10 src=r2 offset=-16 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=3 dst=r10 src=r2 offset=-20 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=4 dst=r10 src=r2 offset=-24 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=5 dst=r10 src=r2 offset=-28 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=6 dst=r10 src=r2 offset=-32 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=7 dst=r10 src=r2 offset=-36 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-36)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=8 dst=r10 src=r2 offset=-40 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=9 dst=r10 src=r2 offset=-44 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-44)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=10 dst=r2 src=r1 offset=4 imm=0
#line 37 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(4));
    // EBPF_OP_STXW pc=11 dst=r10 src=r2 offset=-48 imm=0
#line 37 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint32_t)r2;
    // EBPF_OP_LDXH pc=12 dst=r2 src=r1 offset=20 imm=0
#line 38 "sample/cgroup_sock_addr.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(20));
    // EBPF_OP_STXH pc=13 dst=r10 src=r2 offset=-32 imm=0
#line 38 "sample/cgroup_sock_addr.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r2;
    // EBPF_OP_LDXW pc=14 dst=r2 src=r1 offset=24 imm=0
#line 39 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_STXW pc=15 dst=r10 src=r2 offset=-28 imm=0
#line 39 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint32_t)r2;
    // EBPF_OP_LDXH pc=16 dst=r2 src=r1 offset=40 imm=0
#line 40 "sample/cgroup_sock_addr.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_STXH pc=17 dst=r10 src=r2 offset=-12 imm=0
#line 40 "sample/cgroup_sock_addr.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r2;
    // EBPF_OP_LDXW pc=18 dst=r1 src=r1 offset=44 imm=0
#line 41 "sample/cgroup_sock_addr.c"
    r1 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_STXW pc=19 dst=r10 src=r1 offset=-8 imm=0
#line 41 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=20 dst=r2 src=r10 offset=0 imm=0
#line 41 "sample/cgroup_sock_addr.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=21 dst=r2 src=r0 offset=0 imm=-48
#line 41 "sample/cgroup_sock_addr.c"
    r2 += IMMEDIATE(-48);
    // EBPF_OP_LDDW pc=22 dst=r1 src=r0 offset=0 imm=0
#line 43 "sample/cgroup_sock_addr.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=1
#line 43 "sample/cgroup_sock_addr.c"
    r0 = authorize_connect4_helpers[0].address
#line 43 "sample/cgroup_sock_addr.c"
         (r1, r2, r3, r4, r5);
#line 43 "sample/cgroup_sock_addr.c"
    if ((authorize_connect4_helpers[0].tail_call) && (r0 == 0))
#line 43 "sample/cgroup_sock_addr.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=25 dst=r1 src=r0 offset=0 imm=0
#line 43 "sample/cgroup_sock_addr.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=26 dst=r0 src=r0 offset=0 imm=1
#line 43 "sample/cgroup_sock_addr.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=27 dst=r1 src=r0 offset=1 imm=0
#line 45 "sample/cgroup_sock_addr.c"
    if (r1 == IMMEDIATE(0))
#line 45 "sample/cgroup_sock_addr.c"
        goto label_1;
        // EBPF_OP_LDXW pc=28 dst=r0 src=r1 offset=0 imm=0
#line 45 "sample/cgroup_sock_addr.c"
    r0 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
label_1:
    // EBPF_OP_EXIT pc=29 dst=r0 src=r0 offset=0 imm=0
#line 68 "sample/cgroup_sock_addr.c"
    return r0;
#line 68 "sample/cgroup_sock_addr.c"
}
#line __LINE__ __FILE__

static helper_function_entry_t authorize_connect6_helpers[] = {
    {NULL, 1, "helper_id_1"},
};

static GUID authorize_connect6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID authorize_connect6_attach_type_guid = {
    0x00000000, 0x0000, 0x0000, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
static uint16_t authorize_connect6_maps[] = {
    1,
};

static uint64_t
authorize_connect6(void* context)
{
#line 73 "sample/cgroup_sock_addr.c"
    // Prologue
#line 73 "sample/cgroup_sock_addr.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 73 "sample/cgroup_sock_addr.c"
    register uint64_t r0 = 0;
#line 73 "sample/cgroup_sock_addr.c"
    register uint64_t r1 = 0;
#line 73 "sample/cgroup_sock_addr.c"
    register uint64_t r2 = 0;
#line 73 "sample/cgroup_sock_addr.c"
    register uint64_t r3 = 0;
#line 73 "sample/cgroup_sock_addr.c"
    register uint64_t r4 = 0;
#line 73 "sample/cgroup_sock_addr.c"
    register uint64_t r5 = 0;
#line 73 "sample/cgroup_sock_addr.c"
    register uint64_t r10 = 0;

#line 73 "sample/cgroup_sock_addr.c"
    r1 = (uintptr_t)context;
#line 73 "sample/cgroup_sock_addr.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r2 src=r0 offset=0 imm=0
#line 73 "sample/cgroup_sock_addr.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=1 dst=r10 src=r2 offset=-16 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=2 dst=r10 src=r2 offset=-24 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=3 dst=r10 src=r2 offset=-32 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r2;
    // EBPF_OP_LDXW pc=4 dst=r2 src=r1 offset=8 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(8));
    // EBPF_OP_LSH64_IMM pc=5 dst=r2 src=r0 offset=0 imm=32
#line 53 "sample/cgroup_sock_addr.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_LDXW pc=6 dst=r3 src=r1 offset=4 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    r3 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(4));
    // EBPF_OP_OR64_REG pc=7 dst=r2 src=r3 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    r2 |= r3;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r2 offset=-48 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r2;
    // EBPF_OP_LDXW pc=9 dst=r2 src=r1 offset=16 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(16));
    // EBPF_OP_LSH64_IMM pc=10 dst=r2 src=r0 offset=0 imm=32
#line 53 "sample/cgroup_sock_addr.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_LDXW pc=11 dst=r3 src=r1 offset=12 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    r3 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(12));
    // EBPF_OP_OR64_REG pc=12 dst=r2 src=r3 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    r2 |= r3;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r2 offset=-40 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r2;
    // EBPF_OP_LDXH pc=14 dst=r2 src=r1 offset=20 imm=0
#line 54 "sample/cgroup_sock_addr.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(20));
    // EBPF_OP_STXH pc=15 dst=r10 src=r2 offset=-32 imm=0
#line 54 "sample/cgroup_sock_addr.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r2;
    // EBPF_OP_LDXW pc=16 dst=r2 src=r1 offset=24 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_STXW pc=17 dst=r10 src=r2 offset=-28 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=18 dst=r2 src=r1 offset=28 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(28));
    // EBPF_OP_STXW pc=19 dst=r10 src=r2 offset=-24 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=20 dst=r2 src=r1 offset=32 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(32));
    // EBPF_OP_STXW pc=21 dst=r10 src=r2 offset=-20 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=22 dst=r2 src=r1 offset=36 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(36));
    // EBPF_OP_STXW pc=23 dst=r10 src=r2 offset=-16 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r2;
    // EBPF_OP_LDXH pc=24 dst=r2 src=r1 offset=40 imm=0
#line 56 "sample/cgroup_sock_addr.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_STXH pc=25 dst=r10 src=r2 offset=-12 imm=0
#line 56 "sample/cgroup_sock_addr.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r2;
    // EBPF_OP_LDXW pc=26 dst=r1 src=r1 offset=44 imm=0
#line 57 "sample/cgroup_sock_addr.c"
    r1 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_STXW pc=27 dst=r10 src=r1 offset=-8 imm=0
#line 57 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=28 dst=r2 src=r10 offset=0 imm=0
#line 57 "sample/cgroup_sock_addr.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=29 dst=r2 src=r0 offset=0 imm=-48
#line 57 "sample/cgroup_sock_addr.c"
    r2 += IMMEDIATE(-48);
    // EBPF_OP_LDDW pc=30 dst=r1 src=r0 offset=0 imm=0
#line 59 "sample/cgroup_sock_addr.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=32 dst=r0 src=r0 offset=0 imm=1
#line 59 "sample/cgroup_sock_addr.c"
    r0 = authorize_connect6_helpers[0].address
#line 59 "sample/cgroup_sock_addr.c"
         (r1, r2, r3, r4, r5);
#line 59 "sample/cgroup_sock_addr.c"
    if ((authorize_connect6_helpers[0].tail_call) && (r0 == 0))
#line 59 "sample/cgroup_sock_addr.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=33 dst=r1 src=r0 offset=0 imm=0
#line 59 "sample/cgroup_sock_addr.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=34 dst=r0 src=r0 offset=0 imm=1
#line 59 "sample/cgroup_sock_addr.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=35 dst=r1 src=r0 offset=1 imm=0
#line 61 "sample/cgroup_sock_addr.c"
    if (r1 == IMMEDIATE(0))
#line 61 "sample/cgroup_sock_addr.c"
        goto label_1;
        // EBPF_OP_LDXW pc=36 dst=r0 src=r1 offset=0 imm=0
#line 61 "sample/cgroup_sock_addr.c"
    r0 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
label_1:
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 75 "sample/cgroup_sock_addr.c"
    return r0;
#line 75 "sample/cgroup_sock_addr.c"
}
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

static uint64_t
authorize_recv_accept4(void* context)
{
#line 80 "sample/cgroup_sock_addr.c"
    // Prologue
#line 80 "sample/cgroup_sock_addr.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 80 "sample/cgroup_sock_addr.c"
    register uint64_t r0 = 0;
#line 80 "sample/cgroup_sock_addr.c"
    register uint64_t r1 = 0;
#line 80 "sample/cgroup_sock_addr.c"
    register uint64_t r2 = 0;
#line 80 "sample/cgroup_sock_addr.c"
    register uint64_t r3 = 0;
#line 80 "sample/cgroup_sock_addr.c"
    register uint64_t r4 = 0;
#line 80 "sample/cgroup_sock_addr.c"
    register uint64_t r5 = 0;
#line 80 "sample/cgroup_sock_addr.c"
    register uint64_t r10 = 0;

#line 80 "sample/cgroup_sock_addr.c"
    r1 = (uintptr_t)context;
#line 80 "sample/cgroup_sock_addr.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r2 src=r0 offset=0 imm=0
#line 80 "sample/cgroup_sock_addr.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r2 offset=-12 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=2 dst=r10 src=r2 offset=-16 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=3 dst=r10 src=r2 offset=-20 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=4 dst=r10 src=r2 offset=-24 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=5 dst=r10 src=r2 offset=-28 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=6 dst=r10 src=r2 offset=-32 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=7 dst=r10 src=r2 offset=-36 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-36)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=8 dst=r10 src=r2 offset=-40 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=9 dst=r10 src=r2 offset=-44 imm=0
#line 34 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-44)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=10 dst=r2 src=r1 offset=4 imm=0
#line 37 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(4));
    // EBPF_OP_STXW pc=11 dst=r10 src=r2 offset=-48 imm=0
#line 37 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint32_t)r2;
    // EBPF_OP_LDXH pc=12 dst=r2 src=r1 offset=20 imm=0
#line 38 "sample/cgroup_sock_addr.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(20));
    // EBPF_OP_STXH pc=13 dst=r10 src=r2 offset=-32 imm=0
#line 38 "sample/cgroup_sock_addr.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r2;
    // EBPF_OP_LDXW pc=14 dst=r2 src=r1 offset=24 imm=0
#line 39 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_STXW pc=15 dst=r10 src=r2 offset=-28 imm=0
#line 39 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint32_t)r2;
    // EBPF_OP_LDXH pc=16 dst=r2 src=r1 offset=40 imm=0
#line 40 "sample/cgroup_sock_addr.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_STXH pc=17 dst=r10 src=r2 offset=-12 imm=0
#line 40 "sample/cgroup_sock_addr.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r2;
    // EBPF_OP_LDXW pc=18 dst=r1 src=r1 offset=44 imm=0
#line 41 "sample/cgroup_sock_addr.c"
    r1 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_STXW pc=19 dst=r10 src=r1 offset=-8 imm=0
#line 41 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=20 dst=r2 src=r10 offset=0 imm=0
#line 41 "sample/cgroup_sock_addr.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=21 dst=r2 src=r0 offset=0 imm=-48
#line 41 "sample/cgroup_sock_addr.c"
    r2 += IMMEDIATE(-48);
    // EBPF_OP_LDDW pc=22 dst=r1 src=r0 offset=0 imm=0
#line 43 "sample/cgroup_sock_addr.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=1
#line 43 "sample/cgroup_sock_addr.c"
    r0 = authorize_recv_accept4_helpers[0].address
#line 43 "sample/cgroup_sock_addr.c"
         (r1, r2, r3, r4, r5);
#line 43 "sample/cgroup_sock_addr.c"
    if ((authorize_recv_accept4_helpers[0].tail_call) && (r0 == 0))
#line 43 "sample/cgroup_sock_addr.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=25 dst=r1 src=r0 offset=0 imm=0
#line 43 "sample/cgroup_sock_addr.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=26 dst=r0 src=r0 offset=0 imm=1
#line 43 "sample/cgroup_sock_addr.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=27 dst=r1 src=r0 offset=1 imm=0
#line 45 "sample/cgroup_sock_addr.c"
    if (r1 == IMMEDIATE(0))
#line 45 "sample/cgroup_sock_addr.c"
        goto label_1;
        // EBPF_OP_LDXW pc=28 dst=r0 src=r1 offset=0 imm=0
#line 45 "sample/cgroup_sock_addr.c"
    r0 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
label_1:
    // EBPF_OP_EXIT pc=29 dst=r0 src=r0 offset=0 imm=0
#line 82 "sample/cgroup_sock_addr.c"
    return r0;
#line 82 "sample/cgroup_sock_addr.c"
}
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

static uint64_t
authorize_recv_accept6(void* context)
{
#line 87 "sample/cgroup_sock_addr.c"
    // Prologue
#line 87 "sample/cgroup_sock_addr.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 87 "sample/cgroup_sock_addr.c"
    register uint64_t r0 = 0;
#line 87 "sample/cgroup_sock_addr.c"
    register uint64_t r1 = 0;
#line 87 "sample/cgroup_sock_addr.c"
    register uint64_t r2 = 0;
#line 87 "sample/cgroup_sock_addr.c"
    register uint64_t r3 = 0;
#line 87 "sample/cgroup_sock_addr.c"
    register uint64_t r4 = 0;
#line 87 "sample/cgroup_sock_addr.c"
    register uint64_t r5 = 0;
#line 87 "sample/cgroup_sock_addr.c"
    register uint64_t r10 = 0;

#line 87 "sample/cgroup_sock_addr.c"
    r1 = (uintptr_t)context;
#line 87 "sample/cgroup_sock_addr.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r2 src=r0 offset=0 imm=0
#line 87 "sample/cgroup_sock_addr.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=1 dst=r10 src=r2 offset=-16 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=2 dst=r10 src=r2 offset=-24 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=3 dst=r10 src=r2 offset=-32 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r2;
    // EBPF_OP_LDXW pc=4 dst=r2 src=r1 offset=8 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(8));
    // EBPF_OP_LSH64_IMM pc=5 dst=r2 src=r0 offset=0 imm=32
#line 53 "sample/cgroup_sock_addr.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_LDXW pc=6 dst=r3 src=r1 offset=4 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    r3 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(4));
    // EBPF_OP_OR64_REG pc=7 dst=r2 src=r3 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    r2 |= r3;
    // EBPF_OP_STXDW pc=8 dst=r10 src=r2 offset=-48 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r2;
    // EBPF_OP_LDXW pc=9 dst=r2 src=r1 offset=16 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(16));
    // EBPF_OP_LSH64_IMM pc=10 dst=r2 src=r0 offset=0 imm=32
#line 53 "sample/cgroup_sock_addr.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_LDXW pc=11 dst=r3 src=r1 offset=12 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    r3 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(12));
    // EBPF_OP_OR64_REG pc=12 dst=r2 src=r3 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    r2 |= r3;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r2 offset=-40 imm=0
#line 53 "sample/cgroup_sock_addr.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r2;
    // EBPF_OP_LDXH pc=14 dst=r2 src=r1 offset=20 imm=0
#line 54 "sample/cgroup_sock_addr.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(20));
    // EBPF_OP_STXH pc=15 dst=r10 src=r2 offset=-32 imm=0
#line 54 "sample/cgroup_sock_addr.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r2;
    // EBPF_OP_LDXW pc=16 dst=r2 src=r1 offset=24 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_STXW pc=17 dst=r10 src=r2 offset=-28 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=18 dst=r2 src=r1 offset=28 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(28));
    // EBPF_OP_STXW pc=19 dst=r10 src=r2 offset=-24 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=20 dst=r2 src=r1 offset=32 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(32));
    // EBPF_OP_STXW pc=21 dst=r10 src=r2 offset=-20 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=22 dst=r2 src=r1 offset=36 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(36));
    // EBPF_OP_STXW pc=23 dst=r10 src=r2 offset=-16 imm=0
#line 55 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r2;
    // EBPF_OP_LDXH pc=24 dst=r2 src=r1 offset=40 imm=0
#line 56 "sample/cgroup_sock_addr.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_STXH pc=25 dst=r10 src=r2 offset=-12 imm=0
#line 56 "sample/cgroup_sock_addr.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r2;
    // EBPF_OP_LDXW pc=26 dst=r1 src=r1 offset=44 imm=0
#line 57 "sample/cgroup_sock_addr.c"
    r1 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_STXW pc=27 dst=r10 src=r1 offset=-8 imm=0
#line 57 "sample/cgroup_sock_addr.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=28 dst=r2 src=r10 offset=0 imm=0
#line 57 "sample/cgroup_sock_addr.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=29 dst=r2 src=r0 offset=0 imm=-48
#line 57 "sample/cgroup_sock_addr.c"
    r2 += IMMEDIATE(-48);
    // EBPF_OP_LDDW pc=30 dst=r1 src=r0 offset=0 imm=0
#line 59 "sample/cgroup_sock_addr.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=32 dst=r0 src=r0 offset=0 imm=1
#line 59 "sample/cgroup_sock_addr.c"
    r0 = authorize_recv_accept6_helpers[0].address
#line 59 "sample/cgroup_sock_addr.c"
         (r1, r2, r3, r4, r5);
#line 59 "sample/cgroup_sock_addr.c"
    if ((authorize_recv_accept6_helpers[0].tail_call) && (r0 == 0))
#line 59 "sample/cgroup_sock_addr.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=33 dst=r1 src=r0 offset=0 imm=0
#line 59 "sample/cgroup_sock_addr.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=34 dst=r0 src=r0 offset=0 imm=1
#line 59 "sample/cgroup_sock_addr.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=35 dst=r1 src=r0 offset=1 imm=0
#line 61 "sample/cgroup_sock_addr.c"
    if (r1 == IMMEDIATE(0))
#line 61 "sample/cgroup_sock_addr.c"
        goto label_1;
        // EBPF_OP_LDXW pc=36 dst=r0 src=r1 offset=0 imm=0
#line 61 "sample/cgroup_sock_addr.c"
    r0 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
label_1:
    // EBPF_OP_EXIT pc=37 dst=r0 src=r0 offset=0 imm=0
#line 89 "sample/cgroup_sock_addr.c"
    return r0;
#line 89 "sample/cgroup_sock_addr.c"
}
#line __LINE__ __FILE__

static program_entry_t _programs[] = {
    {
        authorize_connect4,
        "cgroup/connect4",
        "authorize_connect4",
        authorize_connect4_maps,
        1,
        authorize_connect4_helpers,
        1,
        30,
        &authorize_connect4_program_type_guid,
        &authorize_connect4_attach_type_guid,
    },
    {
        authorize_connect6,
        "cgroup/connect6",
        "authorize_connect6",
        authorize_connect6_maps,
        1,
        authorize_connect6_helpers,
        1,
        38,
        &authorize_connect6_program_type_guid,
        &authorize_connect6_attach_type_guid,
    },
    {
        authorize_recv_accept4,
        "cgroup/recv_accept4",
        "authorize_recv_accept4",
        authorize_recv_accept4_maps,
        1,
        authorize_recv_accept4_helpers,
        1,
        30,
        &authorize_recv_accept4_program_type_guid,
        &authorize_recv_accept4_attach_type_guid,
    },
    {
        authorize_recv_accept6,
        "cgroup/recv_accept6",
        "authorize_recv_accept6",
        authorize_recv_accept6_maps,
        1,
        authorize_recv_accept6_helpers,
        1,
        38,
        &authorize_recv_accept6_program_type_guid,
        &authorize_recv_accept6_attach_type_guid,
    },
};

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 4;
}

metadata_table_t cgroup_sock_addr_metadata_table = {_get_programs, _get_maps, _get_hash};
