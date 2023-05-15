// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from cgroup_mt_connect4.o

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

static GUID tcp_mt_connect4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID tcp_mt_connect4_attach_type_guid = {
    0xa82e37b1, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
#pragma code_seg(push, "cgroup~1")
static uint64_t
tcp_mt_connect4(void* context)
#line 27 "sample/cgroup_mt_connect4.c"
{
#line 27 "sample/cgroup_mt_connect4.c"
    // Prologue
#line 27 "sample/cgroup_mt_connect4.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 27 "sample/cgroup_mt_connect4.c"
    register uint64_t r0 = 0;
#line 27 "sample/cgroup_mt_connect4.c"
    register uint64_t r1 = 0;
#line 27 "sample/cgroup_mt_connect4.c"
    register uint64_t r2 = 0;
#line 27 "sample/cgroup_mt_connect4.c"
    register uint64_t r3 = 0;
#line 27 "sample/cgroup_mt_connect4.c"
    register uint64_t r4 = 0;
#line 27 "sample/cgroup_mt_connect4.c"
    register uint64_t r5 = 0;
#line 27 "sample/cgroup_mt_connect4.c"
    register uint64_t r10 = 0;

#line 27 "sample/cgroup_mt_connect4.c"
    r1 = (uintptr_t)context;
#line 27 "sample/cgroup_mt_connect4.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXW pc=0 dst=r2 src=r1 offset=44 imm=0
#line 27 "sample/cgroup_mt_connect4.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_MOV64_IMM pc=1 dst=r0 src=r0 offset=0 imm=1
#line 27 "sample/cgroup_mt_connect4.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JNE_IMM pc=2 dst=r2 src=r0 offset=20 imm=6
#line 27 "sample/cgroup_mt_connect4.c"
    if (r2 != IMMEDIATE(6))
#line 27 "sample/cgroup_mt_connect4.c"
        goto label_1;
    // EBPF_OP_LDXH pc=3 dst=r2 src=r1 offset=40 imm=0
#line 33 "sample/cgroup_mt_connect4.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_MOV64_IMM pc=4 dst=r3 src=r0 offset=0 imm=7459
#line 33 "sample/cgroup_mt_connect4.c"
    r3 = IMMEDIATE(7459);
    // EBPF_OP_MOV64_IMM pc=5 dst=r0 src=r0 offset=0 imm=1
#line 33 "sample/cgroup_mt_connect4.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JGT_REG pc=6 dst=r3 src=r2 offset=16 imm=0
#line 33 "sample/cgroup_mt_connect4.c"
    if (r3 > r2)
#line 33 "sample/cgroup_mt_connect4.c"
        goto label_1;
    // EBPF_OP_MOV64_IMM pc=7 dst=r0 src=r0 offset=0 imm=0
#line 33 "sample/cgroup_mt_connect4.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_MOV64_REG pc=8 dst=r3 src=r2 offset=0 imm=0
#line 33 "sample/cgroup_mt_connect4.c"
    r3 = r2;
    // EBPF_OP_BE pc=9 dst=r3 src=r0 offset=0 imm=16
#line 33 "sample/cgroup_mt_connect4.c"
    r3 = htobe16((uint16_t)r3);
#line 33 "sample/cgroup_mt_connect4.c"
    r3 &= UINT32_MAX;
    // EBPF_OP_LDDW pc=10 dst=r4 src=r0 offset=0 imm=-1431655765
#line 33 "sample/cgroup_mt_connect4.c"
    r4 = (uint64_t)12297829382473034411;
    // EBPF_OP_MOV64_REG pc=12 dst=r5 src=r3 offset=0 imm=0
#line 41 "sample/cgroup_mt_connect4.c"
    r5 = r3;
    // EBPF_OP_MUL64_REG pc=13 dst=r5 src=r4 offset=0 imm=0
#line 41 "sample/cgroup_mt_connect4.c"
    r5 *= r4;
    // EBPF_OP_LDDW pc=14 dst=r4 src=r0 offset=0 imm=1431655766
#line 41 "sample/cgroup_mt_connect4.c"
    r4 = (uint64_t)6148914691236517206;
    // EBPF_OP_JGT_REG pc=16 dst=r4 src=r5 offset=6 imm=0
#line 41 "sample/cgroup_mt_connect4.c"
    if (r4 > r5)
#line 41 "sample/cgroup_mt_connect4.c"
        goto label_1;
    // EBPF_OP_AND64_IMM pc=17 dst=r3 src=r0 offset=0 imm=1
#line 46 "sample/cgroup_mt_connect4.c"
    r3 &= IMMEDIATE(1);
    // EBPF_OP_MOV64_IMM pc=18 dst=r0 src=r0 offset=0 imm=1
#line 46 "sample/cgroup_mt_connect4.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=19 dst=r3 src=r0 offset=3 imm=0
#line 46 "sample/cgroup_mt_connect4.c"
    if (r3 == IMMEDIATE(0))
#line 46 "sample/cgroup_mt_connect4.c"
        goto label_1;
    // EBPF_OP_ADD64_IMM pc=20 dst=r2 src=r0 offset=0 imm=-6141
#line 54 "sample/cgroup_mt_connect4.c"
    r2 += IMMEDIATE(-6141);
    // EBPF_OP_STXH pc=21 dst=r1 src=r2 offset=40 imm=0
#line 54 "sample/cgroup_mt_connect4.c"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(40)) = (uint16_t)r2;
    // EBPF_OP_MOV64_IMM pc=22 dst=r0 src=r0 offset=0 imm=1
#line 54 "sample/cgroup_mt_connect4.c"
    r0 = IMMEDIATE(1);
label_1:
    // EBPF_OP_EXIT pc=23 dst=r0 src=r0 offset=0 imm=0
#line 58 "sample/cgroup_mt_connect4.c"
    return r0;
#line 58 "sample/cgroup_mt_connect4.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        tcp_mt_connect4,
        "cgroup~1",
        "cgroup/connect4",
        "tcp_mt_connect4",
        NULL,
        0,
        NULL,
        0,
        24,
        &tcp_mt_connect4_program_type_guid,
        &tcp_mt_connect4_attach_type_guid,
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
    version->minor = 9;
    version->revision = 0;
}

metadata_table_t cgroup_mt_connect4_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
