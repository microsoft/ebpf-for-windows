// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from bindmonitor_bpf2bpf.o

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

// Forward references for local functions.
static uint64_t
BindMonitor_Callee(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10);

static GUID BindMonitor_Caller_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Caller_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
#pragma code_seg(push, "bind")
static uint64_t
BindMonitor_Caller(void* context)
#line 27 "sample/bindmonitor_bpf2bpf.c"
{
#line 27 "sample/bindmonitor_bpf2bpf.c"
    // Prologue.
#line 27 "sample/bindmonitor_bpf2bpf.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 27 "sample/bindmonitor_bpf2bpf.c"
    register uint64_t r0 = 0;
#line 27 "sample/bindmonitor_bpf2bpf.c"
    register uint64_t r1 = 0;
#line 27 "sample/bindmonitor_bpf2bpf.c"
    register uint64_t r2 = 0;
#line 27 "sample/bindmonitor_bpf2bpf.c"
    register uint64_t r3 = 0;
#line 27 "sample/bindmonitor_bpf2bpf.c"
    register uint64_t r4 = 0;
#line 27 "sample/bindmonitor_bpf2bpf.c"
    register uint64_t r5 = 0;
#line 27 "sample/bindmonitor_bpf2bpf.c"
    register uint64_t r6 = 0;
#line 27 "sample/bindmonitor_bpf2bpf.c"
    register uint64_t r10 = 0;

#line 27 "sample/bindmonitor_bpf2bpf.c"
    r1 = (uintptr_t)context;
#line 27 "sample/bindmonitor_bpf2bpf.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 27 "sample/bindmonitor_bpf2bpf.c"
    r6 = r1;
    // EBPF_OP_ADD64_IMM pc=1 dst=r6 src=r0 offset=0 imm=48
#line 29 "sample/bindmonitor_bpf2bpf.c"
    r6 += IMMEDIATE(48);
    // EBPF_OP_MOV64_REG pc=2 dst=r1 src=r6 offset=0 imm=0
#line 30 "sample/bindmonitor_bpf2bpf.c"
    r1 = r6;
    // EBPF_OP_CALL pc=3 dst=r0 src=r1 offset=0 imm=10
#line 30 "sample/bindmonitor_bpf2bpf.c"
    r0 = BindMonitor_Callee(r1, r2, r3, r4, r5, r10);
    // EBPF_OP_MOV64_REG pc=4 dst=r1 src=r0 offset=0 imm=0
#line 30 "sample/bindmonitor_bpf2bpf.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=5 dst=r0 src=r0 offset=0 imm=1
#line 30 "sample/bindmonitor_bpf2bpf.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_LSH64_IMM pc=6 dst=r1 src=r0 offset=0 imm=32
#line 30 "sample/bindmonitor_bpf2bpf.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=7 dst=r1 src=r0 offset=0 imm=32
#line 30 "sample/bindmonitor_bpf2bpf.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JNE_IMM pc=8 dst=r1 src=r0 offset=4 imm=0
#line 30 "sample/bindmonitor_bpf2bpf.c"
    if (r1 != IMMEDIATE(0)) {
#line 30 "sample/bindmonitor_bpf2bpf.c"
        goto label_2;
#line 30 "sample/bindmonitor_bpf2bpf.c"
    }
    // EBPF_OP_LDXB pc=9 dst=r1 src=r6 offset=0 imm=0
#line 29 "sample/bindmonitor_bpf2bpf.c"
    r1 = *(uint8_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=10 dst=r1 src=r0 offset=1 imm=1
#line 29 "sample/bindmonitor_bpf2bpf.c"
    if (r1 == IMMEDIATE(1)) {
#line 29 "sample/bindmonitor_bpf2bpf.c"
        goto label_1;
#line 29 "sample/bindmonitor_bpf2bpf.c"
    }
    // EBPF_OP_MOV64_IMM pc=11 dst=r0 src=r0 offset=0 imm=0
#line 29 "sample/bindmonitor_bpf2bpf.c"
    r0 = IMMEDIATE(0);
label_1:
    // EBPF_OP_LSH64_IMM pc=12 dst=r0 src=r0 offset=0 imm=1
#line 29 "sample/bindmonitor_bpf2bpf.c"
    r0 <<= (IMMEDIATE(1) & 63);
label_2:
    // EBPF_OP_EXIT pc=13 dst=r0 src=r0 offset=0 imm=0
#line 38 "sample/bindmonitor_bpf2bpf.c"
    return r0;
#line 27 "sample/bindmonitor_bpf2bpf.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static uint64_t
BindMonitor_Callee(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10)
{
    register uint64_t r0 = 0;
    (void)r2;
    (void)r3;
    (void)r4;
    (void)r5;
    (void)r10;

    // EBPF_OP_LDXB pc=0 dst=r1 src=r1 offset=0 imm=0
#line 43 "sample/bindmonitor_bpf2bpf.c"
    r1 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_MOV64_IMM pc=1 dst=r0 src=r0 offset=0 imm=1
#line 43 "sample/bindmonitor_bpf2bpf.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=2 dst=r1 src=r0 offset=1 imm=0
#line 43 "sample/bindmonitor_bpf2bpf.c"
    if (r1 == IMMEDIATE(0)) {
#line 43 "sample/bindmonitor_bpf2bpf.c"
        goto label_1;
#line 43 "sample/bindmonitor_bpf2bpf.c"
    }
    // EBPF_OP_MOV64_IMM pc=3 dst=r0 src=r0 offset=0 imm=0
#line 43 "sample/bindmonitor_bpf2bpf.c"
    r0 = IMMEDIATE(0);
label_1:
    // EBPF_OP_EXIT pc=4 dst=r0 src=r0 offset=0 imm=0
#line 43 "sample/bindmonitor_bpf2bpf.c"
    return r0;
}
#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        BindMonitor_Caller,
        "bind",
        "bind",
        "BindMonitor_Caller",
        NULL,
        0,
        NULL,
        0,
        14,
        &BindMonitor_Caller_program_type_guid,
        &BindMonitor_Caller_attach_type_guid,
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
    version->minor = 20;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t bindmonitor_bpf2bpf_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};
