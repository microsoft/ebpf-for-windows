// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from bindmonitor_ringbuf.o

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
         BPF_MAP_TYPE_RINGBUF, // Type of map.
         0,                    // Size in bytes of a map key.
         0,                    // Size in bytes of a map value.
         262144,               // Maximum number of entries allowed in the map.
         0,                    // Inner map index.
         PIN_NONE,             // Pinning type for the map.
         0,                    // Identifier for a map template.
         0,                    // The id of the inner map template.
     },
     "process_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 1;
}

static helper_function_entry_t bind_monitor_helpers[] = {
    {NULL, 11, "helper_id_11"},
};

static GUID bind_monitor_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID bind_monitor_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t bind_monitor_maps[] = {
    0,
};

#pragma code_seg(push, "bind")
static uint64_t
bind_monitor(void* context)
#line 23 "sample/bindmonitor_ringbuf.c"
{
#line 23 "sample/bindmonitor_ringbuf.c"
    // Prologue
#line 23 "sample/bindmonitor_ringbuf.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 23 "sample/bindmonitor_ringbuf.c"
    register uint64_t r0 = 0;
#line 23 "sample/bindmonitor_ringbuf.c"
    register uint64_t r1 = 0;
#line 23 "sample/bindmonitor_ringbuf.c"
    register uint64_t r2 = 0;
#line 23 "sample/bindmonitor_ringbuf.c"
    register uint64_t r3 = 0;
#line 23 "sample/bindmonitor_ringbuf.c"
    register uint64_t r4 = 0;
#line 23 "sample/bindmonitor_ringbuf.c"
    register uint64_t r5 = 0;
#line 23 "sample/bindmonitor_ringbuf.c"
    register uint64_t r10 = 0;

#line 23 "sample/bindmonitor_ringbuf.c"
    r1 = (uintptr_t)context;
#line 23 "sample/bindmonitor_ringbuf.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXW pc=0 dst=r2 src=r1 offset=44 imm=0
#line 23 "sample/bindmonitor_ringbuf.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_JNE_IMM pc=1 dst=r2 src=r0 offset=8 imm=0
#line 23 "sample/bindmonitor_ringbuf.c"
    if (r2 != IMMEDIATE(0))
#line 23 "sample/bindmonitor_ringbuf.c"
        goto label_1;
    // EBPF_OP_LDXDW pc=2 dst=r2 src=r1 offset=0 imm=0
#line 25 "sample/bindmonitor_ringbuf.c"
    r2 = *(uint64_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_LDXDW pc=3 dst=r3 src=r1 offset=8 imm=0
#line 25 "sample/bindmonitor_ringbuf.c"
    r3 = *(uint64_t*)(uintptr_t)(r1 + OFFSET(8));
    // EBPF_OP_JGE_REG pc=4 dst=r2 src=r3 offset=5 imm=0
#line 25 "sample/bindmonitor_ringbuf.c"
    if (r2 >= r3)
#line 25 "sample/bindmonitor_ringbuf.c"
        goto label_1;
    // EBPF_OP_SUB64_REG pc=5 dst=r3 src=r2 offset=0 imm=0
#line 26 "sample/bindmonitor_ringbuf.c"
    r3 -= r2;
    // EBPF_OP_LDDW pc=6 dst=r1 src=r0 offset=0 imm=0
#line 26 "sample/bindmonitor_ringbuf.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=8 dst=r4 src=r0 offset=0 imm=0
#line 26 "sample/bindmonitor_ringbuf.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=9 dst=r0 src=r0 offset=0 imm=11
#line 26 "sample/bindmonitor_ringbuf.c"
    r0 = bind_monitor_helpers[0].address
#line 26 "sample/bindmonitor_ringbuf.c"
         (r1, r2, r3, r4, r5);
#line 26 "sample/bindmonitor_ringbuf.c"
    if ((bind_monitor_helpers[0].tail_call) && (r0 == 0))
#line 26 "sample/bindmonitor_ringbuf.c"
        return 0;
label_1:
    // EBPF_OP_MOV64_IMM pc=10 dst=r0 src=r0 offset=0 imm=0
#line 33 "sample/bindmonitor_ringbuf.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=11 dst=r0 src=r0 offset=0 imm=0
#line 33 "sample/bindmonitor_ringbuf.c"
    return r0;
#line 33 "sample/bindmonitor_ringbuf.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        bind_monitor,
        "bind",
        "bind",
        "bind_monitor",
        bind_monitor_maps,
        1,
        bind_monitor_helpers,
        1,
        12,
        &bind_monitor_program_type_guid,
        &bind_monitor_attach_type_guid,
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

metadata_table_t bindmonitor_ringbuf_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
