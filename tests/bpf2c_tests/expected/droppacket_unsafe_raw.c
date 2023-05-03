// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from droppacket_unsafe.o

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
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         8,                  // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         PIN_NONE,           // Pinning type for the map.
         0,                  // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "port_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 1;
}

static helper_function_entry_t DropPacket_helpers[] = {
    {NULL, 1, "helper_id_1"},
};

static GUID DropPacket_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID DropPacket_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t DropPacket_maps[] = {
    0,
};

#pragma code_seg(push, "xdp")
static uint64_t
DropPacket(void* context)
#line 30 "sample/unsafe/droppacket_unsafe.c"
{
#line 30 "sample/unsafe/droppacket_unsafe.c"
    // Prologue
#line 30 "sample/unsafe/droppacket_unsafe.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 30 "sample/unsafe/droppacket_unsafe.c"
    register uint64_t r0 = 0;
#line 30 "sample/unsafe/droppacket_unsafe.c"
    register uint64_t r1 = 0;
#line 30 "sample/unsafe/droppacket_unsafe.c"
    register uint64_t r2 = 0;
#line 30 "sample/unsafe/droppacket_unsafe.c"
    register uint64_t r3 = 0;
#line 30 "sample/unsafe/droppacket_unsafe.c"
    register uint64_t r4 = 0;
#line 30 "sample/unsafe/droppacket_unsafe.c"
    register uint64_t r5 = 0;
#line 30 "sample/unsafe/droppacket_unsafe.c"
    register uint64_t r10 = 0;

#line 30 "sample/unsafe/droppacket_unsafe.c"
    r1 = (uintptr_t)context;
#line 30 "sample/unsafe/droppacket_unsafe.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r0 src=r0 offset=0 imm=1
#line 30 "sample/unsafe/droppacket_unsafe.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_LDXDW pc=1 dst=r1 src=r1 offset=0 imm=0
#line 32 "sample/unsafe/droppacket_unsafe.c"
    r1 = *(uint64_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_LDXB pc=2 dst=r2 src=r1 offset=9 imm=0
#line 37 "sample/unsafe/droppacket_unsafe.c"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(9));
    // EBPF_OP_JNE_IMM pc=3 dst=r2 src=r0 offset=15 imm=17
#line 37 "sample/unsafe/droppacket_unsafe.c"
    if (r2 != IMMEDIATE(17))
#line 37 "sample/unsafe/droppacket_unsafe.c"
        goto label_2;
    // EBPF_OP_LDXH pc=4 dst=r1 src=r1 offset=24 imm=0
#line 38 "sample/unsafe/droppacket_unsafe.c"
    r1 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_BE pc=5 dst=r1 src=r0 offset=0 imm=16
#line 38 "sample/unsafe/droppacket_unsafe.c"
    r1 = htobe16((uint16_t)r1);
#line 38 "sample/unsafe/droppacket_unsafe.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_JGT_IMM pc=6 dst=r1 src=r0 offset=12 imm=8
#line 38 "sample/unsafe/droppacket_unsafe.c"
    if (r1 > IMMEDIATE(8))
#line 38 "sample/unsafe/droppacket_unsafe.c"
        goto label_2;
    // EBPF_OP_MOV64_IMM pc=7 dst=r1 src=r0 offset=0 imm=0
#line 38 "sample/unsafe/droppacket_unsafe.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=8 dst=r10 src=r1 offset=-8 imm=0
#line 39 "sample/unsafe/droppacket_unsafe.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r2 src=r10 offset=0 imm=0
#line 39 "sample/unsafe/droppacket_unsafe.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r2 src=r0 offset=0 imm=-8
#line 39 "sample/unsafe/droppacket_unsafe.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=0
#line 40 "sample/unsafe/droppacket_unsafe.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=1
#line 40 "sample/unsafe/droppacket_unsafe.c"
    r0 = DropPacket_helpers[0].address
#line 40 "sample/unsafe/droppacket_unsafe.c"
         (r1, r2, r3, r4, r5);
#line 40 "sample/unsafe/droppacket_unsafe.c"
    if ((DropPacket_helpers[0].tail_call) && (r0 == 0))
#line 40 "sample/unsafe/droppacket_unsafe.c"
        return 0;
    // EBPF_OP_JEQ_IMM pc=14 dst=r0 src=r0 offset=3 imm=0
#line 41 "sample/unsafe/droppacket_unsafe.c"
    if (r0 == IMMEDIATE(0))
#line 41 "sample/unsafe/droppacket_unsafe.c"
        goto label_1;
    // EBPF_OP_LDXDW pc=15 dst=r1 src=r0 offset=0 imm=0
#line 42 "sample/unsafe/droppacket_unsafe.c"
    r1 = *(uint64_t*)(uintptr_t)(r0 + OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=16 dst=r1 src=r0 offset=0 imm=1
#line 42 "sample/unsafe/droppacket_unsafe.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=17 dst=r0 src=r1 offset=0 imm=0
#line 42 "sample/unsafe/droppacket_unsafe.c"
    *(uint64_t*)(uintptr_t)(r0 + OFFSET(0)) = (uint64_t)r1;
label_1:
    // EBPF_OP_MOV64_IMM pc=18 dst=r0 src=r0 offset=0 imm=2
#line 42 "sample/unsafe/droppacket_unsafe.c"
    r0 = IMMEDIATE(2);
label_2:
    // EBPF_OP_EXIT pc=19 dst=r0 src=r0 offset=0 imm=0
#line 47 "sample/unsafe/droppacket_unsafe.c"
    return r0;
#line 47 "sample/unsafe/droppacket_unsafe.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        DropPacket,
        "xdp",
        "xdp",
        "DropPacket",
        DropPacket_maps,
        1,
        DropPacket_helpers,
        1,
        20,
        &DropPacket_program_type_guid,
        &DropPacket_attach_type_guid,
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

metadata_table_t droppacket_unsafe_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
