// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from hello_world.o

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

static helper_function_entry_t HelloWorld_helpers[] = {
    {NULL, 12, "helper_id_12"},
};

static GUID HelloWorld_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID HelloWorld_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint64_t
HelloWorld(void* context)
{
#line 18 "sample/hello_world.c"
    // Prologue
#line 18 "sample/hello_world.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 18 "sample/hello_world.c"
    register uint64_t r0 = 0;
#line 18 "sample/hello_world.c"
    register uint64_t r1 = 0;
#line 18 "sample/hello_world.c"
    register uint64_t r2 = 0;
#line 18 "sample/hello_world.c"
    register uint64_t r3 = 0;
#line 18 "sample/hello_world.c"
    register uint64_t r4 = 0;
#line 18 "sample/hello_world.c"
    register uint64_t r5 = 0;
#line 18 "sample/hello_world.c"
    register uint64_t r10 = 0;

#line 18 "sample/hello_world.c"
    r1 = (uintptr_t)context;
#line 18 "sample/hello_world.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r1 src=r0 offset=0 imm=560229490
#line 18 "sample/hello_world.c"
    r1 = IMMEDIATE(560229490);
    // EBPF_OP_STXW pc=1 dst=r10 src=r1 offset=-8 imm=0
#line 20 "sample/hello_world.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=2 dst=r1 src=r0 offset=0 imm=1819043144
#line 20 "sample/hello_world.c"
    r1 = (uint64_t)8022916924116329800;
    // EBPF_OP_STXDW pc=4 dst=r10 src=r1 offset=-16 imm=0
#line 20 "sample/hello_world.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=5 dst=r1 src=r0 offset=0 imm=0
#line 20 "sample/hello_world.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=6 dst=r10 src=r1 offset=-4 imm=0
#line 20 "sample/hello_world.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint8_t)r1;
    // EBPF_OP_MOV64_REG pc=7 dst=r1 src=r10 offset=0 imm=0
#line 20 "sample/hello_world.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=8 dst=r1 src=r0 offset=0 imm=-16
#line 20 "sample/hello_world.c"
    r1 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_IMM pc=9 dst=r2 src=r0 offset=0 imm=13
#line 20 "sample/hello_world.c"
    r2 = IMMEDIATE(13);
    // EBPF_OP_CALL pc=10 dst=r0 src=r0 offset=0 imm=12
#line 20 "sample/hello_world.c"
    r0 = HelloWorld_helpers[0].address
#line 20 "sample/hello_world.c"
         (r1, r2, r3, r4, r5);
#line 20 "sample/hello_world.c"
    if ((HelloWorld_helpers[0].tail_call) && (r0 == 0))
#line 20 "sample/hello_world.c"
        return 0;
        // EBPF_OP_MOV64_IMM pc=11 dst=r0 src=r0 offset=0 imm=0
#line 21 "sample/hello_world.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=12 dst=r0 src=r0 offset=0 imm=0
#line 21 "sample/hello_world.c"
    return r0;
#line 21 "sample/hello_world.c"
}
#line __LINE__ __FILE__

static program_entry_t _programs[] = {
    {
        HelloWorld,
        "bind",
        "HelloWorld",
        NULL,
        0,
        HelloWorld_helpers,
        1,
        13,
        &HelloWorld_program_type_guid,
        &HelloWorld_attach_type_guid,
    },
};

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 1;
}

metadata_table_t hello_world_metadata_table = {_get_programs, _get_maps, _get_hash};
