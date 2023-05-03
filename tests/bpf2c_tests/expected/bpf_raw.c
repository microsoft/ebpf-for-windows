// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from bpf.o

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

static GUID func_program_type_guid = {0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID func_attach_type_guid = {0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
#pragma code_seg(push, ".text")
static uint64_t
func(void* context)
#line 17 "sample/custom_program_type/bpf.c"
{
#line 17 "sample/custom_program_type/bpf.c"
    // Prologue
#line 17 "sample/custom_program_type/bpf.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 17 "sample/custom_program_type/bpf.c"
    register uint64_t r0 = 0;
#line 17 "sample/custom_program_type/bpf.c"
    register uint64_t r1 = 0;
#line 17 "sample/custom_program_type/bpf.c"
    register uint64_t r10 = 0;

#line 17 "sample/custom_program_type/bpf.c"
    r1 = (uintptr_t)context;
#line 17 "sample/custom_program_type/bpf.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r0 src=r0 offset=0 imm=42
#line 17 "sample/custom_program_type/bpf.c"
    r0 = IMMEDIATE(42);
    // EBPF_OP_EXIT pc=1 dst=r0 src=r0 offset=0 imm=0
#line 17 "sample/custom_program_type/bpf.c"
    return r0;
#line 17 "sample/custom_program_type/bpf.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        func,
        ".text",
        ".text",
        "func",
        NULL,
        0,
        NULL,
        0,
        2,
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
    version->minor = 9;
    version->revision = 0;
}

metadata_table_t bpf_metadata_table = {sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
