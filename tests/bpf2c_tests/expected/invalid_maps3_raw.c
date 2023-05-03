// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from invalid_maps3.o

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
         4,                 // Size in bytes of a map value.
         1024,              // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         10,                // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
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

static GUID BindMonitor_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
#pragma code_seg(push, "bind")
static uint64_t
BindMonitor(void* context)
#line 52 "sample/unsafe/invalid_maps3.c"
{
#line 52 "sample/unsafe/invalid_maps3.c"
    // Prologue
#line 52 "sample/unsafe/invalid_maps3.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 52 "sample/unsafe/invalid_maps3.c"
    register uint64_t r0 = 0;
#line 52 "sample/unsafe/invalid_maps3.c"
    register uint64_t r1 = 0;
#line 52 "sample/unsafe/invalid_maps3.c"
    register uint64_t r10 = 0;

#line 52 "sample/unsafe/invalid_maps3.c"
    r1 = (uintptr_t)context;
#line 52 "sample/unsafe/invalid_maps3.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r0 src=r0 offset=0 imm=0
#line 52 "sample/unsafe/invalid_maps3.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=1 dst=r0 src=r0 offset=0 imm=0
#line 52 "sample/unsafe/invalid_maps3.c"
    return r0;
#line 52 "sample/unsafe/invalid_maps3.c"
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
        NULL,
        0,
        NULL,
        0,
        2,
        &BindMonitor_program_type_guid,
        &BindMonitor_attach_type_guid,
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

metadata_table_t invalid_maps3_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
