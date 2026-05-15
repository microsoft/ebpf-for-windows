// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from cgroup_sock_addr_bind.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers.
#include <windows.h>

#define metadata_table cgroup_sock_addr_bind##_metadata_table
extern metadata_table_t metadata_table;

bool APIENTRY
DllMain(_In_ HMODULE hModule, unsigned int ul_reason_for_call, _In_ void* lpReserved)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

__declspec(dllexport) metadata_table_t*
get_metadata_table()
{
    return &metadata_table;
}

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
         4,                 // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         256,               // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         17,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "bind_verdict_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 1;
}

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static helper_function_entry_t authorize_bind4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID authorize_bind4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID authorize_bind4_attach_type_guid = {
    0x0d7ce21a, 0x7773, 0x405c, {0x93, 0xb6, 0xd5, 0xbf, 0xb9, 0x2e, 0x74, 0xbc}};
static uint16_t authorize_bind4_maps[] = {
    0,
};

#pragma code_seg(push, "cgroup~2")
static uint64_t
authorize_bind4(void* context, const program_runtime_context_t* runtime_context)
#line 53 "sample/cgroup_sock_addr_bind.c"
{
#line 53 "sample/cgroup_sock_addr_bind.c"
    // Prologue.
#line 53 "sample/cgroup_sock_addr_bind.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 53 "sample/cgroup_sock_addr_bind.c"
    register uint64_t r0 = 0;
#line 53 "sample/cgroup_sock_addr_bind.c"
    register uint64_t r1 = 0;
#line 53 "sample/cgroup_sock_addr_bind.c"
    register uint64_t r2 = 0;
#line 53 "sample/cgroup_sock_addr_bind.c"
    register uint64_t r3 = 0;
#line 53 "sample/cgroup_sock_addr_bind.c"
    register uint64_t r4 = 0;
#line 53 "sample/cgroup_sock_addr_bind.c"
    register uint64_t r5 = 0;
#line 53 "sample/cgroup_sock_addr_bind.c"
    register uint64_t r10 = 0;

#line 53 "sample/cgroup_sock_addr_bind.c"
    r1 = (uintptr_t)context;
#line 53 "sample/cgroup_sock_addr_bind.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r2 src=r0 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr_bind.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r2 offset=-4 imm=0
#line 40 "sample/cgroup_sock_addr_bind.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-4));
    // EBPF_OP_LDXH pc=2 dst=r2 src=r1 offset=40 imm=0
#line 41 "sample/cgroup_sock_addr_bind.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_STXH pc=3 dst=r10 src=r2 offset=-4 imm=0
#line 41 "sample/cgroup_sock_addr_bind.c"
    WRITE_ONCE_16(r10, (uint16_t)r2, OFFSET(-4));
    // EBPF_OP_LDXW pc=4 dst=r1 src=r1 offset=44 imm=0
#line 42 "sample/cgroup_sock_addr_bind.c"
    READ_ONCE_32(r1, r1, OFFSET(44));
    // EBPF_OP_STXB pc=5 dst=r10 src=r1 offset=-2 imm=0
#line 42 "sample/cgroup_sock_addr_bind.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-2));
    // EBPF_OP_MOV64_REG pc=6 dst=r2 src=r10 offset=0 imm=0
#line 42 "sample/cgroup_sock_addr_bind.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r2 src=r0 offset=0 imm=-4
#line 42 "sample/cgroup_sock_addr_bind.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=8 dst=r1 src=r1 offset=0 imm=1
#line 44 "sample/cgroup_sock_addr_bind.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=10 dst=r0 src=r0 offset=0 imm=1
#line 44 "sample/cgroup_sock_addr_bind.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=11 dst=r1 src=r0 offset=0 imm=0
#line 44 "sample/cgroup_sock_addr_bind.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=12 dst=r0 src=r0 offset=0 imm=1
#line 44 "sample/cgroup_sock_addr_bind.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=13 dst=r1 src=r0 offset=1 imm=0
#line 45 "sample/cgroup_sock_addr_bind.c"
    if (r1 == IMMEDIATE(0)) {
#line 45 "sample/cgroup_sock_addr_bind.c"
        goto label_1;
#line 45 "sample/cgroup_sock_addr_bind.c"
    }
    // EBPF_OP_LDXW pc=14 dst=r0 src=r1 offset=0 imm=0
#line 46 "sample/cgroup_sock_addr_bind.c"
    READ_ONCE_32(r0, r1, OFFSET(0));
label_1:
    // EBPF_OP_EXIT pc=15 dst=r0 src=r0 offset=0 imm=0
#line 55 "sample/cgroup_sock_addr_bind.c"
    return r0;
#line 53 "sample/cgroup_sock_addr_bind.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t authorize_bind6_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID authorize_bind6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID authorize_bind6_attach_type_guid = {
    0x81de64c0, 0x2973, 0x468d, {0x83, 0x82, 0x67, 0x69, 0xf0, 0x33, 0xd7, 0x59}};
static uint16_t authorize_bind6_maps[] = {
    0,
};

#pragma code_seg(push, "cgroup~1")
static uint64_t
authorize_bind6(void* context, const program_runtime_context_t* runtime_context)
#line 60 "sample/cgroup_sock_addr_bind.c"
{
#line 60 "sample/cgroup_sock_addr_bind.c"
    // Prologue.
#line 60 "sample/cgroup_sock_addr_bind.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 60 "sample/cgroup_sock_addr_bind.c"
    register uint64_t r0 = 0;
#line 60 "sample/cgroup_sock_addr_bind.c"
    register uint64_t r1 = 0;
#line 60 "sample/cgroup_sock_addr_bind.c"
    register uint64_t r2 = 0;
#line 60 "sample/cgroup_sock_addr_bind.c"
    register uint64_t r3 = 0;
#line 60 "sample/cgroup_sock_addr_bind.c"
    register uint64_t r4 = 0;
#line 60 "sample/cgroup_sock_addr_bind.c"
    register uint64_t r5 = 0;
#line 60 "sample/cgroup_sock_addr_bind.c"
    register uint64_t r10 = 0;

#line 60 "sample/cgroup_sock_addr_bind.c"
    r1 = (uintptr_t)context;
#line 60 "sample/cgroup_sock_addr_bind.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r2 src=r0 offset=0 imm=0
#line 60 "sample/cgroup_sock_addr_bind.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r2 offset=-4 imm=0
#line 40 "sample/cgroup_sock_addr_bind.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-4));
    // EBPF_OP_LDXH pc=2 dst=r2 src=r1 offset=40 imm=0
#line 41 "sample/cgroup_sock_addr_bind.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_STXH pc=3 dst=r10 src=r2 offset=-4 imm=0
#line 41 "sample/cgroup_sock_addr_bind.c"
    WRITE_ONCE_16(r10, (uint16_t)r2, OFFSET(-4));
    // EBPF_OP_LDXW pc=4 dst=r1 src=r1 offset=44 imm=0
#line 42 "sample/cgroup_sock_addr_bind.c"
    READ_ONCE_32(r1, r1, OFFSET(44));
    // EBPF_OP_STXB pc=5 dst=r10 src=r1 offset=-2 imm=0
#line 42 "sample/cgroup_sock_addr_bind.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-2));
    // EBPF_OP_MOV64_REG pc=6 dst=r2 src=r10 offset=0 imm=0
#line 42 "sample/cgroup_sock_addr_bind.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r2 src=r0 offset=0 imm=-4
#line 42 "sample/cgroup_sock_addr_bind.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=8 dst=r1 src=r1 offset=0 imm=1
#line 44 "sample/cgroup_sock_addr_bind.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=10 dst=r0 src=r0 offset=0 imm=1
#line 44 "sample/cgroup_sock_addr_bind.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=11 dst=r1 src=r0 offset=0 imm=0
#line 44 "sample/cgroup_sock_addr_bind.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=12 dst=r0 src=r0 offset=0 imm=1
#line 44 "sample/cgroup_sock_addr_bind.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=13 dst=r1 src=r0 offset=1 imm=0
#line 45 "sample/cgroup_sock_addr_bind.c"
    if (r1 == IMMEDIATE(0)) {
#line 45 "sample/cgroup_sock_addr_bind.c"
        goto label_1;
#line 45 "sample/cgroup_sock_addr_bind.c"
    }
    // EBPF_OP_LDXW pc=14 dst=r0 src=r1 offset=0 imm=0
#line 46 "sample/cgroup_sock_addr_bind.c"
    READ_ONCE_32(r0, r1, OFFSET(0));
label_1:
    // EBPF_OP_EXIT pc=15 dst=r0 src=r0 offset=0 imm=0
#line 62 "sample/cgroup_sock_addr_bind.c"
    return r0;
#line 60 "sample/cgroup_sock_addr_bind.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        authorize_bind4,
        "cgroup~2",
        "cgroup/bind4",
        "authorize_bind4",
        authorize_bind4_maps,
        1,
        authorize_bind4_helpers,
        1,
        16,
        &authorize_bind4_program_type_guid,
        &authorize_bind4_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        authorize_bind6,
        "cgroup~1",
        "cgroup/bind6",
        "authorize_bind6",
        authorize_bind6_maps,
        1,
        authorize_bind6_helpers,
        1,
        16,
        &authorize_bind6_program_type_guid,
        &authorize_bind6_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 2;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = 1;
    version->minor = 3;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t cgroup_sock_addr_bind_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
