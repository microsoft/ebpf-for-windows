// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from cgroup_connect_authorization_readonly.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers.
#include <windows.h>

#define metadata_table cgroup_connect_authorization_readonly##_metadata_table
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

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = NULL;
    *count = 0;
}

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static GUID mutate_connect_authorization4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID mutate_connect_authorization4_attach_type_guid = {
    0x6076c13a, 0xf04f, 0x4ff8, {0x83, 0x80, 0x90, 0x85, 0x53, 0xf2, 0x22, 0x76}};
#pragma code_seg(push, "cgroup~2")
static uint64_t
mutate_connect_authorization4(void* context, const program_runtime_context_t* runtime_context)
#line 11 "sample/cgroup_connect_authorization_readonly.c"
{
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    // Prologue.
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    register uint64_t r0 = 0;
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    register uint64_t r1 = 0;
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    register uint64_t r2 = 0;
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    register uint64_t r10 = 0;

#line 11 "sample/cgroup_connect_authorization_readonly.c"
    r1 = (uintptr_t)context;
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    UNREFERENCED_PARAMETER(runtime_context);

    // EBPF_OP_LDXW pc=0 dst=r2 src=r1 offset=0 imm=0
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    READ_ONCE_32(r2, r1, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=1 dst=r2 src=r0 offset=6 imm=2
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    if (r2 != IMMEDIATE(2)) {
#line 11 "sample/cgroup_connect_authorization_readonly.c"
        goto label_2;
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    }
    // EBPF_OP_LDXW pc=2 dst=r2 src=r1 offset=44 imm=0
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    READ_ONCE_32(r2, r1, OFFSET(44));
    // EBPF_OP_JEQ_IMM pc=3 dst=r2 src=r0 offset=1 imm=17
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    if (r2 == IMMEDIATE(17)) {
#line 11 "sample/cgroup_connect_authorization_readonly.c"
        goto label_1;
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    }
    // EBPF_OP_JNE_IMM pc=4 dst=r2 src=r0 offset=3 imm=6
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    if (r2 != IMMEDIATE(6)) {
#line 11 "sample/cgroup_connect_authorization_readonly.c"
        goto label_2;
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    }
label_1:
    // EBPF_OP_LDXH pc=5 dst=r2 src=r1 offset=40 imm=0
#line 17 "sample/cgroup_connect_authorization_readonly.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_XOR64_IMM pc=6 dst=r2 src=r0 offset=0 imm=1
#line 17 "sample/cgroup_connect_authorization_readonly.c"
    r2 ^= IMMEDIATE(1);
    // EBPF_OP_STXH pc=7 dst=r1 src=r2 offset=40 imm=0
#line 17 "sample/cgroup_connect_authorization_readonly.c"
    WRITE_ONCE_16(r1, (uint16_t)r2, OFFSET(40));
label_2:
    // EBPF_OP_MOV64_IMM pc=8 dst=r0 src=r0 offset=0 imm=1
#line 25 "sample/cgroup_connect_authorization_readonly.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=9 dst=r0 src=r0 offset=0 imm=0
#line 25 "sample/cgroup_connect_authorization_readonly.c"
    return r0;
#line 11 "sample/cgroup_connect_authorization_readonly.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static GUID mutate_connect_authorization6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID mutate_connect_authorization6_attach_type_guid = {
    0x54b0b6ed, 0x432a, 0x4674, {0x8b, 0x27, 0x8d, 0x9f, 0x5b, 0x40, 0xc6, 0x75}};
#pragma code_seg(push, "cgroup~1")
static uint64_t
mutate_connect_authorization6(void* context, const program_runtime_context_t* runtime_context)
#line 11 "sample/cgroup_connect_authorization_readonly.c"
{
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    // Prologue.
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    register uint64_t r0 = 0;
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    register uint64_t r1 = 0;
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    register uint64_t r2 = 0;
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    register uint64_t r10 = 0;

#line 11 "sample/cgroup_connect_authorization_readonly.c"
    r1 = (uintptr_t)context;
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    UNREFERENCED_PARAMETER(runtime_context);

    // EBPF_OP_LDXW pc=0 dst=r2 src=r1 offset=0 imm=0
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    READ_ONCE_32(r2, r1, OFFSET(0));
    // EBPF_OP_JNE_IMM pc=1 dst=r2 src=r0 offset=6 imm=23
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    if (r2 != IMMEDIATE(23)) {
#line 11 "sample/cgroup_connect_authorization_readonly.c"
        goto label_2;
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    }
    // EBPF_OP_LDXW pc=2 dst=r2 src=r1 offset=44 imm=0
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    READ_ONCE_32(r2, r1, OFFSET(44));
    // EBPF_OP_JEQ_IMM pc=3 dst=r2 src=r0 offset=1 imm=17
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    if (r2 == IMMEDIATE(17)) {
#line 11 "sample/cgroup_connect_authorization_readonly.c"
        goto label_1;
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    }
    // EBPF_OP_JNE_IMM pc=4 dst=r2 src=r0 offset=3 imm=6
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    if (r2 != IMMEDIATE(6)) {
#line 11 "sample/cgroup_connect_authorization_readonly.c"
        goto label_2;
#line 11 "sample/cgroup_connect_authorization_readonly.c"
    }
label_1:
    // EBPF_OP_LDXH pc=5 dst=r2 src=r1 offset=40 imm=0
#line 17 "sample/cgroup_connect_authorization_readonly.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_XOR64_IMM pc=6 dst=r2 src=r0 offset=0 imm=1
#line 17 "sample/cgroup_connect_authorization_readonly.c"
    r2 ^= IMMEDIATE(1);
    // EBPF_OP_STXH pc=7 dst=r1 src=r2 offset=40 imm=0
#line 17 "sample/cgroup_connect_authorization_readonly.c"
    WRITE_ONCE_16(r1, (uint16_t)r2, OFFSET(40));
label_2:
    // EBPF_OP_MOV64_IMM pc=8 dst=r0 src=r0 offset=0 imm=1
#line 32 "sample/cgroup_connect_authorization_readonly.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=9 dst=r0 src=r0 offset=0 imm=0
#line 32 "sample/cgroup_connect_authorization_readonly.c"
    return r0;
#line 11 "sample/cgroup_connect_authorization_readonly.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        mutate_connect_authorization4,
        "cgroup~2",
        "cgroup/connect_authorization4",
        "mutate_connect_authorization4",
        NULL,
        0,
        NULL,
        0,
        10,
        &mutate_connect_authorization4_program_type_guid,
        &mutate_connect_authorization4_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        mutate_connect_authorization6,
        "cgroup~1",
        "cgroup/connect_authorization6",
        "mutate_connect_authorization6",
        NULL,
        0,
        NULL,
        0,
        10,
        &mutate_connect_authorization6_program_type_guid,
        &mutate_connect_authorization6_attach_type_guid,
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
    version->minor = 5;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t cgroup_connect_authorization_readonly_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
