// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from cgroup_mt_connect6.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers.
#include <windows.h>

#define metadata_table cgroup_mt_connect6##_metadata_table
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

static GUID tcp_mt_connect6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID tcp_mt_connect6_attach_type_guid = {
    0xa82e37b2, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
#pragma code_seg(push, "cgroup~1")
static uint64_t
tcp_mt_connect6(void* context, const program_runtime_context_t* runtime_context)
#line 27 "sample/cgroup_mt_connect6.c"
{
#line 27 "sample/cgroup_mt_connect6.c"
    // Prologue.
#line 27 "sample/cgroup_mt_connect6.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 27 "sample/cgroup_mt_connect6.c"
    register uint64_t r0 = 0;
#line 27 "sample/cgroup_mt_connect6.c"
    register uint64_t r1 = 0;
#line 27 "sample/cgroup_mt_connect6.c"
    register uint64_t r2 = 0;
#line 27 "sample/cgroup_mt_connect6.c"
    register uint64_t r3 = 0;
#line 27 "sample/cgroup_mt_connect6.c"
    register uint64_t r4 = 0;
#line 27 "sample/cgroup_mt_connect6.c"
    register uint64_t r10 = 0;

#line 27 "sample/cgroup_mt_connect6.c"
    r1 = (uintptr_t)context;
#line 27 "sample/cgroup_mt_connect6.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));
#line 27 "sample/cgroup_mt_connect6.c"
    UNREFERENCED_PARAMETER(runtime_context);

#line 27 "sample/cgroup_mt_connect6.c"
    READ_ONCE_32(r2, r1, OFFSET(44));
#line 27 "sample/cgroup_mt_connect6.c"
    r0 = IMMEDIATE(1);
#line 27 "sample/cgroup_mt_connect6.c"
    if (r2 != IMMEDIATE(6)) {
#line 27 "sample/cgroup_mt_connect6.c"
        goto label_1;
#line 27 "sample/cgroup_mt_connect6.c"
    }
#line 33 "sample/cgroup_mt_connect6.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
#line 33 "sample/cgroup_mt_connect6.c"
    r3 = IMMEDIATE(7459);
#line 33 "sample/cgroup_mt_connect6.c"
    if (r3 > r2) {
#line 33 "sample/cgroup_mt_connect6.c"
        goto label_1;
#line 33 "sample/cgroup_mt_connect6.c"
    }
#line 33 "sample/cgroup_mt_connect6.c"
    r0 = IMMEDIATE(0);
#line 41 "sample/cgroup_mt_connect6.c"
    r3 = r2;
#line 41 "sample/cgroup_mt_connect6.c"
    r3 = htobe16((uint16_t)r3);
#line 41 "sample/cgroup_mt_connect6.c"
    r3 &= UINT32_MAX;
#line 41 "sample/cgroup_mt_connect6.c"
    r4 = r3;
#line 41 "sample/cgroup_mt_connect6.c"
    r4 = IMMEDIATE(3) ? (r4 % IMMEDIATE(3)) : r4;
#line 41 "sample/cgroup_mt_connect6.c"
    if (r4 == IMMEDIATE(0)) {
#line 41 "sample/cgroup_mt_connect6.c"
        goto label_1;
#line 41 "sample/cgroup_mt_connect6.c"
    }
#line 41 "sample/cgroup_mt_connect6.c"
    r3 &= IMMEDIATE(1);
#line 41 "sample/cgroup_mt_connect6.c"
    r0 = IMMEDIATE(1);
#line 46 "sample/cgroup_mt_connect6.c"
    if (r3 == IMMEDIATE(0)) {
#line 46 "sample/cgroup_mt_connect6.c"
        goto label_1;
#line 46 "sample/cgroup_mt_connect6.c"
    }
#line 54 "sample/cgroup_mt_connect6.c"
    r2 += IMMEDIATE(-6141);
#line 54 "sample/cgroup_mt_connect6.c"
    WRITE_ONCE_16(r1, (uint16_t)r2, OFFSET(40));
label_1:
#line 58 "sample/cgroup_mt_connect6.c"
    return r0;
#line 27 "sample/cgroup_mt_connect6.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        tcp_mt_connect6,
        "cgroup~1",
        "cgroup/connect6",
        "tcp_mt_connect6",
        NULL,
        0,
        NULL,
        0,
        18,
        &tcp_mt_connect6_program_type_guid,
        &tcp_mt_connect6_attach_type_guid,
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
    version->major = 1;
    version->minor = 1;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t cgroup_mt_connect6_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
