// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from xdp_invalid_socket_cookie.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table xdp_invalid_socket_cookie##_metadata_table
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

__declspec(dllexport) metadata_table_t* get_metadata_table() { return &metadata_table; }

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

static helper_function_entry_t xdp_invalid_socket_cookie_helpers[] = {
    {NULL, 26, "helper_id_26"},
    {NULL, 13, "helper_id_13"},
};

static GUID xdp_invalid_socket_cookie_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID xdp_invalid_socket_cookie_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
#pragma code_seg(push, "xdp")
static uint64_t
xdp_invalid_socket_cookie(void* context)
#line 20 "sample/xdp_invalid_socket_cookie.c"
{
#line 20 "sample/xdp_invalid_socket_cookie.c"
    // Prologue
#line 20 "sample/xdp_invalid_socket_cookie.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 20 "sample/xdp_invalid_socket_cookie.c"
    register uint64_t r0 = 0;
#line 20 "sample/xdp_invalid_socket_cookie.c"
    register uint64_t r1 = 0;
#line 20 "sample/xdp_invalid_socket_cookie.c"
    register uint64_t r2 = 0;
#line 20 "sample/xdp_invalid_socket_cookie.c"
    register uint64_t r3 = 0;
#line 20 "sample/xdp_invalid_socket_cookie.c"
    register uint64_t r4 = 0;
#line 20 "sample/xdp_invalid_socket_cookie.c"
    register uint64_t r5 = 0;
#line 20 "sample/xdp_invalid_socket_cookie.c"
    register uint64_t r10 = 0;

#line 20 "sample/xdp_invalid_socket_cookie.c"
    r1 = (uintptr_t)context;
#line 20 "sample/xdp_invalid_socket_cookie.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_CALL pc=0 dst=r0 src=r0 offset=0 imm=26
#line 20 "sample/xdp_invalid_socket_cookie.c"
    r0 = xdp_invalid_socket_cookie_helpers[0].address
#line 20 "sample/xdp_invalid_socket_cookie.c"
         (r1, r2, r3, r4, r5);
#line 20 "sample/xdp_invalid_socket_cookie.c"
    if ((xdp_invalid_socket_cookie_helpers[0].tail_call) && (r0 == 0))
#line 20 "sample/xdp_invalid_socket_cookie.c"
        return 0;
        // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 20 "sample/xdp_invalid_socket_cookie.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=2 dst=r10 src=r1 offset=-4 imm=0
#line 22 "sample/xdp_invalid_socket_cookie.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=3 dst=r1 src=r0 offset=0 imm=175664236
#line 22 "sample/xdp_invalid_socket_cookie.c"
    r1 = IMMEDIATE(175664236);
    // EBPF_OP_STXW pc=4 dst=r10 src=r1 offset=-8 imm=0
#line 22 "sample/xdp_invalid_socket_cookie.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=1768648559
#line 22 "sample/xdp_invalid_socket_cookie.c"
    r1 = (uint64_t)2675202385892831087;
    // EBPF_OP_STXDW pc=7 dst=r10 src=r1 offset=-16 imm=0
#line 22 "sample/xdp_invalid_socket_cookie.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=8 dst=r1 src=r0 offset=0 imm=1801678707
#line 22 "sample/xdp_invalid_socket_cookie.c"
    r1 = (uint64_t)7160569911484575603;
    // EBPF_OP_STXDW pc=10 dst=r10 src=r1 offset=-24 imm=0
#line 22 "sample/xdp_invalid_socket_cookie.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=11 dst=r1 src=r10 offset=0 imm=0
#line 22 "sample/xdp_invalid_socket_cookie.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=12 dst=r1 src=r0 offset=0 imm=-24
#line 22 "sample/xdp_invalid_socket_cookie.c"
    r1 += IMMEDIATE(-24);
    // EBPF_OP_MOV64_IMM pc=13 dst=r2 src=r0 offset=0 imm=21
#line 22 "sample/xdp_invalid_socket_cookie.c"
    r2 = IMMEDIATE(21);
    // EBPF_OP_MOV64_REG pc=14 dst=r3 src=r0 offset=0 imm=0
#line 22 "sample/xdp_invalid_socket_cookie.c"
    r3 = r0;
    // EBPF_OP_CALL pc=15 dst=r0 src=r0 offset=0 imm=13
#line 22 "sample/xdp_invalid_socket_cookie.c"
    r0 = xdp_invalid_socket_cookie_helpers[1].address
#line 22 "sample/xdp_invalid_socket_cookie.c"
         (r1, r2, r3, r4, r5);
#line 22 "sample/xdp_invalid_socket_cookie.c"
    if ((xdp_invalid_socket_cookie_helpers[1].tail_call) && (r0 == 0))
#line 22 "sample/xdp_invalid_socket_cookie.c"
        return 0;
        // EBPF_OP_MOV64_IMM pc=16 dst=r0 src=r0 offset=0 imm=1
#line 25 "sample/xdp_invalid_socket_cookie.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=17 dst=r0 src=r0 offset=0 imm=0
#line 25 "sample/xdp_invalid_socket_cookie.c"
    return r0;
#line 25 "sample/xdp_invalid_socket_cookie.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        xdp_invalid_socket_cookie,
        "xdp",
        "xdp",
        "xdp_invalid_socket_cookie",
        NULL,
        0,
        xdp_invalid_socket_cookie_helpers,
        2,
        18,
        &xdp_invalid_socket_cookie_program_type_guid,
        &xdp_invalid_socket_cookie_attach_type_guid,
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
    version->minor = 15;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t xdp_invalid_socket_cookie_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};
