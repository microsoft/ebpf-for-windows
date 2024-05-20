// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from xdp_datasize_unsafe.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table xdp_datasize_unsafe##_metadata_table
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

static GUID unsafe_program_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID unsafe_program_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
#pragma code_seg(push, "xdp")
static uint64_t
unsafe_program(void* context, const program_runtime_context_t* runtime_context)
#line 26 "sample/unsafe/xdp_datasize_unsafe.c"
{
#line 26 "sample/unsafe/xdp_datasize_unsafe.c"
    // Prologue
#line 26 "sample/unsafe/xdp_datasize_unsafe.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 26 "sample/unsafe/xdp_datasize_unsafe.c"
    register uint64_t r0 = 0;
#line 26 "sample/unsafe/xdp_datasize_unsafe.c"
    register uint64_t r1 = 0;
#line 26 "sample/unsafe/xdp_datasize_unsafe.c"
    register uint64_t r2 = 0;
#line 26 "sample/unsafe/xdp_datasize_unsafe.c"
    register uint64_t r3 = 0;
#line 26 "sample/unsafe/xdp_datasize_unsafe.c"
    register uint64_t r10 = 0;

#line 26 "sample/unsafe/xdp_datasize_unsafe.c"
    r1 = (uintptr_t)context;
#line 26 "sample/unsafe/xdp_datasize_unsafe.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));
#line 26 "sample/unsafe/xdp_datasize_unsafe.c"
    UNREFERENCED_PARAMETER(runtime_context);

    // EBPF_OP_MOV64_IMM pc=0 dst=r0 src=r0 offset=0 imm=1
#line 26 "sample/unsafe/xdp_datasize_unsafe.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=1 dst=r2 src=r1 offset=0 imm=0
#line 20 "sample/unsafe/xdp_datasize_unsafe.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_LDXDW pc=2 dst=r1 src=r1 offset=8 imm=0
#line 32 "sample/unsafe/xdp_datasize_unsafe.c"
    r1 = *(uint64_t*)(uintptr_t)(r1 + OFFSET(8));
    // EBPF_OP_MOV64_REG pc=3 dst=r3 src=r2 offset=0 imm=0
#line 32 "sample/unsafe/xdp_datasize_unsafe.c"
    r3 = r2;
    // EBPF_OP_ADD64_IMM pc=4 dst=r3 src=r0 offset=0 imm=14
#line 32 "sample/unsafe/xdp_datasize_unsafe.c"
    r3 += IMMEDIATE(14);
    // EBPF_OP_JGT_REG pc=5 dst=r3 src=r1 offset=4 imm=0
#line 32 "sample/unsafe/xdp_datasize_unsafe.c"
    if (r3 > r1) {
#line 32 "sample/unsafe/xdp_datasize_unsafe.c"
        goto label_1;
#line 32 "sample/unsafe/xdp_datasize_unsafe.c"
    }
    // EBPF_OP_LDXH pc=6 dst=r1 src=r2 offset=12 imm=0
#line 38 "sample/unsafe/xdp_datasize_unsafe.c"
    r1 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(12));
    // EBPF_OP_JEQ_IMM pc=7 dst=r1 src=r0 offset=2 imm=8
#line 38 "sample/unsafe/xdp_datasize_unsafe.c"
    if (r1 == IMMEDIATE(8)) {
#line 38 "sample/unsafe/xdp_datasize_unsafe.c"
        goto label_1;
#line 38 "sample/unsafe/xdp_datasize_unsafe.c"
    }
    // EBPF_OP_JEQ_IMM pc=8 dst=r1 src=r0 offset=1 imm=56710
#line 38 "sample/unsafe/xdp_datasize_unsafe.c"
    if (r1 == IMMEDIATE(56710)) {
#line 38 "sample/unsafe/xdp_datasize_unsafe.c"
        goto label_1;
#line 38 "sample/unsafe/xdp_datasize_unsafe.c"
    }
    // EBPF_OP_MOV64_IMM pc=9 dst=r0 src=r0 offset=0 imm=2
#line 38 "sample/unsafe/xdp_datasize_unsafe.c"
    r0 = IMMEDIATE(2);
label_1:
    // EBPF_OP_EXIT pc=10 dst=r0 src=r0 offset=0 imm=0
#line 43 "sample/unsafe/xdp_datasize_unsafe.c"
    return r0;
#line 43 "sample/unsafe/xdp_datasize_unsafe.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        unsafe_program,
        "xdp",
        "xdp",
        "unsafe_program",
        NULL,
        0,
        NULL,
        0,
        11,
        &unsafe_program_program_type_guid,
        &unsafe_program_attach_type_guid,
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
    version->minor = 17;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t xdp_datasize_unsafe_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};
