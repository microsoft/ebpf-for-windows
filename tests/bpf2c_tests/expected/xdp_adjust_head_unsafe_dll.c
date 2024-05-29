// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from xdp_adjust_head_unsafe.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table xdp_adjust_head_unsafe##_metadata_table
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

static helper_function_entry_t xdp_adjust_head_unsafe_helpers[] = {
    {65536, "helper_id_65536"},
};

static GUID xdp_adjust_head_unsafe_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID xdp_adjust_head_unsafe_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
#pragma code_seg(push, "xdp")
static uint64_t
xdp_adjust_head_unsafe(void* context, const program_runtime_context_t* runtime_context)
#line 17 "sample/unsafe/xdp_adjust_head_unsafe.c"
{
#line 17 "sample/unsafe/xdp_adjust_head_unsafe.c"
    // Prologue
#line 17 "sample/unsafe/xdp_adjust_head_unsafe.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 17 "sample/unsafe/xdp_adjust_head_unsafe.c"
    register uint64_t r0 = 0;
#line 17 "sample/unsafe/xdp_adjust_head_unsafe.c"
    register uint64_t r1 = 0;
#line 17 "sample/unsafe/xdp_adjust_head_unsafe.c"
    register uint64_t r2 = 0;
#line 17 "sample/unsafe/xdp_adjust_head_unsafe.c"
    register uint64_t r3 = 0;
#line 17 "sample/unsafe/xdp_adjust_head_unsafe.c"
    register uint64_t r4 = 0;
#line 17 "sample/unsafe/xdp_adjust_head_unsafe.c"
    register uint64_t r5 = 0;
#line 17 "sample/unsafe/xdp_adjust_head_unsafe.c"
    register uint64_t r6 = 0;
#line 17 "sample/unsafe/xdp_adjust_head_unsafe.c"
    register uint64_t r7 = 0;
#line 17 "sample/unsafe/xdp_adjust_head_unsafe.c"
    register uint64_t r8 = 0;
#line 17 "sample/unsafe/xdp_adjust_head_unsafe.c"
    register uint64_t r10 = 0;

#line 17 "sample/unsafe/xdp_adjust_head_unsafe.c"
    r1 = (uintptr_t)context;
#line 17 "sample/unsafe/xdp_adjust_head_unsafe.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r7 src=r1 offset=0 imm=0
#line 17 "sample/unsafe/xdp_adjust_head_unsafe.c"
    r7 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r6 src=r0 offset=0 imm=2
#line 17 "sample/unsafe/xdp_adjust_head_unsafe.c"
    r6 = IMMEDIATE(2);
    // EBPF_OP_LDXDW pc=2 dst=r2 src=r7 offset=8 imm=0
#line 26 "sample/unsafe/xdp_adjust_head_unsafe.c"
    r2 = *(uint64_t*)(uintptr_t)(r7 + OFFSET(8));
    // EBPF_OP_LDXDW pc=3 dst=r1 src=r7 offset=0 imm=0
#line 22 "sample/unsafe/xdp_adjust_head_unsafe.c"
    r1 = *(uint64_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=4 dst=r3 src=r1 offset=0 imm=0
#line 26 "sample/unsafe/xdp_adjust_head_unsafe.c"
    r3 = r1;
    // EBPF_OP_ADD64_IMM pc=5 dst=r3 src=r0 offset=0 imm=14
#line 26 "sample/unsafe/xdp_adjust_head_unsafe.c"
    r3 += IMMEDIATE(14);
    // EBPF_OP_JGT_REG pc=6 dst=r3 src=r2 offset=12 imm=0
#line 26 "sample/unsafe/xdp_adjust_head_unsafe.c"
    if (r3 > r2) {
#line 26 "sample/unsafe/xdp_adjust_head_unsafe.c"
        goto label_1;
#line 26 "sample/unsafe/xdp_adjust_head_unsafe.c"
    }
    // EBPF_OP_MOV64_IMM pc=7 dst=r8 src=r0 offset=0 imm=2048
#line 26 "sample/unsafe/xdp_adjust_head_unsafe.c"
    r8 = IMMEDIATE(2048);
    // EBPF_OP_STXH pc=8 dst=r1 src=r8 offset=12 imm=0
#line 31 "sample/unsafe/xdp_adjust_head_unsafe.c"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(12)) = (uint16_t)r8;
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r7 offset=0 imm=0
#line 34 "sample/unsafe/xdp_adjust_head_unsafe.c"
    r1 = r7;
    // EBPF_OP_MOV64_IMM pc=10 dst=r2 src=r0 offset=0 imm=14
#line 34 "sample/unsafe/xdp_adjust_head_unsafe.c"
    r2 = IMMEDIATE(14);
    // EBPF_OP_CALL pc=11 dst=r0 src=r0 offset=0 imm=65536
#line 34 "sample/unsafe/xdp_adjust_head_unsafe.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5);
#line 34 "sample/unsafe/xdp_adjust_head_unsafe.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 34 "sample/unsafe/xdp_adjust_head_unsafe.c"
        return 0;
#line 34 "sample/unsafe/xdp_adjust_head_unsafe.c"
    }
    // EBPF_OP_LSH64_IMM pc=12 dst=r0 src=r0 offset=0 imm=32
#line 34 "sample/unsafe/xdp_adjust_head_unsafe.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=13 dst=r0 src=r0 offset=0 imm=32
#line 34 "sample/unsafe/xdp_adjust_head_unsafe.c"
    r0 = (int64_t)r0 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_IMM pc=14 dst=r1 src=r0 offset=0 imm=0
#line 34 "sample/unsafe/xdp_adjust_head_unsafe.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=15 dst=r1 src=r0 offset=3 imm=0
#line 34 "sample/unsafe/xdp_adjust_head_unsafe.c"
    if ((int64_t)r1 > (int64_t)r0) {
#line 34 "sample/unsafe/xdp_adjust_head_unsafe.c"
        goto label_1;
#line 34 "sample/unsafe/xdp_adjust_head_unsafe.c"
    }
    // EBPF_OP_LDXDW pc=16 dst=r1 src=r7 offset=0 imm=0
#line 41 "sample/unsafe/xdp_adjust_head_unsafe.c"
    r1 = *(uint64_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_STXH pc=17 dst=r1 src=r8 offset=12 imm=0
#line 42 "sample/unsafe/xdp_adjust_head_unsafe.c"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(12)) = (uint16_t)r8;
    // EBPF_OP_MOV64_IMM pc=18 dst=r6 src=r0 offset=0 imm=1
#line 42 "sample/unsafe/xdp_adjust_head_unsafe.c"
    r6 = IMMEDIATE(1);
label_1:
    // EBPF_OP_MOV64_REG pc=19 dst=r0 src=r6 offset=0 imm=0
#line 45 "sample/unsafe/xdp_adjust_head_unsafe.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 45 "sample/unsafe/xdp_adjust_head_unsafe.c"
    return r0;
#line 45 "sample/unsafe/xdp_adjust_head_unsafe.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        xdp_adjust_head_unsafe,
        "xdp",
        "xdp",
        "xdp_adjust_head_unsafe",
        NULL,
        0,
        xdp_adjust_head_unsafe_helpers,
        1,
        21,
        &xdp_adjust_head_unsafe_program_type_guid,
        &xdp_adjust_head_unsafe_attach_type_guid,
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

metadata_table_t xdp_adjust_head_unsafe_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};
