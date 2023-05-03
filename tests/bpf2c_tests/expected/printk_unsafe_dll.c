// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from printk_unsafe.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table printk_unsafe##_metadata_table
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

static helper_function_entry_t func_helpers[] = {
    {NULL, 13, "helper_id_13"},
};

static GUID func_program_type_guid = {0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID func_attach_type_guid = {0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
#pragma code_seg(push, "bind")
static uint64_t
func(void* context)
#line 18 "sample/unsafe/printk_unsafe.c"
{
#line 18 "sample/unsafe/printk_unsafe.c"
    // Prologue
#line 18 "sample/unsafe/printk_unsafe.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 18 "sample/unsafe/printk_unsafe.c"
    register uint64_t r0 = 0;
#line 18 "sample/unsafe/printk_unsafe.c"
    register uint64_t r1 = 0;
#line 18 "sample/unsafe/printk_unsafe.c"
    register uint64_t r2 = 0;
#line 18 "sample/unsafe/printk_unsafe.c"
    register uint64_t r3 = 0;
#line 18 "sample/unsafe/printk_unsafe.c"
    register uint64_t r4 = 0;
#line 18 "sample/unsafe/printk_unsafe.c"
    register uint64_t r5 = 0;
#line 18 "sample/unsafe/printk_unsafe.c"
    register uint64_t r10 = 0;

#line 18 "sample/unsafe/printk_unsafe.c"
    r1 = (uintptr_t)context;
#line 18 "sample/unsafe/printk_unsafe.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r3 src=r1 offset=0 imm=0
#line 18 "sample/unsafe/printk_unsafe.c"
    r3 = r1;
    // EBPF_OP_LDDW pc=1 dst=r1 src=r0 offset=0 imm=980972643
#line 18 "sample/unsafe/printk_unsafe.c"
    r1 = (uint64_t)32973392625300579;
    // EBPF_OP_STXDW pc=3 dst=r10 src=r1 offset=-8 imm=0
#line 22 "sample/unsafe/printk_unsafe.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=4 dst=r1 src=r10 offset=0 imm=0
#line 22 "sample/unsafe/printk_unsafe.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=5 dst=r1 src=r0 offset=0 imm=-8
#line 22 "sample/unsafe/printk_unsafe.c"
    r1 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=6 dst=r2 src=r0 offset=0 imm=8
#line 22 "sample/unsafe/printk_unsafe.c"
    r2 = IMMEDIATE(8);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=13
#line 22 "sample/unsafe/printk_unsafe.c"
    r0 = func_helpers[0].address
#line 22 "sample/unsafe/printk_unsafe.c"
         (r1, r2, r3, r4, r5);
#line 22 "sample/unsafe/printk_unsafe.c"
    if ((func_helpers[0].tail_call) && (r0 == 0))
#line 22 "sample/unsafe/printk_unsafe.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=8 dst=r0 src=r0 offset=0 imm=0
#line 23 "sample/unsafe/printk_unsafe.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=9 dst=r0 src=r0 offset=0 imm=0
#line 23 "sample/unsafe/printk_unsafe.c"
    return r0;
#line 23 "sample/unsafe/printk_unsafe.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        func,
        "bind",
        "bind",
        "func",
        NULL,
        0,
        func_helpers,
        1,
        10,
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

metadata_table_t printk_unsafe_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
