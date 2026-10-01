// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from printk.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers.
#include <windows.h>

#define metadata_table printk##_metadata_table
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

static helper_function_entry_t func_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     12,
     "helper_id_12",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     15,
     "helper_id_15",
    },
};

static GUID func_program_type_guid = {0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID func_attach_type_guid = {0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
#pragma code_seg(push, "sample~1")
static uint64_t
func(void* context, const program_runtime_context_t* runtime_context)
#line 19 "sample/printk.c"
{
#line 19 "sample/printk.c"
    // Prologue.
#line 19 "sample/printk.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 19 "sample/printk.c"
    register uint64_t r0 = 0;
#line 19 "sample/printk.c"
    register uint64_t r1 = 0;
#line 19 "sample/printk.c"
    register uint64_t r2 = 0;
#line 19 "sample/printk.c"
    register uint64_t r3 = 0;
#line 19 "sample/printk.c"
    register uint64_t r4 = 0;
#line 19 "sample/printk.c"
    register uint64_t r5 = 0;
#line 19 "sample/printk.c"
    register uint64_t r6 = 0;
#line 19 "sample/printk.c"
    register uint64_t r7 = 0;
#line 19 "sample/printk.c"
    register uint64_t r8 = 0;
#line 19 "sample/printk.c"
    register uint64_t r9 = 0;
#line 19 "sample/printk.c"
    register uint64_t r10 = 0;

#line 19 "sample/printk.c"
    r1 = (uintptr_t)context;
#line 19 "sample/printk.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 19 "sample/printk.c"
    r7 = r1;
#line 19 "sample/printk.c"
    r1 = IMMEDIATE(0);
#line 24 "sample/printk.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-20));
#line 24 "sample/printk.c"
    r6 = IMMEDIATE(1684828783);
#line 24 "sample/printk.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-24));
#line 24 "sample/printk.c"
    r8 = (uint64_t)8583909746840200520;
#line 24 "sample/printk.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-32));
#line 24 "sample/printk.c"
    r1 = r10;
#line 24 "sample/printk.c"
    r1 += IMMEDIATE(-32);
#line 24 "sample/printk.c"
    r2 = IMMEDIATE(13);
#line 24 "sample/printk.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 24 "sample/printk.c"
    r9 = r0;
#line 24 "sample/printk.c"
    r1 = IMMEDIATE(10);
#line 25 "sample/printk.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-20));
#line 25 "sample/printk.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-24));
#line 25 "sample/printk.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-32));
#line 25 "sample/printk.c"
    r1 = r10;
#line 25 "sample/printk.c"
    r1 += IMMEDIATE(-32);
#line 25 "sample/printk.c"
    r2 = IMMEDIATE(14);
#line 25 "sample/printk.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 25 "sample/printk.c"
    r6 = r0;
#line 29 "sample/printk.c"
    READ_ONCE_32(r8, r7, OFFSET(28));
#line 29 "sample/printk.c"
    r1 = (uint64_t)2676581182147752821;
#line 30 "sample/printk.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 30 "sample/printk.c"
    r1 = (uint64_t)2338816401835575632;
#line 30 "sample/printk.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 25 "sample/printk.c"
    r6 += r9;
#line 25 "sample/printk.c"
    r1 = IMMEDIATE(117);
#line 30 "sample/printk.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-16));
#line 30 "sample/printk.c"
    r9 = IMMEDIATE(117);
#line 30 "sample/printk.c"
    r1 = r10;
#line 30 "sample/printk.c"
    r1 += IMMEDIATE(-32);
#line 30 "sample/printk.c"
    r2 = IMMEDIATE(18);
#line 30 "sample/printk.c"
    r3 = r8;
#line 30 "sample/printk.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 30 "sample/printk.c"
    r1 = IMMEDIATE(7695397);
#line 31 "sample/printk.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
#line 31 "sample/printk.c"
    r1 = (uint64_t)2675251902571312416;
#line 31 "sample/printk.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 31 "sample/printk.c"
    r1 = (uint64_t)8461178620269054288;
#line 31 "sample/printk.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 30 "sample/printk.c"
    r6 += r0;
#line 30 "sample/printk.c"
    r1 = r10;
#line 30 "sample/printk.c"
    r1 += IMMEDIATE(-32);
#line 31 "sample/printk.c"
    r2 = IMMEDIATE(20);
#line 31 "sample/printk.c"
    r3 = r8;
#line 31 "sample/printk.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 31 "sample/printk.c"
    r1 = IMMEDIATE(1819026725);
#line 32 "sample/printk.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
#line 32 "sample/printk.c"
    r1 = (uint64_t)2334956331002568821;
#line 32 "sample/printk.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 32 "sample/printk.c"
    r1 = (uint64_t)7812660273927702864;
#line 32 "sample/printk.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 31 "sample/printk.c"
    r6 += r0;
#line 32 "sample/printk.c"
    WRITE_ONCE_16(r10, (uint16_t)r9, OFFSET(-12));
#line 32 "sample/printk.c"
    r1 = r10;
#line 32 "sample/printk.c"
    r1 += IMMEDIATE(-32);
#line 32 "sample/printk.c"
    r2 = IMMEDIATE(22);
#line 32 "sample/printk.c"
    r3 = r8;
#line 32 "sample/printk.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 32 "sample/printk.c"
    r1 = IMMEDIATE(29989);
#line 33 "sample/printk.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-16));
#line 32 "sample/printk.c"
    r6 += r0;
#line 32 "sample/printk.c"
    r1 = IMMEDIATE(0);
#line 33 "sample/printk.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-14));
#line 33 "sample/printk.c"
    r8 = (uint64_t)2322244790516799008;
#line 33 "sample/printk.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-24));
#line 33 "sample/printk.c"
    r9 = (uint64_t)8441188511152095556;
#line 33 "sample/printk.c"
    WRITE_ONCE_64(r10, (uint64_t)r9, OFFSET(-32));
#line 33 "sample/printk.c"
    READ_ONCE_16(r4, r7, OFFSET(20));
#line 33 "sample/printk.c"
    READ_ONCE_32(r3, r7, OFFSET(16));
#line 33 "sample/printk.c"
    r1 = r10;
#line 33 "sample/printk.c"
    r1 += IMMEDIATE(-32);
#line 33 "sample/printk.c"
    r2 = IMMEDIATE(19);
#line 33 "sample/printk.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 35 "sample/printk.c"
    r1 = IMMEDIATE(117);
#line 35 "sample/printk.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-4));
#line 35 "sample/printk.c"
    r1 = IMMEDIATE(622869074);
#line 35 "sample/printk.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 35 "sample/printk.c"
    r1 = (uint64_t)4994575847200421157;
#line 35 "sample/printk.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 35 "sample/printk.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-24));
#line 35 "sample/printk.c"
    WRITE_ONCE_64(r10, (uint64_t)r9, OFFSET(-32));
#line 33 "sample/printk.c"
    r6 += r0;
#line 35 "sample/printk.c"
    READ_ONCE_32(r5, r7, OFFSET(24));
#line 35 "sample/printk.c"
    READ_ONCE_16(r4, r7, OFFSET(20));
#line 35 "sample/printk.c"
    READ_ONCE_32(r3, r7, OFFSET(16));
#line 35 "sample/printk.c"
    r1 = r10;
#line 35 "sample/printk.c"
    r1 += IMMEDIATE(-32);
#line 35 "sample/printk.c"
    r2 = IMMEDIATE(30);
#line 35 "sample/printk.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 35 "sample/printk.c"
    r1 = IMMEDIATE(9504);
#line 39 "sample/printk.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-28));
#line 39 "sample/printk.c"
    r1 = IMMEDIATE(826556738);
#line 39 "sample/printk.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-32));
#line 34 "sample/printk.c"
    r6 += r0;
#line 34 "sample/printk.c"
    r8 = IMMEDIATE(0);
#line 39 "sample/printk.c"
    WRITE_ONCE_8(r10, (uint8_t)r8, OFFSET(-26));
#line 39 "sample/printk.c"
    r1 = r10;
#line 39 "sample/printk.c"
    r1 += IMMEDIATE(-32);
#line 39 "sample/printk.c"
    r2 = IMMEDIATE(7);
#line 39 "sample/printk.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 39 "sample/printk.c"
    r1 = (uint64_t)7812660273793483074;
#line 40 "sample/printk.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 39 "sample/printk.c"
    r6 += r0;
#line 40 "sample/printk.c"
    WRITE_ONCE_8(r10, (uint8_t)r8, OFFSET(-24));
#line 40 "sample/printk.c"
    r1 = r10;
#line 40 "sample/printk.c"
    r1 += IMMEDIATE(-32);
#line 40 "sample/printk.c"
    r2 = IMMEDIATE(9);
#line 40 "sample/printk.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 40 "sample/printk.c"
    r1 = (uint64_t)7220718397787750722;
#line 41 "sample/printk.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 40 "sample/printk.c"
    r6 += r0;
#line 41 "sample/printk.c"
    WRITE_ONCE_8(r10, (uint8_t)r8, OFFSET(-24));
#line 41 "sample/printk.c"
    READ_ONCE_32(r3, r7, OFFSET(16));
#line 41 "sample/printk.c"
    r1 = r10;
#line 41 "sample/printk.c"
    r1 += IMMEDIATE(-32);
#line 41 "sample/printk.c"
    r2 = IMMEDIATE(9);
#line 41 "sample/printk.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 41 "sample/printk.c"
    r1 = (uint64_t)31566017637663042;
#line 42 "sample/printk.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 41 "sample/printk.c"
    r6 += r0;
#line 42 "sample/printk.c"
    READ_ONCE_32(r3, r7, OFFSET(16));
#line 42 "sample/printk.c"
    r1 = r10;
#line 42 "sample/printk.c"
    r1 += IMMEDIATE(-32);
#line 42 "sample/printk.c"
    r2 = IMMEDIATE(8);
#line 42 "sample/printk.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 42 "sample/printk.c"
    r1 = IMMEDIATE(893665602);
#line 46 "sample/printk.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-32));
#line 42 "sample/printk.c"
    r6 += r0;
#line 46 "sample/printk.c"
    WRITE_ONCE_8(r10, (uint8_t)r8, OFFSET(-28));
#line 46 "sample/printk.c"
    READ_ONCE_32(r3, r7, OFFSET(16));
#line 46 "sample/printk.c"
    r1 = r10;
#line 46 "sample/printk.c"
    r1 += IMMEDIATE(-32);
#line 46 "sample/printk.c"
    r2 = IMMEDIATE(5);
#line 46 "sample/printk.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 46 "sample/printk.c"
    r1 = (uint64_t)32973392554770754;
#line 47 "sample/printk.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 46 "sample/printk.c"
    r6 += r0;
#line 46 "sample/printk.c"
    r1 = r10;
#line 46 "sample/printk.c"
    r1 += IMMEDIATE(-32);
#line 47 "sample/printk.c"
    r2 = IMMEDIATE(8);
#line 47 "sample/printk.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 50 "sample/printk.c"
    WRITE_ONCE_8(r10, (uint8_t)r8, OFFSET(-22));
#line 50 "sample/printk.c"
    r1 = IMMEDIATE(25966);
#line 50 "sample/printk.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-24));
#line 50 "sample/printk.c"
    r1 = (uint64_t)8026575779790860337;
#line 50 "sample/printk.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 47 "sample/printk.c"
    r6 += r0;
#line 47 "sample/printk.c"
    r1 = r10;
#line 47 "sample/printk.c"
    r1 += IMMEDIATE(-32);
#line 50 "sample/printk.c"
    r2 = IMMEDIATE(11);
#line 50 "sample/printk.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 50 "sample/printk.c"
    r6 += r0;
#line 52 "sample/printk.c"
    r0 = r6;
#line 52 "sample/printk.c"
    return r0;
#line 19 "sample/printk.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 154, 160}, // Version header.
        func,
        "sample~1",
        "sample_ext",
        "func",
        NULL,
        0,
        func_helpers,
        4,
        171,
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
    version->major = 1;
    version->minor = 7;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t printk_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
