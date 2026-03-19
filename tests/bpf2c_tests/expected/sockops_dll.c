// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from sockops.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers.
#include <windows.h>

#define metadata_table sockops##_metadata_table
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
    {{0, 0},
     {
         1,  // Current Version.
         80, // Struct size up to the last field.
         80, // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         56,                // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         2,                 // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         21,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "connection_map"},
    {{0, 0},
     {
         1,  // Current Version.
         80, // Struct size up to the last field.
         80, // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_RINGBUF, // Type of map.
         0,                    // Size in bytes of a map key.
         0,                    // Size in bytes of a map value.
         262144,               // Maximum number of entries allowed in the map.
         0,                    // Inner map index.
         LIBBPF_PIN_NONE,      // Pinning type for the map.
         27,                   // Identifier for a map template.
         0,                    // The id of the inner map template.
     },
     "audit_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 2;
}

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static helper_function_entry_t connection_monitor_helpers[] = {
    {
        {1, 40, 40}, // Version header.
        19,
        "helper_id_19",
    },
    {
        {1, 40, 40}, // Version header.
        1,
        "helper_id_1",
    },
    {
        {1, 40, 40}, // Version header.
        11,
        "helper_id_11",
    },
};

static GUID connection_monitor_program_type_guid = {
    0x43fb224d, 0x68f8, 0x46d6, {0xaa, 0x3f, 0xc8, 0x56, 0x51, 0x8c, 0xbb, 0x32}};
static GUID connection_monitor_attach_type_guid = {
    0x837d02cd, 0x3251, 0x4632, {0x8d, 0x94, 0x60, 0xd3, 0xb4, 0x57, 0x69, 0xf2}};
static uint16_t connection_monitor_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sockops")
static uint64_t
connection_monitor(void* context, const program_runtime_context_t* runtime_context)
#line 78 "sample/sockops.c"
{
#line 78 "sample/sockops.c"
    // Prologue.
#line 78 "sample/sockops.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 78 "sample/sockops.c"
    register uint64_t r0 = 0;
#line 78 "sample/sockops.c"
    register uint64_t r1 = 0;
#line 78 "sample/sockops.c"
    register uint64_t r2 = 0;
#line 78 "sample/sockops.c"
    register uint64_t r3 = 0;
#line 78 "sample/sockops.c"
    register uint64_t r4 = 0;
#line 78 "sample/sockops.c"
    register uint64_t r5 = 0;
#line 78 "sample/sockops.c"
    register uint64_t r6 = 0;
#line 78 "sample/sockops.c"
    register uint64_t r10 = 0;

#line 78 "sample/sockops.c"
    r1 = (uintptr_t)context;
#line 78 "sample/sockops.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 78 "sample/sockops.c"
    r6 = IMMEDIATE(2);
#line 78 "sample/sockops.c"
    r2 = IMMEDIATE(1);
#line 83 "sample/sockops.c"
    READ_ONCE_32(r3, r1, OFFSET(0));
#line 83 "sample/sockops.c"
    if (r3 == IMMEDIATE(0)) {
#line 83 "sample/sockops.c"
        goto label_2;
#line 83 "sample/sockops.c"
    }
#line 83 "sample/sockops.c"
    if (r3 == IMMEDIATE(2)) {
#line 83 "sample/sockops.c"
        goto label_1;
#line 83 "sample/sockops.c"
    }
#line 83 "sample/sockops.c"
    r0 = (uint64_t)4294967295;
#line 83 "sample/sockops.c"
    if (r3 != IMMEDIATE(1)) {
#line 83 "sample/sockops.c"
        goto label_5;
#line 83 "sample/sockops.c"
    }
#line 83 "sample/sockops.c"
    r2 = IMMEDIATE(0);
#line 83 "sample/sockops.c"
    goto label_2;
label_1:
#line 83 "sample/sockops.c"
    r2 = IMMEDIATE(0);
#line 83 "sample/sockops.c"
    r6 = IMMEDIATE(0);
label_2:
#line 100 "sample/sockops.c"
    READ_ONCE_32(r3, r1, OFFSET(4));
#line 100 "sample/sockops.c"
    if (r3 != IMMEDIATE(2)) {
#line 100 "sample/sockops.c"
        goto label_3;
#line 100 "sample/sockops.c"
    }
#line 100 "sample/sockops.c"
    r3 = IMMEDIATE(0);
#line 36 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r3, OFFSET(-8));
#line 36 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r3, OFFSET(-16));
#line 36 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r3, OFFSET(-24));
#line 36 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r3, OFFSET(-32));
#line 36 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r3, OFFSET(-40));
#line 36 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r3, OFFSET(-48));
#line 36 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r3, OFFSET(-56));
#line 36 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r3, OFFSET(-64));
#line 36 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r3, OFFSET(-72));
#line 38 "sample/sockops.c"
    READ_ONCE_32(r3, r1, OFFSET(8));
#line 38 "sample/sockops.c"
    WRITE_ONCE_32(r10, (uint32_t)r3, OFFSET(-72));
#line 39 "sample/sockops.c"
    READ_ONCE_32(r3, r1, OFFSET(24));
#line 39 "sample/sockops.c"
    WRITE_ONCE_16(r10, (uint16_t)r3, OFFSET(-56));
#line 40 "sample/sockops.c"
    READ_ONCE_32(r3, r1, OFFSET(28));
#line 40 "sample/sockops.c"
    WRITE_ONCE_32(r10, (uint32_t)r3, OFFSET(-52));
#line 47 "sample/sockops.c"
    r6 |= r2;
#line 41 "sample/sockops.c"
    READ_ONCE_32(r2, r1, OFFSET(44));
#line 41 "sample/sockops.c"
    WRITE_ONCE_16(r10, (uint16_t)r2, OFFSET(-36));
#line 42 "sample/sockops.c"
    READ_ONCE_8(r2, r1, OFFSET(48));
#line 42 "sample/sockops.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-32));
#line 43 "sample/sockops.c"
    READ_ONCE_64(r1, r1, OFFSET(56));
#line 43 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 44 "sample/sockops.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 48 "sample/sockops.c"
    WRITE_ONCE_8(r10, (uint8_t)r6, OFFSET(-8));
#line 46 "sample/sockops.c"
    r0 >>= (IMMEDIATE(32) & 63);
#line 46 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-16));
#line 46 "sample/sockops.c"
    r2 = r10;
#line 46 "sample/sockops.c"
    r2 += IMMEDIATE(-72);
#line 26 "sample/sockops.c"
    r1 = POINTER(runtime_context->map_data[0].address);
#line 26 "sample/sockops.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 26 "sample/sockops.c"
    r1 = r0;
#line 26 "sample/sockops.c"
    r0 = (uint64_t)4294967295;
#line 26 "sample/sockops.c"
    if (r1 == IMMEDIATE(0)) {
#line 26 "sample/sockops.c"
        goto label_5;
#line 26 "sample/sockops.c"
    }
#line 26 "sample/sockops.c"
    goto label_4;
label_3:
#line 26 "sample/sockops.c"
    r3 = IMMEDIATE(0);
#line 56 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r3, OFFSET(-8));
#line 56 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r3, OFFSET(-16));
#line 56 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r3, OFFSET(-24));
#line 56 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r3, OFFSET(-32));
#line 56 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r3, OFFSET(-40));
#line 56 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r3, OFFSET(-48));
#line 56 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r3, OFFSET(-56));
#line 60 "sample/sockops.c"
    READ_ONCE_8(r4, r1, OFFSET(17));
#line 60 "sample/sockops.c"
    r4 <<= (IMMEDIATE(8) & 63);
#line 60 "sample/sockops.c"
    READ_ONCE_8(r3, r1, OFFSET(16));
#line 60 "sample/sockops.c"
    r4 |= r3;
#line 60 "sample/sockops.c"
    READ_ONCE_8(r5, r1, OFFSET(18));
#line 60 "sample/sockops.c"
    r5 <<= (IMMEDIATE(16) & 63);
#line 60 "sample/sockops.c"
    READ_ONCE_8(r3, r1, OFFSET(19));
#line 60 "sample/sockops.c"
    r3 <<= (IMMEDIATE(24) & 63);
#line 60 "sample/sockops.c"
    r3 |= r5;
#line 60 "sample/sockops.c"
    r3 |= r4;
#line 60 "sample/sockops.c"
    READ_ONCE_8(r5, r1, OFFSET(21));
#line 60 "sample/sockops.c"
    r5 <<= (IMMEDIATE(8) & 63);
#line 60 "sample/sockops.c"
    READ_ONCE_8(r4, r1, OFFSET(20));
#line 60 "sample/sockops.c"
    r5 |= r4;
#line 60 "sample/sockops.c"
    READ_ONCE_8(r0, r1, OFFSET(22));
#line 60 "sample/sockops.c"
    r0 <<= (IMMEDIATE(16) & 63);
#line 60 "sample/sockops.c"
    READ_ONCE_8(r4, r1, OFFSET(23));
#line 60 "sample/sockops.c"
    r4 <<= (IMMEDIATE(24) & 63);
#line 60 "sample/sockops.c"
    r4 |= r0;
#line 60 "sample/sockops.c"
    r4 |= r5;
#line 60 "sample/sockops.c"
    r4 <<= (IMMEDIATE(32) & 63);
#line 60 "sample/sockops.c"
    r4 |= r3;
#line 60 "sample/sockops.c"
    READ_ONCE_8(r5, r1, OFFSET(9));
#line 60 "sample/sockops.c"
    r5 <<= (IMMEDIATE(8) & 63);
#line 60 "sample/sockops.c"
    READ_ONCE_8(r3, r1, OFFSET(8));
#line 60 "sample/sockops.c"
    r5 |= r3;
#line 60 "sample/sockops.c"
    READ_ONCE_8(r0, r1, OFFSET(10));
#line 60 "sample/sockops.c"
    r0 <<= (IMMEDIATE(16) & 63);
#line 60 "sample/sockops.c"
    READ_ONCE_8(r3, r1, OFFSET(11));
#line 60 "sample/sockops.c"
    r3 <<= (IMMEDIATE(24) & 63);
#line 60 "sample/sockops.c"
    r3 |= r0;
#line 70 "sample/sockops.c"
    r6 |= r2;
#line 60 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r4, OFFSET(-64));
#line 60 "sample/sockops.c"
    r3 |= r5;
#line 60 "sample/sockops.c"
    READ_ONCE_8(r2, r1, OFFSET(13));
#line 60 "sample/sockops.c"
    r2 <<= (IMMEDIATE(8) & 63);
#line 60 "sample/sockops.c"
    READ_ONCE_8(r4, r1, OFFSET(12));
#line 60 "sample/sockops.c"
    r2 |= r4;
#line 60 "sample/sockops.c"
    READ_ONCE_8(r4, r1, OFFSET(14));
#line 60 "sample/sockops.c"
    r4 <<= (IMMEDIATE(16) & 63);
#line 60 "sample/sockops.c"
    READ_ONCE_8(r5, r1, OFFSET(15));
#line 60 "sample/sockops.c"
    r5 <<= (IMMEDIATE(24) & 63);
#line 60 "sample/sockops.c"
    r5 |= r4;
#line 60 "sample/sockops.c"
    r5 |= r2;
#line 60 "sample/sockops.c"
    r5 <<= (IMMEDIATE(32) & 63);
#line 60 "sample/sockops.c"
    r5 |= r3;
#line 60 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r5, OFFSET(-72));
#line 61 "sample/sockops.c"
    READ_ONCE_32(r2, r1, OFFSET(24));
#line 61 "sample/sockops.c"
    WRITE_ONCE_16(r10, (uint16_t)r2, OFFSET(-56));
#line 63 "sample/sockops.c"
    READ_ONCE_8(r3, r1, OFFSET(41));
#line 63 "sample/sockops.c"
    r3 <<= (IMMEDIATE(8) & 63);
#line 63 "sample/sockops.c"
    READ_ONCE_8(r2, r1, OFFSET(40));
#line 63 "sample/sockops.c"
    r3 |= r2;
#line 63 "sample/sockops.c"
    READ_ONCE_8(r4, r1, OFFSET(42));
#line 63 "sample/sockops.c"
    r4 <<= (IMMEDIATE(16) & 63);
#line 63 "sample/sockops.c"
    READ_ONCE_8(r2, r1, OFFSET(43));
#line 63 "sample/sockops.c"
    r2 <<= (IMMEDIATE(24) & 63);
#line 63 "sample/sockops.c"
    r2 |= r4;
#line 63 "sample/sockops.c"
    READ_ONCE_8(r5, r1, OFFSET(29));
#line 63 "sample/sockops.c"
    r5 <<= (IMMEDIATE(8) & 63);
#line 63 "sample/sockops.c"
    READ_ONCE_8(r4, r1, OFFSET(28));
#line 63 "sample/sockops.c"
    r5 |= r4;
#line 63 "sample/sockops.c"
    READ_ONCE_8(r0, r1, OFFSET(30));
#line 63 "sample/sockops.c"
    r0 <<= (IMMEDIATE(16) & 63);
#line 63 "sample/sockops.c"
    READ_ONCE_8(r4, r1, OFFSET(31));
#line 63 "sample/sockops.c"
    r4 <<= (IMMEDIATE(24) & 63);
#line 63 "sample/sockops.c"
    r4 |= r0;
#line 63 "sample/sockops.c"
    r4 |= r5;
#line 63 "sample/sockops.c"
    r2 |= r3;
#line 63 "sample/sockops.c"
    READ_ONCE_8(r3, r1, OFFSET(37));
#line 63 "sample/sockops.c"
    r3 <<= (IMMEDIATE(8) & 63);
#line 63 "sample/sockops.c"
    READ_ONCE_8(r5, r1, OFFSET(36));
#line 63 "sample/sockops.c"
    r3 |= r5;
#line 63 "sample/sockops.c"
    READ_ONCE_8(r5, r1, OFFSET(38));
#line 63 "sample/sockops.c"
    r5 <<= (IMMEDIATE(16) & 63);
#line 63 "sample/sockops.c"
    READ_ONCE_8(r0, r1, OFFSET(39));
#line 63 "sample/sockops.c"
    r0 <<= (IMMEDIATE(24) & 63);
#line 63 "sample/sockops.c"
    r0 |= r5;
#line 63 "sample/sockops.c"
    r0 |= r3;
#line 63 "sample/sockops.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-44));
#line 63 "sample/sockops.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-40));
#line 63 "sample/sockops.c"
    WRITE_ONCE_32(r10, (uint32_t)r4, OFFSET(-52));
#line 63 "sample/sockops.c"
    READ_ONCE_8(r2, r1, OFFSET(33));
#line 63 "sample/sockops.c"
    r2 <<= (IMMEDIATE(8) & 63);
#line 63 "sample/sockops.c"
    READ_ONCE_8(r3, r1, OFFSET(32));
#line 63 "sample/sockops.c"
    r2 |= r3;
#line 63 "sample/sockops.c"
    READ_ONCE_8(r3, r1, OFFSET(34));
#line 63 "sample/sockops.c"
    r3 <<= (IMMEDIATE(16) & 63);
#line 63 "sample/sockops.c"
    READ_ONCE_8(r4, r1, OFFSET(35));
#line 63 "sample/sockops.c"
    r4 <<= (IMMEDIATE(24) & 63);
#line 63 "sample/sockops.c"
    r4 |= r3;
#line 63 "sample/sockops.c"
    r4 |= r2;
#line 63 "sample/sockops.c"
    WRITE_ONCE_32(r10, (uint32_t)r4, OFFSET(-48));
#line 64 "sample/sockops.c"
    READ_ONCE_32(r2, r1, OFFSET(44));
#line 64 "sample/sockops.c"
    WRITE_ONCE_16(r10, (uint16_t)r2, OFFSET(-36));
#line 65 "sample/sockops.c"
    READ_ONCE_8(r2, r1, OFFSET(48));
#line 65 "sample/sockops.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-32));
#line 66 "sample/sockops.c"
    READ_ONCE_64(r1, r1, OFFSET(56));
#line 66 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 67 "sample/sockops.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 71 "sample/sockops.c"
    WRITE_ONCE_8(r10, (uint8_t)r6, OFFSET(-8));
#line 69 "sample/sockops.c"
    r0 >>= (IMMEDIATE(32) & 63);
#line 69 "sample/sockops.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-16));
#line 69 "sample/sockops.c"
    r2 = r10;
#line 69 "sample/sockops.c"
    r2 += IMMEDIATE(-72);
#line 26 "sample/sockops.c"
    r1 = POINTER(runtime_context->map_data[0].address);
#line 26 "sample/sockops.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 26 "sample/sockops.c"
    r1 = r0;
#line 26 "sample/sockops.c"
    r0 = (uint64_t)4294967295;
#line 26 "sample/sockops.c"
    if (r1 == IMMEDIATE(0)) {
#line 26 "sample/sockops.c"
        goto label_5;
#line 26 "sample/sockops.c"
    }
label_4:
#line 26 "sample/sockops.c"
    r2 = r10;
#line 100 "sample/sockops.c"
    r2 += IMMEDIATE(-72);
#line 100 "sample/sockops.c"
    r1 = POINTER(runtime_context->map_data[1].address);
#line 100 "sample/sockops.c"
    r3 = IMMEDIATE(72);
#line 100 "sample/sockops.c"
    r4 = IMMEDIATE(0);
#line 100 "sample/sockops.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_5:
#line 103 "sample/sockops.c"
    return r0;
#line 78 "sample/sockops.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        connection_monitor,
        "sockops",
        "sockops",
        "connection_monitor",
        connection_monitor_maps,
        2,
        connection_monitor_helpers,
        3,
        179,
        &connection_monitor_program_type_guid,
        &connection_monitor_attach_type_guid,
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

metadata_table_t sockops_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
