// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from cgroup_sock_addr_helpers.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers.
#include <windows.h>

#define metadata_table cgroup_sock_addr_helpers##_metadata_table
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
         32,                // Size in bytes of a map value.
         1000,              // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         15,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "network_context_map"},
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
         8,                 // Size in bytes of a map value.
         1,                 // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         18,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "connection_count_map"},
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
         32,                // Size in bytes of a map value.
         4,                 // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         28,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "sock_addr_helper_results_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 3;
}

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static helper_function_entry_t conditional_authorization_v4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     65538,
     "helper_id_65538",
    },
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID conditional_authorization_v4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID conditional_authorization_v4_attach_type_guid = {
    0x6076c13a, 0xf04f, 0x4ff8, {0x83, 0x80, 0x90, 0x85, 0x53, 0xf2, 0x22, 0x76}};
static uint16_t conditional_authorization_v4_maps[] = {
    1,
};

#pragma code_seg(push, "cgroup~7")
static uint64_t
conditional_authorization_v4(void* context, const program_runtime_context_t* runtime_context)
#line 75 "sample/cgroup_sock_addr_helpers.c"
{
#line 75 "sample/cgroup_sock_addr_helpers.c"
    // Prologue.
#line 75 "sample/cgroup_sock_addr_helpers.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 75 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r0 = 0;
#line 75 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r1 = 0;
#line 75 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r2 = 0;
#line 75 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r3 = 0;
#line 75 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r4 = 0;
#line 75 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r5 = 0;
#line 75 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r6 = 0;
#line 75 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r10 = 0;

#line 75 "sample/cgroup_sock_addr_helpers.c"
    r1 = (uintptr_t)context;
#line 75 "sample/cgroup_sock_addr_helpers.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=1
#line 75 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=1 dst=r2 src=r1 offset=44 imm=0
#line 80 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r2, r1, OFFSET(44));
    // EBPF_OP_JNE_IMM pc=2 dst=r2 src=r0 offset=37 imm=6
#line 80 "sample/cgroup_sock_addr_helpers.c"
    if (r2 != IMMEDIATE(6)) {
#line 80 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 80 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_IMM pc=3 dst=r6 src=r0 offset=0 imm=0
#line 85 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=4 dst=r10 src=r6 offset=-8 imm=0
#line 85 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-8));
    // EBPF_OP_STXDW pc=5 dst=r10 src=r6 offset=-16 imm=0
#line 85 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-16));
    // EBPF_OP_STXDW pc=6 dst=r10 src=r6 offset=-24 imm=0
#line 85 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-24));
    // EBPF_OP_STXDW pc=7 dst=r10 src=r6 offset=-32 imm=0
#line 85 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-32));
    // EBPF_OP_MOV64_REG pc=8 dst=r2 src=r10 offset=0 imm=0
#line 85 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=9 dst=r2 src=r0 offset=0 imm=-32
#line 88 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=10 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/cgroup_sock_addr_helpers.c"
    r3 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=11 dst=r0 src=r0 offset=0 imm=65538
#line 88 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LSH64_IMM pc=12 dst=r0 src=r0 offset=0 imm=32
#line 88 "sample/cgroup_sock_addr_helpers.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=13 dst=r0 src=r0 offset=0 imm=32
#line 88 "sample/cgroup_sock_addr_helpers.c"
    r0 = (int64_t)r0 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=14 dst=r6 src=r0 offset=25 imm=0
#line 85 "sample/cgroup_sock_addr_helpers.c"
    if ((int64_t)r6 > (int64_t)r0) {
#line 85 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 85 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXW pc=15 dst=r1 src=r10 offset=-28 imm=0
#line 89 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r1, r10, OFFSET(-28));
    // EBPF_OP_JEQ_IMM pc=16 dst=r1 src=r0 offset=23 imm=23
#line 89 "sample/cgroup_sock_addr_helpers.c"
    if (r1 == IMMEDIATE(23)) {
#line 89 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 89 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXW pc=17 dst=r1 src=r10 offset=-24 imm=0
#line 89 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r1, r10, OFFSET(-24));
    // EBPF_OP_MOV64_IMM pc=18 dst=r6 src=r0 offset=0 imm=1
#line 89 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=19 dst=r1 src=r0 offset=20 imm=0
#line 89 "sample/cgroup_sock_addr_helpers.c"
    if (r1 == IMMEDIATE(0)) {
#line 89 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 89 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_IMM pc=20 dst=r1 src=r0 offset=0 imm=100
#line 89 "sample/cgroup_sock_addr_helpers.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXW pc=21 dst=r10 src=r1 offset=-36 imm=0
#line 96 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-36));
    // EBPF_OP_STXDW pc=22 dst=r10 src=r6 offset=-48 imm=0
#line 96 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-48));
    // EBPF_OP_MOV64_REG pc=23 dst=r2 src=r10 offset=0 imm=0
#line 96 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=24 dst=r2 src=r0 offset=0 imm=-36
#line 96 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-36);
    // EBPF_OP_LDDW pc=25 dst=r1 src=r1 offset=0 imm=2
#line 96 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=27 dst=r0 src=r0 offset=0 imm=1
#line 96 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=28 dst=r0 src=r0 offset=3 imm=0
#line 96 "sample/cgroup_sock_addr_helpers.c"
    if (r0 == IMMEDIATE(0)) {
#line 96 "sample/cgroup_sock_addr_helpers.c"
        goto label_1;
#line 96 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXDW pc=29 dst=r1 src=r0 offset=0 imm=0
#line 99 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_64(r1, r0, OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=30 dst=r1 src=r0 offset=0 imm=1
#line 100 "sample/cgroup_sock_addr_helpers.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=31 dst=r10 src=r1 offset=-48 imm=0
#line 100 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
label_1:
    // EBPF_OP_MOV64_REG pc=32 dst=r2 src=r10 offset=0 imm=0
#line 96 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=33 dst=r2 src=r0 offset=0 imm=-36
#line 101 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-36);
    // EBPF_OP_MOV64_REG pc=34 dst=r3 src=r10 offset=0 imm=0
#line 101 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=35 dst=r3 src=r0 offset=0 imm=-48
#line 101 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-48);
    // EBPF_OP_LDDW pc=36 dst=r1 src=r1 offset=0 imm=2
#line 102 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=38 dst=r4 src=r0 offset=0 imm=0
#line 103 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=39 dst=r0 src=r0 offset=0 imm=2
#line 103 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_2:
    // EBPF_OP_MOV64_REG pc=40 dst=r0 src=r6 offset=0 imm=0
#line 103 "sample/cgroup_sock_addr_helpers.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=41 dst=r0 src=r0 offset=0 imm=0
#line 105 "sample/cgroup_sock_addr_helpers.c"
    return r0;
#line 75 "sample/cgroup_sock_addr_helpers.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t test_bind_helpers_v4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     65538,
     "helper_id_65538",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
    {
     {1, 40, 40}, // Version header.
     19,
     "helper_id_19",
    },
    {
     {1, 40, 40}, // Version header.
     20,
     "helper_id_20",
    },
    {
     {1, 40, 40}, // Version header.
     21,
     "helper_id_21",
    },
    {
     {1, 40, 40}, // Version header.
     65537,
     "helper_id_65537",
    },
    {
     {1, 40, 40}, // Version header.
     26,
     "helper_id_26",
    },
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID test_bind_helpers_v4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID test_bind_helpers_v4_attach_type_guid = {
    0x0d7ce21a, 0x7773, 0x405c, {0x93, 0xb6, 0xd5, 0xbf, 0xb9, 0x2e, 0x74, 0xbc}};
static uint16_t test_bind_helpers_v4_maps[] = {
    0,
    1,
    2,
};

#pragma code_seg(push, "cgroup~4")
static uint64_t
test_bind_helpers_v4(void* context, const program_runtime_context_t* runtime_context)
#line 236 "sample/cgroup_sock_addr_helpers.c"
{
#line 236 "sample/cgroup_sock_addr_helpers.c"
    // Prologue.
#line 236 "sample/cgroup_sock_addr_helpers.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 236 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r0 = 0;
#line 236 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r1 = 0;
#line 236 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r2 = 0;
#line 236 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r3 = 0;
#line 236 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r4 = 0;
#line 236 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r5 = 0;
#line 236 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r6 = 0;
#line 236 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r7 = 0;
#line 236 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r10 = 0;

#line 236 "sample/cgroup_sock_addr_helpers.c"
    r1 = (uintptr_t)context;
#line 236 "sample/cgroup_sock_addr_helpers.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 236 "sample/cgroup_sock_addr_helpers.c"
    r6 = r1;
    // EBPF_OP_LDXH pc=1 dst=r1 src=r6 offset=40 imm=0
#line 241 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_16(r1, r6, OFFSET(40));
    // EBPF_OP_LSH64_IMM pc=2 dst=r1 src=r0 offset=0 imm=16
#line 241 "sample/cgroup_sock_addr_helpers.c"
    r1 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_LDXW pc=3 dst=r2 src=r6 offset=24 imm=0
#line 241 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r2, r6, OFFSET(24));
    // EBPF_OP_XOR64_REG pc=4 dst=r1 src=r2 offset=0 imm=0
#line 241 "sample/cgroup_sock_addr_helpers.c"
    r1 ^= r2;
    // EBPF_OP_STXW pc=5 dst=r10 src=r1 offset=-4 imm=0
#line 241 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MOV64_IMM pc=6 dst=r7 src=r0 offset=0 imm=0
#line 241 "sample/cgroup_sock_addr_helpers.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=7 dst=r10 src=r7 offset=-16 imm=0
#line 243 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-16));
    // EBPF_OP_STXDW pc=8 dst=r10 src=r7 offset=-24 imm=0
#line 243 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-24));
    // EBPF_OP_STXDW pc=9 dst=r10 src=r7 offset=-32 imm=0
#line 243 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-32));
    // EBPF_OP_STXDW pc=10 dst=r10 src=r7 offset=-40 imm=0
#line 243 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-40));
    // EBPF_OP_MOV64_REG pc=11 dst=r2 src=r10 offset=0 imm=0
#line 243 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=12 dst=r2 src=r0 offset=0 imm=-40
#line 243 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-40);
    // EBPF_OP_MOV64_REG pc=13 dst=r1 src=r6 offset=0 imm=0
#line 244 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_MOV64_IMM pc=14 dst=r3 src=r0 offset=0 imm=32
#line 244 "sample/cgroup_sock_addr_helpers.c"
    r3 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=15 dst=r0 src=r0 offset=0 imm=65538
#line 244 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LSH64_IMM pc=16 dst=r0 src=r0 offset=0 imm=32
#line 244 "sample/cgroup_sock_addr_helpers.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=17 dst=r0 src=r0 offset=0 imm=32
#line 244 "sample/cgroup_sock_addr_helpers.c"
    r0 = (int64_t)r0 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=18 dst=r7 src=r0 offset=56 imm=0
#line 244 "sample/cgroup_sock_addr_helpers.c"
    if ((int64_t)r7 > (int64_t)r0) {
#line 244 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 244 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_REG pc=19 dst=r2 src=r10 offset=0 imm=0
#line 244 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=20 dst=r2 src=r0 offset=0 imm=-4
#line 249 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=21 dst=r3 src=r10 offset=0 imm=0
#line 249 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r3 src=r0 offset=0 imm=-40
#line 249 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-40);
    // EBPF_OP_LDDW pc=23 dst=r1 src=r1 offset=0 imm=1
#line 249 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=25 dst=r4 src=r0 offset=0 imm=0
#line 249 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=26 dst=r0 src=r0 offset=0 imm=2
#line 249 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXW pc=27 dst=r10 src=r7 offset=-44 imm=0
#line 256 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-44));
    // EBPF_OP_CALL pc=28 dst=r0 src=r0 offset=0 imm=19
#line 258 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXDW pc=29 dst=r10 src=r0 offset=-80 imm=0
#line 258 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-80));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 259 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=31 dst=r0 src=r0 offset=0 imm=20
#line 259 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXDW pc=32 dst=r10 src=r0 offset=-72 imm=0
#line 259 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-72));
    // EBPF_OP_MOV64_REG pc=33 dst=r1 src=r6 offset=0 imm=0
#line 260 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=21
#line 260 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXW pc=35 dst=r10 src=r0 offset=-64 imm=0
#line 260 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-64));
    // EBPF_OP_MOV64_REG pc=36 dst=r2 src=r10 offset=0 imm=0
#line 260 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=37 dst=r2 src=r0 offset=0 imm=-44
#line 249 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-44);
    // EBPF_OP_MOV64_IMM pc=38 dst=r7 src=r0 offset=0 imm=4
#line 249 "sample/cgroup_sock_addr_helpers.c"
    r7 = IMMEDIATE(4);
    // EBPF_OP_MOV64_REG pc=39 dst=r1 src=r6 offset=0 imm=0
#line 261 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_MOV64_IMM pc=40 dst=r3 src=r0 offset=0 imm=4
#line 261 "sample/cgroup_sock_addr_helpers.c"
    r3 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=41 dst=r0 src=r0 offset=0 imm=65537
#line 261 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXW pc=42 dst=r10 src=r0 offset=-60 imm=0
#line 261 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-60));
    // EBPF_OP_MOV64_REG pc=43 dst=r1 src=r6 offset=0 imm=0
#line 262 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=44 dst=r0 src=r0 offset=0 imm=26
#line 262 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 262 "sample/cgroup_sock_addr_helpers.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[2].address);
    // EBPF_OP_STXDW pc=45 dst=r10 src=r0 offset=-56 imm=0
#line 262 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-56));
    // EBPF_OP_STXW pc=46 dst=r10 src=r7 offset=-84 imm=0
#line 263 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-84));
    // EBPF_OP_MOV64_REG pc=47 dst=r2 src=r10 offset=0 imm=0
#line 263 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=48 dst=r2 src=r0 offset=0 imm=-84
#line 249 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-84);
    // EBPF_OP_MOV64_REG pc=49 dst=r3 src=r10 offset=0 imm=0
#line 249 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=50 dst=r3 src=r0 offset=0 imm=-80
#line 249 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-80);
    // EBPF_OP_LDDW pc=51 dst=r1 src=r1 offset=0 imm=3
#line 264 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_MOV64_IMM pc=53 dst=r4 src=r0 offset=0 imm=0
#line 264 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=54 dst=r0 src=r0 offset=0 imm=2
#line 264 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 264 "sample/cgroup_sock_addr_helpers.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[1].address);
    // EBPF_OP_STXW pc=55 dst=r10 src=r7 offset=-88 imm=0
#line 266 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-88));
    // EBPF_OP_MOV64_IMM pc=56 dst=r7 src=r0 offset=0 imm=1
#line 266 "sample/cgroup_sock_addr_helpers.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_STXDW pc=57 dst=r10 src=r7 offset=-96 imm=0
#line 267 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-96));
    // EBPF_OP_MOV64_REG pc=58 dst=r2 src=r10 offset=0 imm=0
#line 267 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=59 dst=r2 src=r0 offset=0 imm=-88
#line 249 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-88);
    // EBPF_OP_LDDW pc=60 dst=r1 src=r1 offset=0 imm=2
#line 268 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=62 dst=r0 src=r0 offset=0 imm=1
#line 268 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=63 dst=r0 src=r0 offset=3 imm=0
#line 269 "sample/cgroup_sock_addr_helpers.c"
    if (r0 == IMMEDIATE(0)) {
#line 269 "sample/cgroup_sock_addr_helpers.c"
        goto label_1;
#line 269 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXDW pc=64 dst=r1 src=r0 offset=0 imm=0
#line 270 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_64(r1, r0, OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=65 dst=r1 src=r0 offset=0 imm=1
#line 270 "sample/cgroup_sock_addr_helpers.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=66 dst=r10 src=r1 offset=-96 imm=0
#line 270 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
label_1:
    // EBPF_OP_MOV64_REG pc=67 dst=r2 src=r10 offset=0 imm=0
#line 270 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=68 dst=r2 src=r0 offset=0 imm=-88
#line 272 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-88);
    // EBPF_OP_MOV64_REG pc=69 dst=r3 src=r10 offset=0 imm=0
#line 272 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=70 dst=r3 src=r0 offset=0 imm=-96
#line 272 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-96);
    // EBPF_OP_LDDW pc=71 dst=r1 src=r1 offset=0 imm=2
#line 272 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=73 dst=r4 src=r0 offset=0 imm=0
#line 272 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=74 dst=r0 src=r0 offset=0 imm=2
#line 272 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
label_2:
    // EBPF_OP_MOV64_REG pc=75 dst=r0 src=r7 offset=0 imm=0
#line 275 "sample/cgroup_sock_addr_helpers.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=76 dst=r0 src=r0 offset=0 imm=0
#line 275 "sample/cgroup_sock_addr_helpers.c"
    return r0;
#line 236 "sample/cgroup_sock_addr_helpers.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t test_bind_helpers_v6_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     65538,
     "helper_id_65538",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
    {
     {1, 40, 40}, // Version header.
     19,
     "helper_id_19",
    },
    {
     {1, 40, 40}, // Version header.
     20,
     "helper_id_20",
    },
    {
     {1, 40, 40}, // Version header.
     21,
     "helper_id_21",
    },
    {
     {1, 40, 40}, // Version header.
     65537,
     "helper_id_65537",
    },
    {
     {1, 40, 40}, // Version header.
     26,
     "helper_id_26",
    },
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID test_bind_helpers_v6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID test_bind_helpers_v6_attach_type_guid = {
    0x81de64c0, 0x2973, 0x468d, {0x83, 0x82, 0x67, 0x69, 0xf0, 0x33, 0xd7, 0x59}};
static uint16_t test_bind_helpers_v6_maps[] = {
    0,
    1,
    2,
};

#pragma code_seg(push, "cgroup~2")
static uint64_t
test_bind_helpers_v6(void* context, const program_runtime_context_t* runtime_context)
#line 336 "sample/cgroup_sock_addr_helpers.c"
{
#line 336 "sample/cgroup_sock_addr_helpers.c"
    // Prologue.
#line 336 "sample/cgroup_sock_addr_helpers.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 336 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r0 = 0;
#line 336 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r1 = 0;
#line 336 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r2 = 0;
#line 336 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r3 = 0;
#line 336 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r4 = 0;
#line 336 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r5 = 0;
#line 336 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r6 = 0;
#line 336 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r7 = 0;
#line 336 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r10 = 0;

#line 336 "sample/cgroup_sock_addr_helpers.c"
    r1 = (uintptr_t)context;
#line 336 "sample/cgroup_sock_addr_helpers.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 336 "sample/cgroup_sock_addr_helpers.c"
    r6 = r1;
    // EBPF_OP_LDXW pc=1 dst=r1 src=r6 offset=24 imm=0
#line 341 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r1, r6, OFFSET(24));
    // EBPF_OP_LDXW pc=2 dst=r2 src=r6 offset=36 imm=0
#line 341 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r2, r6, OFFSET(36));
    // EBPF_OP_XOR64_REG pc=3 dst=r2 src=r1 offset=0 imm=0
#line 341 "sample/cgroup_sock_addr_helpers.c"
    r2 ^= r1;
    // EBPF_OP_LDXH pc=4 dst=r1 src=r6 offset=40 imm=0
#line 341 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_16(r1, r6, OFFSET(40));
    // EBPF_OP_LSH64_IMM pc=5 dst=r1 src=r0 offset=0 imm=16
#line 341 "sample/cgroup_sock_addr_helpers.c"
    r1 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_XOR64_REG pc=6 dst=r2 src=r1 offset=0 imm=0
#line 341 "sample/cgroup_sock_addr_helpers.c"
    r2 ^= r1;
    // EBPF_OP_STXW pc=7 dst=r10 src=r2 offset=-4 imm=0
#line 341 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-4));
    // EBPF_OP_MOV64_IMM pc=8 dst=r7 src=r0 offset=0 imm=0
#line 341 "sample/cgroup_sock_addr_helpers.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=9 dst=r10 src=r7 offset=-16 imm=0
#line 343 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-16));
    // EBPF_OP_STXDW pc=10 dst=r10 src=r7 offset=-24 imm=0
#line 343 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-24));
    // EBPF_OP_STXDW pc=11 dst=r10 src=r7 offset=-32 imm=0
#line 343 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-32));
    // EBPF_OP_STXDW pc=12 dst=r10 src=r7 offset=-40 imm=0
#line 343 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-40));
    // EBPF_OP_MOV64_REG pc=13 dst=r2 src=r10 offset=0 imm=0
#line 343 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=14 dst=r2 src=r0 offset=0 imm=-40
#line 343 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-40);
    // EBPF_OP_MOV64_REG pc=15 dst=r1 src=r6 offset=0 imm=0
#line 344 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_MOV64_IMM pc=16 dst=r3 src=r0 offset=0 imm=32
#line 344 "sample/cgroup_sock_addr_helpers.c"
    r3 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=17 dst=r0 src=r0 offset=0 imm=65538
#line 344 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LSH64_IMM pc=18 dst=r0 src=r0 offset=0 imm=32
#line 344 "sample/cgroup_sock_addr_helpers.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=19 dst=r0 src=r0 offset=0 imm=32
#line 344 "sample/cgroup_sock_addr_helpers.c"
    r0 = (int64_t)r0 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=20 dst=r7 src=r0 offset=57 imm=0
#line 344 "sample/cgroup_sock_addr_helpers.c"
    if ((int64_t)r7 > (int64_t)r0) {
#line 344 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 344 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_REG pc=21 dst=r2 src=r10 offset=0 imm=0
#line 344 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r2 src=r0 offset=0 imm=-4
#line 349 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=23 dst=r3 src=r10 offset=0 imm=0
#line 349 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=24 dst=r3 src=r0 offset=0 imm=-40
#line 349 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-40);
    // EBPF_OP_LDDW pc=25 dst=r1 src=r1 offset=0 imm=1
#line 349 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=27 dst=r4 src=r0 offset=0 imm=0
#line 349 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=28 dst=r0 src=r0 offset=0 imm=2
#line 349 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXW pc=29 dst=r10 src=r7 offset=-44 imm=0
#line 352 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-44));
    // EBPF_OP_CALL pc=30 dst=r0 src=r0 offset=0 imm=19
#line 354 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXDW pc=31 dst=r10 src=r0 offset=-80 imm=0
#line 354 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-80));
    // EBPF_OP_MOV64_REG pc=32 dst=r1 src=r6 offset=0 imm=0
#line 355 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=20
#line 355 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXDW pc=34 dst=r10 src=r0 offset=-72 imm=0
#line 355 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-72));
    // EBPF_OP_MOV64_REG pc=35 dst=r1 src=r6 offset=0 imm=0
#line 356 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=36 dst=r0 src=r0 offset=0 imm=21
#line 356 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXW pc=37 dst=r10 src=r0 offset=-64 imm=0
#line 356 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-64));
    // EBPF_OP_MOV64_REG pc=38 dst=r2 src=r10 offset=0 imm=0
#line 356 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=39 dst=r2 src=r0 offset=0 imm=-44
#line 349 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-44);
    // EBPF_OP_MOV64_REG pc=40 dst=r1 src=r6 offset=0 imm=0
#line 357 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_MOV64_IMM pc=41 dst=r3 src=r0 offset=0 imm=4
#line 357 "sample/cgroup_sock_addr_helpers.c"
    r3 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=42 dst=r0 src=r0 offset=0 imm=65537
#line 357 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXW pc=43 dst=r10 src=r0 offset=-60 imm=0
#line 357 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-60));
    // EBPF_OP_MOV64_REG pc=44 dst=r1 src=r6 offset=0 imm=0
#line 358 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=45 dst=r0 src=r0 offset=0 imm=26
#line 358 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 358 "sample/cgroup_sock_addr_helpers.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[2].address);
    // EBPF_OP_STXDW pc=46 dst=r10 src=r0 offset=-56 imm=0
#line 358 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-56));
    // EBPF_OP_MOV64_IMM pc=47 dst=r1 src=r0 offset=0 imm=6
#line 358 "sample/cgroup_sock_addr_helpers.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=48 dst=r10 src=r1 offset=-84 imm=0
#line 359 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-84));
    // EBPF_OP_MOV64_REG pc=49 dst=r2 src=r10 offset=0 imm=0
#line 359 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=50 dst=r2 src=r0 offset=0 imm=-84
#line 349 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-84);
    // EBPF_OP_MOV64_REG pc=51 dst=r3 src=r10 offset=0 imm=0
#line 349 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=52 dst=r3 src=r0 offset=0 imm=-80
#line 349 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-80);
    // EBPF_OP_LDDW pc=53 dst=r1 src=r1 offset=0 imm=3
#line 360 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_MOV64_IMM pc=55 dst=r4 src=r0 offset=0 imm=0
#line 360 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=56 dst=r0 src=r0 offset=0 imm=2
#line 360 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 360 "sample/cgroup_sock_addr_helpers.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=57 dst=r1 src=r0 offset=0 imm=5
#line 360 "sample/cgroup_sock_addr_helpers.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=58 dst=r10 src=r1 offset=-88 imm=0
#line 362 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-88));
    // EBPF_OP_MOV64_IMM pc=59 dst=r7 src=r0 offset=0 imm=1
#line 362 "sample/cgroup_sock_addr_helpers.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_STXDW pc=60 dst=r10 src=r7 offset=-96 imm=0
#line 363 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-96));
    // EBPF_OP_MOV64_REG pc=61 dst=r2 src=r10 offset=0 imm=0
#line 363 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=62 dst=r2 src=r0 offset=0 imm=-88
#line 349 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-88);
    // EBPF_OP_LDDW pc=63 dst=r1 src=r1 offset=0 imm=2
#line 364 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=65 dst=r0 src=r0 offset=0 imm=1
#line 364 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=66 dst=r0 src=r0 offset=3 imm=0
#line 365 "sample/cgroup_sock_addr_helpers.c"
    if (r0 == IMMEDIATE(0)) {
#line 365 "sample/cgroup_sock_addr_helpers.c"
        goto label_1;
#line 365 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXDW pc=67 dst=r1 src=r0 offset=0 imm=0
#line 366 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_64(r1, r0, OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=68 dst=r1 src=r0 offset=0 imm=1
#line 366 "sample/cgroup_sock_addr_helpers.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=69 dst=r10 src=r1 offset=-96 imm=0
#line 366 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
label_1:
    // EBPF_OP_MOV64_REG pc=70 dst=r2 src=r10 offset=0 imm=0
#line 366 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=71 dst=r2 src=r0 offset=0 imm=-88
#line 368 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-88);
    // EBPF_OP_MOV64_REG pc=72 dst=r3 src=r10 offset=0 imm=0
#line 368 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=73 dst=r3 src=r0 offset=0 imm=-96
#line 368 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-96);
    // EBPF_OP_LDDW pc=74 dst=r1 src=r1 offset=0 imm=2
#line 368 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=76 dst=r4 src=r0 offset=0 imm=0
#line 368 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=77 dst=r0 src=r0 offset=0 imm=2
#line 368 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
label_2:
    // EBPF_OP_MOV64_REG pc=78 dst=r0 src=r7 offset=0 imm=0
#line 371 "sample/cgroup_sock_addr_helpers.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=79 dst=r0 src=r0 offset=0 imm=0
#line 371 "sample/cgroup_sock_addr_helpers.c"
    return r0;
#line 336 "sample/cgroup_sock_addr_helpers.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t test_listen_helpers_v4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     65538,
     "helper_id_65538",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
    {
     {1, 40, 40}, // Version header.
     19,
     "helper_id_19",
    },
    {
     {1, 40, 40}, // Version header.
     20,
     "helper_id_20",
    },
    {
     {1, 40, 40}, // Version header.
     21,
     "helper_id_21",
    },
    {
     {1, 40, 40}, // Version header.
     65537,
     "helper_id_65537",
    },
    {
     {1, 40, 40}, // Version header.
     26,
     "helper_id_26",
    },
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID test_listen_helpers_v4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID test_listen_helpers_v4_attach_type_guid = {
    0xe1b0cb3d, 0xd70c, 0x4ee2, {0xb2, 0x3a, 0x07, 0x42, 0xbe, 0xdb, 0x06, 0xd6}};
static uint16_t test_listen_helpers_v4_maps[] = {
    0,
    1,
    2,
};

#pragma code_seg(push, "cgroup~3")
static uint64_t
test_listen_helpers_v4(void* context, const program_runtime_context_t* runtime_context)
#line 286 "sample/cgroup_sock_addr_helpers.c"
{
#line 286 "sample/cgroup_sock_addr_helpers.c"
    // Prologue.
#line 286 "sample/cgroup_sock_addr_helpers.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 286 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r0 = 0;
#line 286 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r1 = 0;
#line 286 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r2 = 0;
#line 286 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r3 = 0;
#line 286 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r4 = 0;
#line 286 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r5 = 0;
#line 286 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r6 = 0;
#line 286 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r7 = 0;
#line 286 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r10 = 0;

#line 286 "sample/cgroup_sock_addr_helpers.c"
    r1 = (uintptr_t)context;
#line 286 "sample/cgroup_sock_addr_helpers.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 286 "sample/cgroup_sock_addr_helpers.c"
    r6 = r1;
    // EBPF_OP_LDXH pc=1 dst=r1 src=r6 offset=40 imm=0
#line 291 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_16(r1, r6, OFFSET(40));
    // EBPF_OP_LSH64_IMM pc=2 dst=r1 src=r0 offset=0 imm=16
#line 291 "sample/cgroup_sock_addr_helpers.c"
    r1 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_LDXW pc=3 dst=r2 src=r6 offset=24 imm=0
#line 291 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r2, r6, OFFSET(24));
    // EBPF_OP_XOR64_REG pc=4 dst=r1 src=r2 offset=0 imm=0
#line 291 "sample/cgroup_sock_addr_helpers.c"
    r1 ^= r2;
    // EBPF_OP_STXW pc=5 dst=r10 src=r1 offset=-4 imm=0
#line 291 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MOV64_IMM pc=6 dst=r7 src=r0 offset=0 imm=0
#line 291 "sample/cgroup_sock_addr_helpers.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=7 dst=r10 src=r7 offset=-16 imm=0
#line 293 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-16));
    // EBPF_OP_STXDW pc=8 dst=r10 src=r7 offset=-24 imm=0
#line 293 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-24));
    // EBPF_OP_STXDW pc=9 dst=r10 src=r7 offset=-32 imm=0
#line 293 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-32));
    // EBPF_OP_STXDW pc=10 dst=r10 src=r7 offset=-40 imm=0
#line 293 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-40));
    // EBPF_OP_MOV64_REG pc=11 dst=r2 src=r10 offset=0 imm=0
#line 293 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=12 dst=r2 src=r0 offset=0 imm=-40
#line 293 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-40);
    // EBPF_OP_MOV64_REG pc=13 dst=r1 src=r6 offset=0 imm=0
#line 294 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_MOV64_IMM pc=14 dst=r3 src=r0 offset=0 imm=32
#line 294 "sample/cgroup_sock_addr_helpers.c"
    r3 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=15 dst=r0 src=r0 offset=0 imm=65538
#line 294 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LSH64_IMM pc=16 dst=r0 src=r0 offset=0 imm=32
#line 294 "sample/cgroup_sock_addr_helpers.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=17 dst=r0 src=r0 offset=0 imm=32
#line 294 "sample/cgroup_sock_addr_helpers.c"
    r0 = (int64_t)r0 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=18 dst=r7 src=r0 offset=57 imm=0
#line 294 "sample/cgroup_sock_addr_helpers.c"
    if ((int64_t)r7 > (int64_t)r0) {
#line 294 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 294 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_REG pc=19 dst=r2 src=r10 offset=0 imm=0
#line 294 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=20 dst=r2 src=r0 offset=0 imm=-4
#line 299 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=21 dst=r3 src=r10 offset=0 imm=0
#line 299 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r3 src=r0 offset=0 imm=-40
#line 299 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-40);
    // EBPF_OP_LDDW pc=23 dst=r1 src=r1 offset=0 imm=1
#line 299 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=25 dst=r4 src=r0 offset=0 imm=0
#line 299 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=26 dst=r0 src=r0 offset=0 imm=2
#line 299 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXW pc=27 dst=r10 src=r7 offset=-44 imm=0
#line 306 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-44));
    // EBPF_OP_CALL pc=28 dst=r0 src=r0 offset=0 imm=19
#line 308 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXDW pc=29 dst=r10 src=r0 offset=-80 imm=0
#line 308 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-80));
    // EBPF_OP_MOV64_REG pc=30 dst=r1 src=r6 offset=0 imm=0
#line 309 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=31 dst=r0 src=r0 offset=0 imm=20
#line 309 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXDW pc=32 dst=r10 src=r0 offset=-72 imm=0
#line 309 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-72));
    // EBPF_OP_MOV64_REG pc=33 dst=r1 src=r6 offset=0 imm=0
#line 310 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=21
#line 310 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXW pc=35 dst=r10 src=r0 offset=-64 imm=0
#line 310 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-64));
    // EBPF_OP_MOV64_REG pc=36 dst=r2 src=r10 offset=0 imm=0
#line 310 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=37 dst=r2 src=r0 offset=0 imm=-44
#line 299 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-44);
    // EBPF_OP_MOV64_REG pc=38 dst=r1 src=r6 offset=0 imm=0
#line 311 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_MOV64_IMM pc=39 dst=r3 src=r0 offset=0 imm=4
#line 311 "sample/cgroup_sock_addr_helpers.c"
    r3 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=40 dst=r0 src=r0 offset=0 imm=65537
#line 311 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXW pc=41 dst=r10 src=r0 offset=-60 imm=0
#line 311 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-60));
    // EBPF_OP_MOV64_REG pc=42 dst=r1 src=r6 offset=0 imm=0
#line 312 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=43 dst=r0 src=r0 offset=0 imm=26
#line 312 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 312 "sample/cgroup_sock_addr_helpers.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[2].address);
    // EBPF_OP_STXDW pc=44 dst=r10 src=r0 offset=-56 imm=0
#line 312 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-56));
    // EBPF_OP_MOV64_IMM pc=45 dst=r1 src=r0 offset=0 imm=8
#line 312 "sample/cgroup_sock_addr_helpers.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=46 dst=r10 src=r1 offset=-84 imm=0
#line 313 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-84));
    // EBPF_OP_MOV64_REG pc=47 dst=r2 src=r10 offset=0 imm=0
#line 313 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=48 dst=r2 src=r0 offset=0 imm=-84
#line 299 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-84);
    // EBPF_OP_MOV64_REG pc=49 dst=r3 src=r10 offset=0 imm=0
#line 299 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=50 dst=r3 src=r0 offset=0 imm=-80
#line 299 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-80);
    // EBPF_OP_LDDW pc=51 dst=r1 src=r1 offset=0 imm=3
#line 314 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_MOV64_IMM pc=53 dst=r4 src=r0 offset=0 imm=0
#line 314 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=54 dst=r0 src=r0 offset=0 imm=2
#line 314 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 314 "sample/cgroup_sock_addr_helpers.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=55 dst=r1 src=r0 offset=0 imm=6
#line 314 "sample/cgroup_sock_addr_helpers.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=56 dst=r10 src=r1 offset=-88 imm=0
#line 316 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-88));
    // EBPF_OP_MOV64_IMM pc=57 dst=r7 src=r0 offset=0 imm=1
#line 316 "sample/cgroup_sock_addr_helpers.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_STXDW pc=58 dst=r10 src=r7 offset=-96 imm=0
#line 317 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-96));
    // EBPF_OP_MOV64_REG pc=59 dst=r2 src=r10 offset=0 imm=0
#line 317 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=60 dst=r2 src=r0 offset=0 imm=-88
#line 299 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-88);
    // EBPF_OP_LDDW pc=61 dst=r1 src=r1 offset=0 imm=2
#line 318 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=63 dst=r0 src=r0 offset=0 imm=1
#line 318 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=64 dst=r0 src=r0 offset=3 imm=0
#line 319 "sample/cgroup_sock_addr_helpers.c"
    if (r0 == IMMEDIATE(0)) {
#line 319 "sample/cgroup_sock_addr_helpers.c"
        goto label_1;
#line 319 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXDW pc=65 dst=r1 src=r0 offset=0 imm=0
#line 320 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_64(r1, r0, OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=66 dst=r1 src=r0 offset=0 imm=1
#line 320 "sample/cgroup_sock_addr_helpers.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=67 dst=r10 src=r1 offset=-96 imm=0
#line 320 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
label_1:
    // EBPF_OP_MOV64_REG pc=68 dst=r2 src=r10 offset=0 imm=0
#line 320 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=69 dst=r2 src=r0 offset=0 imm=-88
#line 322 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-88);
    // EBPF_OP_MOV64_REG pc=70 dst=r3 src=r10 offset=0 imm=0
#line 322 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=71 dst=r3 src=r0 offset=0 imm=-96
#line 322 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-96);
    // EBPF_OP_LDDW pc=72 dst=r1 src=r1 offset=0 imm=2
#line 322 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=74 dst=r4 src=r0 offset=0 imm=0
#line 322 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=75 dst=r0 src=r0 offset=0 imm=2
#line 322 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
label_2:
    // EBPF_OP_MOV64_REG pc=76 dst=r0 src=r7 offset=0 imm=0
#line 325 "sample/cgroup_sock_addr_helpers.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=77 dst=r0 src=r0 offset=0 imm=0
#line 325 "sample/cgroup_sock_addr_helpers.c"
    return r0;
#line 286 "sample/cgroup_sock_addr_helpers.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t test_listen_helpers_v6_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     65538,
     "helper_id_65538",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
    {
     {1, 40, 40}, // Version header.
     19,
     "helper_id_19",
    },
    {
     {1, 40, 40}, // Version header.
     20,
     "helper_id_20",
    },
    {
     {1, 40, 40}, // Version header.
     21,
     "helper_id_21",
    },
    {
     {1, 40, 40}, // Version header.
     65537,
     "helper_id_65537",
    },
    {
     {1, 40, 40}, // Version header.
     26,
     "helper_id_26",
    },
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID test_listen_helpers_v6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID test_listen_helpers_v6_attach_type_guid = {
    0x4e72f92e, 0x5ed0, 0x4fe5, {0xb8, 0x51, 0xb1, 0x24, 0xfe, 0x14, 0x07, 0x4d}};
static uint16_t test_listen_helpers_v6_maps[] = {
    0,
    1,
    2,
};

#pragma code_seg(push, "cgroup~1")
static uint64_t
test_listen_helpers_v6(void* context, const program_runtime_context_t* runtime_context)
#line 381 "sample/cgroup_sock_addr_helpers.c"
{
#line 381 "sample/cgroup_sock_addr_helpers.c"
    // Prologue.
#line 381 "sample/cgroup_sock_addr_helpers.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 381 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r0 = 0;
#line 381 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r1 = 0;
#line 381 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r2 = 0;
#line 381 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r3 = 0;
#line 381 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r4 = 0;
#line 381 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r5 = 0;
#line 381 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r6 = 0;
#line 381 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r7 = 0;
#line 381 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r10 = 0;

#line 381 "sample/cgroup_sock_addr_helpers.c"
    r1 = (uintptr_t)context;
#line 381 "sample/cgroup_sock_addr_helpers.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 381 "sample/cgroup_sock_addr_helpers.c"
    r6 = r1;
    // EBPF_OP_LDXW pc=1 dst=r1 src=r6 offset=24 imm=0
#line 385 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r1, r6, OFFSET(24));
    // EBPF_OP_LDXW pc=2 dst=r2 src=r6 offset=36 imm=0
#line 385 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r2, r6, OFFSET(36));
    // EBPF_OP_XOR64_REG pc=3 dst=r2 src=r1 offset=0 imm=0
#line 385 "sample/cgroup_sock_addr_helpers.c"
    r2 ^= r1;
    // EBPF_OP_LDXH pc=4 dst=r1 src=r6 offset=40 imm=0
#line 385 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_16(r1, r6, OFFSET(40));
    // EBPF_OP_LSH64_IMM pc=5 dst=r1 src=r0 offset=0 imm=16
#line 385 "sample/cgroup_sock_addr_helpers.c"
    r1 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_XOR64_REG pc=6 dst=r2 src=r1 offset=0 imm=0
#line 385 "sample/cgroup_sock_addr_helpers.c"
    r2 ^= r1;
    // EBPF_OP_STXW pc=7 dst=r10 src=r2 offset=-4 imm=0
#line 385 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-4));
    // EBPF_OP_MOV64_IMM pc=8 dst=r7 src=r0 offset=0 imm=0
#line 385 "sample/cgroup_sock_addr_helpers.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=9 dst=r10 src=r7 offset=-16 imm=0
#line 387 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-16));
    // EBPF_OP_STXDW pc=10 dst=r10 src=r7 offset=-24 imm=0
#line 387 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-24));
    // EBPF_OP_STXDW pc=11 dst=r10 src=r7 offset=-32 imm=0
#line 387 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-32));
    // EBPF_OP_STXDW pc=12 dst=r10 src=r7 offset=-40 imm=0
#line 387 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-40));
    // EBPF_OP_MOV64_REG pc=13 dst=r2 src=r10 offset=0 imm=0
#line 387 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=14 dst=r2 src=r0 offset=0 imm=-40
#line 387 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-40);
    // EBPF_OP_MOV64_REG pc=15 dst=r1 src=r6 offset=0 imm=0
#line 388 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_MOV64_IMM pc=16 dst=r3 src=r0 offset=0 imm=32
#line 388 "sample/cgroup_sock_addr_helpers.c"
    r3 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=17 dst=r0 src=r0 offset=0 imm=65538
#line 388 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LSH64_IMM pc=18 dst=r0 src=r0 offset=0 imm=32
#line 388 "sample/cgroup_sock_addr_helpers.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=19 dst=r0 src=r0 offset=0 imm=32
#line 388 "sample/cgroup_sock_addr_helpers.c"
    r0 = (int64_t)r0 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=20 dst=r7 src=r0 offset=57 imm=0
#line 388 "sample/cgroup_sock_addr_helpers.c"
    if ((int64_t)r7 > (int64_t)r0) {
#line 388 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 388 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_REG pc=21 dst=r2 src=r10 offset=0 imm=0
#line 388 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r2 src=r0 offset=0 imm=-4
#line 393 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=23 dst=r3 src=r10 offset=0 imm=0
#line 393 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=24 dst=r3 src=r0 offset=0 imm=-40
#line 393 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-40);
    // EBPF_OP_LDDW pc=25 dst=r1 src=r1 offset=0 imm=1
#line 393 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=27 dst=r4 src=r0 offset=0 imm=0
#line 393 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=28 dst=r0 src=r0 offset=0 imm=2
#line 393 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXW pc=29 dst=r10 src=r7 offset=-44 imm=0
#line 397 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-44));
    // EBPF_OP_CALL pc=30 dst=r0 src=r0 offset=0 imm=19
#line 399 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXDW pc=31 dst=r10 src=r0 offset=-80 imm=0
#line 399 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-80));
    // EBPF_OP_MOV64_REG pc=32 dst=r1 src=r6 offset=0 imm=0
#line 400 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=20
#line 400 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXDW pc=34 dst=r10 src=r0 offset=-72 imm=0
#line 400 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-72));
    // EBPF_OP_MOV64_REG pc=35 dst=r1 src=r6 offset=0 imm=0
#line 401 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=36 dst=r0 src=r0 offset=0 imm=21
#line 401 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXW pc=37 dst=r10 src=r0 offset=-64 imm=0
#line 401 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-64));
    // EBPF_OP_MOV64_REG pc=38 dst=r2 src=r10 offset=0 imm=0
#line 401 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=39 dst=r2 src=r0 offset=0 imm=-44
#line 393 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-44);
    // EBPF_OP_MOV64_REG pc=40 dst=r1 src=r6 offset=0 imm=0
#line 402 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_MOV64_IMM pc=41 dst=r3 src=r0 offset=0 imm=4
#line 402 "sample/cgroup_sock_addr_helpers.c"
    r3 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=42 dst=r0 src=r0 offset=0 imm=65537
#line 402 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_STXW pc=43 dst=r10 src=r0 offset=-60 imm=0
#line 402 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-60));
    // EBPF_OP_MOV64_REG pc=44 dst=r1 src=r6 offset=0 imm=0
#line 403 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=45 dst=r0 src=r0 offset=0 imm=26
#line 403 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 403 "sample/cgroup_sock_addr_helpers.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[2].address);
    // EBPF_OP_STXDW pc=46 dst=r10 src=r0 offset=-56 imm=0
#line 403 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-56));
    // EBPF_OP_MOV64_IMM pc=47 dst=r1 src=r0 offset=0 imm=9
#line 403 "sample/cgroup_sock_addr_helpers.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=48 dst=r10 src=r1 offset=-84 imm=0
#line 404 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-84));
    // EBPF_OP_MOV64_REG pc=49 dst=r2 src=r10 offset=0 imm=0
#line 404 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=50 dst=r2 src=r0 offset=0 imm=-84
#line 393 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-84);
    // EBPF_OP_MOV64_REG pc=51 dst=r3 src=r10 offset=0 imm=0
#line 393 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=52 dst=r3 src=r0 offset=0 imm=-80
#line 393 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-80);
    // EBPF_OP_LDDW pc=53 dst=r1 src=r1 offset=0 imm=3
#line 405 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_MOV64_IMM pc=55 dst=r4 src=r0 offset=0 imm=0
#line 405 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=56 dst=r0 src=r0 offset=0 imm=2
#line 405 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 405 "sample/cgroup_sock_addr_helpers.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=57 dst=r1 src=r0 offset=0 imm=7
#line 405 "sample/cgroup_sock_addr_helpers.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=58 dst=r10 src=r1 offset=-88 imm=0
#line 407 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-88));
    // EBPF_OP_MOV64_IMM pc=59 dst=r7 src=r0 offset=0 imm=1
#line 407 "sample/cgroup_sock_addr_helpers.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_STXDW pc=60 dst=r10 src=r7 offset=-96 imm=0
#line 408 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-96));
    // EBPF_OP_MOV64_REG pc=61 dst=r2 src=r10 offset=0 imm=0
#line 408 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=62 dst=r2 src=r0 offset=0 imm=-88
#line 393 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-88);
    // EBPF_OP_LDDW pc=63 dst=r1 src=r1 offset=0 imm=2
#line 409 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=65 dst=r0 src=r0 offset=0 imm=1
#line 409 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=66 dst=r0 src=r0 offset=3 imm=0
#line 410 "sample/cgroup_sock_addr_helpers.c"
    if (r0 == IMMEDIATE(0)) {
#line 410 "sample/cgroup_sock_addr_helpers.c"
        goto label_1;
#line 410 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXDW pc=67 dst=r1 src=r0 offset=0 imm=0
#line 411 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_64(r1, r0, OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=68 dst=r1 src=r0 offset=0 imm=1
#line 411 "sample/cgroup_sock_addr_helpers.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=69 dst=r10 src=r1 offset=-96 imm=0
#line 411 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
label_1:
    // EBPF_OP_MOV64_REG pc=70 dst=r2 src=r10 offset=0 imm=0
#line 411 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=71 dst=r2 src=r0 offset=0 imm=-88
#line 413 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-88);
    // EBPF_OP_MOV64_REG pc=72 dst=r3 src=r10 offset=0 imm=0
#line 413 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=73 dst=r3 src=r0 offset=0 imm=-96
#line 413 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-96);
    // EBPF_OP_LDDW pc=74 dst=r1 src=r1 offset=0 imm=2
#line 413 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=76 dst=r4 src=r0 offset=0 imm=0
#line 413 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=77 dst=r0 src=r0 offset=0 imm=2
#line 413 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
label_2:
    // EBPF_OP_MOV64_REG pc=78 dst=r0 src=r7 offset=0 imm=0
#line 416 "sample/cgroup_sock_addr_helpers.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=79 dst=r0 src=r0 offset=0 imm=0
#line 416 "sample/cgroup_sock_addr_helpers.c"
    return r0;
#line 381 "sample/cgroup_sock_addr_helpers.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t test_recv_accept_helpers_v4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     65538,
     "helper_id_65538",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID test_recv_accept_helpers_v4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID test_recv_accept_helpers_v4_attach_type_guid = {
    0xa82e37b3, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t test_recv_accept_helpers_v4_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "cgroup~5")
static uint64_t
test_recv_accept_helpers_v4(void* context, const program_runtime_context_t* runtime_context)
#line 198 "sample/cgroup_sock_addr_helpers.c"
{
#line 198 "sample/cgroup_sock_addr_helpers.c"
    // Prologue.
#line 198 "sample/cgroup_sock_addr_helpers.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 198 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r0 = 0;
#line 198 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r1 = 0;
#line 198 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r2 = 0;
#line 198 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r3 = 0;
#line 198 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r4 = 0;
#line 198 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r5 = 0;
#line 198 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r6 = 0;
#line 198 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r10 = 0;

#line 198 "sample/cgroup_sock_addr_helpers.c"
    r1 = (uintptr_t)context;
#line 198 "sample/cgroup_sock_addr_helpers.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=1
#line 198 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=1 dst=r2 src=r1 offset=44 imm=0
#line 202 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r2, r1, OFFSET(44));
    // EBPF_OP_JNE_IMM pc=2 dst=r2 src=r0 offset=46 imm=6
#line 202 "sample/cgroup_sock_addr_helpers.c"
    if (r2 != IMMEDIATE(6)) {
#line 202 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 202 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXH pc=3 dst=r2 src=r1 offset=40 imm=0
#line 206 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_LSH64_IMM pc=4 dst=r2 src=r0 offset=0 imm=16
#line 206 "sample/cgroup_sock_addr_helpers.c"
    r2 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_LDXW pc=5 dst=r3 src=r1 offset=24 imm=0
#line 206 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r3, r1, OFFSET(24));
    // EBPF_OP_XOR64_REG pc=6 dst=r2 src=r3 offset=0 imm=0
#line 206 "sample/cgroup_sock_addr_helpers.c"
    r2 ^= r3;
    // EBPF_OP_STXW pc=7 dst=r10 src=r2 offset=-4 imm=0
#line 206 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-4));
    // EBPF_OP_MOV64_IMM pc=8 dst=r6 src=r0 offset=0 imm=0
#line 206 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=9 dst=r10 src=r6 offset=-40 imm=0
#line 208 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-40));
    // EBPF_OP_STXDW pc=10 dst=r10 src=r6 offset=-32 imm=0
#line 208 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-32));
    // EBPF_OP_STXDW pc=11 dst=r10 src=r6 offset=-24 imm=0
#line 208 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-24));
    // EBPF_OP_STXDW pc=12 dst=r10 src=r6 offset=-16 imm=0
#line 208 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=13 dst=r2 src=r10 offset=0 imm=0
#line 208 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=14 dst=r2 src=r0 offset=0 imm=-40
#line 206 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-40);
    // EBPF_OP_MOV64_IMM pc=15 dst=r3 src=r0 offset=0 imm=32
#line 209 "sample/cgroup_sock_addr_helpers.c"
    r3 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=16 dst=r0 src=r0 offset=0 imm=65538
#line 209 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LSH64_IMM pc=17 dst=r0 src=r0 offset=0 imm=32
#line 209 "sample/cgroup_sock_addr_helpers.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=18 dst=r0 src=r0 offset=0 imm=32
#line 209 "sample/cgroup_sock_addr_helpers.c"
    r0 = (int64_t)r0 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=19 dst=r6 src=r0 offset=29 imm=0
#line 209 "sample/cgroup_sock_addr_helpers.c"
    if ((int64_t)r6 > (int64_t)r0) {
#line 209 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 209 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_REG pc=20 dst=r2 src=r10 offset=0 imm=0
#line 209 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=21 dst=r2 src=r0 offset=0 imm=-4
#line 214 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=22 dst=r3 src=r10 offset=0 imm=0
#line 214 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r3 src=r0 offset=0 imm=-40
#line 214 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-40);
    // EBPF_OP_LDDW pc=24 dst=r1 src=r1 offset=0 imm=1
#line 214 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=26 dst=r4 src=r0 offset=0 imm=0
#line 214 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=27 dst=r0 src=r0 offset=0 imm=2
#line 214 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 214 "sample/cgroup_sock_addr_helpers.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=3
#line 214 "sample/cgroup_sock_addr_helpers.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=29 dst=r10 src=r1 offset=-44 imm=0
#line 216 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-44));
    // EBPF_OP_MOV64_IMM pc=30 dst=r6 src=r0 offset=0 imm=1
#line 216 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_STXDW pc=31 dst=r10 src=r6 offset=-56 imm=0
#line 217 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-56));
    // EBPF_OP_MOV64_REG pc=32 dst=r2 src=r10 offset=0 imm=0
#line 217 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=33 dst=r2 src=r0 offset=0 imm=-44
#line 214 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-44);
    // EBPF_OP_LDDW pc=34 dst=r1 src=r1 offset=0 imm=2
#line 218 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=36 dst=r0 src=r0 offset=0 imm=1
#line 218 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=37 dst=r0 src=r0 offset=3 imm=0
#line 219 "sample/cgroup_sock_addr_helpers.c"
    if (r0 == IMMEDIATE(0)) {
#line 219 "sample/cgroup_sock_addr_helpers.c"
        goto label_1;
#line 219 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXDW pc=38 dst=r1 src=r0 offset=0 imm=0
#line 220 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_64(r1, r0, OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=39 dst=r1 src=r0 offset=0 imm=1
#line 220 "sample/cgroup_sock_addr_helpers.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=40 dst=r10 src=r1 offset=-56 imm=0
#line 220 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-56));
label_1:
    // EBPF_OP_MOV64_REG pc=41 dst=r2 src=r10 offset=0 imm=0
#line 220 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=42 dst=r2 src=r0 offset=0 imm=-44
#line 222 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-44);
    // EBPF_OP_MOV64_REG pc=43 dst=r3 src=r10 offset=0 imm=0
#line 222 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=44 dst=r3 src=r0 offset=0 imm=-56
#line 222 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-56);
    // EBPF_OP_LDDW pc=45 dst=r1 src=r1 offset=0 imm=2
#line 222 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=47 dst=r4 src=r0 offset=0 imm=0
#line 222 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=48 dst=r0 src=r0 offset=0 imm=2
#line 222 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
label_2:
    // EBPF_OP_MOV64_REG pc=49 dst=r0 src=r6 offset=0 imm=0
#line 225 "sample/cgroup_sock_addr_helpers.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=50 dst=r0 src=r0 offset=0 imm=0
#line 225 "sample/cgroup_sock_addr_helpers.c"
    return r0;
#line 198 "sample/cgroup_sock_addr_helpers.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t test_sock_addr_helpers_v4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     65538,
     "helper_id_65538",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID test_sock_addr_helpers_v4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID test_sock_addr_helpers_v4_attach_type_guid = {
    0x6076c13a, 0xf04f, 0x4ff8, {0x83, 0x80, 0x90, 0x85, 0x53, 0xf2, 0x22, 0x76}};
static uint16_t test_sock_addr_helpers_v4_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "cgroup~8")
static uint64_t
test_sock_addr_helpers_v4(void* context, const program_runtime_context_t* runtime_context)
#line 75 "sample/cgroup_sock_addr_helpers.c"
{
#line 75 "sample/cgroup_sock_addr_helpers.c"
    // Prologue.
#line 75 "sample/cgroup_sock_addr_helpers.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 75 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r0 = 0;
#line 75 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r1 = 0;
#line 75 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r2 = 0;
#line 75 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r3 = 0;
#line 75 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r4 = 0;
#line 75 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r5 = 0;
#line 75 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r6 = 0;
#line 75 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r10 = 0;

#line 75 "sample/cgroup_sock_addr_helpers.c"
    r1 = (uintptr_t)context;
#line 75 "sample/cgroup_sock_addr_helpers.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=1
#line 75 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=1 dst=r2 src=r1 offset=44 imm=0
#line 80 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r2, r1, OFFSET(44));
    // EBPF_OP_JNE_IMM pc=2 dst=r2 src=r0 offset=45 imm=6
#line 80 "sample/cgroup_sock_addr_helpers.c"
    if (r2 != IMMEDIATE(6)) {
#line 80 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 80 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXH pc=3 dst=r2 src=r1 offset=40 imm=0
#line 85 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_LSH64_IMM pc=4 dst=r2 src=r0 offset=0 imm=16
#line 85 "sample/cgroup_sock_addr_helpers.c"
    r2 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_LDXW pc=5 dst=r3 src=r1 offset=24 imm=0
#line 85 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r3, r1, OFFSET(24));
    // EBPF_OP_XOR64_REG pc=6 dst=r2 src=r3 offset=0 imm=0
#line 85 "sample/cgroup_sock_addr_helpers.c"
    r2 ^= r3;
    // EBPF_OP_STXW pc=7 dst=r10 src=r2 offset=-4 imm=0
#line 85 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-4));
    // EBPF_OP_MOV64_IMM pc=8 dst=r6 src=r0 offset=0 imm=0
#line 85 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=9 dst=r10 src=r6 offset=-40 imm=0
#line 88 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-40));
    // EBPF_OP_STXDW pc=10 dst=r10 src=r6 offset=-32 imm=0
#line 88 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-32));
    // EBPF_OP_STXDW pc=11 dst=r10 src=r6 offset=-24 imm=0
#line 88 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-24));
    // EBPF_OP_STXDW pc=12 dst=r10 src=r6 offset=-16 imm=0
#line 88 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=13 dst=r2 src=r10 offset=0 imm=0
#line 88 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=14 dst=r2 src=r0 offset=0 imm=-40
#line 85 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-40);
    // EBPF_OP_MOV64_IMM pc=15 dst=r3 src=r0 offset=0 imm=32
#line 89 "sample/cgroup_sock_addr_helpers.c"
    r3 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=16 dst=r0 src=r0 offset=0 imm=65538
#line 89 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LSH64_IMM pc=17 dst=r0 src=r0 offset=0 imm=32
#line 89 "sample/cgroup_sock_addr_helpers.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=18 dst=r0 src=r0 offset=0 imm=32
#line 89 "sample/cgroup_sock_addr_helpers.c"
    r0 = (int64_t)r0 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=19 dst=r6 src=r0 offset=28 imm=0
#line 89 "sample/cgroup_sock_addr_helpers.c"
    if ((int64_t)r6 > (int64_t)r0) {
#line 89 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 89 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_REG pc=20 dst=r2 src=r10 offset=0 imm=0
#line 89 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=21 dst=r2 src=r0 offset=0 imm=-4
#line 96 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=22 dst=r3 src=r10 offset=0 imm=0
#line 96 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r3 src=r0 offset=0 imm=-40
#line 96 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-40);
    // EBPF_OP_LDDW pc=24 dst=r1 src=r1 offset=0 imm=1
#line 96 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=26 dst=r4 src=r0 offset=0 imm=0
#line 96 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=27 dst=r0 src=r0 offset=0 imm=2
#line 96 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 96 "sample/cgroup_sock_addr_helpers.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=28 dst=r6 src=r0 offset=0 imm=1
#line 96 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=29 dst=r10 src=r6 offset=-44 imm=0
#line 99 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-44));
    // EBPF_OP_STXDW pc=30 dst=r10 src=r6 offset=-56 imm=0
#line 100 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-56));
    // EBPF_OP_MOV64_REG pc=31 dst=r2 src=r10 offset=0 imm=0
#line 100 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=32 dst=r2 src=r0 offset=0 imm=-44
#line 96 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-44);
    // EBPF_OP_LDDW pc=33 dst=r1 src=r1 offset=0 imm=2
#line 101 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=35 dst=r0 src=r0 offset=0 imm=1
#line 101 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=36 dst=r0 src=r0 offset=3 imm=0
#line 102 "sample/cgroup_sock_addr_helpers.c"
    if (r0 == IMMEDIATE(0)) {
#line 102 "sample/cgroup_sock_addr_helpers.c"
        goto label_1;
#line 102 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXDW pc=37 dst=r1 src=r0 offset=0 imm=0
#line 103 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_64(r1, r0, OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=38 dst=r1 src=r0 offset=0 imm=1
#line 103 "sample/cgroup_sock_addr_helpers.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=39 dst=r10 src=r1 offset=-56 imm=0
#line 103 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-56));
label_1:
    // EBPF_OP_MOV64_REG pc=40 dst=r2 src=r10 offset=0 imm=0
#line 103 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=41 dst=r2 src=r0 offset=0 imm=-44
#line 105 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-44);
    // EBPF_OP_MOV64_REG pc=42 dst=r3 src=r10 offset=0 imm=0
#line 105 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=43 dst=r3 src=r0 offset=0 imm=-56
#line 105 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-56);
    // EBPF_OP_LDDW pc=44 dst=r1 src=r1 offset=0 imm=2
#line 105 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=46 dst=r4 src=r0 offset=0 imm=0
#line 105 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=47 dst=r0 src=r0 offset=0 imm=2
#line 105 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
label_2:
    // EBPF_OP_MOV64_REG pc=48 dst=r0 src=r6 offset=0 imm=0
#line 108 "sample/cgroup_sock_addr_helpers.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=49 dst=r0 src=r0 offset=0 imm=0
#line 108 "sample/cgroup_sock_addr_helpers.c"
    return r0;
#line 75 "sample/cgroup_sock_addr_helpers.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t test_sock_addr_helpers_v6_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     65538,
     "helper_id_65538",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID test_sock_addr_helpers_v6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID test_sock_addr_helpers_v6_attach_type_guid = {
    0x54b0b6ed, 0x432a, 0x4674, {0x8b, 0x27, 0x8d, 0x9f, 0x5b, 0x40, 0xc6, 0x75}};
static uint16_t test_sock_addr_helpers_v6_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "cgroup~6")
static uint64_t
test_sock_addr_helpers_v6(void* context, const program_runtime_context_t* runtime_context)
#line 116 "sample/cgroup_sock_addr_helpers.c"
{
#line 116 "sample/cgroup_sock_addr_helpers.c"
    // Prologue.
#line 116 "sample/cgroup_sock_addr_helpers.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 116 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r0 = 0;
#line 116 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r1 = 0;
#line 116 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r2 = 0;
#line 116 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r3 = 0;
#line 116 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r4 = 0;
#line 116 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r5 = 0;
#line 116 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r6 = 0;
#line 116 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r10 = 0;

#line 116 "sample/cgroup_sock_addr_helpers.c"
    r1 = (uintptr_t)context;
#line 116 "sample/cgroup_sock_addr_helpers.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=1
#line 116 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=1 dst=r2 src=r1 offset=44 imm=0
#line 121 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r2, r1, OFFSET(44));
    // EBPF_OP_JNE_IMM pc=2 dst=r2 src=r0 offset=48 imm=6
#line 121 "sample/cgroup_sock_addr_helpers.c"
    if (r2 != IMMEDIATE(6)) {
#line 121 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 121 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXW pc=3 dst=r2 src=r1 offset=24 imm=0
#line 127 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r2, r1, OFFSET(24));
    // EBPF_OP_LDXW pc=4 dst=r3 src=r1 offset=36 imm=0
#line 127 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r3, r1, OFFSET(36));
    // EBPF_OP_XOR64_REG pc=5 dst=r3 src=r2 offset=0 imm=0
#line 127 "sample/cgroup_sock_addr_helpers.c"
    r3 ^= r2;
    // EBPF_OP_LDXH pc=6 dst=r2 src=r1 offset=40 imm=0
#line 127 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_LSH64_IMM pc=7 dst=r2 src=r0 offset=0 imm=16
#line 127 "sample/cgroup_sock_addr_helpers.c"
    r2 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_XOR64_REG pc=8 dst=r3 src=r2 offset=0 imm=0
#line 127 "sample/cgroup_sock_addr_helpers.c"
    r3 ^= r2;
    // EBPF_OP_STXW pc=9 dst=r10 src=r3 offset=-4 imm=0
#line 127 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r3, OFFSET(-4));
    // EBPF_OP_MOV64_IMM pc=10 dst=r6 src=r0 offset=0 imm=0
#line 127 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=11 dst=r10 src=r6 offset=-40 imm=0
#line 130 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-40));
    // EBPF_OP_STXDW pc=12 dst=r10 src=r6 offset=-32 imm=0
#line 130 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-32));
    // EBPF_OP_STXDW pc=13 dst=r10 src=r6 offset=-24 imm=0
#line 130 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-24));
    // EBPF_OP_STXDW pc=14 dst=r10 src=r6 offset=-16 imm=0
#line 130 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=15 dst=r2 src=r10 offset=0 imm=0
#line 130 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=16 dst=r2 src=r0 offset=0 imm=-40
#line 127 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-40);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=32
#line 131 "sample/cgroup_sock_addr_helpers.c"
    r3 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=65538
#line 131 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LSH64_IMM pc=19 dst=r0 src=r0 offset=0 imm=32
#line 131 "sample/cgroup_sock_addr_helpers.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=20 dst=r0 src=r0 offset=0 imm=32
#line 131 "sample/cgroup_sock_addr_helpers.c"
    r0 = (int64_t)r0 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=21 dst=r6 src=r0 offset=29 imm=0
#line 131 "sample/cgroup_sock_addr_helpers.c"
    if ((int64_t)r6 > (int64_t)r0) {
#line 131 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 131 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_REG pc=22 dst=r2 src=r10 offset=0 imm=0
#line 131 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r2 src=r0 offset=0 imm=-4
#line 137 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=24 dst=r3 src=r10 offset=0 imm=0
#line 137 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=25 dst=r3 src=r0 offset=0 imm=-40
#line 137 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-40);
    // EBPF_OP_LDDW pc=26 dst=r1 src=r1 offset=0 imm=1
#line 137 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=28 dst=r4 src=r0 offset=0 imm=0
#line 137 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=29 dst=r0 src=r0 offset=0 imm=2
#line 137 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 137 "sample/cgroup_sock_addr_helpers.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=30 dst=r1 src=r0 offset=0 imm=2
#line 137 "sample/cgroup_sock_addr_helpers.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=31 dst=r10 src=r1 offset=-44 imm=0
#line 140 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-44));
    // EBPF_OP_MOV64_IMM pc=32 dst=r6 src=r0 offset=0 imm=1
#line 140 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_STXDW pc=33 dst=r10 src=r6 offset=-56 imm=0
#line 141 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-56));
    // EBPF_OP_MOV64_REG pc=34 dst=r2 src=r10 offset=0 imm=0
#line 141 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=35 dst=r2 src=r0 offset=0 imm=-44
#line 137 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-44);
    // EBPF_OP_LDDW pc=36 dst=r1 src=r1 offset=0 imm=2
#line 142 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=38 dst=r0 src=r0 offset=0 imm=1
#line 142 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=39 dst=r0 src=r0 offset=3 imm=0
#line 143 "sample/cgroup_sock_addr_helpers.c"
    if (r0 == IMMEDIATE(0)) {
#line 143 "sample/cgroup_sock_addr_helpers.c"
        goto label_1;
#line 143 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXDW pc=40 dst=r1 src=r0 offset=0 imm=0
#line 144 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_64(r1, r0, OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=41 dst=r1 src=r0 offset=0 imm=1
#line 144 "sample/cgroup_sock_addr_helpers.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=42 dst=r10 src=r1 offset=-56 imm=0
#line 144 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-56));
label_1:
    // EBPF_OP_MOV64_REG pc=43 dst=r2 src=r10 offset=0 imm=0
#line 144 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=44 dst=r2 src=r0 offset=0 imm=-44
#line 146 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-44);
    // EBPF_OP_MOV64_REG pc=45 dst=r3 src=r10 offset=0 imm=0
#line 146 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=46 dst=r3 src=r0 offset=0 imm=-56
#line 146 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-56);
    // EBPF_OP_LDDW pc=47 dst=r1 src=r1 offset=0 imm=2
#line 146 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=49 dst=r4 src=r0 offset=0 imm=0
#line 146 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=50 dst=r0 src=r0 offset=0 imm=2
#line 146 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
label_2:
    // EBPF_OP_MOV64_REG pc=51 dst=r0 src=r6 offset=0 imm=0
#line 149 "sample/cgroup_sock_addr_helpers.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=52 dst=r0 src=r0 offset=0 imm=0
#line 149 "sample/cgroup_sock_addr_helpers.c"
    return r0;
#line 116 "sample/cgroup_sock_addr_helpers.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = conditional_authorization_v4,
        .pe_section_name = "cgroup~7",
        .section_name = "cgroup/connect_authorization4",
        .program_name = "conditional_authorization_v4",
        .referenced_map_indices = conditional_authorization_v4_maps,
        .referenced_map_count = 1,
        .helpers = conditional_authorization_v4_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 42,
        .program_type = &conditional_authorization_v4_program_type_guid,
        .expected_attach_type = &conditional_authorization_v4_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = test_bind_helpers_v4,
        .pe_section_name = "cgroup~4",
        .section_name = "cgroup/bind4",
        .program_name = "test_bind_helpers_v4",
        .referenced_map_indices = test_bind_helpers_v4_maps,
        .referenced_map_count = 3,
        .helpers = test_bind_helpers_v4_helpers,
        .helper_count = 8,
        .bpf_instruction_count = 77,
        .program_type = &test_bind_helpers_v4_program_type_guid,
        .expected_attach_type = &test_bind_helpers_v4_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = test_bind_helpers_v6,
        .pe_section_name = "cgroup~2",
        .section_name = "cgroup/bind6",
        .program_name = "test_bind_helpers_v6",
        .referenced_map_indices = test_bind_helpers_v6_maps,
        .referenced_map_count = 3,
        .helpers = test_bind_helpers_v6_helpers,
        .helper_count = 8,
        .bpf_instruction_count = 80,
        .program_type = &test_bind_helpers_v6_program_type_guid,
        .expected_attach_type = &test_bind_helpers_v6_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = test_listen_helpers_v4,
        .pe_section_name = "cgroup~3",
        .section_name = "cgroup/listen4",
        .program_name = "test_listen_helpers_v4",
        .referenced_map_indices = test_listen_helpers_v4_maps,
        .referenced_map_count = 3,
        .helpers = test_listen_helpers_v4_helpers,
        .helper_count = 8,
        .bpf_instruction_count = 78,
        .program_type = &test_listen_helpers_v4_program_type_guid,
        .expected_attach_type = &test_listen_helpers_v4_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = test_listen_helpers_v6,
        .pe_section_name = "cgroup~1",
        .section_name = "cgroup/listen6",
        .program_name = "test_listen_helpers_v6",
        .referenced_map_indices = test_listen_helpers_v6_maps,
        .referenced_map_count = 3,
        .helpers = test_listen_helpers_v6_helpers,
        .helper_count = 8,
        .bpf_instruction_count = 80,
        .program_type = &test_listen_helpers_v6_program_type_guid,
        .expected_attach_type = &test_listen_helpers_v6_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = test_recv_accept_helpers_v4,
        .pe_section_name = "cgroup~5",
        .section_name = "cgroup/recv_accept4",
        .program_name = "test_recv_accept_helpers_v4",
        .referenced_map_indices = test_recv_accept_helpers_v4_maps,
        .referenced_map_count = 2,
        .helpers = test_recv_accept_helpers_v4_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 51,
        .program_type = &test_recv_accept_helpers_v4_program_type_guid,
        .expected_attach_type = &test_recv_accept_helpers_v4_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = test_sock_addr_helpers_v4,
        .pe_section_name = "cgroup~8",
        .section_name = "cgroup/connect_authorization4",
        .program_name = "test_sock_addr_helpers_v4",
        .referenced_map_indices = test_sock_addr_helpers_v4_maps,
        .referenced_map_count = 2,
        .helpers = test_sock_addr_helpers_v4_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 50,
        .program_type = &test_sock_addr_helpers_v4_program_type_guid,
        .expected_attach_type = &test_sock_addr_helpers_v4_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = test_sock_addr_helpers_v6,
        .pe_section_name = "cgroup~6",
        .section_name = "cgroup/connect_authorization6",
        .program_name = "test_sock_addr_helpers_v6",
        .referenced_map_indices = test_sock_addr_helpers_v6_maps,
        .referenced_map_count = 2,
        .helpers = test_sock_addr_helpers_v6_helpers,
        .helper_count = 3,
        .bpf_instruction_count = 53,
        .program_type = &test_sock_addr_helpers_v6_program_type_guid,
        .expected_attach_type = &test_sock_addr_helpers_v6_attach_type_guid,
        .btf_resolved_functions = NULL,
        .btf_resolved_function_count = 0,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 8;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = 1;
    version->minor = 4;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t cgroup_sock_addr_helpers_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
