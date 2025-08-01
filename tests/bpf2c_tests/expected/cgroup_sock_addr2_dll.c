// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from cgroup_sock_addr2.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table cgroup_sock_addr2##_metadata_table
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
         24,                // Size in bytes of a map key.
         24,                // Size in bytes of a map value.
         100,               // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         21,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "policy_map"},
    {
     {0, 0},
     {
         1,                 // Current Version.
         80,                // Struct size up to the last field.
         80,                // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         8,                 // Size in bytes of a map key.
         32,                // Size in bytes of a map value.
         100,               // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         30,                // Identifier for a map template.
         0,                 // The id of the inner map template.
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

static helper_function_entry_t connect_redirect4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     65537,
     "helper_id_65537",
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
     26,
     "helper_id_26",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID connect_redirect4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID connect_redirect4_attach_type_guid = {
    0xa82e37b1, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t connect_redirect4_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "cgroup~2")
static uint64_t
connect_redirect4(void* context, const program_runtime_context_t* runtime_context)
#line 130 "sample/cgroup_sock_addr2.c"
{
#line 130 "sample/cgroup_sock_addr2.c"
    // Prologue.
#line 130 "sample/cgroup_sock_addr2.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 130 "sample/cgroup_sock_addr2.c"
    register uint64_t r0 = 0;
#line 130 "sample/cgroup_sock_addr2.c"
    register uint64_t r1 = 0;
#line 130 "sample/cgroup_sock_addr2.c"
    register uint64_t r2 = 0;
#line 130 "sample/cgroup_sock_addr2.c"
    register uint64_t r3 = 0;
#line 130 "sample/cgroup_sock_addr2.c"
    register uint64_t r4 = 0;
#line 130 "sample/cgroup_sock_addr2.c"
    register uint64_t r5 = 0;
#line 130 "sample/cgroup_sock_addr2.c"
    register uint64_t r6 = 0;
#line 130 "sample/cgroup_sock_addr2.c"
    register uint64_t r7 = 0;
#line 130 "sample/cgroup_sock_addr2.c"
    register uint64_t r8 = 0;
#line 130 "sample/cgroup_sock_addr2.c"
    register uint64_t r10 = 0;

#line 130 "sample/cgroup_sock_addr2.c"
    r1 = (uintptr_t)context;
#line 130 "sample/cgroup_sock_addr2.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 130 "sample/cgroup_sock_addr2.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r0 src=r0 offset=0 imm=0
#line 130 "sample/cgroup_sock_addr2.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r0 offset=-16 imm=0
#line 58 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r0;
    // EBPF_OP_STXW pc=3 dst=r10 src=r0 offset=-20 imm=0
#line 58 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint32_t)r0;
    // EBPF_OP_STXW pc=4 dst=r10 src=r0 offset=-24 imm=0
#line 58 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r0;
    // EBPF_OP_STXW pc=5 dst=r10 src=r0 offset=-28 imm=0
#line 58 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint32_t)r0;
    // EBPF_OP_MOV64_IMM pc=6 dst=r1 src=r0 offset=0 imm=25959
#line 58 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(25959);
    // EBPF_OP_STXH pc=7 dst=r10 src=r1 offset=-40 imm=0
#line 59 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=8 dst=r1 src=r0 offset=0 imm=1299477349
#line 59 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7022083122929103717;
    // EBPF_OP_STXDW pc=10 dst=r10 src=r1 offset=-48 imm=0
#line 59 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1953394499
#line 59 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)6085621373624807235;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-56 imm=0
#line 59 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=1768187218
#line 59 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)8386658473162859858;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-64 imm=0
#line 59 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_STXB pc=17 dst=r10 src=r0 offset=-38 imm=0
#line 59 "sample/cgroup_sock_addr2.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-38)) = (uint8_t)r0;
    // EBPF_OP_LDXW pc=18 dst=r1 src=r6 offset=44 imm=0
#line 61 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_JEQ_IMM pc=19 dst=r1 src=r0 offset=1 imm=17
#line 61 "sample/cgroup_sock_addr2.c"
    if (r1 == IMMEDIATE(17)) {
#line 61 "sample/cgroup_sock_addr2.c"
        goto label_1;
#line 61 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_JNE_IMM pc=20 dst=r1 src=r0 offset=79 imm=6
#line 61 "sample/cgroup_sock_addr2.c"
    if (r1 != IMMEDIATE(6)) {
#line 61 "sample/cgroup_sock_addr2.c"
        goto label_3;
#line 61 "sample/cgroup_sock_addr2.c"
    }
label_1:
    // EBPF_OP_LDXW pc=21 dst=r2 src=r6 offset=0 imm=0
#line 61 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=22 dst=r2 src=r0 offset=77 imm=2
#line 61 "sample/cgroup_sock_addr2.c"
    if (r2 != IMMEDIATE(2)) {
#line 61 "sample/cgroup_sock_addr2.c"
        goto label_3;
#line 61 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_LDXW pc=23 dst=r2 src=r6 offset=24 imm=0
#line 65 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(24));
    // EBPF_OP_STXW pc=24 dst=r10 src=r2 offset=-32 imm=0
#line 65 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r2;
    // EBPF_OP_LDXH pc=25 dst=r2 src=r6 offset=40 imm=0
#line 66 "sample/cgroup_sock_addr2.c"
    r2 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(40));
    // EBPF_OP_STXW pc=26 dst=r10 src=r1 offset=-12 imm=0
#line 67 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint32_t)r1;
    // EBPF_OP_STXH pc=27 dst=r10 src=r2 offset=-16 imm=0
#line 66 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r2;
    // EBPF_OP_MOV64_REG pc=28 dst=r2 src=r10 offset=0 imm=0
#line 66 "sample/cgroup_sock_addr2.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=29 dst=r2 src=r0 offset=0 imm=-32
#line 65 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-32);
    // EBPF_OP_LDDW pc=30 dst=r1 src=r1 offset=0 imm=1
#line 70 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=32 dst=r0 src=r0 offset=0 imm=1
#line 70 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 70 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 70 "sample/cgroup_sock_addr2.c"
        return 0;
#line 70 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_MOV64_REG pc=33 dst=r7 src=r0 offset=0 imm=0
#line 70 "sample/cgroup_sock_addr2.c"
    r7 = r0;
    // EBPF_OP_MOV64_IMM pc=34 dst=r8 src=r0 offset=0 imm=0
#line 70 "sample/cgroup_sock_addr2.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_MOV64_IMM pc=35 dst=r1 src=r0 offset=0 imm=0
#line 70 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_JEQ_IMM pc=36 dst=r7 src=r0 offset=37 imm=0
#line 71 "sample/cgroup_sock_addr2.c"
    if (r7 == IMMEDIATE(0)) {
#line 71 "sample/cgroup_sock_addr2.c"
        goto label_2;
#line 71 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_MOV64_IMM pc=37 dst=r1 src=r0 offset=0 imm=29989
#line 71 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(29989);
    // EBPF_OP_STXH pc=38 dst=r10 src=r1 offset=-72 imm=0
#line 72 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=39 dst=r1 src=r0 offset=0 imm=540697973
#line 72 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)2318356710503900533;
    // EBPF_OP_STXDW pc=41 dst=r10 src=r1 offset=-80 imm=0
#line 72 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=42 dst=r1 src=r0 offset=0 imm=2037544046
#line 72 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7809653110685725806;
    // EBPF_OP_STXDW pc=44 dst=r10 src=r1 offset=-88 imm=0
#line 72 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=45 dst=r1 src=r0 offset=0 imm=1869770784
#line 72 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7286957755258269728;
    // EBPF_OP_STXDW pc=47 dst=r10 src=r1 offset=-96 imm=0
#line 72 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=48 dst=r1 src=r0 offset=0 imm=1853189958
#line 72 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)3780244552946118470;
    // EBPF_OP_STXDW pc=50 dst=r10 src=r1 offset=-104 imm=0
#line 72 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=51 dst=r1 src=r0 offset=0 imm=0
#line 72 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=52 dst=r10 src=r1 offset=-70 imm=0
#line 72 "sample/cgroup_sock_addr2.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-70)) = (uint8_t)r1;
    // EBPF_OP_LDXH pc=53 dst=r4 src=r7 offset=16 imm=0
#line 72 "sample/cgroup_sock_addr2.c"
    r4 = *(uint16_t*)(uintptr_t)(r7 + OFFSET(16));
    // EBPF_OP_LDXW pc=54 dst=r3 src=r7 offset=0 imm=0
#line 72 "sample/cgroup_sock_addr2.c"
    r3 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=55 dst=r1 src=r10 offset=0 imm=0
#line 72 "sample/cgroup_sock_addr2.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=56 dst=r1 src=r0 offset=0 imm=-104
#line 72 "sample/cgroup_sock_addr2.c"
    r1 += IMMEDIATE(-104);
    // EBPF_OP_MOV64_IMM pc=57 dst=r2 src=r0 offset=0 imm=35
#line 72 "sample/cgroup_sock_addr2.c"
    r2 = IMMEDIATE(35);
    // EBPF_OP_CALL pc=58 dst=r0 src=r0 offset=0 imm=14
#line 72 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 72 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 72 "sample/cgroup_sock_addr2.c"
        return 0;
#line 72 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_MOV64_REG pc=59 dst=r2 src=r10 offset=0 imm=0
#line 72 "sample/cgroup_sock_addr2.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=60 dst=r2 src=r0 offset=0 imm=-64
#line 72 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_REG pc=61 dst=r1 src=r6 offset=0 imm=0
#line 75 "sample/cgroup_sock_addr2.c"
    r1 = r6;
    // EBPF_OP_MOV64_IMM pc=62 dst=r3 src=r0 offset=0 imm=27
#line 75 "sample/cgroup_sock_addr2.c"
    r3 = IMMEDIATE(27);
    // EBPF_OP_CALL pc=63 dst=r0 src=r0 offset=0 imm=65537
#line 75 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 75 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 75 "sample/cgroup_sock_addr2.c"
        return 0;
#line 75 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_MOV64_REG pc=64 dst=r1 src=r0 offset=0 imm=0
#line 75 "sample/cgroup_sock_addr2.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=65 dst=r0 src=r0 offset=0 imm=0
#line 75 "sample/cgroup_sock_addr2.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_LSH64_IMM pc=66 dst=r1 src=r0 offset=0 imm=32
#line 75 "sample/cgroup_sock_addr2.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=67 dst=r1 src=r0 offset=0 imm=32
#line 75 "sample/cgroup_sock_addr2.c"
    r1 = (int64_t)r1 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=68 dst=r0 src=r1 offset=31 imm=0
#line 75 "sample/cgroup_sock_addr2.c"
    if ((int64_t)r0 > (int64_t)r1) {
#line 75 "sample/cgroup_sock_addr2.c"
        goto label_3;
#line 75 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_LDXW pc=69 dst=r1 src=r7 offset=0 imm=0
#line 79 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_STXW pc=70 dst=r6 src=r1 offset=24 imm=0
#line 79 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r6 + OFFSET(24)) = (uint32_t)r1;
    // EBPF_OP_LDXH pc=71 dst=r1 src=r7 offset=16 imm=0
#line 80 "sample/cgroup_sock_addr2.c"
    r1 = *(uint16_t*)(uintptr_t)(r7 + OFFSET(16));
    // EBPF_OP_STXH pc=72 dst=r6 src=r1 offset=40 imm=0
#line 80 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(40)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=73 dst=r1 src=r0 offset=0 imm=1
#line 80 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(1);
label_2:
    // EBPF_OP_STXDW pc=74 dst=r10 src=r8 offset=-88 imm=0
#line 43 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r8;
    // EBPF_OP_MOV64_REG pc=75 dst=r8 src=r1 offset=0 imm=0
#line 43 "sample/cgroup_sock_addr2.c"
    r8 = r1;
    // EBPF_OP_CALL pc=76 dst=r0 src=r0 offset=0 imm=19
#line 44 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 44 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 44 "sample/cgroup_sock_addr2.c"
        return 0;
#line 44 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_MOV64_REG pc=77 dst=r7 src=r0 offset=0 imm=0
#line 44 "sample/cgroup_sock_addr2.c"
    r7 = r0;
    // EBPF_OP_STXDW pc=78 dst=r10 src=r7 offset=-96 imm=0
#line 44 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r7;
    // EBPF_OP_MOV64_REG pc=79 dst=r1 src=r6 offset=0 imm=0
#line 45 "sample/cgroup_sock_addr2.c"
    r1 = r6;
    // EBPF_OP_CALL pc=80 dst=r0 src=r0 offset=0 imm=20
#line 45 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 45 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 45 "sample/cgroup_sock_addr2.c"
        return 0;
#line 45 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_STXDW pc=81 dst=r10 src=r0 offset=-104 imm=0
#line 45 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r0;
    // EBPF_OP_MOV64_REG pc=82 dst=r1 src=r6 offset=0 imm=0
#line 46 "sample/cgroup_sock_addr2.c"
    r1 = r6;
    // EBPF_OP_CALL pc=83 dst=r0 src=r0 offset=0 imm=21
#line 46 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 46 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[5].tail_call) && (r0 == 0)) {
#line 46 "sample/cgroup_sock_addr2.c"
        return 0;
#line 46 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_STXW pc=84 dst=r10 src=r0 offset=-88 imm=0
#line 46 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint32_t)r0;
    // EBPF_OP_LDXH pc=85 dst=r1 src=r6 offset=20 imm=0
#line 47 "sample/cgroup_sock_addr2.c"
    r1 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(20));
    // EBPF_OP_STXH pc=86 dst=r10 src=r1 offset=-84 imm=0
#line 47 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-84)) = (uint16_t)r1;
    // EBPF_OP_MOV64_REG pc=87 dst=r1 src=r6 offset=0 imm=0
#line 48 "sample/cgroup_sock_addr2.c"
    r1 = r6;
    // EBPF_OP_CALL pc=88 dst=r0 src=r0 offset=0 imm=26
#line 48 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 48 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 48 "sample/cgroup_sock_addr2.c"
        return 0;
#line 48 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_STXDW pc=89 dst=r10 src=r0 offset=-80 imm=0
#line 48 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r0;
    // EBPF_OP_STXDW pc=90 dst=r10 src=r7 offset=-8 imm=0
#line 50 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r7;
    // EBPF_OP_MOV64_REG pc=91 dst=r2 src=r10 offset=0 imm=0
#line 50 "sample/cgroup_sock_addr2.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=92 dst=r2 src=r0 offset=0 imm=-8
#line 50 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=93 dst=r3 src=r10 offset=0 imm=0
#line 50 "sample/cgroup_sock_addr2.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=94 dst=r3 src=r0 offset=0 imm=-104
#line 50 "sample/cgroup_sock_addr2.c"
    r3 += IMMEDIATE(-104);
    // EBPF_OP_LDDW pc=95 dst=r1 src=r1 offset=0 imm=2
#line 51 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=97 dst=r4 src=r0 offset=0 imm=0
#line 51 "sample/cgroup_sock_addr2.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=98 dst=r0 src=r0 offset=0 imm=2
#line 51 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 51 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 51 "sample/cgroup_sock_addr2.c"
        return 0;
#line 51 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_MOV64_REG pc=99 dst=r0 src=r8 offset=0 imm=0
#line 51 "sample/cgroup_sock_addr2.c"
    r0 = r8;
label_3:
    // EBPF_OP_EXIT pc=100 dst=r0 src=r0 offset=0 imm=0
#line 132 "sample/cgroup_sock_addr2.c"
    return r0;
#line 130 "sample/cgroup_sock_addr2.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t connect_redirect6_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     12,
     "helper_id_12",
    },
    {
     {1, 40, 40}, // Version header.
     65537,
     "helper_id_65537",
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
     26,
     "helper_id_26",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID connect_redirect6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID connect_redirect6_attach_type_guid = {
    0xa82e37b2, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t connect_redirect6_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "cgroup~1")
static uint64_t
connect_redirect6(void* context, const program_runtime_context_t* runtime_context)
#line 137 "sample/cgroup_sock_addr2.c"
{
#line 137 "sample/cgroup_sock_addr2.c"
    // Prologue.
#line 137 "sample/cgroup_sock_addr2.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 137 "sample/cgroup_sock_addr2.c"
    register uint64_t r0 = 0;
#line 137 "sample/cgroup_sock_addr2.c"
    register uint64_t r1 = 0;
#line 137 "sample/cgroup_sock_addr2.c"
    register uint64_t r2 = 0;
#line 137 "sample/cgroup_sock_addr2.c"
    register uint64_t r3 = 0;
#line 137 "sample/cgroup_sock_addr2.c"
    register uint64_t r4 = 0;
#line 137 "sample/cgroup_sock_addr2.c"
    register uint64_t r5 = 0;
#line 137 "sample/cgroup_sock_addr2.c"
    register uint64_t r6 = 0;
#line 137 "sample/cgroup_sock_addr2.c"
    register uint64_t r7 = 0;
#line 137 "sample/cgroup_sock_addr2.c"
    register uint64_t r8 = 0;
#line 137 "sample/cgroup_sock_addr2.c"
    register uint64_t r10 = 0;

#line 137 "sample/cgroup_sock_addr2.c"
    r1 = (uintptr_t)context;
#line 137 "sample/cgroup_sock_addr2.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 137 "sample/cgroup_sock_addr2.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r0 src=r0 offset=0 imm=0
#line 137 "sample/cgroup_sock_addr2.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r0 offset=-48 imm=0
#line 94 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint32_t)r0;
    // EBPF_OP_MOV64_IMM pc=3 dst=r1 src=r0 offset=0 imm=25959
#line 94 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(25959);
    // EBPF_OP_STXH pc=4 dst=r10 src=r1 offset=-72 imm=0
#line 95 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=1299477349
#line 95 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7022083122929103717;
    // EBPF_OP_STXDW pc=7 dst=r10 src=r1 offset=-80 imm=0
#line 95 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=8 dst=r1 src=r0 offset=0 imm=1953394499
#line 95 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)6085621373624807235;
    // EBPF_OP_STXDW pc=10 dst=r10 src=r1 offset=-88 imm=0
#line 95 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=1768187218
#line 95 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)8386658473162859858;
    // EBPF_OP_STXDW pc=13 dst=r10 src=r1 offset=-96 imm=0
#line 95 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_STXB pc=14 dst=r10 src=r0 offset=-70 imm=0
#line 95 "sample/cgroup_sock_addr2.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-70)) = (uint8_t)r0;
    // EBPF_OP_LDXW pc=15 dst=r1 src=r6 offset=44 imm=0
#line 97 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_JEQ_IMM pc=16 dst=r1 src=r0 offset=1 imm=17
#line 97 "sample/cgroup_sock_addr2.c"
    if (r1 == IMMEDIATE(17)) {
#line 97 "sample/cgroup_sock_addr2.c"
        goto label_1;
#line 97 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_JNE_IMM pc=17 dst=r1 src=r0 offset=90 imm=6
#line 97 "sample/cgroup_sock_addr2.c"
    if (r1 != IMMEDIATE(6)) {
#line 97 "sample/cgroup_sock_addr2.c"
        goto label_3;
#line 97 "sample/cgroup_sock_addr2.c"
    }
label_1:
    // EBPF_OP_LDXW pc=18 dst=r2 src=r6 offset=0 imm=0
#line 97 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=19 dst=r2 src=r0 offset=88 imm=23
#line 97 "sample/cgroup_sock_addr2.c"
    if (r2 != IMMEDIATE(23)) {
#line 97 "sample/cgroup_sock_addr2.c"
        goto label_3;
#line 97 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_LDXW pc=20 dst=r2 src=r6 offset=36 imm=0
#line 104 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(36));
    // EBPF_OP_LSH64_IMM pc=21 dst=r2 src=r0 offset=0 imm=32
#line 104 "sample/cgroup_sock_addr2.c"
    r2 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDXW pc=22 dst=r3 src=r6 offset=32 imm=0
#line 104 "sample/cgroup_sock_addr2.c"
    r3 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(32));
    // EBPF_OP_OR64_REG pc=23 dst=r2 src=r3 offset=0 imm=0
#line 104 "sample/cgroup_sock_addr2.c"
    r2 |= r3;
    // EBPF_OP_STXDW pc=24 dst=r10 src=r2 offset=-56 imm=0
#line 104 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r2;
    // EBPF_OP_LDXW pc=25 dst=r2 src=r6 offset=28 imm=0
#line 104 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(28));
    // EBPF_OP_LSH64_IMM pc=26 dst=r2 src=r0 offset=0 imm=32
#line 104 "sample/cgroup_sock_addr2.c"
    r2 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDXW pc=27 dst=r3 src=r6 offset=24 imm=0
#line 104 "sample/cgroup_sock_addr2.c"
    r3 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(24));
    // EBPF_OP_OR64_REG pc=28 dst=r2 src=r3 offset=0 imm=0
#line 104 "sample/cgroup_sock_addr2.c"
    r2 |= r3;
    // EBPF_OP_STXDW pc=29 dst=r10 src=r2 offset=-64 imm=0
#line 104 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r2;
    // EBPF_OP_LDXH pc=30 dst=r2 src=r6 offset=40 imm=0
#line 105 "sample/cgroup_sock_addr2.c"
    r2 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(40));
    // EBPF_OP_STXH pc=31 dst=r10 src=r2 offset=-48 imm=0
#line 105 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint16_t)r2;
    // EBPF_OP_STXW pc=32 dst=r10 src=r1 offset=-44 imm=0
#line 106 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-44)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=33 dst=r2 src=r10 offset=0 imm=0
#line 106 "sample/cgroup_sock_addr2.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=34 dst=r2 src=r0 offset=0 imm=-64
#line 104 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=35 dst=r1 src=r1 offset=0 imm=1
#line 109 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=37 dst=r0 src=r0 offset=0 imm=1
#line 109 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 109 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 109 "sample/cgroup_sock_addr2.c"
        return 0;
#line 109 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_MOV64_REG pc=38 dst=r7 src=r0 offset=0 imm=0
#line 109 "sample/cgroup_sock_addr2.c"
    r7 = r0;
    // EBPF_OP_MOV64_IMM pc=39 dst=r8 src=r0 offset=0 imm=0
#line 109 "sample/cgroup_sock_addr2.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_MOV64_IMM pc=40 dst=r1 src=r0 offset=0 imm=0
#line 109 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_JEQ_IMM pc=41 dst=r7 src=r0 offset=40 imm=0
#line 110 "sample/cgroup_sock_addr2.c"
    if (r7 == IMMEDIATE(0)) {
#line 110 "sample/cgroup_sock_addr2.c"
        goto label_2;
#line 110 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_MOV64_IMM pc=42 dst=r1 src=r0 offset=0 imm=25973
#line 110 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(25973);
    // EBPF_OP_STXH pc=43 dst=r10 src=r1 offset=-16 imm=0
#line 111 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=44 dst=r1 src=r0 offset=0 imm=2037544046
#line 111 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7809653110685725806;
    // EBPF_OP_STXDW pc=46 dst=r10 src=r1 offset=-24 imm=0
#line 111 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=47 dst=r1 src=r0 offset=0 imm=1869770784
#line 111 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7286957755258269728;
    // EBPF_OP_STXDW pc=49 dst=r10 src=r1 offset=-32 imm=0
#line 111 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=50 dst=r1 src=r0 offset=0 imm=1853189958
#line 111 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)3924359741021974342;
    // EBPF_OP_STXDW pc=52 dst=r10 src=r1 offset=-40 imm=0
#line 111 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=53 dst=r1 src=r0 offset=0 imm=0
#line 111 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=54 dst=r10 src=r1 offset=-14 imm=0
#line 111 "sample/cgroup_sock_addr2.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-14)) = (uint8_t)r1;
    // EBPF_OP_MOV64_REG pc=55 dst=r1 src=r10 offset=0 imm=0
#line 111 "sample/cgroup_sock_addr2.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=56 dst=r1 src=r0 offset=0 imm=-40
#line 111 "sample/cgroup_sock_addr2.c"
    r1 += IMMEDIATE(-40);
    // EBPF_OP_MOV64_IMM pc=57 dst=r2 src=r0 offset=0 imm=27
#line 111 "sample/cgroup_sock_addr2.c"
    r2 = IMMEDIATE(27);
    // EBPF_OP_CALL pc=58 dst=r0 src=r0 offset=0 imm=12
#line 111 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 111 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 111 "sample/cgroup_sock_addr2.c"
        return 0;
#line 111 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_MOV64_REG pc=59 dst=r2 src=r10 offset=0 imm=0
#line 111 "sample/cgroup_sock_addr2.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=60 dst=r2 src=r0 offset=0 imm=-96
#line 111 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-96);
    // EBPF_OP_MOV64_REG pc=61 dst=r1 src=r6 offset=0 imm=0
#line 114 "sample/cgroup_sock_addr2.c"
    r1 = r6;
    // EBPF_OP_MOV64_IMM pc=62 dst=r3 src=r0 offset=0 imm=27
#line 114 "sample/cgroup_sock_addr2.c"
    r3 = IMMEDIATE(27);
    // EBPF_OP_CALL pc=63 dst=r0 src=r0 offset=0 imm=65537
#line 114 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 114 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 114 "sample/cgroup_sock_addr2.c"
        return 0;
#line 114 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_MOV64_REG pc=64 dst=r1 src=r0 offset=0 imm=0
#line 114 "sample/cgroup_sock_addr2.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=65 dst=r0 src=r0 offset=0 imm=0
#line 114 "sample/cgroup_sock_addr2.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_LSH64_IMM pc=66 dst=r1 src=r0 offset=0 imm=32
#line 114 "sample/cgroup_sock_addr2.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=67 dst=r1 src=r0 offset=0 imm=32
#line 114 "sample/cgroup_sock_addr2.c"
    r1 = (int64_t)r1 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=68 dst=r0 src=r1 offset=39 imm=0
#line 114 "sample/cgroup_sock_addr2.c"
    if ((int64_t)r0 > (int64_t)r1) {
#line 114 "sample/cgroup_sock_addr2.c"
        goto label_3;
#line 114 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_MOV64_REG pc=69 dst=r1 src=r6 offset=0 imm=0
#line 114 "sample/cgroup_sock_addr2.c"
    r1 = r6;
    // EBPF_OP_ADD64_IMM pc=70 dst=r1 src=r0 offset=0 imm=24
#line 114 "sample/cgroup_sock_addr2.c"
    r1 += IMMEDIATE(24);
    // EBPF_OP_LDXW pc=71 dst=r2 src=r7 offset=12 imm=0
#line 117 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(12));
    // EBPF_OP_STXW pc=72 dst=r1 src=r2 offset=12 imm=0
#line 117 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(12)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=73 dst=r2 src=r7 offset=8 imm=0
#line 117 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(8));
    // EBPF_OP_STXW pc=74 dst=r1 src=r2 offset=8 imm=0
#line 117 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(8)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=75 dst=r2 src=r7 offset=4 imm=0
#line 117 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(4));
    // EBPF_OP_STXW pc=76 dst=r1 src=r2 offset=4 imm=0
#line 117 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(4)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=77 dst=r2 src=r7 offset=0 imm=0
#line 117 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_STXW pc=78 dst=r1 src=r2 offset=0 imm=0
#line 117 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(0)) = (uint32_t)r2;
    // EBPF_OP_LDXH pc=79 dst=r1 src=r7 offset=16 imm=0
#line 118 "sample/cgroup_sock_addr2.c"
    r1 = *(uint16_t*)(uintptr_t)(r7 + OFFSET(16));
    // EBPF_OP_STXH pc=80 dst=r6 src=r1 offset=40 imm=0
#line 118 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(40)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=81 dst=r1 src=r0 offset=0 imm=1
#line 118 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(1);
label_2:
    // EBPF_OP_STXDW pc=82 dst=r10 src=r8 offset=-24 imm=0
#line 43 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r8;
    // EBPF_OP_MOV64_REG pc=83 dst=r8 src=r1 offset=0 imm=0
#line 43 "sample/cgroup_sock_addr2.c"
    r8 = r1;
    // EBPF_OP_CALL pc=84 dst=r0 src=r0 offset=0 imm=19
#line 44 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 44 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 44 "sample/cgroup_sock_addr2.c"
        return 0;
#line 44 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_MOV64_REG pc=85 dst=r7 src=r0 offset=0 imm=0
#line 44 "sample/cgroup_sock_addr2.c"
    r7 = r0;
    // EBPF_OP_STXDW pc=86 dst=r10 src=r7 offset=-32 imm=0
#line 44 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r7;
    // EBPF_OP_MOV64_REG pc=87 dst=r1 src=r6 offset=0 imm=0
#line 45 "sample/cgroup_sock_addr2.c"
    r1 = r6;
    // EBPF_OP_CALL pc=88 dst=r0 src=r0 offset=0 imm=20
#line 45 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 45 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 45 "sample/cgroup_sock_addr2.c"
        return 0;
#line 45 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_STXDW pc=89 dst=r10 src=r0 offset=-40 imm=0
#line 45 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r0;
    // EBPF_OP_MOV64_REG pc=90 dst=r1 src=r6 offset=0 imm=0
#line 46 "sample/cgroup_sock_addr2.c"
    r1 = r6;
    // EBPF_OP_CALL pc=91 dst=r0 src=r0 offset=0 imm=21
#line 46 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 46 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[5].tail_call) && (r0 == 0)) {
#line 46 "sample/cgroup_sock_addr2.c"
        return 0;
#line 46 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_STXW pc=92 dst=r10 src=r0 offset=-24 imm=0
#line 46 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r0;
    // EBPF_OP_LDXH pc=93 dst=r1 src=r6 offset=20 imm=0
#line 47 "sample/cgroup_sock_addr2.c"
    r1 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(20));
    // EBPF_OP_STXH pc=94 dst=r10 src=r1 offset=-20 imm=0
#line 47 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint16_t)r1;
    // EBPF_OP_MOV64_REG pc=95 dst=r1 src=r6 offset=0 imm=0
#line 48 "sample/cgroup_sock_addr2.c"
    r1 = r6;
    // EBPF_OP_CALL pc=96 dst=r0 src=r0 offset=0 imm=26
#line 48 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 48 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 48 "sample/cgroup_sock_addr2.c"
        return 0;
#line 48 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_STXDW pc=97 dst=r10 src=r0 offset=-16 imm=0
#line 48 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r0;
    // EBPF_OP_STXDW pc=98 dst=r10 src=r7 offset=-8 imm=0
#line 50 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r7;
    // EBPF_OP_MOV64_REG pc=99 dst=r2 src=r10 offset=0 imm=0
#line 50 "sample/cgroup_sock_addr2.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=100 dst=r2 src=r0 offset=0 imm=-8
#line 50 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=101 dst=r3 src=r10 offset=0 imm=0
#line 50 "sample/cgroup_sock_addr2.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=102 dst=r3 src=r0 offset=0 imm=-40
#line 50 "sample/cgroup_sock_addr2.c"
    r3 += IMMEDIATE(-40);
    // EBPF_OP_LDDW pc=103 dst=r1 src=r1 offset=0 imm=2
#line 51 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=105 dst=r4 src=r0 offset=0 imm=0
#line 51 "sample/cgroup_sock_addr2.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=106 dst=r0 src=r0 offset=0 imm=2
#line 51 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 51 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 51 "sample/cgroup_sock_addr2.c"
        return 0;
#line 51 "sample/cgroup_sock_addr2.c"
    }
    // EBPF_OP_MOV64_REG pc=107 dst=r0 src=r8 offset=0 imm=0
#line 51 "sample/cgroup_sock_addr2.c"
    r0 = r8;
label_3:
    // EBPF_OP_EXIT pc=108 dst=r0 src=r0 offset=0 imm=0
#line 139 "sample/cgroup_sock_addr2.c"
    return r0;
#line 137 "sample/cgroup_sock_addr2.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        connect_redirect4,
        "cgroup~2",
        "cgroup/connect4",
        "connect_redirect4",
        connect_redirect4_maps,
        2,
        connect_redirect4_helpers,
        8,
        101,
        &connect_redirect4_program_type_guid,
        &connect_redirect4_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        connect_redirect6,
        "cgroup~1",
        "cgroup/connect6",
        "connect_redirect6",
        connect_redirect6_maps,
        2,
        connect_redirect6_helpers,
        8,
        109,
        &connect_redirect6_program_type_guid,
        &connect_redirect6_attach_type_guid,
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
    version->major = 0;
    version->minor = 22;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t cgroup_sock_addr2_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
