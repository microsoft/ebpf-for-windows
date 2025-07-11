// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from map.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table map##_metadata_table
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
         4,                 // Size in bytes of a map value.
         10,                // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "HASH_map"},
    {
     {0, 0},
     {
         1,                        // Current Version.
         80,                       // Struct size up to the last field.
         80,                       // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_PERCPU_HASH, // Type of map.
         4,                        // Size in bytes of a map key.
         4,                        // Size in bytes of a map value.
         10,                       // Maximum number of entries allowed in the map.
         0,                        // Inner map index.
         LIBBPF_PIN_NONE,          // Pinning type for the map.
         0,                        // Identifier for a map template.
         0,                        // The id of the inner map template.
     },
     "PERCPU_HASH_map"},
    {
     {0, 0},
     {
         1,                  // Current Version.
         80,                 // Struct size up to the last field.
         80,                 // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         10,                 // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         0,                  // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "ARRAY_map"},
    {
     {0, 0},
     {
         1,                         // Current Version.
         80,                        // Struct size up to the last field.
         80,                        // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_PERCPU_ARRAY, // Type of map.
         4,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         10,                        // Maximum number of entries allowed in the map.
         0,                         // Inner map index.
         LIBBPF_PIN_NONE,           // Pinning type for the map.
         0,                         // Identifier for a map template.
         0,                         // The id of the inner map template.
     },
     "PERCPU_ARRAY_map"},
    {
     {0, 0},
     {
         1,                     // Current Version.
         80,                    // Struct size up to the last field.
         80,                    // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_LRU_HASH, // Type of map.
         4,                     // Size in bytes of a map key.
         4,                     // Size in bytes of a map value.
         10,                    // Maximum number of entries allowed in the map.
         0,                     // Inner map index.
         LIBBPF_PIN_NONE,       // Pinning type for the map.
         0,                     // Identifier for a map template.
         0,                     // The id of the inner map template.
     },
     "LRU_HASH_map"},
    {
     {0, 0},
     {
         1,                            // Current Version.
         80,                           // Struct size up to the last field.
         80,                           // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_LRU_PERCPU_HASH, // Type of map.
         4,                            // Size in bytes of a map key.
         4,                            // Size in bytes of a map value.
         10,                           // Maximum number of entries allowed in the map.
         0,                            // Inner map index.
         LIBBPF_PIN_NONE,              // Pinning type for the map.
         0,                            // Identifier for a map template.
         0,                            // The id of the inner map template.
     },
     "LRU_PERCPU_HASH_map"},
    {
     {0, 0},
     {
         1,                  // Current Version.
         80,                 // Struct size up to the last field.
         80,                 // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_QUEUE, // Type of map.
         0,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         10,                 // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         0,                  // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "QUEUE_map"},
    {
     {0, 0},
     {
         1,                  // Current Version.
         80,                 // Struct size up to the last field.
         80,                 // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_STACK, // Type of map.
         0,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         10,                 // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         0,                  // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "STACK_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 8;
}

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static helper_function_entry_t test_maps_helpers[] = {
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
    {
     {1, 40, 40}, // Version header.
     12,
     "helper_id_12",
    },
    {
     {1, 40, 40}, // Version header.
     3,
     "helper_id_3",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     4,
     "helper_id_4",
    },
    {
     {1, 40, 40}, // Version header.
     18,
     "helper_id_18",
    },
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     17,
     "helper_id_17",
    },
    {
     {1, 40, 40}, // Version header.
     16,
     "helper_id_16",
    },
    {
     {1, 40, 40}, // Version header.
     15,
     "helper_id_15",
    },
};

static GUID test_maps_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID test_maps_attach_type_guid = {0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t test_maps_maps[] = {
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
};

#pragma code_seg(push, "sample~1")
static uint64_t
test_maps(void* context, const program_runtime_context_t* runtime_context)
#line 202 "sample/undocked/map.c"
{
#line 202 "sample/undocked/map.c"
    // Prologue.
#line 202 "sample/undocked/map.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 202 "sample/undocked/map.c"
    register uint64_t r0 = 0;
#line 202 "sample/undocked/map.c"
    register uint64_t r1 = 0;
#line 202 "sample/undocked/map.c"
    register uint64_t r2 = 0;
#line 202 "sample/undocked/map.c"
    register uint64_t r3 = 0;
#line 202 "sample/undocked/map.c"
    register uint64_t r4 = 0;
#line 202 "sample/undocked/map.c"
    register uint64_t r5 = 0;
#line 202 "sample/undocked/map.c"
    register uint64_t r6 = 0;
#line 202 "sample/undocked/map.c"
    register uint64_t r7 = 0;
#line 202 "sample/undocked/map.c"
    register uint64_t r10 = 0;

#line 202 "sample/undocked/map.c"
    r1 = (uintptr_t)context;
#line 202 "sample/undocked/map.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV_IMM pc=0 dst=r1 src=r0 offset=0 imm=0
#line 202 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 202 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=1 dst=r10 src=r1 offset=-64 imm=0
#line 70 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_MOV_IMM pc=2 dst=r1 src=r0 offset=0 imm=1
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
#line 70 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=3 dst=r10 src=r1 offset=-4 imm=0
#line 71 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=4 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=5 dst=r2 src=r0 offset=0 imm=-64
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_REG pc=6 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r3 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=8 dst=r1 src=r1 offset=0 imm=1
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=10 dst=r4 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=11 dst=r0 src=r0 offset=0 imm=2
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 74 "sample/undocked/map.c"
        return 0;
#line 74 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=12 dst=r6 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r6 = r0;
    //  pc=13 dst=r6 src=r0 offset=9 imm=-1
#line 75 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 75 "sample/undocked/map.c"
        goto label_2;
#line 75 "sample/undocked/map.c"
    }
label_1:
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=1684369010
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-96 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=544040300
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-104 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=20 dst=r1 src=r0 offset=0 imm=1633972341
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=22 dst=r0 src=r0 offset=41 imm=0
#line 75 "sample/undocked/map.c"
    goto label_5;
label_2:
    // EBPF_OP_MOV64_REG pc=23 dst=r2 src=r10 offset=0 imm=0
#line 75 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=24 dst=r2 src=r0 offset=0 imm=-64
#line 75 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=25 dst=r1 src=r1 offset=0 imm=1
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=27 dst=r0 src=r0 offset=0 imm=1
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 80 "sample/undocked/map.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 80 "sample/undocked/map.c"
        return 0;
#line 80 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=28 dst=r0 src=r0 offset=20 imm=0
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_4;
#line 81 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=29 dst=r1 src=r0 offset=0 imm=76
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
#line 81 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=30 dst=r10 src=r1 offset=-88 imm=0
#line 82 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=31 dst=r1 src=r0 offset=0 imm=1684369010
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=33 dst=r10 src=r1 offset=-96 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=34 dst=r1 src=r0 offset=0 imm=544040300
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=36 dst=r10 src=r1 offset=-104 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=37 dst=r1 src=r0 offset=0 imm=1802465132
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=39 dst=r10 src=r1 offset=-112 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=40 dst=r1 src=r0 offset=0 imm=1600548962
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=42 dst=r10 src=r1 offset=-120 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=43 dst=r1 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=44 dst=r1 src=r0 offset=0 imm=-120
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=45 dst=r2 src=r0 offset=0 imm=34
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
#line 82 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
label_3:
    // EBPF_OP_CALL pc=46 dst=r0 src=r0 offset=0 imm=12
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 82 "sample/undocked/map.c"
        return 0;
#line 82 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=47 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/undocked/map.c"
    r6 = IMMEDIATE(-1);
#line 82 "sample/undocked/map.c"
    r6 &= UINT32_MAX;
    // EBPF_OP_JA pc=48 dst=r0 src=r0 offset=26 imm=0
#line 82 "sample/undocked/map.c"
    goto label_6;
label_4:
    // EBPF_OP_MOV64_REG pc=49 dst=r2 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=50 dst=r2 src=r0 offset=0 imm=-64
#line 82 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=51 dst=r1 src=r1 offset=0 imm=1
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=53 dst=r0 src=r0 offset=0 imm=3
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 86 "sample/undocked/map.c"
        return 0;
#line 86 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=54 dst=r6 src=r0 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r6 = r0;
    //  pc=55 dst=r6 src=r0 offset=44 imm=-1
#line 87 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_9;
#line 87 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=56 dst=r1 src=r0 offset=0 imm=1684369010
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=58 dst=r10 src=r1 offset=-96 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=59 dst=r1 src=r0 offset=0 imm=544040300
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=61 dst=r10 src=r1 offset=-104 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=62 dst=r1 src=r0 offset=0 imm=1701602660
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
label_5:
    // EBPF_OP_STXDW pc=64 dst=r10 src=r1 offset=-112 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=65 dst=r1 src=r0 offset=0 imm=1600548962
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=67 dst=r10 src=r1 offset=-120 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=68 dst=r3 src=r6 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=69 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=70 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=71 dst=r1 src=r10 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=72 dst=r1 src=r0 offset=0 imm=-120
#line 88 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=73 dst=r2 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
#line 88 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_CALL pc=74 dst=r0 src=r0 offset=0 imm=13
#line 88 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/map.c"
        return 0;
#line 88 "sample/undocked/map.c"
    }
label_6:
    // EBPF_OP_MOV_IMM pc=75 dst=r1 src=r0 offset=0 imm=100
#line 88 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
#line 88 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=76 dst=r10 src=r1 offset=-84 imm=0
#line 205 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-84)) = (uint16_t)r1;
    // EBPF_OP_MOV_IMM pc=77 dst=r1 src=r0 offset=0 imm=622879845
#line 205 "sample/undocked/map.c"
    r1 = IMMEDIATE(622879845);
#line 205 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=78 dst=r10 src=r1 offset=-88 imm=0
#line 205 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=79 dst=r1 src=r0 offset=0 imm=1701978184
#line 205 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722056;
    // EBPF_OP_STXDW pc=81 dst=r10 src=r1 offset=-96 imm=0
#line 205 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=82 dst=r1 src=r0 offset=0 imm=1885433120
#line 205 "sample/undocked/map.c"
    r1 = (uint64_t)5999155482795797792;
    // EBPF_OP_STXDW pc=84 dst=r10 src=r1 offset=-104 imm=0
#line 205 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=85 dst=r1 src=r0 offset=0 imm=1279349317
#line 205 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=87 dst=r10 src=r1 offset=-112 imm=0
#line 205 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=88 dst=r1 src=r0 offset=0 imm=1953719636
#line 205 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=90 dst=r10 src=r1 offset=-120 imm=0
#line 205 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV_REG pc=91 dst=r3 src=r6 offset=0 imm=0
#line 205 "sample/undocked/map.c"
    r3 = r6;
#line 205 "sample/undocked/map.c"
    r3 &= UINT32_MAX;
    // EBPF_OP_LSH64_IMM pc=92 dst=r3 src=r0 offset=0 imm=32
#line 205 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=93 dst=r3 src=r0 offset=0 imm=32
#line 205 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=94 dst=r1 src=r10 offset=0 imm=0
#line 205 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=95 dst=r1 src=r0 offset=0 imm=-120
#line 205 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=96 dst=r2 src=r0 offset=0 imm=38
#line 205 "sample/undocked/map.c"
    r2 = IMMEDIATE(38);
#line 205 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
label_7:
    // EBPF_OP_CALL pc=97 dst=r0 src=r0 offset=0 imm=13
#line 205 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 205 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 205 "sample/undocked/map.c"
        return 0;
#line 205 "sample/undocked/map.c"
    }
label_8:
    // EBPF_OP_MOV_REG pc=98 dst=r0 src=r6 offset=0 imm=0
#line 218 "sample/undocked/map.c"
    r0 = r6;
#line 218 "sample/undocked/map.c"
    r0 &= UINT32_MAX;
    // EBPF_OP_EXIT pc=99 dst=r0 src=r0 offset=0 imm=0
#line 218 "sample/undocked/map.c"
    return r0;
label_9:
    // EBPF_OP_MOV64_REG pc=100 dst=r2 src=r10 offset=0 imm=0
#line 218 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=101 dst=r2 src=r0 offset=0 imm=-64
#line 218 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_REG pc=102 dst=r3 src=r10 offset=0 imm=0
#line 218 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=103 dst=r3 src=r0 offset=0 imm=-4
#line 218 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=104 dst=r1 src=r1 offset=0 imm=1
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=106 dst=r4 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=107 dst=r0 src=r0 offset=0 imm=2
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 92 "sample/undocked/map.c"
        return 0;
#line 92 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=108 dst=r6 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r6 = r0;
    //  pc=109 dst=r6 src=r0 offset=1 imm=-1
#line 93 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_10;
#line 93 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=110 dst=r0 src=r0 offset=-97 imm=0
#line 93 "sample/undocked/map.c"
    goto label_1;
label_10:
    // EBPF_OP_MOV64_REG pc=111 dst=r2 src=r10 offset=0 imm=0
#line 93 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=112 dst=r2 src=r0 offset=0 imm=-64
#line 93 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=113 dst=r1 src=r1 offset=0 imm=1
#line 103 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=115 dst=r0 src=r0 offset=0 imm=4
#line 103 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 103 "sample/undocked/map.c"
    if ((runtime_context->helper_data[5].tail_call) && (r0 == 0)) {
#line 103 "sample/undocked/map.c"
        return 0;
#line 103 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=116 dst=r0 src=r0 offset=23 imm=0
#line 104 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 104 "sample/undocked/map.c"
        goto label_11;
#line 104 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=117 dst=r1 src=r0 offset=0 imm=0
#line 104 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 104 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=118 dst=r10 src=r1 offset=-76 imm=0
#line 105 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-76)) = (uint8_t)r1;
    // EBPF_OP_MOV_IMM pc=119 dst=r1 src=r0 offset=0 imm=1280070990
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(1280070990);
#line 105 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=120 dst=r10 src=r1 offset=-80 imm=0
#line 105 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=121 dst=r1 src=r0 offset=0 imm=1920300133
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)2334102031925867621;
    // EBPF_OP_STXDW pc=123 dst=r10 src=r1 offset=-88 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=124 dst=r1 src=r0 offset=0 imm=1818582885
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8223693201956233061;
    // EBPF_OP_STXDW pc=126 dst=r10 src=r1 offset=-96 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=127 dst=r1 src=r0 offset=0 imm=1683973230
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8387229063778886766;
    // EBPF_OP_STXDW pc=129 dst=r10 src=r1 offset=-104 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=130 dst=r1 src=r0 offset=0 imm=1802465132
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)7016450394082471788;
    // EBPF_OP_STXDW pc=132 dst=r10 src=r1 offset=-112 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=133 dst=r1 src=r0 offset=0 imm=1600548962
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=135 dst=r10 src=r1 offset=-120 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=136 dst=r1 src=r10 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=137 dst=r1 src=r0 offset=0 imm=-120
#line 105 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=138 dst=r2 src=r0 offset=0 imm=45
#line 105 "sample/undocked/map.c"
    r2 = IMMEDIATE(45);
#line 105 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_JA pc=139 dst=r0 src=r0 offset=-94 imm=0
#line 105 "sample/undocked/map.c"
    goto label_3;
label_11:
    // EBPF_OP_MOV_IMM pc=140 dst=r1 src=r0 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 105 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=141 dst=r10 src=r1 offset=-64 imm=0
#line 70 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_MOV_IMM pc=142 dst=r1 src=r0 offset=0 imm=1
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
#line 70 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=143 dst=r10 src=r1 offset=-4 imm=0
#line 71 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=144 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=145 dst=r2 src=r0 offset=0 imm=-64
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_REG pc=146 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=147 dst=r3 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=148 dst=r1 src=r1 offset=0 imm=2
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=150 dst=r4 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=151 dst=r0 src=r0 offset=0 imm=2
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 74 "sample/undocked/map.c"
        return 0;
#line 74 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=152 dst=r6 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r6 = r0;
    //  pc=153 dst=r6 src=r0 offset=9 imm=-1
#line 75 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 75 "sample/undocked/map.c"
        goto label_13;
#line 75 "sample/undocked/map.c"
    }
label_12:
    // EBPF_OP_LDDW pc=154 dst=r1 src=r0 offset=0 imm=1684369010
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=156 dst=r10 src=r1 offset=-96 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=157 dst=r1 src=r0 offset=0 imm=544040300
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=159 dst=r10 src=r1 offset=-104 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=160 dst=r1 src=r0 offset=0 imm=1633972341
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=162 dst=r0 src=r0 offset=41 imm=0
#line 75 "sample/undocked/map.c"
    goto label_16;
label_13:
    // EBPF_OP_MOV64_REG pc=163 dst=r2 src=r10 offset=0 imm=0
#line 75 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=164 dst=r2 src=r0 offset=0 imm=-64
#line 75 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=165 dst=r1 src=r1 offset=0 imm=2
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=167 dst=r0 src=r0 offset=0 imm=1
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 80 "sample/undocked/map.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 80 "sample/undocked/map.c"
        return 0;
#line 80 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=168 dst=r0 src=r0 offset=20 imm=0
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_15;
#line 81 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=169 dst=r1 src=r0 offset=0 imm=76
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
#line 81 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=170 dst=r10 src=r1 offset=-88 imm=0
#line 82 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=171 dst=r1 src=r0 offset=0 imm=1684369010
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=173 dst=r10 src=r1 offset=-96 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=174 dst=r1 src=r0 offset=0 imm=544040300
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=176 dst=r10 src=r1 offset=-104 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=177 dst=r1 src=r0 offset=0 imm=1802465132
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=179 dst=r10 src=r1 offset=-112 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=180 dst=r1 src=r0 offset=0 imm=1600548962
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=182 dst=r10 src=r1 offset=-120 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=183 dst=r1 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=184 dst=r1 src=r0 offset=0 imm=-120
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=185 dst=r2 src=r0 offset=0 imm=34
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
#line 82 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
label_14:
    // EBPF_OP_CALL pc=186 dst=r0 src=r0 offset=0 imm=12
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 82 "sample/undocked/map.c"
        return 0;
#line 82 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=187 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/undocked/map.c"
    r6 = IMMEDIATE(-1);
#line 82 "sample/undocked/map.c"
    r6 &= UINT32_MAX;
    // EBPF_OP_JA pc=188 dst=r0 src=r0 offset=26 imm=0
#line 82 "sample/undocked/map.c"
    goto label_17;
label_15:
    // EBPF_OP_MOV64_REG pc=189 dst=r2 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=190 dst=r2 src=r0 offset=0 imm=-64
#line 82 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=191 dst=r1 src=r1 offset=0 imm=2
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=193 dst=r0 src=r0 offset=0 imm=3
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 86 "sample/undocked/map.c"
        return 0;
#line 86 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=194 dst=r6 src=r0 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r6 = r0;
    //  pc=195 dst=r6 src=r0 offset=45 imm=-1
#line 87 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_18;
#line 87 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=196 dst=r1 src=r0 offset=0 imm=1684369010
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=198 dst=r10 src=r1 offset=-96 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=199 dst=r1 src=r0 offset=0 imm=544040300
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=201 dst=r10 src=r1 offset=-104 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=202 dst=r1 src=r0 offset=0 imm=1701602660
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
label_16:
    // EBPF_OP_STXDW pc=204 dst=r10 src=r1 offset=-112 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=205 dst=r1 src=r0 offset=0 imm=1600548962
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=207 dst=r10 src=r1 offset=-120 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=208 dst=r3 src=r6 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=209 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=210 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=211 dst=r1 src=r10 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=212 dst=r1 src=r0 offset=0 imm=-120
#line 88 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=213 dst=r2 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
#line 88 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_CALL pc=214 dst=r0 src=r0 offset=0 imm=13
#line 88 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/map.c"
        return 0;
#line 88 "sample/undocked/map.c"
    }
label_17:
    // EBPF_OP_MOV_IMM pc=215 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 88 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=216 dst=r10 src=r1 offset=-76 imm=0
#line 206 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-76)) = (uint8_t)r1;
    // EBPF_OP_MOV_IMM pc=217 dst=r1 src=r0 offset=0 imm=1680154724
#line 206 "sample/undocked/map.c"
    r1 = IMMEDIATE(1680154724);
#line 206 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=218 dst=r10 src=r1 offset=-80 imm=0
#line 206 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=219 dst=r1 src=r0 offset=0 imm=1952805408
#line 206 "sample/undocked/map.c"
    r1 = (uint64_t)7308905094058439200;
    // EBPF_OP_STXDW pc=221 dst=r10 src=r1 offset=-88 imm=0
#line 206 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=222 dst=r1 src=r0 offset=0 imm=1599426627
#line 206 "sample/undocked/map.c"
    r1 = (uint64_t)5211580972890673219;
    // EBPF_OP_STXDW pc=224 dst=r10 src=r1 offset=-96 imm=0
#line 206 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=225 dst=r1 src=r0 offset=0 imm=1885433120
#line 206 "sample/undocked/map.c"
    r1 = (uint64_t)5928232584757734688;
    // EBPF_OP_STXDW pc=227 dst=r10 src=r1 offset=-104 imm=0
#line 206 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=228 dst=r1 src=r0 offset=0 imm=1279349317
#line 206 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=230 dst=r10 src=r1 offset=-112 imm=0
#line 206 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=231 dst=r1 src=r0 offset=0 imm=1953719636
#line 206 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=233 dst=r10 src=r1 offset=-120 imm=0
#line 206 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV_REG pc=234 dst=r3 src=r6 offset=0 imm=0
#line 206 "sample/undocked/map.c"
    r3 = r6;
#line 206 "sample/undocked/map.c"
    r3 &= UINT32_MAX;
    // EBPF_OP_LSH64_IMM pc=235 dst=r3 src=r0 offset=0 imm=32
#line 206 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=236 dst=r3 src=r0 offset=0 imm=32
#line 206 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=237 dst=r1 src=r10 offset=0 imm=0
#line 206 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=238 dst=r1 src=r0 offset=0 imm=-120
#line 206 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=239 dst=r2 src=r0 offset=0 imm=45
#line 206 "sample/undocked/map.c"
    r2 = IMMEDIATE(45);
#line 206 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_JA pc=240 dst=r0 src=r0 offset=-144 imm=0
#line 206 "sample/undocked/map.c"
    goto label_7;
label_18:
    // EBPF_OP_MOV64_REG pc=241 dst=r2 src=r10 offset=0 imm=0
#line 206 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=242 dst=r2 src=r0 offset=0 imm=-64
#line 206 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_REG pc=243 dst=r3 src=r10 offset=0 imm=0
#line 206 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=244 dst=r3 src=r0 offset=0 imm=-4
#line 206 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=245 dst=r1 src=r1 offset=0 imm=2
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=247 dst=r4 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=248 dst=r0 src=r0 offset=0 imm=2
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 92 "sample/undocked/map.c"
        return 0;
#line 92 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=249 dst=r6 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r6 = r0;
    //  pc=250 dst=r6 src=r0 offset=1 imm=-1
#line 93 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_19;
#line 93 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=251 dst=r0 src=r0 offset=-98 imm=0
#line 93 "sample/undocked/map.c"
    goto label_12;
label_19:
    // EBPF_OP_MOV64_REG pc=252 dst=r2 src=r10 offset=0 imm=0
#line 93 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=253 dst=r2 src=r0 offset=0 imm=-64
#line 93 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=254 dst=r1 src=r1 offset=0 imm=2
#line 103 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=256 dst=r0 src=r0 offset=0 imm=4
#line 103 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 103 "sample/undocked/map.c"
    if ((runtime_context->helper_data[5].tail_call) && (r0 == 0)) {
#line 103 "sample/undocked/map.c"
        return 0;
#line 103 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=257 dst=r0 src=r0 offset=23 imm=0
#line 104 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 104 "sample/undocked/map.c"
        goto label_20;
#line 104 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=258 dst=r1 src=r0 offset=0 imm=0
#line 104 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 104 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=259 dst=r10 src=r1 offset=-76 imm=0
#line 105 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-76)) = (uint8_t)r1;
    // EBPF_OP_MOV_IMM pc=260 dst=r1 src=r0 offset=0 imm=1280070990
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(1280070990);
#line 105 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=261 dst=r10 src=r1 offset=-80 imm=0
#line 105 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=262 dst=r1 src=r0 offset=0 imm=1920300133
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)2334102031925867621;
    // EBPF_OP_STXDW pc=264 dst=r10 src=r1 offset=-88 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=265 dst=r1 src=r0 offset=0 imm=1818582885
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8223693201956233061;
    // EBPF_OP_STXDW pc=267 dst=r10 src=r1 offset=-96 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=268 dst=r1 src=r0 offset=0 imm=1683973230
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8387229063778886766;
    // EBPF_OP_STXDW pc=270 dst=r10 src=r1 offset=-104 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=271 dst=r1 src=r0 offset=0 imm=1802465132
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)7016450394082471788;
    // EBPF_OP_STXDW pc=273 dst=r10 src=r1 offset=-112 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=274 dst=r1 src=r0 offset=0 imm=1600548962
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=276 dst=r10 src=r1 offset=-120 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=277 dst=r1 src=r10 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=278 dst=r1 src=r0 offset=0 imm=-120
#line 105 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=279 dst=r2 src=r0 offset=0 imm=45
#line 105 "sample/undocked/map.c"
    r2 = IMMEDIATE(45);
#line 105 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_JA pc=280 dst=r0 src=r0 offset=-95 imm=0
#line 105 "sample/undocked/map.c"
    goto label_14;
label_20:
    // EBPF_OP_MOV_IMM pc=281 dst=r1 src=r0 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 105 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=282 dst=r10 src=r1 offset=-64 imm=0
#line 70 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_MOV_IMM pc=283 dst=r1 src=r0 offset=0 imm=1
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
#line 70 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=284 dst=r10 src=r1 offset=-4 imm=0
#line 71 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=285 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=286 dst=r2 src=r0 offset=0 imm=-64
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_REG pc=287 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=288 dst=r3 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=289 dst=r1 src=r1 offset=0 imm=3
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_MOV64_IMM pc=291 dst=r4 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=292 dst=r0 src=r0 offset=0 imm=2
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 74 "sample/undocked/map.c"
        return 0;
#line 74 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=293 dst=r6 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r6 = r0;
    //  pc=294 dst=r6 src=r0 offset=9 imm=-1
#line 75 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 75 "sample/undocked/map.c"
        goto label_22;
#line 75 "sample/undocked/map.c"
    }
label_21:
    // EBPF_OP_LDDW pc=295 dst=r1 src=r0 offset=0 imm=1684369010
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=297 dst=r10 src=r1 offset=-96 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=298 dst=r1 src=r0 offset=0 imm=544040300
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=300 dst=r10 src=r1 offset=-104 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=301 dst=r1 src=r0 offset=0 imm=1633972341
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=303 dst=r0 src=r0 offset=41 imm=0
#line 75 "sample/undocked/map.c"
    goto label_24;
label_22:
    // EBPF_OP_MOV64_REG pc=304 dst=r2 src=r10 offset=0 imm=0
#line 75 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=305 dst=r2 src=r0 offset=0 imm=-64
#line 75 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=306 dst=r1 src=r1 offset=0 imm=3
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_CALL pc=308 dst=r0 src=r0 offset=0 imm=1
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 80 "sample/undocked/map.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 80 "sample/undocked/map.c"
        return 0;
#line 80 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=309 dst=r0 src=r0 offset=20 imm=0
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_23;
#line 81 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=310 dst=r1 src=r0 offset=0 imm=76
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
#line 81 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=311 dst=r10 src=r1 offset=-88 imm=0
#line 82 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=312 dst=r1 src=r0 offset=0 imm=1684369010
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=314 dst=r10 src=r1 offset=-96 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=315 dst=r1 src=r0 offset=0 imm=544040300
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=317 dst=r10 src=r1 offset=-104 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=318 dst=r1 src=r0 offset=0 imm=1802465132
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=320 dst=r10 src=r1 offset=-112 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=321 dst=r1 src=r0 offset=0 imm=1600548962
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=323 dst=r10 src=r1 offset=-120 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=324 dst=r1 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=325 dst=r1 src=r0 offset=0 imm=-120
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=326 dst=r2 src=r0 offset=0 imm=34
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
#line 82 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_CALL pc=327 dst=r0 src=r0 offset=0 imm=12
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 82 "sample/undocked/map.c"
        return 0;
#line 82 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=328 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/undocked/map.c"
    r6 = IMMEDIATE(-1);
#line 82 "sample/undocked/map.c"
    r6 &= UINT32_MAX;
    // EBPF_OP_JA pc=329 dst=r0 src=r0 offset=26 imm=0
#line 82 "sample/undocked/map.c"
    goto label_25;
label_23:
    // EBPF_OP_MOV64_REG pc=330 dst=r2 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=331 dst=r2 src=r0 offset=0 imm=-64
#line 82 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=332 dst=r1 src=r1 offset=0 imm=3
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_CALL pc=334 dst=r0 src=r0 offset=0 imm=3
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 86 "sample/undocked/map.c"
        return 0;
#line 86 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=335 dst=r6 src=r0 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r6 = r0;
    //  pc=336 dst=r6 src=r0 offset=44 imm=-1
#line 87 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_26;
#line 87 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=337 dst=r1 src=r0 offset=0 imm=1684369010
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=339 dst=r10 src=r1 offset=-96 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=340 dst=r1 src=r0 offset=0 imm=544040300
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=342 dst=r10 src=r1 offset=-104 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=343 dst=r1 src=r0 offset=0 imm=1701602660
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
label_24:
    // EBPF_OP_STXDW pc=345 dst=r10 src=r1 offset=-112 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=346 dst=r1 src=r0 offset=0 imm=1600548962
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=348 dst=r10 src=r1 offset=-120 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=349 dst=r3 src=r6 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=350 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=351 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=352 dst=r1 src=r10 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=353 dst=r1 src=r0 offset=0 imm=-120
#line 88 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=354 dst=r2 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
#line 88 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_CALL pc=355 dst=r0 src=r0 offset=0 imm=13
#line 88 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/map.c"
        return 0;
#line 88 "sample/undocked/map.c"
    }
label_25:
    // EBPF_OP_MOV_IMM pc=356 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 88 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=357 dst=r10 src=r1 offset=-82 imm=0
#line 207 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-82)) = (uint8_t)r1;
    // EBPF_OP_MOV_IMM pc=358 dst=r1 src=r0 offset=0 imm=25637
#line 207 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
#line 207 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=359 dst=r10 src=r1 offset=-84 imm=0
#line 207 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-84)) = (uint16_t)r1;
    // EBPF_OP_MOV_IMM pc=360 dst=r1 src=r0 offset=0 imm=543450478
#line 207 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
#line 207 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=361 dst=r10 src=r1 offset=-88 imm=0
#line 207 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=362 dst=r1 src=r0 offset=0 imm=1914722625
#line 207 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654172993;
    // EBPF_OP_STXDW pc=364 dst=r10 src=r1 offset=-96 imm=0
#line 207 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=365 dst=r1 src=r0 offset=0 imm=1885433120
#line 207 "sample/undocked/map.c"
    r1 = (uint64_t)5931875266780556576;
    // EBPF_OP_STXDW pc=367 dst=r10 src=r1 offset=-104 imm=0
#line 207 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=368 dst=r1 src=r0 offset=0 imm=1279349317
#line 207 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=370 dst=r10 src=r1 offset=-112 imm=0
#line 207 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=371 dst=r1 src=r0 offset=0 imm=1953719636
#line 207 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=373 dst=r10 src=r1 offset=-120 imm=0
#line 207 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV_REG pc=374 dst=r3 src=r6 offset=0 imm=0
#line 207 "sample/undocked/map.c"
    r3 = r6;
#line 207 "sample/undocked/map.c"
    r3 &= UINT32_MAX;
    // EBPF_OP_LSH64_IMM pc=375 dst=r3 src=r0 offset=0 imm=32
#line 207 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=376 dst=r3 src=r0 offset=0 imm=32
#line 207 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=377 dst=r1 src=r10 offset=0 imm=0
#line 207 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=378 dst=r1 src=r0 offset=0 imm=-120
#line 207 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=379 dst=r2 src=r0 offset=0 imm=39
#line 207 "sample/undocked/map.c"
    r2 = IMMEDIATE(39);
#line 207 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_JA pc=380 dst=r0 src=r0 offset=-284 imm=0
#line 207 "sample/undocked/map.c"
    goto label_7;
label_26:
    // EBPF_OP_MOV64_REG pc=381 dst=r2 src=r10 offset=0 imm=0
#line 207 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=382 dst=r2 src=r0 offset=0 imm=-64
#line 207 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_REG pc=383 dst=r3 src=r10 offset=0 imm=0
#line 207 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=384 dst=r3 src=r0 offset=0 imm=-4
#line 207 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=385 dst=r1 src=r1 offset=0 imm=3
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_MOV64_IMM pc=387 dst=r4 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=388 dst=r0 src=r0 offset=0 imm=2
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 92 "sample/undocked/map.c"
        return 0;
#line 92 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=389 dst=r6 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r6 = r0;
    //  pc=390 dst=r6 src=r0 offset=1 imm=-1
#line 93 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_27;
#line 93 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=391 dst=r0 src=r0 offset=-97 imm=0
#line 93 "sample/undocked/map.c"
    goto label_21;
label_27:
    // EBPF_OP_MOV_IMM pc=392 dst=r1 src=r0 offset=0 imm=0
#line 93 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 93 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=393 dst=r10 src=r1 offset=-64 imm=0
#line 70 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_MOV_IMM pc=394 dst=r1 src=r0 offset=0 imm=1
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
#line 70 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=395 dst=r10 src=r1 offset=-4 imm=0
#line 71 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=396 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=397 dst=r2 src=r0 offset=0 imm=-64
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_REG pc=398 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=399 dst=r3 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=400 dst=r1 src=r1 offset=0 imm=4
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_MOV64_IMM pc=402 dst=r4 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=403 dst=r0 src=r0 offset=0 imm=2
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 74 "sample/undocked/map.c"
        return 0;
#line 74 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=404 dst=r6 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r6 = r0;
    //  pc=405 dst=r6 src=r0 offset=52 imm=0
#line 75 "sample/undocked/map.c"
    if ((int32_t)r6 < IMMEDIATE(0)) {
#line 75 "sample/undocked/map.c"
        goto label_30;
#line 75 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=406 dst=r2 src=r10 offset=0 imm=0
#line 75 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=407 dst=r2 src=r0 offset=0 imm=-64
#line 75 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=408 dst=r1 src=r1 offset=0 imm=4
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_CALL pc=410 dst=r0 src=r0 offset=0 imm=1
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 80 "sample/undocked/map.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 80 "sample/undocked/map.c"
        return 0;
#line 80 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=411 dst=r0 src=r0 offset=20 imm=0
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_28;
#line 81 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=412 dst=r1 src=r0 offset=0 imm=76
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
#line 81 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=413 dst=r10 src=r1 offset=-88 imm=0
#line 82 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=414 dst=r1 src=r0 offset=0 imm=1684369010
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=416 dst=r10 src=r1 offset=-96 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=417 dst=r1 src=r0 offset=0 imm=544040300
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=419 dst=r10 src=r1 offset=-104 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=420 dst=r1 src=r0 offset=0 imm=1802465132
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=422 dst=r10 src=r1 offset=-112 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=423 dst=r1 src=r0 offset=0 imm=1600548962
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=425 dst=r10 src=r1 offset=-120 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=426 dst=r1 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=427 dst=r1 src=r0 offset=0 imm=-120
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=428 dst=r2 src=r0 offset=0 imm=34
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
#line 82 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_CALL pc=429 dst=r0 src=r0 offset=0 imm=12
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 82 "sample/undocked/map.c"
        return 0;
#line 82 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=430 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/undocked/map.c"
    r6 = IMMEDIATE(-1);
#line 82 "sample/undocked/map.c"
    r6 &= UINT32_MAX;
    // EBPF_OP_JA pc=431 dst=r0 src=r0 offset=45 imm=0
#line 83 "sample/undocked/map.c"
    goto label_32;
label_28:
    // EBPF_OP_MOV64_REG pc=432 dst=r2 src=r10 offset=0 imm=0
#line 83 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=433 dst=r2 src=r0 offset=0 imm=-64
#line 83 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=434 dst=r1 src=r1 offset=0 imm=4
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_CALL pc=436 dst=r0 src=r0 offset=0 imm=3
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 86 "sample/undocked/map.c"
        return 0;
#line 86 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=437 dst=r6 src=r0 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r6 = r0;
    //  pc=438 dst=r6 src=r0 offset=9 imm=-1
#line 87 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_29;
#line 87 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=439 dst=r1 src=r0 offset=0 imm=1684369010
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=441 dst=r10 src=r1 offset=-96 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=442 dst=r1 src=r0 offset=0 imm=544040300
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=444 dst=r10 src=r1 offset=-104 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=445 dst=r1 src=r0 offset=0 imm=1701602660
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
    // EBPF_OP_JA pc=447 dst=r0 src=r0 offset=18 imm=0
#line 88 "sample/undocked/map.c"
    goto label_31;
label_29:
    // EBPF_OP_MOV64_REG pc=448 dst=r2 src=r10 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=449 dst=r2 src=r0 offset=0 imm=-64
#line 88 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_REG pc=450 dst=r3 src=r10 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=451 dst=r3 src=r0 offset=0 imm=-4
#line 88 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=452 dst=r1 src=r1 offset=0 imm=4
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_MOV64_IMM pc=454 dst=r4 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=455 dst=r0 src=r0 offset=0 imm=2
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 92 "sample/undocked/map.c"
        return 0;
#line 92 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=456 dst=r6 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r6 = r0;
    //  pc=457 dst=r6 src=r0 offset=45 imm=-1
#line 93 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_33;
#line 93 "sample/undocked/map.c"
    }
label_30:
    // EBPF_OP_LDDW pc=458 dst=r1 src=r0 offset=0 imm=1684369010
#line 93 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=460 dst=r10 src=r1 offset=-96 imm=0
#line 93 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=461 dst=r1 src=r0 offset=0 imm=544040300
#line 93 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=463 dst=r10 src=r1 offset=-104 imm=0
#line 93 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=464 dst=r1 src=r0 offset=0 imm=1633972341
#line 93 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
label_31:
    // EBPF_OP_STXDW pc=466 dst=r10 src=r1 offset=-112 imm=0
#line 93 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=467 dst=r1 src=r0 offset=0 imm=1600548962
#line 93 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=469 dst=r10 src=r1 offset=-120 imm=0
#line 93 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=470 dst=r3 src=r6 offset=0 imm=0
#line 93 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=471 dst=r3 src=r0 offset=0 imm=32
#line 93 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=472 dst=r3 src=r0 offset=0 imm=32
#line 93 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=473 dst=r1 src=r10 offset=0 imm=0
#line 93 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=474 dst=r1 src=r0 offset=0 imm=-120
#line 93 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=475 dst=r2 src=r0 offset=0 imm=32
#line 93 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
#line 93 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_CALL pc=476 dst=r0 src=r0 offset=0 imm=13
#line 93 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 93 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 93 "sample/undocked/map.c"
        return 0;
#line 93 "sample/undocked/map.c"
    }
label_32:
    // EBPF_OP_MOV_IMM pc=477 dst=r1 src=r0 offset=0 imm=100
#line 93 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
#line 93 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=478 dst=r10 src=r1 offset=-76 imm=0
#line 208 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-76)) = (uint16_t)r1;
    // EBPF_OP_MOV_IMM pc=479 dst=r1 src=r0 offset=0 imm=622879845
#line 208 "sample/undocked/map.c"
    r1 = IMMEDIATE(622879845);
#line 208 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=480 dst=r10 src=r1 offset=-80 imm=0
#line 208 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=481 dst=r1 src=r0 offset=0 imm=1701978201
#line 208 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722073;
    // EBPF_OP_STXDW pc=483 dst=r10 src=r1 offset=-88 imm=0
#line 208 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=484 dst=r1 src=r0 offset=0 imm=1599426627
#line 208 "sample/undocked/map.c"
    r1 = (uint64_t)4706915001281368131;
    // EBPF_OP_STXDW pc=486 dst=r10 src=r1 offset=-96 imm=0
#line 208 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=487 dst=r1 src=r0 offset=0 imm=1885433120
#line 208 "sample/undocked/map.c"
    r1 = (uint64_t)5928232584757734688;
    // EBPF_OP_STXDW pc=489 dst=r10 src=r1 offset=-104 imm=0
#line 208 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=490 dst=r1 src=r0 offset=0 imm=1279349317
#line 208 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=492 dst=r10 src=r1 offset=-112 imm=0
#line 208 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=493 dst=r1 src=r0 offset=0 imm=1953719636
#line 208 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=495 dst=r10 src=r1 offset=-120 imm=0
#line 208 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV_REG pc=496 dst=r3 src=r6 offset=0 imm=0
#line 208 "sample/undocked/map.c"
    r3 = r6;
#line 208 "sample/undocked/map.c"
    r3 &= UINT32_MAX;
    // EBPF_OP_LSH64_IMM pc=497 dst=r3 src=r0 offset=0 imm=32
#line 208 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=498 dst=r3 src=r0 offset=0 imm=32
#line 208 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=499 dst=r1 src=r10 offset=0 imm=0
#line 208 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=500 dst=r1 src=r0 offset=0 imm=-120
#line 208 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=501 dst=r2 src=r0 offset=0 imm=46
#line 208 "sample/undocked/map.c"
    r2 = IMMEDIATE(46);
#line 208 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_JA pc=502 dst=r0 src=r0 offset=-406 imm=0
#line 208 "sample/undocked/map.c"
    goto label_7;
label_33:
    // EBPF_OP_MOV_IMM pc=503 dst=r1 src=r0 offset=0 imm=0
#line 208 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 208 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=504 dst=r10 src=r1 offset=-64 imm=0
#line 70 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_MOV_IMM pc=505 dst=r1 src=r0 offset=0 imm=1
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
#line 70 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=506 dst=r10 src=r1 offset=-4 imm=0
#line 71 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=507 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=508 dst=r2 src=r0 offset=0 imm=-64
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_REG pc=509 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=510 dst=r3 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=511 dst=r1 src=r1 offset=0 imm=5
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_IMM pc=513 dst=r4 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=514 dst=r0 src=r0 offset=0 imm=2
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 74 "sample/undocked/map.c"
        return 0;
#line 74 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=515 dst=r6 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r6 = r0;
    //  pc=516 dst=r6 src=r0 offset=9 imm=-1
#line 75 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 75 "sample/undocked/map.c"
        goto label_35;
#line 75 "sample/undocked/map.c"
    }
label_34:
    // EBPF_OP_LDDW pc=517 dst=r1 src=r0 offset=0 imm=1684369010
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=519 dst=r10 src=r1 offset=-96 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=520 dst=r1 src=r0 offset=0 imm=544040300
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=522 dst=r10 src=r1 offset=-104 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=523 dst=r1 src=r0 offset=0 imm=1633972341
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=525 dst=r0 src=r0 offset=41 imm=0
#line 75 "sample/undocked/map.c"
    goto label_38;
label_35:
    // EBPF_OP_MOV64_REG pc=526 dst=r2 src=r10 offset=0 imm=0
#line 75 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=527 dst=r2 src=r0 offset=0 imm=-64
#line 75 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=528 dst=r1 src=r1 offset=0 imm=5
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_CALL pc=530 dst=r0 src=r0 offset=0 imm=1
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 80 "sample/undocked/map.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 80 "sample/undocked/map.c"
        return 0;
#line 80 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=531 dst=r0 src=r0 offset=20 imm=0
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_37;
#line 81 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=532 dst=r1 src=r0 offset=0 imm=76
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
#line 81 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=533 dst=r10 src=r1 offset=-88 imm=0
#line 82 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=534 dst=r1 src=r0 offset=0 imm=1684369010
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=536 dst=r10 src=r1 offset=-96 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=537 dst=r1 src=r0 offset=0 imm=544040300
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=539 dst=r10 src=r1 offset=-104 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=540 dst=r1 src=r0 offset=0 imm=1802465132
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=542 dst=r10 src=r1 offset=-112 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=543 dst=r1 src=r0 offset=0 imm=1600548962
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=545 dst=r10 src=r1 offset=-120 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=546 dst=r1 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=547 dst=r1 src=r0 offset=0 imm=-120
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=548 dst=r2 src=r0 offset=0 imm=34
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
#line 82 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
label_36:
    // EBPF_OP_CALL pc=549 dst=r0 src=r0 offset=0 imm=12
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 82 "sample/undocked/map.c"
        return 0;
#line 82 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=550 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/undocked/map.c"
    r6 = IMMEDIATE(-1);
#line 82 "sample/undocked/map.c"
    r6 &= UINT32_MAX;
    // EBPF_OP_JA pc=551 dst=r0 src=r0 offset=26 imm=0
#line 82 "sample/undocked/map.c"
    goto label_39;
label_37:
    // EBPF_OP_MOV64_REG pc=552 dst=r2 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=553 dst=r2 src=r0 offset=0 imm=-64
#line 82 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=554 dst=r1 src=r1 offset=0 imm=5
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_CALL pc=556 dst=r0 src=r0 offset=0 imm=3
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 86 "sample/undocked/map.c"
        return 0;
#line 86 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=557 dst=r6 src=r0 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r6 = r0;
    //  pc=558 dst=r6 src=r0 offset=43 imm=-1
#line 87 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_40;
#line 87 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=559 dst=r1 src=r0 offset=0 imm=1684369010
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=561 dst=r10 src=r1 offset=-96 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=562 dst=r1 src=r0 offset=0 imm=544040300
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=564 dst=r10 src=r1 offset=-104 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=565 dst=r1 src=r0 offset=0 imm=1701602660
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
label_38:
    // EBPF_OP_STXDW pc=567 dst=r10 src=r1 offset=-112 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=568 dst=r1 src=r0 offset=0 imm=1600548962
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=570 dst=r10 src=r1 offset=-120 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=571 dst=r3 src=r6 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=572 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=573 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=574 dst=r1 src=r10 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=575 dst=r1 src=r0 offset=0 imm=-120
#line 88 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=576 dst=r2 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
#line 88 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_CALL pc=577 dst=r0 src=r0 offset=0 imm=13
#line 88 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/map.c"
        return 0;
#line 88 "sample/undocked/map.c"
    }
label_39:
    // EBPF_OP_MOV_IMM pc=578 dst=r1 src=r0 offset=0 imm=100
#line 88 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
#line 88 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=579 dst=r10 src=r1 offset=-80 imm=0
#line 209 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=580 dst=r1 src=r0 offset=0 imm=1852994932
#line 209 "sample/undocked/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=582 dst=r10 src=r1 offset=-88 imm=0
#line 209 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=583 dst=r1 src=r0 offset=0 imm=1396787295
#line 209 "sample/undocked/map.c"
    r1 = (uint64_t)7309940640182257759;
    // EBPF_OP_STXDW pc=585 dst=r10 src=r1 offset=-96 imm=0
#line 209 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=586 dst=r1 src=r0 offset=0 imm=1885433120
#line 209 "sample/undocked/map.c"
    r1 = (uint64_t)6148060143522245920;
    // EBPF_OP_STXDW pc=588 dst=r10 src=r1 offset=-104 imm=0
#line 209 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=589 dst=r1 src=r0 offset=0 imm=1279349317
#line 209 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=591 dst=r10 src=r1 offset=-112 imm=0
#line 209 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=592 dst=r1 src=r0 offset=0 imm=1953719636
#line 209 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=594 dst=r10 src=r1 offset=-120 imm=0
#line 209 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV_REG pc=595 dst=r3 src=r6 offset=0 imm=0
#line 209 "sample/undocked/map.c"
    r3 = r6;
#line 209 "sample/undocked/map.c"
    r3 &= UINT32_MAX;
    // EBPF_OP_LSH64_IMM pc=596 dst=r3 src=r0 offset=0 imm=32
#line 209 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=597 dst=r3 src=r0 offset=0 imm=32
#line 209 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=598 dst=r1 src=r10 offset=0 imm=0
#line 209 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=599 dst=r1 src=r0 offset=0 imm=-120
#line 209 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=600 dst=r2 src=r0 offset=0 imm=42
#line 209 "sample/undocked/map.c"
    r2 = IMMEDIATE(42);
#line 209 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_JA pc=601 dst=r0 src=r0 offset=-505 imm=0
#line 209 "sample/undocked/map.c"
    goto label_7;
label_40:
    // EBPF_OP_MOV64_REG pc=602 dst=r2 src=r10 offset=0 imm=0
#line 209 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=603 dst=r2 src=r0 offset=0 imm=-64
#line 209 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_REG pc=604 dst=r3 src=r10 offset=0 imm=0
#line 209 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=605 dst=r3 src=r0 offset=0 imm=-4
#line 209 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=606 dst=r1 src=r1 offset=0 imm=5
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_IMM pc=608 dst=r4 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=609 dst=r0 src=r0 offset=0 imm=2
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 92 "sample/undocked/map.c"
        return 0;
#line 92 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=610 dst=r6 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r6 = r0;
    //  pc=611 dst=r6 src=r0 offset=1 imm=-1
#line 93 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_41;
#line 93 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=612 dst=r0 src=r0 offset=-96 imm=0
#line 93 "sample/undocked/map.c"
    goto label_34;
label_41:
    // EBPF_OP_MOV64_REG pc=613 dst=r2 src=r10 offset=0 imm=0
#line 93 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=614 dst=r2 src=r0 offset=0 imm=-64
#line 93 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=615 dst=r1 src=r1 offset=0 imm=5
#line 103 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_CALL pc=617 dst=r0 src=r0 offset=0 imm=4
#line 103 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 103 "sample/undocked/map.c"
    if ((runtime_context->helper_data[5].tail_call) && (r0 == 0)) {
#line 103 "sample/undocked/map.c"
        return 0;
#line 103 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=618 dst=r0 src=r0 offset=23 imm=0
#line 104 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 104 "sample/undocked/map.c"
        goto label_42;
#line 104 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=619 dst=r1 src=r0 offset=0 imm=0
#line 104 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 104 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=620 dst=r10 src=r1 offset=-76 imm=0
#line 105 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-76)) = (uint8_t)r1;
    // EBPF_OP_MOV_IMM pc=621 dst=r1 src=r0 offset=0 imm=1280070990
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(1280070990);
#line 105 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=622 dst=r10 src=r1 offset=-80 imm=0
#line 105 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=623 dst=r1 src=r0 offset=0 imm=1920300133
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)2334102031925867621;
    // EBPF_OP_STXDW pc=625 dst=r10 src=r1 offset=-88 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=626 dst=r1 src=r0 offset=0 imm=1818582885
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8223693201956233061;
    // EBPF_OP_STXDW pc=628 dst=r10 src=r1 offset=-96 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=629 dst=r1 src=r0 offset=0 imm=1683973230
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8387229063778886766;
    // EBPF_OP_STXDW pc=631 dst=r10 src=r1 offset=-104 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=632 dst=r1 src=r0 offset=0 imm=1802465132
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)7016450394082471788;
    // EBPF_OP_STXDW pc=634 dst=r10 src=r1 offset=-112 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=635 dst=r1 src=r0 offset=0 imm=1600548962
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=637 dst=r10 src=r1 offset=-120 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=638 dst=r1 src=r10 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=639 dst=r1 src=r0 offset=0 imm=-120
#line 105 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=640 dst=r2 src=r0 offset=0 imm=45
#line 105 "sample/undocked/map.c"
    r2 = IMMEDIATE(45);
#line 105 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_JA pc=641 dst=r0 src=r0 offset=-93 imm=0
#line 105 "sample/undocked/map.c"
    goto label_36;
label_42:
    // EBPF_OP_MOV_IMM pc=642 dst=r1 src=r0 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 105 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=643 dst=r10 src=r1 offset=-64 imm=0
#line 70 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_MOV_IMM pc=644 dst=r1 src=r0 offset=0 imm=1
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
#line 70 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=645 dst=r10 src=r1 offset=-4 imm=0
#line 71 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=646 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=647 dst=r2 src=r0 offset=0 imm=-64
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_REG pc=648 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=649 dst=r3 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=650 dst=r1 src=r1 offset=0 imm=6
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_IMM pc=652 dst=r4 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=653 dst=r0 src=r0 offset=0 imm=2
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 74 "sample/undocked/map.c"
        return 0;
#line 74 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=654 dst=r6 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r6 = r0;
    //  pc=655 dst=r6 src=r0 offset=9 imm=-1
#line 75 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 75 "sample/undocked/map.c"
        goto label_44;
#line 75 "sample/undocked/map.c"
    }
label_43:
    // EBPF_OP_LDDW pc=656 dst=r1 src=r0 offset=0 imm=1684369010
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=658 dst=r10 src=r1 offset=-96 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=659 dst=r1 src=r0 offset=0 imm=544040300
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=661 dst=r10 src=r1 offset=-104 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=662 dst=r1 src=r0 offset=0 imm=1633972341
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=664 dst=r0 src=r0 offset=41 imm=0
#line 75 "sample/undocked/map.c"
    goto label_47;
label_44:
    // EBPF_OP_MOV64_REG pc=665 dst=r2 src=r10 offset=0 imm=0
#line 75 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=666 dst=r2 src=r0 offset=0 imm=-64
#line 75 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=667 dst=r1 src=r1 offset=0 imm=6
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_CALL pc=669 dst=r0 src=r0 offset=0 imm=1
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 80 "sample/undocked/map.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 80 "sample/undocked/map.c"
        return 0;
#line 80 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=670 dst=r0 src=r0 offset=20 imm=0
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_46;
#line 81 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=671 dst=r1 src=r0 offset=0 imm=76
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
#line 81 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=672 dst=r10 src=r1 offset=-88 imm=0
#line 82 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=673 dst=r1 src=r0 offset=0 imm=1684369010
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=675 dst=r10 src=r1 offset=-96 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=676 dst=r1 src=r0 offset=0 imm=544040300
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=678 dst=r10 src=r1 offset=-104 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=679 dst=r1 src=r0 offset=0 imm=1802465132
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=681 dst=r10 src=r1 offset=-112 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=682 dst=r1 src=r0 offset=0 imm=1600548962
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=684 dst=r10 src=r1 offset=-120 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=685 dst=r1 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=686 dst=r1 src=r0 offset=0 imm=-120
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=687 dst=r2 src=r0 offset=0 imm=34
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
#line 82 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
label_45:
    // EBPF_OP_CALL pc=688 dst=r0 src=r0 offset=0 imm=12
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 82 "sample/undocked/map.c"
        return 0;
#line 82 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=689 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/undocked/map.c"
    r6 = IMMEDIATE(-1);
#line 82 "sample/undocked/map.c"
    r6 &= UINT32_MAX;
    // EBPF_OP_JA pc=690 dst=r0 src=r0 offset=26 imm=0
#line 82 "sample/undocked/map.c"
    goto label_48;
label_46:
    // EBPF_OP_MOV64_REG pc=691 dst=r2 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=692 dst=r2 src=r0 offset=0 imm=-64
#line 82 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=693 dst=r1 src=r1 offset=0 imm=6
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_CALL pc=695 dst=r0 src=r0 offset=0 imm=3
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 86 "sample/undocked/map.c"
        return 0;
#line 86 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=696 dst=r6 src=r0 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r6 = r0;
    //  pc=697 dst=r6 src=r0 offset=46 imm=-1
#line 87 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_49;
#line 87 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=698 dst=r1 src=r0 offset=0 imm=1684369010
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=700 dst=r10 src=r1 offset=-96 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=701 dst=r1 src=r0 offset=0 imm=544040300
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=703 dst=r10 src=r1 offset=-104 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=704 dst=r1 src=r0 offset=0 imm=1701602660
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
label_47:
    // EBPF_OP_STXDW pc=706 dst=r10 src=r1 offset=-112 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=707 dst=r1 src=r0 offset=0 imm=1600548962
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=709 dst=r10 src=r1 offset=-120 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=710 dst=r3 src=r6 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=711 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=712 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=713 dst=r1 src=r10 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=714 dst=r1 src=r0 offset=0 imm=-120
#line 88 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=715 dst=r2 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
#line 88 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_CALL pc=716 dst=r0 src=r0 offset=0 imm=13
#line 88 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/map.c"
        return 0;
#line 88 "sample/undocked/map.c"
    }
label_48:
    // EBPF_OP_MOV_IMM pc=717 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 88 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=718 dst=r10 src=r1 offset=-72 imm=0
#line 210 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=719 dst=r1 src=r0 offset=0 imm=1701737077
#line 210 "sample/undocked/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=721 dst=r10 src=r1 offset=-80 imm=0
#line 210 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=722 dst=r1 src=r0 offset=0 imm=1213415752
#line 210 "sample/undocked/map.c"
    r1 = (uint64_t)8387235364025352520;
    // EBPF_OP_STXDW pc=724 dst=r10 src=r1 offset=-88 imm=0
#line 210 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=725 dst=r1 src=r0 offset=0 imm=1380274271
#line 210 "sample/undocked/map.c"
    r1 = (uint64_t)6869485056696864863;
    // EBPF_OP_STXDW pc=727 dst=r10 src=r1 offset=-96 imm=0
#line 210 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=728 dst=r1 src=r0 offset=0 imm=1885433120
#line 210 "sample/undocked/map.c"
    r1 = (uint64_t)6148060143522245920;
    // EBPF_OP_STXDW pc=730 dst=r10 src=r1 offset=-104 imm=0
#line 210 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=731 dst=r1 src=r0 offset=0 imm=1279349317
#line 210 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=733 dst=r10 src=r1 offset=-112 imm=0
#line 210 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=734 dst=r1 src=r0 offset=0 imm=1953719636
#line 210 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=736 dst=r10 src=r1 offset=-120 imm=0
#line 210 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV_REG pc=737 dst=r3 src=r6 offset=0 imm=0
#line 210 "sample/undocked/map.c"
    r3 = r6;
#line 210 "sample/undocked/map.c"
    r3 &= UINT32_MAX;
    // EBPF_OP_LSH64_IMM pc=738 dst=r3 src=r0 offset=0 imm=32
#line 210 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=739 dst=r3 src=r0 offset=0 imm=32
#line 210 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=740 dst=r1 src=r10 offset=0 imm=0
#line 210 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=741 dst=r1 src=r0 offset=0 imm=-120
#line 210 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=742 dst=r2 src=r0 offset=0 imm=49
#line 210 "sample/undocked/map.c"
    r2 = IMMEDIATE(49);
#line 210 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_JA pc=743 dst=r0 src=r0 offset=-647 imm=0
#line 210 "sample/undocked/map.c"
    goto label_7;
label_49:
    // EBPF_OP_MOV64_REG pc=744 dst=r2 src=r10 offset=0 imm=0
#line 210 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=745 dst=r2 src=r0 offset=0 imm=-64
#line 210 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_REG pc=746 dst=r3 src=r10 offset=0 imm=0
#line 210 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=747 dst=r3 src=r0 offset=0 imm=-4
#line 210 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=748 dst=r1 src=r1 offset=0 imm=6
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_IMM pc=750 dst=r4 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=751 dst=r0 src=r0 offset=0 imm=2
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 92 "sample/undocked/map.c"
        return 0;
#line 92 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=752 dst=r6 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r6 = r0;
    //  pc=753 dst=r6 src=r0 offset=1 imm=-1
#line 93 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_50;
#line 93 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=754 dst=r0 src=r0 offset=-99 imm=0
#line 93 "sample/undocked/map.c"
    goto label_43;
label_50:
    // EBPF_OP_MOV64_REG pc=755 dst=r2 src=r10 offset=0 imm=0
#line 93 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=756 dst=r2 src=r0 offset=0 imm=-64
#line 93 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=757 dst=r1 src=r1 offset=0 imm=6
#line 103 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_CALL pc=759 dst=r0 src=r0 offset=0 imm=4
#line 103 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 103 "sample/undocked/map.c"
    if ((runtime_context->helper_data[5].tail_call) && (r0 == 0)) {
#line 103 "sample/undocked/map.c"
        return 0;
#line 103 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=760 dst=r0 src=r0 offset=23 imm=0
#line 104 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 104 "sample/undocked/map.c"
        goto label_51;
#line 104 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=761 dst=r1 src=r0 offset=0 imm=0
#line 104 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 104 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=762 dst=r10 src=r1 offset=-76 imm=0
#line 105 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-76)) = (uint8_t)r1;
    // EBPF_OP_MOV_IMM pc=763 dst=r1 src=r0 offset=0 imm=1280070990
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(1280070990);
#line 105 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=764 dst=r10 src=r1 offset=-80 imm=0
#line 105 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=765 dst=r1 src=r0 offset=0 imm=1920300133
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)2334102031925867621;
    // EBPF_OP_STXDW pc=767 dst=r10 src=r1 offset=-88 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=768 dst=r1 src=r0 offset=0 imm=1818582885
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8223693201956233061;
    // EBPF_OP_STXDW pc=770 dst=r10 src=r1 offset=-96 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=771 dst=r1 src=r0 offset=0 imm=1683973230
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8387229063778886766;
    // EBPF_OP_STXDW pc=773 dst=r10 src=r1 offset=-104 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=774 dst=r1 src=r0 offset=0 imm=1802465132
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)7016450394082471788;
    // EBPF_OP_STXDW pc=776 dst=r10 src=r1 offset=-112 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=777 dst=r1 src=r0 offset=0 imm=1600548962
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=779 dst=r10 src=r1 offset=-120 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=780 dst=r1 src=r10 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=781 dst=r1 src=r0 offset=0 imm=-120
#line 105 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=782 dst=r2 src=r0 offset=0 imm=45
#line 105 "sample/undocked/map.c"
    r2 = IMMEDIATE(45);
#line 105 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_JA pc=783 dst=r0 src=r0 offset=-96 imm=0
#line 105 "sample/undocked/map.c"
    goto label_45;
label_51:
    // EBPF_OP_MOV_IMM pc=784 dst=r1 src=r0 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 105 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=785 dst=r10 src=r1 offset=-64 imm=0
#line 176 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=786 dst=r2 src=r10 offset=0 imm=0
#line 176 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=787 dst=r2 src=r0 offset=0 imm=-64
#line 176 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=788 dst=r1 src=r1 offset=0 imm=7
#line 176 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=790 dst=r0 src=r0 offset=0 imm=18
#line 176 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 176 "sample/undocked/map.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 176 "sample/undocked/map.c"
        return 0;
#line 176 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=791 dst=r6 src=r0 offset=0 imm=0
#line 176 "sample/undocked/map.c"
    r6 = r0;
    //  pc=792 dst=r6 src=r0 offset=30 imm=-7
#line 176 "sample/undocked/map.c"
    if ((uint32_t)r6 == IMMEDIATE(-7)) {
#line 176 "sample/undocked/map.c"
        goto label_52;
#line 176 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=793 dst=r1 src=r0 offset=0 imm=100
#line 176 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
#line 176 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=794 dst=r10 src=r1 offset=-72 imm=0
#line 176 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=795 dst=r1 src=r0 offset=0 imm=1852994932
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=797 dst=r10 src=r1 offset=-80 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=798 dst=r1 src=r0 offset=0 imm=622883948
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=800 dst=r10 src=r1 offset=-88 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=801 dst=r1 src=r0 offset=0 imm=543649385
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=803 dst=r10 src=r1 offset=-96 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=804 dst=r1 src=r0 offset=0 imm=2019893357
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=806 dst=r10 src=r1 offset=-104 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=807 dst=r1 src=r0 offset=0 imm=1801807216
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=809 dst=r10 src=r1 offset=-112 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=810 dst=r1 src=r0 offset=0 imm=1600548962
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=812 dst=r10 src=r1 offset=-120 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=813 dst=r4 src=r6 offset=0 imm=0
#line 176 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=814 dst=r4 src=r0 offset=0 imm=32
#line 176 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=815 dst=r4 src=r0 offset=0 imm=32
#line 176 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=816 dst=r1 src=r10 offset=0 imm=0
#line 176 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=817 dst=r1 src=r0 offset=0 imm=-120
#line 176 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=818 dst=r2 src=r0 offset=0 imm=50
#line 176 "sample/undocked/map.c"
    r2 = IMMEDIATE(50);
#line 176 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_MOV64_IMM pc=819 dst=r3 src=r0 offset=0 imm=-7
#line 176 "sample/undocked/map.c"
    r3 = IMMEDIATE(-7);
    // EBPF_OP_CALL pc=820 dst=r0 src=r0 offset=0 imm=14
#line 176 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 176 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 176 "sample/undocked/map.c"
        return 0;
#line 176 "sample/undocked/map.c"
    }
    //  pc=821 dst=r6 src=r0 offset=91 imm=-1
#line 215 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 215 "sample/undocked/map.c"
        goto label_55;
#line 215 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=822 dst=r0 src=r0 offset=543 imm=0
#line 215 "sample/undocked/map.c"
    goto label_74;
label_52:
    // EBPF_OP_LDXW pc=823 dst=r3 src=r10 offset=-64 imm=0
#line 176 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64));
    //  pc=824 dst=r3 src=r0 offset=25 imm=0
#line 176 "sample/undocked/map.c"
    if ((uint32_t)r3 == IMMEDIATE(0)) {
#line 176 "sample/undocked/map.c"
        goto label_53;
#line 176 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=825 dst=r1 src=r0 offset=0 imm=0
#line 176 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 176 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=826 dst=r10 src=r1 offset=-80 imm=0
#line 176 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=827 dst=r1 src=r0 offset=0 imm=1852404835
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=829 dst=r10 src=r1 offset=-88 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=830 dst=r1 src=r0 offset=0 imm=543434016
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=832 dst=r10 src=r1 offset=-96 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=833 dst=r1 src=r0 offset=0 imm=1701978221
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=835 dst=r10 src=r1 offset=-104 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=836 dst=r1 src=r0 offset=0 imm=1801807216
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=838 dst=r10 src=r1 offset=-112 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=839 dst=r1 src=r0 offset=0 imm=1600548962
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=841 dst=r10 src=r1 offset=-120 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=842 dst=r1 src=r10 offset=0 imm=0
#line 176 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=843 dst=r1 src=r0 offset=0 imm=-120
#line 176 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=844 dst=r2 src=r0 offset=0 imm=41
#line 176 "sample/undocked/map.c"
    r2 = IMMEDIATE(41);
#line 176 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_MOV64_IMM pc=845 dst=r4 src=r0 offset=0 imm=0
#line 176 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=846 dst=r0 src=r0 offset=0 imm=14
#line 176 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 176 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 176 "sample/undocked/map.c"
        return 0;
#line 176 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=847 dst=r6 src=r0 offset=0 imm=-1
#line 176 "sample/undocked/map.c"
    r6 = IMMEDIATE(-1);
#line 176 "sample/undocked/map.c"
    r6 &= UINT32_MAX;
    //  pc=848 dst=r6 src=r0 offset=64 imm=-1
#line 215 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 215 "sample/undocked/map.c"
        goto label_55;
#line 215 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=849 dst=r0 src=r0 offset=516 imm=0
#line 215 "sample/undocked/map.c"
    goto label_74;
label_53:
    // EBPF_OP_MOV_IMM pc=850 dst=r7 src=r0 offset=0 imm=0
#line 215 "sample/undocked/map.c"
    r7 = IMMEDIATE(0);
#line 215 "sample/undocked/map.c"
    r7 &= UINT32_MAX;
    // EBPF_OP_STXW pc=851 dst=r10 src=r7 offset=-64 imm=0
#line 177 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=852 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=853 dst=r2 src=r0 offset=0 imm=-64
#line 177 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=854 dst=r1 src=r1 offset=0 imm=7
#line 177 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=856 dst=r0 src=r0 offset=0 imm=17
#line 177 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 177 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 177 "sample/undocked/map.c"
        return 0;
#line 177 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=857 dst=r6 src=r0 offset=0 imm=0
#line 177 "sample/undocked/map.c"
    r6 = r0;
    //  pc=858 dst=r6 src=r0 offset=29 imm=-7
#line 177 "sample/undocked/map.c"
    if ((uint32_t)r6 == IMMEDIATE(-7)) {
#line 177 "sample/undocked/map.c"
        goto label_54;
#line 177 "sample/undocked/map.c"
    }
    // EBPF_OP_STXB pc=859 dst=r10 src=r7 offset=-72 imm=0
#line 177 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint8_t)r7;
    // EBPF_OP_LDDW pc=860 dst=r1 src=r0 offset=0 imm=1701737077
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=862 dst=r10 src=r1 offset=-80 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=863 dst=r1 src=r0 offset=0 imm=1680154740
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=865 dst=r10 src=r1 offset=-88 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=866 dst=r1 src=r0 offset=0 imm=1914726254
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=868 dst=r10 src=r1 offset=-96 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=869 dst=r1 src=r0 offset=0 imm=1886938400
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=871 dst=r10 src=r1 offset=-104 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=872 dst=r1 src=r0 offset=0 imm=1601204080
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=874 dst=r10 src=r1 offset=-112 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=875 dst=r1 src=r0 offset=0 imm=1600548962
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=877 dst=r10 src=r1 offset=-120 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=878 dst=r4 src=r6 offset=0 imm=0
#line 177 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=879 dst=r4 src=r0 offset=0 imm=32
#line 177 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=880 dst=r4 src=r0 offset=0 imm=32
#line 177 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=881 dst=r1 src=r10 offset=0 imm=0
#line 177 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=882 dst=r1 src=r0 offset=0 imm=-120
#line 177 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=883 dst=r2 src=r0 offset=0 imm=49
#line 177 "sample/undocked/map.c"
    r2 = IMMEDIATE(49);
#line 177 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_MOV64_IMM pc=884 dst=r3 src=r0 offset=0 imm=-7
#line 177 "sample/undocked/map.c"
    r3 = IMMEDIATE(-7);
    // EBPF_OP_CALL pc=885 dst=r0 src=r0 offset=0 imm=14
#line 177 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 177 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 177 "sample/undocked/map.c"
        return 0;
#line 177 "sample/undocked/map.c"
    }
    //  pc=886 dst=r6 src=r0 offset=26 imm=-1
#line 215 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 215 "sample/undocked/map.c"
        goto label_55;
#line 215 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=887 dst=r0 src=r0 offset=478 imm=0
#line 215 "sample/undocked/map.c"
    goto label_74;
label_54:
    // EBPF_OP_LDXW pc=888 dst=r3 src=r10 offset=-64 imm=0
#line 177 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64));
    //  pc=889 dst=r3 src=r0 offset=61 imm=0
#line 177 "sample/undocked/map.c"
    if ((uint32_t)r3 == IMMEDIATE(0)) {
#line 177 "sample/undocked/map.c"
        goto label_58;
#line 177 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=890 dst=r1 src=r0 offset=0 imm=1735289204
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=892 dst=r10 src=r1 offset=-88 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=893 dst=r1 src=r0 offset=0 imm=1696621605
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=895 dst=r10 src=r1 offset=-96 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=896 dst=r1 src=r0 offset=0 imm=1952805408
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=898 dst=r10 src=r1 offset=-104 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=899 dst=r1 src=r0 offset=0 imm=1601204080
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=901 dst=r10 src=r1 offset=-112 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=902 dst=r1 src=r0 offset=0 imm=1600548962
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=904 dst=r10 src=r1 offset=-120 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=905 dst=r1 src=r10 offset=0 imm=0
#line 177 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=906 dst=r1 src=r0 offset=0 imm=-120
#line 177 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=907 dst=r2 src=r0 offset=0 imm=40
#line 177 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
#line 177 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_MOV64_IMM pc=908 dst=r4 src=r0 offset=0 imm=0
#line 177 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=909 dst=r0 src=r0 offset=0 imm=14
#line 177 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 177 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 177 "sample/undocked/map.c"
        return 0;
#line 177 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=910 dst=r6 src=r0 offset=0 imm=-1
#line 177 "sample/undocked/map.c"
    r6 = IMMEDIATE(-1);
#line 177 "sample/undocked/map.c"
    r6 &= UINT32_MAX;
    //  pc=911 dst=r6 src=r0 offset=1 imm=-1
#line 215 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 215 "sample/undocked/map.c"
        goto label_55;
#line 215 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=912 dst=r0 src=r0 offset=453 imm=0
#line 215 "sample/undocked/map.c"
    goto label_74;
label_55:
    // EBPF_OP_MOV_IMM pc=913 dst=r1 src=r0 offset=0 imm=0
#line 215 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 215 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=914 dst=r10 src=r1 offset=-64 imm=0
#line 176 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=915 dst=r2 src=r10 offset=0 imm=0
#line 176 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=916 dst=r2 src=r0 offset=0 imm=-64
#line 176 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=917 dst=r1 src=r1 offset=0 imm=8
#line 176 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=919 dst=r0 src=r0 offset=0 imm=18
#line 176 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 176 "sample/undocked/map.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 176 "sample/undocked/map.c"
        return 0;
#line 176 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=920 dst=r7 src=r0 offset=0 imm=0
#line 176 "sample/undocked/map.c"
    r7 = r0;
    //  pc=921 dst=r7 src=r0 offset=466 imm=-7
#line 176 "sample/undocked/map.c"
    if ((uint32_t)r7 == IMMEDIATE(-7)) {
#line 176 "sample/undocked/map.c"
        goto label_75;
#line 176 "sample/undocked/map.c"
    }
label_56:
    // EBPF_OP_MOV_IMM pc=922 dst=r1 src=r0 offset=0 imm=100
#line 176 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
#line 176 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=923 dst=r10 src=r1 offset=-72 imm=0
#line 176 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=924 dst=r1 src=r0 offset=0 imm=1852994932
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=926 dst=r10 src=r1 offset=-80 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=927 dst=r1 src=r0 offset=0 imm=622883948
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=929 dst=r10 src=r1 offset=-88 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=930 dst=r1 src=r0 offset=0 imm=543649385
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=932 dst=r10 src=r1 offset=-96 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=933 dst=r1 src=r0 offset=0 imm=2019893357
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=935 dst=r10 src=r1 offset=-104 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=936 dst=r1 src=r0 offset=0 imm=1801807216
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=938 dst=r10 src=r1 offset=-112 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=939 dst=r1 src=r0 offset=0 imm=1600548962
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=941 dst=r10 src=r1 offset=-120 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=942 dst=r4 src=r7 offset=0 imm=0
#line 176 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=943 dst=r4 src=r0 offset=0 imm=32
#line 176 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=944 dst=r4 src=r0 offset=0 imm=32
#line 176 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=945 dst=r1 src=r10 offset=0 imm=0
#line 176 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=946 dst=r1 src=r0 offset=0 imm=-120
#line 176 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=947 dst=r2 src=r0 offset=0 imm=50
#line 176 "sample/undocked/map.c"
    r2 = IMMEDIATE(50);
#line 176 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
label_57:
    // EBPF_OP_MOV64_IMM pc=948 dst=r3 src=r0 offset=0 imm=-7
#line 176 "sample/undocked/map.c"
    r3 = IMMEDIATE(-7);
    // EBPF_OP_CALL pc=949 dst=r0 src=r0 offset=0 imm=14
#line 176 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 176 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 176 "sample/undocked/map.c"
        return 0;
#line 176 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=950 dst=r0 src=r0 offset=462 imm=0
#line 176 "sample/undocked/map.c"
    goto label_79;
label_58:
    // EBPF_OP_MOV64_IMM pc=951 dst=r1 src=r0 offset=0 imm=0
#line 176 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=952 dst=r10 src=r1 offset=-64 imm=0
#line 181 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_LDXDW pc=953 dst=r1 src=r10 offset=-64 imm=0
#line 181 "sample/undocked/map.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_JSGT_IMM pc=954 dst=r1 src=r0 offset=15 imm=9
#line 181 "sample/undocked/map.c"
    if ((int64_t)r1 > IMMEDIATE(9)) {
#line 181 "sample/undocked/map.c"
        goto label_60;
#line 181 "sample/undocked/map.c"
    }
label_59:
    // EBPF_OP_LDXDW pc=955 dst=r1 src=r10 offset=-64 imm=0
#line 182 "sample/undocked/map.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_STXW pc=956 dst=r10 src=r1 offset=-4 imm=0
#line 182 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=957 dst=r2 src=r10 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=958 dst=r2 src=r0 offset=0 imm=-4
#line 182 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=959 dst=r1 src=r1 offset=0 imm=7
#line 182 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_MOV64_IMM pc=961 dst=r3 src=r0 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=962 dst=r0 src=r0 offset=0 imm=16
#line 182 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 182 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 182 "sample/undocked/map.c"
        return 0;
#line 182 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=963 dst=r6 src=r0 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r6 = r0;
    //  pc=964 dst=r6 src=r0 offset=94 imm=0
#line 182 "sample/undocked/map.c"
    if ((uint32_t)r6 != IMMEDIATE(0)) {
#line 182 "sample/undocked/map.c"
        goto label_62;
#line 182 "sample/undocked/map.c"
    }
    // EBPF_OP_LDXDW pc=965 dst=r1 src=r10 offset=-64 imm=0
#line 181 "sample/undocked/map.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_ADD64_IMM pc=966 dst=r1 src=r0 offset=0 imm=1
#line 181 "sample/undocked/map.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=967 dst=r10 src=r1 offset=-64 imm=0
#line 181 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_LDXDW pc=968 dst=r1 src=r10 offset=-64 imm=0
#line 181 "sample/undocked/map.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_JSLT_IMM pc=969 dst=r1 src=r0 offset=-15 imm=10
#line 181 "sample/undocked/map.c"
    if ((int64_t)r1 < IMMEDIATE(10)) {
#line 181 "sample/undocked/map.c"
        goto label_59;
#line 181 "sample/undocked/map.c"
    }
label_60:
    // EBPF_OP_MOV_IMM pc=970 dst=r7 src=r0 offset=0 imm=10
#line 181 "sample/undocked/map.c"
    r7 = IMMEDIATE(10);
#line 181 "sample/undocked/map.c"
    r7 &= UINT32_MAX;
    // EBPF_OP_STXW pc=971 dst=r10 src=r7 offset=-64 imm=0
#line 185 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=972 dst=r2 src=r10 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=973 dst=r2 src=r0 offset=0 imm=-64
#line 185 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=974 dst=r1 src=r1 offset=0 imm=7
#line 185 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_MOV64_IMM pc=976 dst=r3 src=r0 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=977 dst=r0 src=r0 offset=0 imm=16
#line 185 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 185 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 185 "sample/undocked/map.c"
        return 0;
#line 185 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=978 dst=r6 src=r0 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r6 = r0;
    //  pc=979 dst=r6 src=r0 offset=35 imm=-29
#line 185 "sample/undocked/map.c"
    if ((uint32_t)r6 == IMMEDIATE(-29)) {
#line 185 "sample/undocked/map.c"
        goto label_61;
#line 185 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=980 dst=r1 src=r0 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 185 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=981 dst=r10 src=r1 offset=-66 imm=0
#line 185 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-66)) = (uint8_t)r1;
    // EBPF_OP_MOV_IMM pc=982 dst=r1 src=r0 offset=0 imm=25637
#line 185 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
#line 185 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=983 dst=r10 src=r1 offset=-68 imm=0
#line 185 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint16_t)r1;
    // EBPF_OP_MOV_IMM pc=984 dst=r1 src=r0 offset=0 imm=543450478
#line 185 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
#line 185 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=985 dst=r10 src=r1 offset=-72 imm=0
#line 185 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=986 dst=r1 src=r0 offset=0 imm=1914725413
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=988 dst=r10 src=r1 offset=-80 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=989 dst=r1 src=r0 offset=0 imm=1667592312
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=991 dst=r10 src=r1 offset=-88 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=992 dst=r1 src=r0 offset=0 imm=543649385
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=994 dst=r10 src=r1 offset=-96 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=995 dst=r1 src=r0 offset=0 imm=1852383341
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=997 dst=r10 src=r1 offset=-104 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=998 dst=r1 src=r0 offset=0 imm=1752397168
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1000 dst=r10 src=r1 offset=-112 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1001 dst=r1 src=r0 offset=0 imm=1600548962
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1003 dst=r10 src=r1 offset=-120 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=1004 dst=r3 src=r10 offset=-64 imm=0
#line 185 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_MOV64_REG pc=1005 dst=r5 src=r6 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1006 dst=r5 src=r0 offset=0 imm=32
#line 185 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1007 dst=r5 src=r0 offset=0 imm=32
#line 185 "sample/undocked/map.c"
    r5 = (int64_t)r5 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1008 dst=r1 src=r10 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1009 dst=r1 src=r0 offset=0 imm=-120
#line 185 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1010 dst=r2 src=r0 offset=0 imm=55
#line 185 "sample/undocked/map.c"
    r2 = IMMEDIATE(55);
#line 185 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_MOV64_IMM pc=1011 dst=r4 src=r0 offset=0 imm=-29
#line 185 "sample/undocked/map.c"
    r4 = IMMEDIATE(-29);
    // EBPF_OP_CALL pc=1012 dst=r0 src=r0 offset=0 imm=15
#line 185 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[10].address(r1, r2, r3, r4, r5, context);
#line 185 "sample/undocked/map.c"
    if ((runtime_context->helper_data[10].tail_call) && (r0 == 0)) {
#line 185 "sample/undocked/map.c"
        return 0;
#line 185 "sample/undocked/map.c"
    }
    //  pc=1013 dst=r6 src=r0 offset=-101 imm=-1
#line 215 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 215 "sample/undocked/map.c"
        goto label_55;
#line 215 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1014 dst=r0 src=r0 offset=351 imm=0
#line 215 "sample/undocked/map.c"
    goto label_74;
label_61:
    // EBPF_OP_STXW pc=1015 dst=r10 src=r7 offset=-64 imm=0
#line 186 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1016 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1017 dst=r2 src=r0 offset=0 imm=-64
#line 186 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=1018 dst=r1 src=r1 offset=0 imm=7
#line 186 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_MOV64_IMM pc=1020 dst=r3 src=r0 offset=0 imm=2
#line 186 "sample/undocked/map.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_CALL pc=1021 dst=r0 src=r0 offset=0 imm=16
#line 186 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 186 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 186 "sample/undocked/map.c"
        return 0;
#line 186 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1022 dst=r6 src=r0 offset=0 imm=0
#line 186 "sample/undocked/map.c"
    r6 = r0;
    //  pc=1023 dst=r6 src=r0 offset=70 imm=0
#line 186 "sample/undocked/map.c"
    if ((uint32_t)r6 == IMMEDIATE(0)) {
#line 186 "sample/undocked/map.c"
        goto label_63;
#line 186 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=1024 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 186 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=1025 dst=r10 src=r1 offset=-66 imm=0
#line 186 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-66)) = (uint8_t)r1;
    // EBPF_OP_MOV_IMM pc=1026 dst=r1 src=r0 offset=0 imm=25637
#line 186 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
#line 186 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=1027 dst=r10 src=r1 offset=-68 imm=0
#line 186 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint16_t)r1;
    // EBPF_OP_MOV_IMM pc=1028 dst=r1 src=r0 offset=0 imm=543450478
#line 186 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
#line 186 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=1029 dst=r10 src=r1 offset=-72 imm=0
#line 186 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1030 dst=r1 src=r0 offset=0 imm=1914725413
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1032 dst=r10 src=r1 offset=-80 imm=0
#line 186 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1033 dst=r1 src=r0 offset=0 imm=1667592312
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1035 dst=r10 src=r1 offset=-88 imm=0
#line 186 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1036 dst=r1 src=r0 offset=0 imm=543649385
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1038 dst=r10 src=r1 offset=-96 imm=0
#line 186 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1039 dst=r1 src=r0 offset=0 imm=1852383341
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1041 dst=r10 src=r1 offset=-104 imm=0
#line 186 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1042 dst=r1 src=r0 offset=0 imm=1752397168
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1044 dst=r10 src=r1 offset=-112 imm=0
#line 186 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1045 dst=r1 src=r0 offset=0 imm=1600548962
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1047 dst=r10 src=r1 offset=-120 imm=0
#line 186 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=1048 dst=r3 src=r10 offset=-64 imm=0
#line 186 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_MOV64_REG pc=1049 dst=r5 src=r6 offset=0 imm=0
#line 186 "sample/undocked/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1050 dst=r5 src=r0 offset=0 imm=32
#line 186 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1051 dst=r5 src=r0 offset=0 imm=32
#line 186 "sample/undocked/map.c"
    r5 = (int64_t)r5 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1052 dst=r1 src=r10 offset=0 imm=0
#line 186 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1053 dst=r1 src=r0 offset=0 imm=-120
#line 186 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1054 dst=r2 src=r0 offset=0 imm=55
#line 186 "sample/undocked/map.c"
    r2 = IMMEDIATE(55);
#line 186 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_MOV64_IMM pc=1055 dst=r4 src=r0 offset=0 imm=0
#line 186 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1056 dst=r0 src=r0 offset=0 imm=15
#line 186 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[10].address(r1, r2, r3, r4, r5, context);
#line 186 "sample/undocked/map.c"
    if ((runtime_context->helper_data[10].tail_call) && (r0 == 0)) {
#line 186 "sample/undocked/map.c"
        return 0;
#line 186 "sample/undocked/map.c"
    }
    //  pc=1057 dst=r6 src=r0 offset=-145 imm=-1
#line 215 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 215 "sample/undocked/map.c"
        goto label_55;
#line 215 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1058 dst=r0 src=r0 offset=307 imm=0
#line 215 "sample/undocked/map.c"
    goto label_74;
label_62:
    // EBPF_OP_MOV_IMM pc=1059 dst=r1 src=r0 offset=0 imm=0
#line 215 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 215 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=1060 dst=r10 src=r1 offset=-66 imm=0
#line 182 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-66)) = (uint8_t)r1;
    // EBPF_OP_MOV_IMM pc=1061 dst=r1 src=r0 offset=0 imm=25637
#line 182 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
#line 182 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=1062 dst=r10 src=r1 offset=-68 imm=0
#line 182 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint16_t)r1;
    // EBPF_OP_MOV_IMM pc=1063 dst=r1 src=r0 offset=0 imm=543450478
#line 182 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
#line 182 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=1064 dst=r10 src=r1 offset=-72 imm=0
#line 182 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1065 dst=r1 src=r0 offset=0 imm=1914725413
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1067 dst=r10 src=r1 offset=-80 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1068 dst=r1 src=r0 offset=0 imm=1667592312
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1070 dst=r10 src=r1 offset=-88 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1071 dst=r1 src=r0 offset=0 imm=543649385
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1073 dst=r10 src=r1 offset=-96 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1074 dst=r1 src=r0 offset=0 imm=1852383341
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1076 dst=r10 src=r1 offset=-104 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1077 dst=r1 src=r0 offset=0 imm=1752397168
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1079 dst=r10 src=r1 offset=-112 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1080 dst=r1 src=r0 offset=0 imm=1600548962
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1082 dst=r10 src=r1 offset=-120 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=1083 dst=r3 src=r10 offset=-4 imm=0
#line 182 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=1084 dst=r5 src=r6 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1085 dst=r5 src=r0 offset=0 imm=32
#line 182 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1086 dst=r5 src=r0 offset=0 imm=32
#line 182 "sample/undocked/map.c"
    r5 = (int64_t)r5 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1087 dst=r1 src=r10 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1088 dst=r1 src=r0 offset=0 imm=-120
#line 182 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1089 dst=r2 src=r0 offset=0 imm=55
#line 182 "sample/undocked/map.c"
    r2 = IMMEDIATE(55);
#line 182 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_MOV64_IMM pc=1090 dst=r4 src=r0 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1091 dst=r0 src=r0 offset=0 imm=15
#line 182 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[10].address(r1, r2, r3, r4, r5, context);
#line 182 "sample/undocked/map.c"
    if ((runtime_context->helper_data[10].tail_call) && (r0 == 0)) {
#line 182 "sample/undocked/map.c"
        return 0;
#line 182 "sample/undocked/map.c"
    }
    //  pc=1092 dst=r6 src=r0 offset=-180 imm=-1
#line 215 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 215 "sample/undocked/map.c"
        goto label_55;
#line 215 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1093 dst=r0 src=r0 offset=272 imm=0
#line 215 "sample/undocked/map.c"
    goto label_74;
label_63:
    // EBPF_OP_MOV_IMM pc=1094 dst=r1 src=r0 offset=0 imm=0
#line 215 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 215 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=1095 dst=r10 src=r1 offset=-64 imm=0
#line 188 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1096 dst=r2 src=r10 offset=0 imm=0
#line 188 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1097 dst=r2 src=r0 offset=0 imm=-64
#line 188 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=1098 dst=r1 src=r1 offset=0 imm=7
#line 188 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=1100 dst=r0 src=r0 offset=0 imm=18
#line 188 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 188 "sample/undocked/map.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 188 "sample/undocked/map.c"
        return 0;
#line 188 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1101 dst=r6 src=r0 offset=0 imm=0
#line 188 "sample/undocked/map.c"
    r6 = r0;
    //  pc=1102 dst=r6 src=r0 offset=30 imm=0
#line 188 "sample/undocked/map.c"
    if ((uint32_t)r6 == IMMEDIATE(0)) {
#line 188 "sample/undocked/map.c"
        goto label_64;
#line 188 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=1103 dst=r1 src=r0 offset=0 imm=100
#line 188 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
#line 188 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=1104 dst=r10 src=r1 offset=-72 imm=0
#line 188 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=1105 dst=r1 src=r0 offset=0 imm=1852994932
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=1107 dst=r10 src=r1 offset=-80 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1108 dst=r1 src=r0 offset=0 imm=622883948
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=1110 dst=r10 src=r1 offset=-88 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1111 dst=r1 src=r0 offset=0 imm=543649385
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=1113 dst=r10 src=r1 offset=-96 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1114 dst=r1 src=r0 offset=0 imm=2019893357
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=1116 dst=r10 src=r1 offset=-104 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1117 dst=r1 src=r0 offset=0 imm=1801807216
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1119 dst=r10 src=r1 offset=-112 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1120 dst=r1 src=r0 offset=0 imm=1600548962
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1122 dst=r10 src=r1 offset=-120 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1123 dst=r4 src=r6 offset=0 imm=0
#line 188 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1124 dst=r4 src=r0 offset=0 imm=32
#line 188 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1125 dst=r4 src=r0 offset=0 imm=32
#line 188 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1126 dst=r1 src=r10 offset=0 imm=0
#line 188 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1127 dst=r1 src=r0 offset=0 imm=-120
#line 188 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1128 dst=r2 src=r0 offset=0 imm=50
#line 188 "sample/undocked/map.c"
    r2 = IMMEDIATE(50);
#line 188 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_MOV64_IMM pc=1129 dst=r3 src=r0 offset=0 imm=0
#line 188 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1130 dst=r0 src=r0 offset=0 imm=14
#line 188 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 188 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 188 "sample/undocked/map.c"
        return 0;
#line 188 "sample/undocked/map.c"
    }
    //  pc=1131 dst=r6 src=r0 offset=-219 imm=-1
#line 215 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 215 "sample/undocked/map.c"
        goto label_55;
#line 215 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1132 dst=r0 src=r0 offset=233 imm=0
#line 215 "sample/undocked/map.c"
    goto label_74;
label_64:
    // EBPF_OP_LDXW pc=1133 dst=r3 src=r10 offset=-64 imm=0
#line 188 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64));
    //  pc=1134 dst=r3 src=r0 offset=25 imm=1
#line 188 "sample/undocked/map.c"
    if ((uint32_t)r3 == IMMEDIATE(1)) {
#line 188 "sample/undocked/map.c"
        goto label_65;
#line 188 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=1135 dst=r1 src=r0 offset=0 imm=0
#line 188 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 188 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=1136 dst=r10 src=r1 offset=-80 imm=0
#line 188 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=1137 dst=r1 src=r0 offset=0 imm=1852404835
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=1139 dst=r10 src=r1 offset=-88 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1140 dst=r1 src=r0 offset=0 imm=543434016
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=1142 dst=r10 src=r1 offset=-96 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1143 dst=r1 src=r0 offset=0 imm=1701978221
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=1145 dst=r10 src=r1 offset=-104 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1146 dst=r1 src=r0 offset=0 imm=1801807216
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1148 dst=r10 src=r1 offset=-112 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1149 dst=r1 src=r0 offset=0 imm=1600548962
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1151 dst=r10 src=r1 offset=-120 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1152 dst=r1 src=r10 offset=0 imm=0
#line 188 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1153 dst=r1 src=r0 offset=0 imm=-120
#line 188 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1154 dst=r2 src=r0 offset=0 imm=41
#line 188 "sample/undocked/map.c"
    r2 = IMMEDIATE(41);
#line 188 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_MOV64_IMM pc=1155 dst=r4 src=r0 offset=0 imm=1
#line 188 "sample/undocked/map.c"
    r4 = IMMEDIATE(1);
    // EBPF_OP_CALL pc=1156 dst=r0 src=r0 offset=0 imm=14
#line 188 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 188 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 188 "sample/undocked/map.c"
        return 0;
#line 188 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=1157 dst=r6 src=r0 offset=0 imm=-1
#line 188 "sample/undocked/map.c"
    r6 = IMMEDIATE(-1);
#line 188 "sample/undocked/map.c"
    r6 &= UINT32_MAX;
    //  pc=1158 dst=r6 src=r0 offset=-246 imm=-1
#line 215 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 215 "sample/undocked/map.c"
        goto label_55;
#line 215 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1159 dst=r0 src=r0 offset=206 imm=0
#line 215 "sample/undocked/map.c"
    goto label_74;
label_65:
    // EBPF_OP_MOV64_IMM pc=1160 dst=r1 src=r0 offset=0 imm=0
#line 215 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=1161 dst=r10 src=r1 offset=-64 imm=0
#line 192 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_LDXDW pc=1162 dst=r1 src=r10 offset=-64 imm=0
#line 192 "sample/undocked/map.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_JSGT_IMM pc=1163 dst=r1 src=r0 offset=7 imm=9
#line 192 "sample/undocked/map.c"
    if ((int64_t)r1 > IMMEDIATE(9)) {
#line 192 "sample/undocked/map.c"
        goto label_67;
#line 192 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=1164 dst=r7 src=r0 offset=0 imm=0
#line 192 "sample/undocked/map.c"
    r7 = IMMEDIATE(0);
#line 192 "sample/undocked/map.c"
    r7 &= UINT32_MAX;
    // EBPF_OP_JA pc=1165 dst=r0 src=r0 offset=44 imm=0
#line 192 "sample/undocked/map.c"
    goto label_68;
label_66:
    // EBPF_OP_LDXDW pc=1166 dst=r1 src=r10 offset=-64 imm=0
#line 192 "sample/undocked/map.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_ADD64_IMM pc=1167 dst=r1 src=r0 offset=0 imm=1
#line 192 "sample/undocked/map.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=1168 dst=r10 src=r1 offset=-64 imm=0
#line 192 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_LDXDW pc=1169 dst=r1 src=r10 offset=-64 imm=0
#line 192 "sample/undocked/map.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_JSLT_IMM pc=1170 dst=r1 src=r0 offset=39 imm=10
#line 192 "sample/undocked/map.c"
    if ((int64_t)r1 < IMMEDIATE(10)) {
#line 192 "sample/undocked/map.c"
        goto label_68;
#line 192 "sample/undocked/map.c"
    }
label_67:
    // EBPF_OP_MOV_IMM pc=1171 dst=r1 src=r0 offset=0 imm=0
#line 192 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 192 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=1172 dst=r10 src=r1 offset=-64 imm=0
#line 196 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1173 dst=r2 src=r10 offset=0 imm=0
#line 196 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1174 dst=r2 src=r0 offset=0 imm=-64
#line 196 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=1175 dst=r1 src=r1 offset=0 imm=7
#line 196 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=1177 dst=r0 src=r0 offset=0 imm=18
#line 196 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 196 "sample/undocked/map.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 196 "sample/undocked/map.c"
        return 0;
#line 196 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1178 dst=r6 src=r0 offset=0 imm=0
#line 196 "sample/undocked/map.c"
    r6 = r0;
    //  pc=1179 dst=r6 src=r0 offset=67 imm=-7
#line 196 "sample/undocked/map.c"
    if ((uint32_t)r6 == IMMEDIATE(-7)) {
#line 196 "sample/undocked/map.c"
        goto label_70;
#line 196 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=1180 dst=r1 src=r0 offset=0 imm=100
#line 196 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
#line 196 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=1181 dst=r10 src=r1 offset=-72 imm=0
#line 196 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=1182 dst=r1 src=r0 offset=0 imm=1852994932
#line 196 "sample/undocked/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=1184 dst=r10 src=r1 offset=-80 imm=0
#line 196 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1185 dst=r1 src=r0 offset=0 imm=622883948
#line 196 "sample/undocked/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=1187 dst=r10 src=r1 offset=-88 imm=0
#line 196 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1188 dst=r1 src=r0 offset=0 imm=543649385
#line 196 "sample/undocked/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=1190 dst=r10 src=r1 offset=-96 imm=0
#line 196 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1191 dst=r1 src=r0 offset=0 imm=2019893357
#line 196 "sample/undocked/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=1193 dst=r10 src=r1 offset=-104 imm=0
#line 196 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1194 dst=r1 src=r0 offset=0 imm=1801807216
#line 196 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1196 dst=r10 src=r1 offset=-112 imm=0
#line 196 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1197 dst=r1 src=r0 offset=0 imm=1600548962
#line 196 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1199 dst=r10 src=r1 offset=-120 imm=0
#line 196 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1200 dst=r4 src=r6 offset=0 imm=0
#line 196 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1201 dst=r4 src=r0 offset=0 imm=32
#line 196 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1202 dst=r4 src=r0 offset=0 imm=32
#line 196 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1203 dst=r1 src=r10 offset=0 imm=0
#line 196 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1204 dst=r1 src=r0 offset=0 imm=-120
#line 196 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1205 dst=r2 src=r0 offset=0 imm=50
#line 196 "sample/undocked/map.c"
    r2 = IMMEDIATE(50);
#line 196 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_MOV64_IMM pc=1206 dst=r3 src=r0 offset=0 imm=-7
#line 196 "sample/undocked/map.c"
    r3 = IMMEDIATE(-7);
    // EBPF_OP_CALL pc=1207 dst=r0 src=r0 offset=0 imm=14
#line 196 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 196 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 196 "sample/undocked/map.c"
        return 0;
#line 196 "sample/undocked/map.c"
    }
    //  pc=1208 dst=r6 src=r0 offset=-296 imm=-1
#line 215 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 215 "sample/undocked/map.c"
        goto label_55;
#line 215 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1209 dst=r0 src=r0 offset=156 imm=0
#line 215 "sample/undocked/map.c"
    goto label_74;
label_68:
    // EBPF_OP_STXW pc=1210 dst=r10 src=r7 offset=-4 imm=0
#line 193 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1211 dst=r2 src=r10 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1212 dst=r2 src=r0 offset=0 imm=-4
#line 193 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1213 dst=r1 src=r1 offset=0 imm=7
#line 193 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=1215 dst=r0 src=r0 offset=0 imm=17
#line 193 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 193 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 193 "sample/undocked/map.c"
        return 0;
#line 193 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1216 dst=r6 src=r0 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r6 = r0;
    //  pc=1217 dst=r6 src=r0 offset=1 imm=0
#line 193 "sample/undocked/map.c"
    if ((uint32_t)r6 == IMMEDIATE(0)) {
#line 193 "sample/undocked/map.c"
        goto label_69;
#line 193 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1218 dst=r0 src=r0 offset=55 imm=0
#line 193 "sample/undocked/map.c"
    goto label_71;
label_69:
    // EBPF_OP_LDXW pc=1219 dst=r3 src=r10 offset=-4 imm=0
#line 193 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDXDW pc=1220 dst=r1 src=r10 offset=-64 imm=0
#line 193 "sample/undocked/map.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_ADD64_IMM pc=1221 dst=r1 src=r0 offset=0 imm=1
#line 193 "sample/undocked/map.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_JEQ_REG pc=1222 dst=r1 src=r3 offset=-57 imm=0
#line 193 "sample/undocked/map.c"
    if (r1 == r3) {
#line 193 "sample/undocked/map.c"
        goto label_66;
#line 193 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=1223 dst=r1 src=r0 offset=0 imm=1735289204
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1225 dst=r10 src=r1 offset=-88 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1226 dst=r1 src=r0 offset=0 imm=1696621605
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1228 dst=r10 src=r1 offset=-96 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1229 dst=r1 src=r0 offset=0 imm=1952805408
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1231 dst=r10 src=r1 offset=-104 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1232 dst=r1 src=r0 offset=0 imm=1601204080
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1234 dst=r10 src=r1 offset=-112 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1235 dst=r1 src=r0 offset=0 imm=1600548962
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1237 dst=r10 src=r1 offset=-120 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_LDXDW pc=1238 dst=r4 src=r10 offset=-64 imm=0
#line 193 "sample/undocked/map.c"
    r4 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_ADD64_IMM pc=1239 dst=r4 src=r0 offset=0 imm=1
#line 193 "sample/undocked/map.c"
    r4 += IMMEDIATE(1);
    // EBPF_OP_MOV64_REG pc=1240 dst=r1 src=r10 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1241 dst=r1 src=r0 offset=0 imm=-120
#line 193 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1242 dst=r2 src=r0 offset=0 imm=40
#line 193 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
#line 193 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_CALL pc=1243 dst=r0 src=r0 offset=0 imm=14
#line 193 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 193 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 193 "sample/undocked/map.c"
        return 0;
#line 193 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=1244 dst=r6 src=r0 offset=0 imm=-1
#line 193 "sample/undocked/map.c"
    r6 = IMMEDIATE(-1);
#line 193 "sample/undocked/map.c"
    r6 &= UINT32_MAX;
    //  pc=1245 dst=r6 src=r0 offset=-333 imm=-1
#line 215 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 215 "sample/undocked/map.c"
        goto label_55;
#line 215 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1246 dst=r0 src=r0 offset=119 imm=0
#line 215 "sample/undocked/map.c"
    goto label_74;
label_70:
    // EBPF_OP_LDXW pc=1247 dst=r3 src=r10 offset=-64 imm=0
#line 196 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64));
    //  pc=1248 dst=r3 src=r0 offset=55 imm=0
#line 196 "sample/undocked/map.c"
    if ((uint32_t)r3 == IMMEDIATE(0)) {
#line 196 "sample/undocked/map.c"
        goto label_72;
#line 196 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=1249 dst=r1 src=r0 offset=0 imm=0
#line 196 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 196 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=1250 dst=r10 src=r1 offset=-80 imm=0
#line 196 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=1251 dst=r1 src=r0 offset=0 imm=1852404835
#line 196 "sample/undocked/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=1253 dst=r10 src=r1 offset=-88 imm=0
#line 196 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1254 dst=r1 src=r0 offset=0 imm=543434016
#line 196 "sample/undocked/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=1256 dst=r10 src=r1 offset=-96 imm=0
#line 196 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1257 dst=r1 src=r0 offset=0 imm=1701978221
#line 196 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=1259 dst=r10 src=r1 offset=-104 imm=0
#line 196 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1260 dst=r1 src=r0 offset=0 imm=1801807216
#line 196 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1262 dst=r10 src=r1 offset=-112 imm=0
#line 196 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1263 dst=r1 src=r0 offset=0 imm=1600548962
#line 196 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1265 dst=r10 src=r1 offset=-120 imm=0
#line 196 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1266 dst=r1 src=r10 offset=0 imm=0
#line 196 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1267 dst=r1 src=r0 offset=0 imm=-120
#line 196 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1268 dst=r2 src=r0 offset=0 imm=41
#line 196 "sample/undocked/map.c"
    r2 = IMMEDIATE(41);
#line 196 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_MOV64_IMM pc=1269 dst=r4 src=r0 offset=0 imm=0
#line 196 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1270 dst=r0 src=r0 offset=0 imm=14
#line 196 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 196 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 196 "sample/undocked/map.c"
        return 0;
#line 196 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=1271 dst=r6 src=r0 offset=0 imm=-1
#line 196 "sample/undocked/map.c"
    r6 = IMMEDIATE(-1);
#line 196 "sample/undocked/map.c"
    r6 &= UINT32_MAX;
    //  pc=1272 dst=r6 src=r0 offset=-360 imm=-1
#line 215 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 215 "sample/undocked/map.c"
        goto label_55;
#line 215 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1273 dst=r0 src=r0 offset=92 imm=0
#line 215 "sample/undocked/map.c"
    goto label_74;
label_71:
    // EBPF_OP_MOV_IMM pc=1274 dst=r1 src=r0 offset=0 imm=0
#line 215 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 215 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=1275 dst=r10 src=r1 offset=-72 imm=0
#line 193 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=1276 dst=r1 src=r0 offset=0 imm=1701737077
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=1278 dst=r10 src=r1 offset=-80 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1279 dst=r1 src=r0 offset=0 imm=1680154740
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=1281 dst=r10 src=r1 offset=-88 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1282 dst=r1 src=r0 offset=0 imm=1914726254
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=1284 dst=r10 src=r1 offset=-96 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1285 dst=r1 src=r0 offset=0 imm=1886938400
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=1287 dst=r10 src=r1 offset=-104 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1288 dst=r1 src=r0 offset=0 imm=1601204080
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1290 dst=r10 src=r1 offset=-112 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1291 dst=r1 src=r0 offset=0 imm=1600548962
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1293 dst=r10 src=r1 offset=-120 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1294 dst=r4 src=r6 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1295 dst=r4 src=r0 offset=0 imm=32
#line 193 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1296 dst=r4 src=r0 offset=0 imm=32
#line 193 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1297 dst=r1 src=r10 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1298 dst=r1 src=r0 offset=0 imm=-120
#line 193 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1299 dst=r2 src=r0 offset=0 imm=49
#line 193 "sample/undocked/map.c"
    r2 = IMMEDIATE(49);
#line 193 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_MOV64_IMM pc=1300 dst=r3 src=r0 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1301 dst=r0 src=r0 offset=0 imm=14
#line 193 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 193 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 193 "sample/undocked/map.c"
        return 0;
#line 193 "sample/undocked/map.c"
    }
    //  pc=1302 dst=r6 src=r0 offset=-390 imm=-1
#line 215 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 215 "sample/undocked/map.c"
        goto label_55;
#line 215 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1303 dst=r0 src=r0 offset=62 imm=0
#line 215 "sample/undocked/map.c"
    goto label_74;
label_72:
    // EBPF_OP_MOV_IMM pc=1304 dst=r7 src=r0 offset=0 imm=0
#line 215 "sample/undocked/map.c"
    r7 = IMMEDIATE(0);
#line 215 "sample/undocked/map.c"
    r7 &= UINT32_MAX;
    // EBPF_OP_STXW pc=1305 dst=r10 src=r7 offset=-64 imm=0
#line 197 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1306 dst=r2 src=r10 offset=0 imm=0
#line 197 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1307 dst=r2 src=r0 offset=0 imm=-64
#line 197 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=1308 dst=r1 src=r1 offset=0 imm=7
#line 197 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=1310 dst=r0 src=r0 offset=0 imm=17
#line 197 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 197 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 197 "sample/undocked/map.c"
        return 0;
#line 197 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1311 dst=r6 src=r0 offset=0 imm=0
#line 197 "sample/undocked/map.c"
    r6 = r0;
    //  pc=1312 dst=r6 src=r0 offset=29 imm=-7
#line 197 "sample/undocked/map.c"
    if ((uint32_t)r6 == IMMEDIATE(-7)) {
#line 197 "sample/undocked/map.c"
        goto label_73;
#line 197 "sample/undocked/map.c"
    }
    // EBPF_OP_STXB pc=1313 dst=r10 src=r7 offset=-72 imm=0
#line 197 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint8_t)r7;
    // EBPF_OP_LDDW pc=1314 dst=r1 src=r0 offset=0 imm=1701737077
#line 197 "sample/undocked/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=1316 dst=r10 src=r1 offset=-80 imm=0
#line 197 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1317 dst=r1 src=r0 offset=0 imm=1680154740
#line 197 "sample/undocked/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=1319 dst=r10 src=r1 offset=-88 imm=0
#line 197 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1320 dst=r1 src=r0 offset=0 imm=1914726254
#line 197 "sample/undocked/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=1322 dst=r10 src=r1 offset=-96 imm=0
#line 197 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1323 dst=r1 src=r0 offset=0 imm=1886938400
#line 197 "sample/undocked/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=1325 dst=r10 src=r1 offset=-104 imm=0
#line 197 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1326 dst=r1 src=r0 offset=0 imm=1601204080
#line 197 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1328 dst=r10 src=r1 offset=-112 imm=0
#line 197 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1329 dst=r1 src=r0 offset=0 imm=1600548962
#line 197 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1331 dst=r10 src=r1 offset=-120 imm=0
#line 197 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1332 dst=r4 src=r6 offset=0 imm=0
#line 197 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1333 dst=r4 src=r0 offset=0 imm=32
#line 197 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1334 dst=r4 src=r0 offset=0 imm=32
#line 197 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1335 dst=r1 src=r10 offset=0 imm=0
#line 197 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1336 dst=r1 src=r0 offset=0 imm=-120
#line 197 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1337 dst=r2 src=r0 offset=0 imm=49
#line 197 "sample/undocked/map.c"
    r2 = IMMEDIATE(49);
#line 197 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_MOV64_IMM pc=1338 dst=r3 src=r0 offset=0 imm=-7
#line 197 "sample/undocked/map.c"
    r3 = IMMEDIATE(-7);
    // EBPF_OP_CALL pc=1339 dst=r0 src=r0 offset=0 imm=14
#line 197 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 197 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 197 "sample/undocked/map.c"
        return 0;
#line 197 "sample/undocked/map.c"
    }
    //  pc=1340 dst=r6 src=r0 offset=-428 imm=-1
#line 215 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 215 "sample/undocked/map.c"
        goto label_55;
#line 215 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1341 dst=r0 src=r0 offset=24 imm=0
#line 215 "sample/undocked/map.c"
    goto label_74;
label_73:
    // EBPF_OP_LDXW pc=1342 dst=r3 src=r10 offset=-64 imm=0
#line 197 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64));
    //  pc=1343 dst=r3 src=r0 offset=-431 imm=0
#line 197 "sample/undocked/map.c"
    if ((uint32_t)r3 == IMMEDIATE(0)) {
#line 197 "sample/undocked/map.c"
        goto label_55;
#line 197 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=1344 dst=r1 src=r0 offset=0 imm=1735289204
#line 197 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1346 dst=r10 src=r1 offset=-88 imm=0
#line 197 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1347 dst=r1 src=r0 offset=0 imm=1696621605
#line 197 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1349 dst=r10 src=r1 offset=-96 imm=0
#line 197 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1350 dst=r1 src=r0 offset=0 imm=1952805408
#line 197 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1352 dst=r10 src=r1 offset=-104 imm=0
#line 197 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1353 dst=r1 src=r0 offset=0 imm=1601204080
#line 197 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1355 dst=r10 src=r1 offset=-112 imm=0
#line 197 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1356 dst=r1 src=r0 offset=0 imm=1600548962
#line 197 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1358 dst=r10 src=r1 offset=-120 imm=0
#line 197 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1359 dst=r1 src=r10 offset=0 imm=0
#line 197 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1360 dst=r1 src=r0 offset=0 imm=-120
#line 197 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1361 dst=r2 src=r0 offset=0 imm=40
#line 197 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
#line 197 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_MOV64_IMM pc=1362 dst=r4 src=r0 offset=0 imm=0
#line 197 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1363 dst=r0 src=r0 offset=0 imm=14
#line 197 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 197 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 197 "sample/undocked/map.c"
        return 0;
#line 197 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=1364 dst=r6 src=r0 offset=0 imm=-1
#line 197 "sample/undocked/map.c"
    r6 = IMMEDIATE(-1);
#line 197 "sample/undocked/map.c"
    r6 &= UINT32_MAX;
    //  pc=1365 dst=r6 src=r0 offset=-453 imm=-1
#line 215 "sample/undocked/map.c"
    if ((int32_t)r6 > IMMEDIATE(-1)) {
#line 215 "sample/undocked/map.c"
        goto label_55;
#line 215 "sample/undocked/map.c"
    }
label_74:
    // EBPF_OP_LDDW pc=1366 dst=r1 src=r0 offset=0 imm=1684369010
#line 215 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=1368 dst=r10 src=r1 offset=-88 imm=0
#line 215 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1369 dst=r1 src=r0 offset=0 imm=541414725
#line 215 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140578096453;
    // EBPF_OP_STXDW pc=1371 dst=r10 src=r1 offset=-96 imm=0
#line 215 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1372 dst=r1 src=r0 offset=0 imm=1634541682
#line 215 "sample/undocked/map.c"
    r1 = (uint64_t)6147730633380405362;
    // EBPF_OP_STXDW pc=1374 dst=r10 src=r1 offset=-104 imm=0
#line 215 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1375 dst=r1 src=r0 offset=0 imm=1330667336
#line 215 "sample/undocked/map.c"
    r1 = (uint64_t)8027138915134627656;
    // EBPF_OP_STXDW pc=1377 dst=r10 src=r1 offset=-112 imm=0
#line 215 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1378 dst=r1 src=r0 offset=0 imm=1953719636
#line 215 "sample/undocked/map.c"
    r1 = (uint64_t)6004793778491319636;
    // EBPF_OP_STXDW pc=1380 dst=r10 src=r1 offset=-120 imm=0
#line 215 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV_REG pc=1381 dst=r3 src=r6 offset=0 imm=0
#line 215 "sample/undocked/map.c"
    r3 = r6;
#line 215 "sample/undocked/map.c"
    r3 &= UINT32_MAX;
    // EBPF_OP_LSH64_IMM pc=1382 dst=r3 src=r0 offset=0 imm=32
#line 215 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1383 dst=r3 src=r0 offset=0 imm=32
#line 215 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1384 dst=r1 src=r10 offset=0 imm=0
#line 215 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1385 dst=r1 src=r0 offset=0 imm=-120
#line 215 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1386 dst=r2 src=r0 offset=0 imm=40
#line 215 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
#line 215 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_JA pc=1387 dst=r0 src=r0 offset=-1291 imm=0
#line 215 "sample/undocked/map.c"
    goto label_7;
label_75:
    // EBPF_OP_LDXW pc=1388 dst=r3 src=r10 offset=-64 imm=0
#line 176 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64));
    //  pc=1389 dst=r3 src=r0 offset=49 imm=0
#line 176 "sample/undocked/map.c"
    if ((uint32_t)r3 == IMMEDIATE(0)) {
#line 176 "sample/undocked/map.c"
        goto label_80;
#line 176 "sample/undocked/map.c"
    }
label_76:
    // EBPF_OP_MOV_IMM pc=1390 dst=r1 src=r0 offset=0 imm=0
#line 176 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 176 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=1391 dst=r10 src=r1 offset=-80 imm=0
#line 176 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=1392 dst=r1 src=r0 offset=0 imm=1852404835
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=1394 dst=r10 src=r1 offset=-88 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1395 dst=r1 src=r0 offset=0 imm=543434016
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=1397 dst=r10 src=r1 offset=-96 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1398 dst=r1 src=r0 offset=0 imm=1701978221
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=1400 dst=r10 src=r1 offset=-104 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1401 dst=r1 src=r0 offset=0 imm=1801807216
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1403 dst=r10 src=r1 offset=-112 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1404 dst=r1 src=r0 offset=0 imm=1600548962
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1406 dst=r10 src=r1 offset=-120 imm=0
#line 176 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1407 dst=r1 src=r10 offset=0 imm=0
#line 176 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1408 dst=r1 src=r0 offset=0 imm=-120
#line 176 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1409 dst=r2 src=r0 offset=0 imm=41
#line 176 "sample/undocked/map.c"
    r2 = IMMEDIATE(41);
#line 176 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
label_77:
    // EBPF_OP_MOV64_IMM pc=1410 dst=r4 src=r0 offset=0 imm=0
#line 176 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
label_78:
    // EBPF_OP_CALL pc=1411 dst=r0 src=r0 offset=0 imm=14
#line 176 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 176 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 176 "sample/undocked/map.c"
        return 0;
#line 176 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=1412 dst=r7 src=r0 offset=0 imm=-1
#line 176 "sample/undocked/map.c"
    r7 = IMMEDIATE(-1);
#line 176 "sample/undocked/map.c"
    r7 &= UINT32_MAX;
label_79:
    // EBPF_OP_MOV_IMM pc=1413 dst=r6 src=r0 offset=0 imm=0
#line 176 "sample/undocked/map.c"
    r6 = IMMEDIATE(0);
#line 176 "sample/undocked/map.c"
    r6 &= UINT32_MAX;
    //  pc=1414 dst=r7 src=r0 offset=-1317 imm=-1
#line 216 "sample/undocked/map.c"
    if ((int32_t)r7 > IMMEDIATE(-1)) {
#line 216 "sample/undocked/map.c"
        goto label_8;
#line 216 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=1415 dst=r1 src=r0 offset=0 imm=1684369010
#line 216 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=1417 dst=r10 src=r1 offset=-88 imm=0
#line 216 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1418 dst=r1 src=r0 offset=0 imm=541803329
#line 216 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140578485057;
    // EBPF_OP_STXDW pc=1420 dst=r10 src=r1 offset=-96 imm=0
#line 216 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1421 dst=r1 src=r0 offset=0 imm=1634541682
#line 216 "sample/undocked/map.c"
    r1 = (uint64_t)6076235989295898738;
    // EBPF_OP_STXDW pc=1423 dst=r10 src=r1 offset=-104 imm=0
#line 216 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1424 dst=r1 src=r0 offset=0 imm=1330667336
#line 216 "sample/undocked/map.c"
    r1 = (uint64_t)8027138915134627656;
    // EBPF_OP_STXDW pc=1426 dst=r10 src=r1 offset=-112 imm=0
#line 216 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1427 dst=r1 src=r0 offset=0 imm=1953719636
#line 216 "sample/undocked/map.c"
    r1 = (uint64_t)6004793778491319636;
    // EBPF_OP_STXDW pc=1429 dst=r10 src=r1 offset=-120 imm=0
#line 216 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV_REG pc=1430 dst=r3 src=r7 offset=0 imm=0
#line 216 "sample/undocked/map.c"
    r3 = r7;
#line 216 "sample/undocked/map.c"
    r3 &= UINT32_MAX;
    // EBPF_OP_LSH64_IMM pc=1431 dst=r3 src=r0 offset=0 imm=32
#line 216 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1432 dst=r3 src=r0 offset=0 imm=32
#line 216 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1433 dst=r1 src=r10 offset=0 imm=0
#line 216 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1434 dst=r1 src=r0 offset=0 imm=-120
#line 216 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1435 dst=r2 src=r0 offset=0 imm=40
#line 216 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
#line 216 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_CALL pc=1436 dst=r0 src=r0 offset=0 imm=13
#line 216 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 216 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 216 "sample/undocked/map.c"
        return 0;
#line 216 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_REG pc=1437 dst=r6 src=r7 offset=0 imm=0
#line 216 "sample/undocked/map.c"
    r6 = r7;
#line 216 "sample/undocked/map.c"
    r6 &= UINT32_MAX;
    // EBPF_OP_JA pc=1438 dst=r0 src=r0 offset=-1341 imm=0
#line 216 "sample/undocked/map.c"
    goto label_8;
label_80:
    // EBPF_OP_MOV_IMM pc=1439 dst=r6 src=r0 offset=0 imm=0
#line 216 "sample/undocked/map.c"
    r6 = IMMEDIATE(0);
#line 216 "sample/undocked/map.c"
    r6 &= UINT32_MAX;
    // EBPF_OP_STXW pc=1440 dst=r10 src=r6 offset=-64 imm=0
#line 177 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=1441 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1442 dst=r2 src=r0 offset=0 imm=-64
#line 177 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=1443 dst=r1 src=r1 offset=0 imm=8
#line 177 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=1445 dst=r0 src=r0 offset=0 imm=17
#line 177 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 177 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 177 "sample/undocked/map.c"
        return 0;
#line 177 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1446 dst=r7 src=r0 offset=0 imm=0
#line 177 "sample/undocked/map.c"
    r7 = r0;
    //  pc=1447 dst=r7 src=r0 offset=26 imm=-7
#line 177 "sample/undocked/map.c"
    if ((uint32_t)r7 == IMMEDIATE(-7)) {
#line 177 "sample/undocked/map.c"
        goto label_82;
#line 177 "sample/undocked/map.c"
    }
label_81:
    // EBPF_OP_STXB pc=1448 dst=r10 src=r6 offset=-72 imm=0
#line 177 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint8_t)r6;
    // EBPF_OP_LDDW pc=1449 dst=r1 src=r0 offset=0 imm=1701737077
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=1451 dst=r10 src=r1 offset=-80 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1452 dst=r1 src=r0 offset=0 imm=1680154740
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=1454 dst=r10 src=r1 offset=-88 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1455 dst=r1 src=r0 offset=0 imm=1914726254
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=1457 dst=r10 src=r1 offset=-96 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1458 dst=r1 src=r0 offset=0 imm=1886938400
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=1460 dst=r10 src=r1 offset=-104 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1461 dst=r1 src=r0 offset=0 imm=1601204080
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1463 dst=r10 src=r1 offset=-112 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1464 dst=r1 src=r0 offset=0 imm=1600548962
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1466 dst=r10 src=r1 offset=-120 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1467 dst=r4 src=r7 offset=0 imm=0
#line 177 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=1468 dst=r4 src=r0 offset=0 imm=32
#line 177 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1469 dst=r4 src=r0 offset=0 imm=32
#line 177 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1470 dst=r1 src=r10 offset=0 imm=0
#line 177 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1471 dst=r1 src=r0 offset=0 imm=-120
#line 177 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1472 dst=r2 src=r0 offset=0 imm=49
#line 177 "sample/undocked/map.c"
    r2 = IMMEDIATE(49);
#line 177 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_JA pc=1473 dst=r0 src=r0 offset=-526 imm=0
#line 177 "sample/undocked/map.c"
    goto label_57;
label_82:
    // EBPF_OP_LDXW pc=1474 dst=r3 src=r10 offset=-64 imm=0
#line 177 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64));
    //  pc=1475 dst=r3 src=r0 offset=19 imm=0
#line 177 "sample/undocked/map.c"
    if ((uint32_t)r3 == IMMEDIATE(0)) {
#line 177 "sample/undocked/map.c"
        goto label_84;
#line 177 "sample/undocked/map.c"
    }
label_83:
    // EBPF_OP_LDDW pc=1476 dst=r1 src=r0 offset=0 imm=1735289204
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1478 dst=r10 src=r1 offset=-88 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1479 dst=r1 src=r0 offset=0 imm=1696621605
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1481 dst=r10 src=r1 offset=-96 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1482 dst=r1 src=r0 offset=0 imm=1952805408
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1484 dst=r10 src=r1 offset=-104 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1485 dst=r1 src=r0 offset=0 imm=1601204080
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1487 dst=r10 src=r1 offset=-112 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1488 dst=r1 src=r0 offset=0 imm=1600548962
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1490 dst=r10 src=r1 offset=-120 imm=0
#line 177 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1491 dst=r1 src=r10 offset=0 imm=0
#line 177 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1492 dst=r1 src=r0 offset=0 imm=-120
#line 177 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1493 dst=r2 src=r0 offset=0 imm=40
#line 177 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
#line 177 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_JA pc=1494 dst=r0 src=r0 offset=-85 imm=0
#line 177 "sample/undocked/map.c"
    goto label_77;
label_84:
    // EBPF_OP_MOV64_IMM pc=1495 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=1496 dst=r10 src=r1 offset=-64 imm=0
#line 181 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_LDXDW pc=1497 dst=r1 src=r10 offset=-64 imm=0
#line 181 "sample/undocked/map.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_JSGT_IMM pc=1498 dst=r1 src=r0 offset=15 imm=9
#line 181 "sample/undocked/map.c"
    if ((int64_t)r1 > IMMEDIATE(9)) {
#line 181 "sample/undocked/map.c"
        goto label_86;
#line 181 "sample/undocked/map.c"
    }
label_85:
    // EBPF_OP_LDXDW pc=1499 dst=r1 src=r10 offset=-64 imm=0
#line 182 "sample/undocked/map.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_STXW pc=1500 dst=r10 src=r1 offset=-4 imm=0
#line 182 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1501 dst=r2 src=r10 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1502 dst=r2 src=r0 offset=0 imm=-4
#line 182 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1503 dst=r1 src=r1 offset=0 imm=8
#line 182 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_MOV64_IMM pc=1505 dst=r3 src=r0 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1506 dst=r0 src=r0 offset=0 imm=16
#line 182 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 182 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 182 "sample/undocked/map.c"
        return 0;
#line 182 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1507 dst=r7 src=r0 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r7 = r0;
    //  pc=1508 dst=r7 src=r0 offset=83 imm=0
#line 182 "sample/undocked/map.c"
    if ((uint32_t)r7 != IMMEDIATE(0)) {
#line 182 "sample/undocked/map.c"
        goto label_88;
#line 182 "sample/undocked/map.c"
    }
    // EBPF_OP_LDXDW pc=1509 dst=r1 src=r10 offset=-64 imm=0
#line 181 "sample/undocked/map.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_ADD64_IMM pc=1510 dst=r1 src=r0 offset=0 imm=1
#line 181 "sample/undocked/map.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=1511 dst=r10 src=r1 offset=-64 imm=0
#line 181 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_LDXDW pc=1512 dst=r1 src=r10 offset=-64 imm=0
#line 181 "sample/undocked/map.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_JSLT_IMM pc=1513 dst=r1 src=r0 offset=-15 imm=10
#line 181 "sample/undocked/map.c"
    if ((int64_t)r1 < IMMEDIATE(10)) {
#line 181 "sample/undocked/map.c"
        goto label_85;
#line 181 "sample/undocked/map.c"
    }
label_86:
    // EBPF_OP_MOV_IMM pc=1514 dst=r6 src=r0 offset=0 imm=10
#line 181 "sample/undocked/map.c"
    r6 = IMMEDIATE(10);
#line 181 "sample/undocked/map.c"
    r6 &= UINT32_MAX;
    // EBPF_OP_STXW pc=1515 dst=r10 src=r6 offset=-64 imm=0
#line 185 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=1516 dst=r2 src=r10 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1517 dst=r2 src=r0 offset=0 imm=-64
#line 185 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=1518 dst=r1 src=r1 offset=0 imm=8
#line 185 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_MOV64_IMM pc=1520 dst=r3 src=r0 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1521 dst=r0 src=r0 offset=0 imm=16
#line 185 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 185 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 185 "sample/undocked/map.c"
        return 0;
#line 185 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1522 dst=r7 src=r0 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r7 = r0;
    //  pc=1523 dst=r7 src=r0 offset=33 imm=-29
#line 185 "sample/undocked/map.c"
    if ((uint32_t)r7 == IMMEDIATE(-29)) {
#line 185 "sample/undocked/map.c"
        goto label_87;
#line 185 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=1524 dst=r1 src=r0 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 185 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=1525 dst=r10 src=r1 offset=-66 imm=0
#line 185 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-66)) = (uint8_t)r1;
    // EBPF_OP_MOV_IMM pc=1526 dst=r1 src=r0 offset=0 imm=25637
#line 185 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
#line 185 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=1527 dst=r10 src=r1 offset=-68 imm=0
#line 185 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint16_t)r1;
    // EBPF_OP_MOV_IMM pc=1528 dst=r1 src=r0 offset=0 imm=543450478
#line 185 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
#line 185 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=1529 dst=r10 src=r1 offset=-72 imm=0
#line 185 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1530 dst=r1 src=r0 offset=0 imm=1914725413
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1532 dst=r10 src=r1 offset=-80 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1533 dst=r1 src=r0 offset=0 imm=1667592312
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1535 dst=r10 src=r1 offset=-88 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1536 dst=r1 src=r0 offset=0 imm=543649385
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1538 dst=r10 src=r1 offset=-96 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1539 dst=r1 src=r0 offset=0 imm=1852383341
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1541 dst=r10 src=r1 offset=-104 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1542 dst=r1 src=r0 offset=0 imm=1752397168
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1544 dst=r10 src=r1 offset=-112 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1545 dst=r1 src=r0 offset=0 imm=1600548962
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1547 dst=r10 src=r1 offset=-120 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=1548 dst=r3 src=r10 offset=-64 imm=0
#line 185 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_MOV64_REG pc=1549 dst=r5 src=r7 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=1550 dst=r5 src=r0 offset=0 imm=32
#line 185 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1551 dst=r5 src=r0 offset=0 imm=32
#line 185 "sample/undocked/map.c"
    r5 = (int64_t)r5 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1552 dst=r1 src=r10 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1553 dst=r1 src=r0 offset=0 imm=-120
#line 185 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1554 dst=r2 src=r0 offset=0 imm=55
#line 185 "sample/undocked/map.c"
    r2 = IMMEDIATE(55);
#line 185 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_MOV64_IMM pc=1555 dst=r4 src=r0 offset=0 imm=-29
#line 185 "sample/undocked/map.c"
    r4 = IMMEDIATE(-29);
    // EBPF_OP_JA pc=1556 dst=r0 src=r0 offset=67 imm=0
#line 185 "sample/undocked/map.c"
    goto label_90;
label_87:
    // EBPF_OP_STXW pc=1557 dst=r10 src=r6 offset=-64 imm=0
#line 186 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=1558 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1559 dst=r2 src=r0 offset=0 imm=-64
#line 186 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=1560 dst=r1 src=r1 offset=0 imm=8
#line 186 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_MOV64_IMM pc=1562 dst=r3 src=r0 offset=0 imm=2
#line 186 "sample/undocked/map.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_CALL pc=1563 dst=r0 src=r0 offset=0 imm=16
#line 186 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 186 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 186 "sample/undocked/map.c"
        return 0;
#line 186 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1564 dst=r7 src=r0 offset=0 imm=0
#line 186 "sample/undocked/map.c"
    r7 = r0;
    //  pc=1565 dst=r7 src=r0 offset=60 imm=0
#line 186 "sample/undocked/map.c"
    if ((uint32_t)r7 == IMMEDIATE(0)) {
#line 186 "sample/undocked/map.c"
        goto label_91;
#line 186 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=1566 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 186 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=1567 dst=r10 src=r1 offset=-66 imm=0
#line 186 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-66)) = (uint8_t)r1;
    // EBPF_OP_MOV_IMM pc=1568 dst=r1 src=r0 offset=0 imm=25637
#line 186 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
#line 186 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=1569 dst=r10 src=r1 offset=-68 imm=0
#line 186 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint16_t)r1;
    // EBPF_OP_MOV_IMM pc=1570 dst=r1 src=r0 offset=0 imm=543450478
#line 186 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
#line 186 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=1571 dst=r10 src=r1 offset=-72 imm=0
#line 186 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1572 dst=r1 src=r0 offset=0 imm=1914725413
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1574 dst=r10 src=r1 offset=-80 imm=0
#line 186 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1575 dst=r1 src=r0 offset=0 imm=1667592312
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1577 dst=r10 src=r1 offset=-88 imm=0
#line 186 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1578 dst=r1 src=r0 offset=0 imm=543649385
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1580 dst=r10 src=r1 offset=-96 imm=0
#line 186 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1581 dst=r1 src=r0 offset=0 imm=1852383341
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1583 dst=r10 src=r1 offset=-104 imm=0
#line 186 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1584 dst=r1 src=r0 offset=0 imm=1752397168
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1586 dst=r10 src=r1 offset=-112 imm=0
#line 186 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1587 dst=r1 src=r0 offset=0 imm=1600548962
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1589 dst=r10 src=r1 offset=-120 imm=0
#line 186 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=1590 dst=r3 src=r10 offset=-64 imm=0
#line 186 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_JA pc=1591 dst=r0 src=r0 offset=25 imm=0
#line 186 "sample/undocked/map.c"
    goto label_89;
label_88:
    // EBPF_OP_MOV_IMM pc=1592 dst=r1 src=r0 offset=0 imm=0
#line 186 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 186 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=1593 dst=r10 src=r1 offset=-66 imm=0
#line 182 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-66)) = (uint8_t)r1;
    // EBPF_OP_MOV_IMM pc=1594 dst=r1 src=r0 offset=0 imm=25637
#line 182 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
#line 182 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=1595 dst=r10 src=r1 offset=-68 imm=0
#line 182 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint16_t)r1;
    // EBPF_OP_MOV_IMM pc=1596 dst=r1 src=r0 offset=0 imm=543450478
#line 182 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
#line 182 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=1597 dst=r10 src=r1 offset=-72 imm=0
#line 182 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1598 dst=r1 src=r0 offset=0 imm=1914725413
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1600 dst=r10 src=r1 offset=-80 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1601 dst=r1 src=r0 offset=0 imm=1667592312
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1603 dst=r10 src=r1 offset=-88 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1604 dst=r1 src=r0 offset=0 imm=543649385
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1606 dst=r10 src=r1 offset=-96 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1607 dst=r1 src=r0 offset=0 imm=1852383341
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1609 dst=r10 src=r1 offset=-104 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1610 dst=r1 src=r0 offset=0 imm=1752397168
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1612 dst=r10 src=r1 offset=-112 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1613 dst=r1 src=r0 offset=0 imm=1600548962
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1615 dst=r10 src=r1 offset=-120 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=1616 dst=r3 src=r10 offset=-4 imm=0
#line 182 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
label_89:
    // EBPF_OP_MOV64_REG pc=1617 dst=r5 src=r7 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=1618 dst=r5 src=r0 offset=0 imm=32
#line 182 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1619 dst=r5 src=r0 offset=0 imm=32
#line 182 "sample/undocked/map.c"
    r5 = (int64_t)r5 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1620 dst=r1 src=r10 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1621 dst=r1 src=r0 offset=0 imm=-120
#line 182 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1622 dst=r2 src=r0 offset=0 imm=55
#line 182 "sample/undocked/map.c"
    r2 = IMMEDIATE(55);
#line 182 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_MOV64_IMM pc=1623 dst=r4 src=r0 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
label_90:
    // EBPF_OP_CALL pc=1624 dst=r0 src=r0 offset=0 imm=15
#line 182 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[10].address(r1, r2, r3, r4, r5, context);
#line 182 "sample/undocked/map.c"
    if ((runtime_context->helper_data[10].tail_call) && (r0 == 0)) {
#line 182 "sample/undocked/map.c"
        return 0;
#line 182 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1625 dst=r0 src=r0 offset=-213 imm=0
#line 182 "sample/undocked/map.c"
    goto label_79;
label_91:
    // EBPF_OP_MOV_IMM pc=1626 dst=r1 src=r0 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 182 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=1627 dst=r10 src=r1 offset=-64 imm=0
#line 188 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1628 dst=r2 src=r10 offset=0 imm=0
#line 188 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1629 dst=r2 src=r0 offset=0 imm=-64
#line 188 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=1630 dst=r1 src=r1 offset=0 imm=8
#line 188 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=1632 dst=r0 src=r0 offset=0 imm=18
#line 188 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 188 "sample/undocked/map.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 188 "sample/undocked/map.c"
        return 0;
#line 188 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1633 dst=r7 src=r0 offset=0 imm=0
#line 188 "sample/undocked/map.c"
    r7 = r0;
    //  pc=1634 dst=r7 src=r0 offset=29 imm=0
#line 188 "sample/undocked/map.c"
    if ((uint32_t)r7 == IMMEDIATE(0)) {
#line 188 "sample/undocked/map.c"
        goto label_93;
#line 188 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=1635 dst=r1 src=r0 offset=0 imm=100
#line 188 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
#line 188 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=1636 dst=r10 src=r1 offset=-72 imm=0
#line 188 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=1637 dst=r1 src=r0 offset=0 imm=1852994932
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=1639 dst=r10 src=r1 offset=-80 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1640 dst=r1 src=r0 offset=0 imm=622883948
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=1642 dst=r10 src=r1 offset=-88 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1643 dst=r1 src=r0 offset=0 imm=543649385
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=1645 dst=r10 src=r1 offset=-96 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1646 dst=r1 src=r0 offset=0 imm=2019893357
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=1648 dst=r10 src=r1 offset=-104 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1649 dst=r1 src=r0 offset=0 imm=1801807216
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1651 dst=r10 src=r1 offset=-112 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1652 dst=r1 src=r0 offset=0 imm=1600548962
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1654 dst=r10 src=r1 offset=-120 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1655 dst=r4 src=r7 offset=0 imm=0
#line 188 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=1656 dst=r4 src=r0 offset=0 imm=32
#line 188 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1657 dst=r4 src=r0 offset=0 imm=32
#line 188 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1658 dst=r1 src=r10 offset=0 imm=0
#line 188 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1659 dst=r1 src=r0 offset=0 imm=-120
#line 188 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1660 dst=r2 src=r0 offset=0 imm=50
#line 188 "sample/undocked/map.c"
    r2 = IMMEDIATE(50);
#line 188 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
label_92:
    // EBPF_OP_MOV64_IMM pc=1661 dst=r3 src=r0 offset=0 imm=0
#line 188 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1662 dst=r0 src=r0 offset=0 imm=14
#line 188 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 188 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 188 "sample/undocked/map.c"
        return 0;
#line 188 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1663 dst=r0 src=r0 offset=-251 imm=0
#line 188 "sample/undocked/map.c"
    goto label_79;
label_93:
    // EBPF_OP_LDXW pc=1664 dst=r3 src=r10 offset=-64 imm=0
#line 188 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64));
    //  pc=1665 dst=r3 src=r0 offset=22 imm=10
#line 188 "sample/undocked/map.c"
    if ((uint32_t)r3 == IMMEDIATE(10)) {
#line 188 "sample/undocked/map.c"
        goto label_94;
#line 188 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=1666 dst=r1 src=r0 offset=0 imm=0
#line 188 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 188 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=1667 dst=r10 src=r1 offset=-80 imm=0
#line 188 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=1668 dst=r1 src=r0 offset=0 imm=1852404835
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=1670 dst=r10 src=r1 offset=-88 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1671 dst=r1 src=r0 offset=0 imm=543434016
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=1673 dst=r10 src=r1 offset=-96 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1674 dst=r1 src=r0 offset=0 imm=1701978221
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=1676 dst=r10 src=r1 offset=-104 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1677 dst=r1 src=r0 offset=0 imm=1801807216
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1679 dst=r10 src=r1 offset=-112 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1680 dst=r1 src=r0 offset=0 imm=1600548962
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1682 dst=r10 src=r1 offset=-120 imm=0
#line 188 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1683 dst=r1 src=r10 offset=0 imm=0
#line 188 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1684 dst=r1 src=r0 offset=0 imm=-120
#line 188 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1685 dst=r2 src=r0 offset=0 imm=41
#line 188 "sample/undocked/map.c"
    r2 = IMMEDIATE(41);
#line 188 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_MOV64_IMM pc=1686 dst=r4 src=r0 offset=0 imm=10
#line 188 "sample/undocked/map.c"
    r4 = IMMEDIATE(10);
    // EBPF_OP_JA pc=1687 dst=r0 src=r0 offset=-277 imm=0
#line 188 "sample/undocked/map.c"
    goto label_78;
label_94:
    // EBPF_OP_MOV64_IMM pc=1688 dst=r1 src=r0 offset=0 imm=0
#line 188 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=1689 dst=r10 src=r1 offset=-64 imm=0
#line 192 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_LDXDW pc=1690 dst=r1 src=r10 offset=-64 imm=0
#line 192 "sample/undocked/map.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_JSGT_IMM pc=1691 dst=r1 src=r0 offset=7 imm=9
#line 192 "sample/undocked/map.c"
    if ((int64_t)r1 > IMMEDIATE(9)) {
#line 192 "sample/undocked/map.c"
        goto label_96;
#line 192 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV_IMM pc=1692 dst=r6 src=r0 offset=0 imm=0
#line 192 "sample/undocked/map.c"
    r6 = IMMEDIATE(0);
#line 192 "sample/undocked/map.c"
    r6 &= UINT32_MAX;
    // EBPF_OP_JA pc=1693 dst=r0 src=r0 offset=15 imm=0
#line 192 "sample/undocked/map.c"
    goto label_97;
label_95:
    // EBPF_OP_LDXDW pc=1694 dst=r1 src=r10 offset=-64 imm=0
#line 192 "sample/undocked/map.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_ADD64_IMM pc=1695 dst=r1 src=r0 offset=0 imm=1
#line 192 "sample/undocked/map.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=1696 dst=r10 src=r1 offset=-64 imm=0
#line 192 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_LDXDW pc=1697 dst=r1 src=r10 offset=-64 imm=0
#line 192 "sample/undocked/map.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_JSLT_IMM pc=1698 dst=r1 src=r0 offset=10 imm=10
#line 192 "sample/undocked/map.c"
    if ((int64_t)r1 < IMMEDIATE(10)) {
#line 192 "sample/undocked/map.c"
        goto label_97;
#line 192 "sample/undocked/map.c"
    }
label_96:
    // EBPF_OP_MOV_IMM pc=1699 dst=r1 src=r0 offset=0 imm=0
#line 192 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 192 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXW pc=1700 dst=r10 src=r1 offset=-64 imm=0
#line 196 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1701 dst=r2 src=r10 offset=0 imm=0
#line 196 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1702 dst=r2 src=r0 offset=0 imm=-64
#line 196 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=1703 dst=r1 src=r1 offset=0 imm=8
#line 196 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=1705 dst=r0 src=r0 offset=0 imm=18
#line 196 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 196 "sample/undocked/map.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 196 "sample/undocked/map.c"
        return 0;
#line 196 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1706 dst=r7 src=r0 offset=0 imm=0
#line 196 "sample/undocked/map.c"
    r7 = r0;
    //  pc=1707 dst=r7 src=r0 offset=37 imm=-7
#line 196 "sample/undocked/map.c"
    if ((uint32_t)r7 == IMMEDIATE(-7)) {
#line 196 "sample/undocked/map.c"
        goto label_99;
#line 196 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1708 dst=r0 src=r0 offset=-787 imm=0
#line 196 "sample/undocked/map.c"
    goto label_56;
label_97:
    // EBPF_OP_STXW pc=1709 dst=r10 src=r6 offset=-4 imm=0
#line 193 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=1710 dst=r2 src=r10 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1711 dst=r2 src=r0 offset=0 imm=-4
#line 193 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1712 dst=r1 src=r1 offset=0 imm=8
#line 193 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=1714 dst=r0 src=r0 offset=0 imm=17
#line 193 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 193 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 193 "sample/undocked/map.c"
        return 0;
#line 193 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1715 dst=r7 src=r0 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r7 = r0;
    //  pc=1716 dst=r7 src=r0 offset=1 imm=0
#line 193 "sample/undocked/map.c"
    if ((uint32_t)r7 == IMMEDIATE(0)) {
#line 193 "sample/undocked/map.c"
        goto label_98;
#line 193 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1717 dst=r0 src=r0 offset=30 imm=0
#line 193 "sample/undocked/map.c"
    goto label_100;
label_98:
    // EBPF_OP_LDXDW pc=1718 dst=r1 src=r10 offset=-64 imm=0
#line 193 "sample/undocked/map.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_MOV64_IMM pc=1719 dst=r2 src=r0 offset=0 imm=10
#line 193 "sample/undocked/map.c"
    r2 = IMMEDIATE(10);
    // EBPF_OP_SUB64_REG pc=1720 dst=r2 src=r1 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r2 -= r1;
    // EBPF_OP_LDXW pc=1721 dst=r3 src=r10 offset=-4 imm=0
#line 193 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_REG pc=1722 dst=r2 src=r3 offset=-29 imm=0
#line 193 "sample/undocked/map.c"
    if (r2 == r3) {
#line 193 "sample/undocked/map.c"
        goto label_95;
#line 193 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=1723 dst=r1 src=r0 offset=0 imm=1735289204
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1725 dst=r10 src=r1 offset=-88 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1726 dst=r1 src=r0 offset=0 imm=1696621605
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1728 dst=r10 src=r1 offset=-96 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1729 dst=r1 src=r0 offset=0 imm=1952805408
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1731 dst=r10 src=r1 offset=-104 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1732 dst=r1 src=r0 offset=0 imm=1601204080
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1734 dst=r10 src=r1 offset=-112 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1735 dst=r1 src=r0 offset=0 imm=1600548962
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1737 dst=r10 src=r1 offset=-120 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_LDXDW pc=1738 dst=r1 src=r10 offset=-64 imm=0
#line 193 "sample/undocked/map.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64));
    // EBPF_OP_MOV64_IMM pc=1739 dst=r4 src=r0 offset=0 imm=10
#line 193 "sample/undocked/map.c"
    r4 = IMMEDIATE(10);
    // EBPF_OP_SUB64_REG pc=1740 dst=r4 src=r1 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r4 -= r1;
    // EBPF_OP_MOV64_REG pc=1741 dst=r1 src=r10 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1742 dst=r1 src=r0 offset=0 imm=-120
#line 193 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1743 dst=r2 src=r0 offset=0 imm=40
#line 193 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
#line 193 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_JA pc=1744 dst=r0 src=r0 offset=-334 imm=0
#line 193 "sample/undocked/map.c"
    goto label_78;
label_99:
    // EBPF_OP_LDXW pc=1745 dst=r3 src=r10 offset=-64 imm=0
#line 196 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64));
    //  pc=1746 dst=r3 src=r0 offset=28 imm=0
#line 196 "sample/undocked/map.c"
    if ((uint32_t)r3 == IMMEDIATE(0)) {
#line 196 "sample/undocked/map.c"
        goto label_101;
#line 196 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1747 dst=r0 src=r0 offset=-358 imm=0
#line 196 "sample/undocked/map.c"
    goto label_76;
label_100:
    // EBPF_OP_MOV_IMM pc=1748 dst=r1 src=r0 offset=0 imm=0
#line 196 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 196 "sample/undocked/map.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXB pc=1749 dst=r10 src=r1 offset=-72 imm=0
#line 193 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=1750 dst=r1 src=r0 offset=0 imm=1701737077
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=1752 dst=r10 src=r1 offset=-80 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1753 dst=r1 src=r0 offset=0 imm=1680154740
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=1755 dst=r10 src=r1 offset=-88 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1756 dst=r1 src=r0 offset=0 imm=1914726254
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=1758 dst=r10 src=r1 offset=-96 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1759 dst=r1 src=r0 offset=0 imm=1886938400
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=1761 dst=r10 src=r1 offset=-104 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1762 dst=r1 src=r0 offset=0 imm=1601204080
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1764 dst=r10 src=r1 offset=-112 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1765 dst=r1 src=r0 offset=0 imm=1600548962
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1767 dst=r10 src=r1 offset=-120 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1768 dst=r4 src=r7 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=1769 dst=r4 src=r0 offset=0 imm=32
#line 193 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1770 dst=r4 src=r0 offset=0 imm=32
#line 193 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1771 dst=r1 src=r10 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1772 dst=r1 src=r0 offset=0 imm=-120
#line 193 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
    // EBPF_OP_MOV_IMM pc=1773 dst=r2 src=r0 offset=0 imm=49
#line 193 "sample/undocked/map.c"
    r2 = IMMEDIATE(49);
#line 193 "sample/undocked/map.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_JA pc=1774 dst=r0 src=r0 offset=-114 imm=0
#line 193 "sample/undocked/map.c"
    goto label_92;
label_101:
    // EBPF_OP_MOV_IMM pc=1775 dst=r6 src=r0 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r6 = IMMEDIATE(0);
#line 193 "sample/undocked/map.c"
    r6 &= UINT32_MAX;
    // EBPF_OP_STXW pc=1776 dst=r10 src=r6 offset=-64 imm=0
#line 197 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=1777 dst=r2 src=r10 offset=0 imm=0
#line 197 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1778 dst=r2 src=r0 offset=0 imm=-64
#line 197 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=1779 dst=r1 src=r1 offset=0 imm=8
#line 197 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=1781 dst=r0 src=r0 offset=0 imm=17
#line 197 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 197 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 197 "sample/undocked/map.c"
        return 0;
#line 197 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1782 dst=r7 src=r0 offset=0 imm=0
#line 197 "sample/undocked/map.c"
    r7 = r0;
    //  pc=1783 dst=r7 src=r0 offset=1 imm=-7
#line 197 "sample/undocked/map.c"
    if ((uint32_t)r7 == IMMEDIATE(-7)) {
#line 197 "sample/undocked/map.c"
        goto label_102;
#line 197 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1784 dst=r0 src=r0 offset=-337 imm=0
#line 197 "sample/undocked/map.c"
    goto label_81;
label_102:
    // EBPF_OP_LDXW pc=1785 dst=r3 src=r10 offset=-64 imm=0
#line 197 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64));
    //  pc=1786 dst=r3 src=r0 offset=1 imm=0
#line 197 "sample/undocked/map.c"
    if ((uint32_t)r3 == IMMEDIATE(0)) {
#line 197 "sample/undocked/map.c"
        goto label_103;
#line 197 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1787 dst=r0 src=r0 offset=-312 imm=0
#line 197 "sample/undocked/map.c"
    goto label_83;
label_103:
    // EBPF_OP_MOV_IMM pc=1788 dst=r6 src=r0 offset=0 imm=0
#line 197 "sample/undocked/map.c"
    r6 = IMMEDIATE(0);
#line 197 "sample/undocked/map.c"
    r6 &= UINT32_MAX;
    // EBPF_OP_JA pc=1789 dst=r0 src=r0 offset=-1692 imm=0
#line 216 "sample/undocked/map.c"
    goto label_8;
#line 202 "sample/undocked/map.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        test_maps,
        "sample~1",
        "sample_ext",
        "test_maps",
        test_maps_maps,
        8,
        test_maps_helpers,
        11,
        1790,
        &test_maps_program_type_guid,
        &test_maps_attach_type_guid,
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
    version->minor = 22;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t map_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
