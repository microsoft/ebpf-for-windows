// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from map.o

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
#line 199 "sample/undocked/map.c"
{
#line 199 "sample/undocked/map.c"
    // Prologue.
#line 199 "sample/undocked/map.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 199 "sample/undocked/map.c"
    register uint64_t r0 = 0;
#line 199 "sample/undocked/map.c"
    register uint64_t r1 = 0;
#line 199 "sample/undocked/map.c"
    register uint64_t r2 = 0;
#line 199 "sample/undocked/map.c"
    register uint64_t r3 = 0;
#line 199 "sample/undocked/map.c"
    register uint64_t r4 = 0;
#line 199 "sample/undocked/map.c"
    register uint64_t r5 = 0;
#line 199 "sample/undocked/map.c"
    register uint64_t r6 = 0;
#line 199 "sample/undocked/map.c"
    register uint64_t r7 = 0;
#line 199 "sample/undocked/map.c"
    register uint64_t r8 = 0;
#line 199 "sample/undocked/map.c"
    register uint64_t r9 = 0;
#line 199 "sample/undocked/map.c"
    register uint64_t r10 = 0;

#line 199 "sample/undocked/map.c"
    r1 = (uintptr_t)context;
#line 199 "sample/undocked/map.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r1 src=r0 offset=0 imm=0
#line 199 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r1 offset=-4 imm=0
#line 70 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=2 dst=r1 src=r0 offset=0 imm=1
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=3 dst=r10 src=r1 offset=-8 imm=0
#line 71 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=4 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=5 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=6 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r3 src=r0 offset=0 imm=-8
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
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
    // EBPF_OP_MOV64_REG pc=13 dst=r3 src=r6 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=14 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=15 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=16 dst=r3 src=r0 offset=9 imm=-1
#line 75 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 75 "sample/undocked/map.c"
        goto label_2;
#line 75 "sample/undocked/map.c"
    }
label_1:
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1684369010
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-88 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=20 dst=r1 src=r0 offset=0 imm=544040300
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=22 dst=r10 src=r1 offset=-96 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=23 dst=r1 src=r0 offset=0 imm=1633972341
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=25 dst=r0 src=r0 offset=45 imm=0
#line 75 "sample/undocked/map.c"
    goto label_5;
label_2:
    // EBPF_OP_MOV64_REG pc=26 dst=r2 src=r10 offset=0 imm=0
#line 75 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=27 dst=r2 src=r0 offset=0 imm=-4
#line 80 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=28 dst=r1 src=r1 offset=0 imm=1
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=30 dst=r0 src=r0 offset=0 imm=1
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 80 "sample/undocked/map.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 80 "sample/undocked/map.c"
        return 0;
#line 80 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=31 dst=r0 src=r0 offset=21 imm=0
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_4;
#line 81 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=32 dst=r1 src=r0 offset=0 imm=76
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=33 dst=r10 src=r1 offset=-80 imm=0
#line 82 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=34 dst=r1 src=r0 offset=0 imm=1684369010
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=36 dst=r10 src=r1 offset=-88 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=37 dst=r1 src=r0 offset=0 imm=544040300
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=39 dst=r10 src=r1 offset=-96 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=40 dst=r1 src=r0 offset=0 imm=1802465132
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=42 dst=r10 src=r1 offset=-104 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=43 dst=r1 src=r0 offset=0 imm=1600548962
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=45 dst=r10 src=r1 offset=-112 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=46 dst=r1 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=47 dst=r1 src=r0 offset=0 imm=-112
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=48 dst=r2 src=r0 offset=0 imm=34
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
label_3:
    // EBPF_OP_CALL pc=49 dst=r0 src=r0 offset=0 imm=12
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 82 "sample/undocked/map.c"
        return 0;
#line 82 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=50 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/undocked/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=52 dst=r0 src=r0 offset=26 imm=0
#line 82 "sample/undocked/map.c"
    goto label_6;
label_4:
    // EBPF_OP_MOV64_REG pc=53 dst=r2 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=54 dst=r2 src=r0 offset=0 imm=-4
#line 86 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=55 dst=r1 src=r1 offset=0 imm=1
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=57 dst=r0 src=r0 offset=0 imm=3
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 86 "sample/undocked/map.c"
        return 0;
#line 86 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=58 dst=r6 src=r0 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=59 dst=r3 src=r6 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=60 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=61 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=62 dst=r3 src=r0 offset=41 imm=-1
#line 87 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_9;
#line 87 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=63 dst=r1 src=r0 offset=0 imm=1684369010
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=65 dst=r10 src=r1 offset=-88 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=66 dst=r1 src=r0 offset=0 imm=544040300
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=68 dst=r10 src=r1 offset=-96 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=69 dst=r1 src=r0 offset=0 imm=1701602660
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
label_5:
    // EBPF_OP_STXDW pc=71 dst=r10 src=r1 offset=-104 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=72 dst=r1 src=r0 offset=0 imm=1600548962
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=74 dst=r10 src=r1 offset=-112 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=75 dst=r1 src=r10 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=76 dst=r1 src=r0 offset=0 imm=-112
#line 88 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=77 dst=r2 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=78 dst=r0 src=r0 offset=0 imm=13
#line 88 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/map.c"
        return 0;
#line 88 "sample/undocked/map.c"
    }
label_6:
    // EBPF_OP_MOV64_IMM pc=79 dst=r1 src=r0 offset=0 imm=100
#line 88 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=80 dst=r10 src=r1 offset=-76 imm=0
#line 202 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-76)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=81 dst=r1 src=r0 offset=0 imm=622879845
#line 202 "sample/undocked/map.c"
    r1 = IMMEDIATE(622879845);
    // EBPF_OP_STXW pc=82 dst=r10 src=r1 offset=-80 imm=0
#line 202 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=83 dst=r1 src=r0 offset=0 imm=1701978184
#line 202 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722056;
    // EBPF_OP_STXDW pc=85 dst=r10 src=r1 offset=-88 imm=0
#line 202 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=86 dst=r1 src=r0 offset=0 imm=1885433120
#line 202 "sample/undocked/map.c"
    r1 = (uint64_t)5999155482795797792;
    // EBPF_OP_STXDW pc=88 dst=r10 src=r1 offset=-96 imm=0
#line 202 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=89 dst=r1 src=r0 offset=0 imm=1279349317
#line 202 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=91 dst=r10 src=r1 offset=-104 imm=0
#line 202 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=92 dst=r1 src=r0 offset=0 imm=1953719636
#line 202 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=94 dst=r10 src=r1 offset=-112 imm=0
#line 202 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=95 dst=r3 src=r6 offset=0 imm=0
#line 202 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=96 dst=r3 src=r0 offset=0 imm=32
#line 202 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=97 dst=r3 src=r0 offset=0 imm=32
#line 202 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=98 dst=r1 src=r10 offset=0 imm=0
#line 202 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=99 dst=r1 src=r0 offset=0 imm=-112
#line 202 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=100 dst=r2 src=r0 offset=0 imm=38
#line 202 "sample/undocked/map.c"
    r2 = IMMEDIATE(38);
label_7:
    // EBPF_OP_CALL pc=101 dst=r0 src=r0 offset=0 imm=13
#line 202 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 202 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 202 "sample/undocked/map.c"
        return 0;
#line 202 "sample/undocked/map.c"
    }
label_8:
    // EBPF_OP_MOV64_REG pc=102 dst=r0 src=r6 offset=0 imm=0
#line 215 "sample/undocked/map.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=103 dst=r0 src=r0 offset=0 imm=0
#line 215 "sample/undocked/map.c"
    return r0;
label_9:
    // EBPF_OP_MOV64_REG pc=104 dst=r2 src=r10 offset=0 imm=0
#line 215 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=105 dst=r2 src=r0 offset=0 imm=-4
#line 92 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=106 dst=r3 src=r10 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=107 dst=r3 src=r0 offset=0 imm=-8
#line 92 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=108 dst=r1 src=r1 offset=0 imm=1
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=110 dst=r4 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=111 dst=r0 src=r0 offset=0 imm=2
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 92 "sample/undocked/map.c"
        return 0;
#line 92 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=112 dst=r6 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=113 dst=r3 src=r6 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=114 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=115 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=116 dst=r3 src=r0 offset=1 imm=-1
#line 93 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_10;
#line 93 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=117 dst=r0 src=r0 offset=-101 imm=0
#line 93 "sample/undocked/map.c"
    goto label_1;
label_10:
    // EBPF_OP_MOV64_REG pc=118 dst=r2 src=r10 offset=0 imm=0
#line 93 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=119 dst=r2 src=r0 offset=0 imm=-4
#line 103 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=120 dst=r1 src=r1 offset=0 imm=1
#line 103 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=122 dst=r0 src=r0 offset=0 imm=4
#line 103 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 103 "sample/undocked/map.c"
    if ((runtime_context->helper_data[5].tail_call) && (r0 == 0)) {
#line 103 "sample/undocked/map.c"
        return 0;
#line 103 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=123 dst=r0 src=r0 offset=23 imm=0
#line 104 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 104 "sample/undocked/map.c"
        goto label_11;
#line 104 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=124 dst=r1 src=r0 offset=0 imm=0
#line 104 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=125 dst=r10 src=r1 offset=-68 imm=0
#line 105 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=126 dst=r1 src=r0 offset=0 imm=1280070990
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(1280070990);
    // EBPF_OP_STXW pc=127 dst=r10 src=r1 offset=-72 imm=0
#line 105 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=128 dst=r1 src=r0 offset=0 imm=1920300133
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)2334102031925867621;
    // EBPF_OP_STXDW pc=130 dst=r10 src=r1 offset=-80 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=131 dst=r1 src=r0 offset=0 imm=1818582885
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8223693201956233061;
    // EBPF_OP_STXDW pc=133 dst=r10 src=r1 offset=-88 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=134 dst=r1 src=r0 offset=0 imm=1683973230
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8387229063778886766;
    // EBPF_OP_STXDW pc=136 dst=r10 src=r1 offset=-96 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=137 dst=r1 src=r0 offset=0 imm=1802465132
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)7016450394082471788;
    // EBPF_OP_STXDW pc=139 dst=r10 src=r1 offset=-104 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=140 dst=r1 src=r0 offset=0 imm=1600548962
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=142 dst=r10 src=r1 offset=-112 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=143 dst=r1 src=r10 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=144 dst=r1 src=r0 offset=0 imm=-112
#line 105 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=145 dst=r2 src=r0 offset=0 imm=45
#line 105 "sample/undocked/map.c"
    r2 = IMMEDIATE(45);
    // EBPF_OP_JA pc=146 dst=r0 src=r0 offset=-98 imm=0
#line 105 "sample/undocked/map.c"
    goto label_3;
label_11:
    // EBPF_OP_MOV64_IMM pc=147 dst=r1 src=r0 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=148 dst=r10 src=r1 offset=-4 imm=0
#line 70 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=149 dst=r1 src=r0 offset=0 imm=1
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=150 dst=r10 src=r1 offset=-8 imm=0
#line 71 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=151 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=152 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=153 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=154 dst=r3 src=r0 offset=0 imm=-8
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=155 dst=r1 src=r1 offset=0 imm=2
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=157 dst=r4 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=158 dst=r0 src=r0 offset=0 imm=2
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 74 "sample/undocked/map.c"
        return 0;
#line 74 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=159 dst=r6 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=160 dst=r3 src=r6 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=161 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=162 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=163 dst=r3 src=r0 offset=9 imm=-1
#line 75 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 75 "sample/undocked/map.c"
        goto label_13;
#line 75 "sample/undocked/map.c"
    }
label_12:
    // EBPF_OP_LDDW pc=164 dst=r1 src=r0 offset=0 imm=1684369010
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=166 dst=r10 src=r1 offset=-88 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=167 dst=r1 src=r0 offset=0 imm=544040300
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=169 dst=r10 src=r1 offset=-96 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=170 dst=r1 src=r0 offset=0 imm=1633972341
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=172 dst=r0 src=r0 offset=45 imm=0
#line 75 "sample/undocked/map.c"
    goto label_16;
label_13:
    // EBPF_OP_MOV64_REG pc=173 dst=r2 src=r10 offset=0 imm=0
#line 75 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=174 dst=r2 src=r0 offset=0 imm=-4
#line 80 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=175 dst=r1 src=r1 offset=0 imm=2
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=177 dst=r0 src=r0 offset=0 imm=1
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 80 "sample/undocked/map.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 80 "sample/undocked/map.c"
        return 0;
#line 80 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=178 dst=r0 src=r0 offset=21 imm=0
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_15;
#line 81 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=179 dst=r1 src=r0 offset=0 imm=76
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=180 dst=r10 src=r1 offset=-80 imm=0
#line 82 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=181 dst=r1 src=r0 offset=0 imm=1684369010
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=183 dst=r10 src=r1 offset=-88 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=184 dst=r1 src=r0 offset=0 imm=544040300
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=186 dst=r10 src=r1 offset=-96 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=187 dst=r1 src=r0 offset=0 imm=1802465132
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=189 dst=r10 src=r1 offset=-104 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=190 dst=r1 src=r0 offset=0 imm=1600548962
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=192 dst=r10 src=r1 offset=-112 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=193 dst=r1 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=194 dst=r1 src=r0 offset=0 imm=-112
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=195 dst=r2 src=r0 offset=0 imm=34
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
label_14:
    // EBPF_OP_CALL pc=196 dst=r0 src=r0 offset=0 imm=12
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 82 "sample/undocked/map.c"
        return 0;
#line 82 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=197 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/undocked/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=199 dst=r0 src=r0 offset=26 imm=0
#line 82 "sample/undocked/map.c"
    goto label_17;
label_15:
    // EBPF_OP_MOV64_REG pc=200 dst=r2 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=201 dst=r2 src=r0 offset=0 imm=-4
#line 86 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=202 dst=r1 src=r1 offset=0 imm=2
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=204 dst=r0 src=r0 offset=0 imm=3
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 86 "sample/undocked/map.c"
        return 0;
#line 86 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=205 dst=r6 src=r0 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=206 dst=r3 src=r6 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=207 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=208 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=209 dst=r3 src=r0 offset=42 imm=-1
#line 87 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_18;
#line 87 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=210 dst=r1 src=r0 offset=0 imm=1684369010
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=212 dst=r10 src=r1 offset=-88 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=213 dst=r1 src=r0 offset=0 imm=544040300
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=215 dst=r10 src=r1 offset=-96 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=216 dst=r1 src=r0 offset=0 imm=1701602660
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
label_16:
    // EBPF_OP_STXDW pc=218 dst=r10 src=r1 offset=-104 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=219 dst=r1 src=r0 offset=0 imm=1600548962
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=221 dst=r10 src=r1 offset=-112 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=222 dst=r1 src=r10 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=223 dst=r1 src=r0 offset=0 imm=-112
#line 88 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=224 dst=r2 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=225 dst=r0 src=r0 offset=0 imm=13
#line 88 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/map.c"
        return 0;
#line 88 "sample/undocked/map.c"
    }
label_17:
    // EBPF_OP_MOV64_IMM pc=226 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=227 dst=r10 src=r1 offset=-68 imm=0
#line 203 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=228 dst=r1 src=r0 offset=0 imm=1680154724
#line 203 "sample/undocked/map.c"
    r1 = IMMEDIATE(1680154724);
    // EBPF_OP_STXW pc=229 dst=r10 src=r1 offset=-72 imm=0
#line 203 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=230 dst=r1 src=r0 offset=0 imm=1952805408
#line 203 "sample/undocked/map.c"
    r1 = (uint64_t)7308905094058439200;
    // EBPF_OP_STXDW pc=232 dst=r10 src=r1 offset=-80 imm=0
#line 203 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=233 dst=r1 src=r0 offset=0 imm=1599426627
#line 203 "sample/undocked/map.c"
    r1 = (uint64_t)5211580972890673219;
    // EBPF_OP_STXDW pc=235 dst=r10 src=r1 offset=-88 imm=0
#line 203 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=236 dst=r1 src=r0 offset=0 imm=1885433120
#line 203 "sample/undocked/map.c"
    r1 = (uint64_t)5928232584757734688;
    // EBPF_OP_STXDW pc=238 dst=r10 src=r1 offset=-96 imm=0
#line 203 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=239 dst=r1 src=r0 offset=0 imm=1279349317
#line 203 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=241 dst=r10 src=r1 offset=-104 imm=0
#line 203 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=242 dst=r1 src=r0 offset=0 imm=1953719636
#line 203 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=244 dst=r10 src=r1 offset=-112 imm=0
#line 203 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=245 dst=r3 src=r6 offset=0 imm=0
#line 203 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=246 dst=r3 src=r0 offset=0 imm=32
#line 203 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=247 dst=r3 src=r0 offset=0 imm=32
#line 203 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=248 dst=r1 src=r10 offset=0 imm=0
#line 203 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=249 dst=r1 src=r0 offset=0 imm=-112
#line 203 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=250 dst=r2 src=r0 offset=0 imm=45
#line 203 "sample/undocked/map.c"
    r2 = IMMEDIATE(45);
    // EBPF_OP_JA pc=251 dst=r0 src=r0 offset=-151 imm=0
#line 203 "sample/undocked/map.c"
    goto label_7;
label_18:
    // EBPF_OP_MOV64_REG pc=252 dst=r2 src=r10 offset=0 imm=0
#line 203 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=253 dst=r2 src=r0 offset=0 imm=-4
#line 92 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=254 dst=r3 src=r10 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=255 dst=r3 src=r0 offset=0 imm=-8
#line 92 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=256 dst=r1 src=r1 offset=0 imm=2
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=258 dst=r4 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=259 dst=r0 src=r0 offset=0 imm=2
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 92 "sample/undocked/map.c"
        return 0;
#line 92 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=260 dst=r6 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=261 dst=r3 src=r6 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=262 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=263 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=264 dst=r3 src=r0 offset=1 imm=-1
#line 93 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_19;
#line 93 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=265 dst=r0 src=r0 offset=-102 imm=0
#line 93 "sample/undocked/map.c"
    goto label_12;
label_19:
    // EBPF_OP_MOV64_REG pc=266 dst=r2 src=r10 offset=0 imm=0
#line 93 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=267 dst=r2 src=r0 offset=0 imm=-4
#line 103 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=268 dst=r1 src=r1 offset=0 imm=2
#line 103 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=270 dst=r0 src=r0 offset=0 imm=4
#line 103 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 103 "sample/undocked/map.c"
    if ((runtime_context->helper_data[5].tail_call) && (r0 == 0)) {
#line 103 "sample/undocked/map.c"
        return 0;
#line 103 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=271 dst=r0 src=r0 offset=23 imm=0
#line 104 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 104 "sample/undocked/map.c"
        goto label_20;
#line 104 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=272 dst=r1 src=r0 offset=0 imm=0
#line 104 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=273 dst=r10 src=r1 offset=-68 imm=0
#line 105 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=274 dst=r1 src=r0 offset=0 imm=1280070990
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(1280070990);
    // EBPF_OP_STXW pc=275 dst=r10 src=r1 offset=-72 imm=0
#line 105 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=276 dst=r1 src=r0 offset=0 imm=1920300133
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)2334102031925867621;
    // EBPF_OP_STXDW pc=278 dst=r10 src=r1 offset=-80 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=279 dst=r1 src=r0 offset=0 imm=1818582885
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8223693201956233061;
    // EBPF_OP_STXDW pc=281 dst=r10 src=r1 offset=-88 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=282 dst=r1 src=r0 offset=0 imm=1683973230
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8387229063778886766;
    // EBPF_OP_STXDW pc=284 dst=r10 src=r1 offset=-96 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=285 dst=r1 src=r0 offset=0 imm=1802465132
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)7016450394082471788;
    // EBPF_OP_STXDW pc=287 dst=r10 src=r1 offset=-104 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=288 dst=r1 src=r0 offset=0 imm=1600548962
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=290 dst=r10 src=r1 offset=-112 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=291 dst=r1 src=r10 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=292 dst=r1 src=r0 offset=0 imm=-112
#line 105 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=293 dst=r2 src=r0 offset=0 imm=45
#line 105 "sample/undocked/map.c"
    r2 = IMMEDIATE(45);
    // EBPF_OP_JA pc=294 dst=r0 src=r0 offset=-99 imm=0
#line 105 "sample/undocked/map.c"
    goto label_14;
label_20:
    // EBPF_OP_MOV64_IMM pc=295 dst=r1 src=r0 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=296 dst=r10 src=r1 offset=-4 imm=0
#line 70 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=297 dst=r1 src=r0 offset=0 imm=1
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=298 dst=r10 src=r1 offset=-8 imm=0
#line 71 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=299 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=300 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=301 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=302 dst=r3 src=r0 offset=0 imm=-8
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=303 dst=r1 src=r1 offset=0 imm=3
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_MOV64_IMM pc=305 dst=r4 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=306 dst=r0 src=r0 offset=0 imm=2
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 74 "sample/undocked/map.c"
        return 0;
#line 74 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=307 dst=r6 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=308 dst=r3 src=r6 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=309 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=310 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=311 dst=r3 src=r0 offset=9 imm=-1
#line 75 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 75 "sample/undocked/map.c"
        goto label_22;
#line 75 "sample/undocked/map.c"
    }
label_21:
    // EBPF_OP_LDDW pc=312 dst=r1 src=r0 offset=0 imm=1684369010
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=314 dst=r10 src=r1 offset=-88 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=315 dst=r1 src=r0 offset=0 imm=544040300
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=317 dst=r10 src=r1 offset=-96 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=318 dst=r1 src=r0 offset=0 imm=1633972341
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=320 dst=r0 src=r0 offset=45 imm=0
#line 75 "sample/undocked/map.c"
    goto label_24;
label_22:
    // EBPF_OP_MOV64_REG pc=321 dst=r2 src=r10 offset=0 imm=0
#line 75 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=322 dst=r2 src=r0 offset=0 imm=-4
#line 80 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=323 dst=r1 src=r1 offset=0 imm=3
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_CALL pc=325 dst=r0 src=r0 offset=0 imm=1
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 80 "sample/undocked/map.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 80 "sample/undocked/map.c"
        return 0;
#line 80 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=326 dst=r0 src=r0 offset=21 imm=0
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_23;
#line 81 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=327 dst=r1 src=r0 offset=0 imm=76
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=328 dst=r10 src=r1 offset=-80 imm=0
#line 82 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=329 dst=r1 src=r0 offset=0 imm=1684369010
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=331 dst=r10 src=r1 offset=-88 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=332 dst=r1 src=r0 offset=0 imm=544040300
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=334 dst=r10 src=r1 offset=-96 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=335 dst=r1 src=r0 offset=0 imm=1802465132
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=337 dst=r10 src=r1 offset=-104 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=338 dst=r1 src=r0 offset=0 imm=1600548962
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=340 dst=r10 src=r1 offset=-112 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=341 dst=r1 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=342 dst=r1 src=r0 offset=0 imm=-112
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=343 dst=r2 src=r0 offset=0 imm=34
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
    // EBPF_OP_CALL pc=344 dst=r0 src=r0 offset=0 imm=12
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 82 "sample/undocked/map.c"
        return 0;
#line 82 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=345 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/undocked/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=347 dst=r0 src=r0 offset=26 imm=0
#line 82 "sample/undocked/map.c"
    goto label_25;
label_23:
    // EBPF_OP_MOV64_REG pc=348 dst=r2 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=349 dst=r2 src=r0 offset=0 imm=-4
#line 86 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=350 dst=r1 src=r1 offset=0 imm=3
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_CALL pc=352 dst=r0 src=r0 offset=0 imm=3
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 86 "sample/undocked/map.c"
        return 0;
#line 86 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=353 dst=r6 src=r0 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=354 dst=r3 src=r6 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=355 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=356 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=357 dst=r3 src=r0 offset=41 imm=-1
#line 87 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_26;
#line 87 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=358 dst=r1 src=r0 offset=0 imm=1684369010
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=360 dst=r10 src=r1 offset=-88 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=361 dst=r1 src=r0 offset=0 imm=544040300
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=363 dst=r10 src=r1 offset=-96 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=364 dst=r1 src=r0 offset=0 imm=1701602660
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
label_24:
    // EBPF_OP_STXDW pc=366 dst=r10 src=r1 offset=-104 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=367 dst=r1 src=r0 offset=0 imm=1600548962
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=369 dst=r10 src=r1 offset=-112 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=370 dst=r1 src=r10 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=371 dst=r1 src=r0 offset=0 imm=-112
#line 88 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=372 dst=r2 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=373 dst=r0 src=r0 offset=0 imm=13
#line 88 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/map.c"
        return 0;
#line 88 "sample/undocked/map.c"
    }
label_25:
    // EBPF_OP_MOV64_IMM pc=374 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=375 dst=r10 src=r1 offset=-74 imm=0
#line 204 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-74)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=376 dst=r1 src=r0 offset=0 imm=25637
#line 204 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=377 dst=r10 src=r1 offset=-76 imm=0
#line 204 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-76)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=378 dst=r1 src=r0 offset=0 imm=543450478
#line 204 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=379 dst=r10 src=r1 offset=-80 imm=0
#line 204 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=380 dst=r1 src=r0 offset=0 imm=1914722625
#line 204 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654172993;
    // EBPF_OP_STXDW pc=382 dst=r10 src=r1 offset=-88 imm=0
#line 204 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=383 dst=r1 src=r0 offset=0 imm=1885433120
#line 204 "sample/undocked/map.c"
    r1 = (uint64_t)5931875266780556576;
    // EBPF_OP_STXDW pc=385 dst=r10 src=r1 offset=-96 imm=0
#line 204 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=386 dst=r1 src=r0 offset=0 imm=1279349317
#line 204 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=388 dst=r10 src=r1 offset=-104 imm=0
#line 204 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=389 dst=r1 src=r0 offset=0 imm=1953719636
#line 204 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=391 dst=r10 src=r1 offset=-112 imm=0
#line 204 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=392 dst=r3 src=r6 offset=0 imm=0
#line 204 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=393 dst=r3 src=r0 offset=0 imm=32
#line 204 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=394 dst=r3 src=r0 offset=0 imm=32
#line 204 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=395 dst=r1 src=r10 offset=0 imm=0
#line 204 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=396 dst=r1 src=r0 offset=0 imm=-112
#line 204 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=397 dst=r2 src=r0 offset=0 imm=39
#line 204 "sample/undocked/map.c"
    r2 = IMMEDIATE(39);
    // EBPF_OP_JA pc=398 dst=r0 src=r0 offset=-298 imm=0
#line 204 "sample/undocked/map.c"
    goto label_7;
label_26:
    // EBPF_OP_MOV64_REG pc=399 dst=r2 src=r10 offset=0 imm=0
#line 204 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=400 dst=r2 src=r0 offset=0 imm=-4
#line 92 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=401 dst=r3 src=r10 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=402 dst=r3 src=r0 offset=0 imm=-8
#line 92 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=403 dst=r7 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=404 dst=r1 src=r1 offset=0 imm=3
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_MOV64_IMM pc=406 dst=r4 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=407 dst=r0 src=r0 offset=0 imm=2
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 92 "sample/undocked/map.c"
        return 0;
#line 92 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=408 dst=r6 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=409 dst=r3 src=r6 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=410 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=411 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=412 dst=r3 src=r0 offset=1 imm=-1
#line 93 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_27;
#line 93 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=413 dst=r0 src=r0 offset=-102 imm=0
#line 93 "sample/undocked/map.c"
    goto label_21;
label_27:
    // EBPF_OP_STXW pc=414 dst=r10 src=r7 offset=-4 imm=0
#line 70 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=415 dst=r1 src=r0 offset=0 imm=1
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=416 dst=r10 src=r1 offset=-8 imm=0
#line 71 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=417 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=418 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=419 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=420 dst=r3 src=r0 offset=0 imm=-8
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=421 dst=r1 src=r1 offset=0 imm=4
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_MOV64_IMM pc=423 dst=r4 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=424 dst=r0 src=r0 offset=0 imm=2
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 74 "sample/undocked/map.c"
        return 0;
#line 74 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=425 dst=r6 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=426 dst=r3 src=r6 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=427 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=428 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=429 dst=r7 src=r3 offset=59 imm=0
#line 75 "sample/undocked/map.c"
    if ((int64_t)r7 > (int64_t)r3) {
#line 75 "sample/undocked/map.c"
        goto label_30;
#line 75 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=430 dst=r2 src=r10 offset=0 imm=0
#line 75 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=431 dst=r2 src=r0 offset=0 imm=-4
#line 80 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=432 dst=r1 src=r1 offset=0 imm=4
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_CALL pc=434 dst=r0 src=r0 offset=0 imm=1
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 80 "sample/undocked/map.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 80 "sample/undocked/map.c"
        return 0;
#line 80 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=435 dst=r0 src=r0 offset=21 imm=0
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_28;
#line 81 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=436 dst=r1 src=r0 offset=0 imm=76
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=437 dst=r10 src=r1 offset=-80 imm=0
#line 82 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=438 dst=r1 src=r0 offset=0 imm=1684369010
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=440 dst=r10 src=r1 offset=-88 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=441 dst=r1 src=r0 offset=0 imm=544040300
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=443 dst=r10 src=r1 offset=-96 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=444 dst=r1 src=r0 offset=0 imm=1802465132
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=446 dst=r10 src=r1 offset=-104 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=447 dst=r1 src=r0 offset=0 imm=1600548962
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=449 dst=r10 src=r1 offset=-112 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=450 dst=r1 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=451 dst=r1 src=r0 offset=0 imm=-112
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=452 dst=r2 src=r0 offset=0 imm=34
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
    // EBPF_OP_CALL pc=453 dst=r0 src=r0 offset=0 imm=12
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 82 "sample/undocked/map.c"
        return 0;
#line 82 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=454 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/undocked/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=456 dst=r0 src=r0 offset=48 imm=0
#line 82 "sample/undocked/map.c"
    goto label_32;
label_28:
    // EBPF_OP_MOV64_REG pc=457 dst=r2 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=458 dst=r2 src=r0 offset=0 imm=-4
#line 86 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=459 dst=r1 src=r1 offset=0 imm=4
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_CALL pc=461 dst=r0 src=r0 offset=0 imm=3
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 86 "sample/undocked/map.c"
        return 0;
#line 86 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=462 dst=r6 src=r0 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=463 dst=r3 src=r6 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=464 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=465 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=466 dst=r3 src=r0 offset=9 imm=-1
#line 87 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_29;
#line 87 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=467 dst=r1 src=r0 offset=0 imm=1684369010
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=469 dst=r10 src=r1 offset=-88 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=470 dst=r1 src=r0 offset=0 imm=544040300
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=472 dst=r10 src=r1 offset=-96 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=473 dst=r1 src=r0 offset=0 imm=1701602660
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
    // EBPF_OP_JA pc=475 dst=r0 src=r0 offset=21 imm=0
#line 88 "sample/undocked/map.c"
    goto label_31;
label_29:
    // EBPF_OP_MOV64_REG pc=476 dst=r2 src=r10 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=477 dst=r2 src=r0 offset=0 imm=-4
#line 92 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=478 dst=r3 src=r10 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=479 dst=r3 src=r0 offset=0 imm=-8
#line 92 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=480 dst=r1 src=r1 offset=0 imm=4
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_MOV64_IMM pc=482 dst=r4 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=483 dst=r0 src=r0 offset=0 imm=2
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 92 "sample/undocked/map.c"
        return 0;
#line 92 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=484 dst=r6 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=485 dst=r3 src=r6 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=486 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=487 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=488 dst=r3 src=r0 offset=42 imm=-1
#line 93 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_33;
#line 93 "sample/undocked/map.c"
    }
label_30:
    // EBPF_OP_LDDW pc=489 dst=r1 src=r0 offset=0 imm=1684369010
#line 93 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=491 dst=r10 src=r1 offset=-88 imm=0
#line 93 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=492 dst=r1 src=r0 offset=0 imm=544040300
#line 93 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=494 dst=r10 src=r1 offset=-96 imm=0
#line 93 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=495 dst=r1 src=r0 offset=0 imm=1633972341
#line 93 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
label_31:
    // EBPF_OP_STXDW pc=497 dst=r10 src=r1 offset=-104 imm=0
#line 93 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=498 dst=r1 src=r0 offset=0 imm=1600548962
#line 93 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=500 dst=r10 src=r1 offset=-112 imm=0
#line 93 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=501 dst=r1 src=r10 offset=0 imm=0
#line 93 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=502 dst=r1 src=r0 offset=0 imm=-112
#line 93 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=503 dst=r2 src=r0 offset=0 imm=32
#line 93 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=504 dst=r0 src=r0 offset=0 imm=13
#line 93 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 93 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 93 "sample/undocked/map.c"
        return 0;
#line 93 "sample/undocked/map.c"
    }
label_32:
    // EBPF_OP_MOV64_IMM pc=505 dst=r1 src=r0 offset=0 imm=100
#line 93 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=506 dst=r10 src=r1 offset=-68 imm=0
#line 205 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=507 dst=r1 src=r0 offset=0 imm=622879845
#line 205 "sample/undocked/map.c"
    r1 = IMMEDIATE(622879845);
    // EBPF_OP_STXW pc=508 dst=r10 src=r1 offset=-72 imm=0
#line 205 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=509 dst=r1 src=r0 offset=0 imm=1701978201
#line 205 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722073;
    // EBPF_OP_STXDW pc=511 dst=r10 src=r1 offset=-80 imm=0
#line 205 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=512 dst=r1 src=r0 offset=0 imm=1599426627
#line 205 "sample/undocked/map.c"
    r1 = (uint64_t)4706915001281368131;
    // EBPF_OP_STXDW pc=514 dst=r10 src=r1 offset=-88 imm=0
#line 205 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=515 dst=r1 src=r0 offset=0 imm=1885433120
#line 205 "sample/undocked/map.c"
    r1 = (uint64_t)5928232584757734688;
    // EBPF_OP_STXDW pc=517 dst=r10 src=r1 offset=-96 imm=0
#line 205 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=518 dst=r1 src=r0 offset=0 imm=1279349317
#line 205 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=520 dst=r10 src=r1 offset=-104 imm=0
#line 205 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=521 dst=r1 src=r0 offset=0 imm=1953719636
#line 205 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=523 dst=r10 src=r1 offset=-112 imm=0
#line 205 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=524 dst=r3 src=r6 offset=0 imm=0
#line 205 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=525 dst=r3 src=r0 offset=0 imm=32
#line 205 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=526 dst=r3 src=r0 offset=0 imm=32
#line 205 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=527 dst=r1 src=r10 offset=0 imm=0
#line 205 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=528 dst=r1 src=r0 offset=0 imm=-112
#line 205 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=529 dst=r2 src=r0 offset=0 imm=46
#line 205 "sample/undocked/map.c"
    r2 = IMMEDIATE(46);
    // EBPF_OP_JA pc=530 dst=r0 src=r0 offset=-430 imm=0
#line 205 "sample/undocked/map.c"
    goto label_7;
label_33:
    // EBPF_OP_STXW pc=531 dst=r10 src=r7 offset=-4 imm=0
#line 70 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=532 dst=r1 src=r0 offset=0 imm=1
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=533 dst=r10 src=r1 offset=-8 imm=0
#line 71 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=534 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=535 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=536 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=537 dst=r3 src=r0 offset=0 imm=-8
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=538 dst=r1 src=r1 offset=0 imm=5
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_IMM pc=540 dst=r4 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=541 dst=r0 src=r0 offset=0 imm=2
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 74 "sample/undocked/map.c"
        return 0;
#line 74 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=542 dst=r6 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=543 dst=r3 src=r6 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=544 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=545 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=546 dst=r3 src=r0 offset=9 imm=-1
#line 75 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 75 "sample/undocked/map.c"
        goto label_35;
#line 75 "sample/undocked/map.c"
    }
label_34:
    // EBPF_OP_LDDW pc=547 dst=r1 src=r0 offset=0 imm=1684369010
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=549 dst=r10 src=r1 offset=-88 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=550 dst=r1 src=r0 offset=0 imm=544040300
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=552 dst=r10 src=r1 offset=-96 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=553 dst=r1 src=r0 offset=0 imm=1633972341
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=555 dst=r0 src=r0 offset=45 imm=0
#line 75 "sample/undocked/map.c"
    goto label_38;
label_35:
    // EBPF_OP_MOV64_REG pc=556 dst=r2 src=r10 offset=0 imm=0
#line 75 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=557 dst=r2 src=r0 offset=0 imm=-4
#line 80 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=558 dst=r1 src=r1 offset=0 imm=5
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_CALL pc=560 dst=r0 src=r0 offset=0 imm=1
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 80 "sample/undocked/map.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 80 "sample/undocked/map.c"
        return 0;
#line 80 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=561 dst=r0 src=r0 offset=21 imm=0
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_37;
#line 81 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=562 dst=r1 src=r0 offset=0 imm=76
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=563 dst=r10 src=r1 offset=-80 imm=0
#line 82 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=564 dst=r1 src=r0 offset=0 imm=1684369010
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=566 dst=r10 src=r1 offset=-88 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=567 dst=r1 src=r0 offset=0 imm=544040300
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=569 dst=r10 src=r1 offset=-96 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=570 dst=r1 src=r0 offset=0 imm=1802465132
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=572 dst=r10 src=r1 offset=-104 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=573 dst=r1 src=r0 offset=0 imm=1600548962
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=575 dst=r10 src=r1 offset=-112 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=576 dst=r1 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=577 dst=r1 src=r0 offset=0 imm=-112
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=578 dst=r2 src=r0 offset=0 imm=34
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
label_36:
    // EBPF_OP_CALL pc=579 dst=r0 src=r0 offset=0 imm=12
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 82 "sample/undocked/map.c"
        return 0;
#line 82 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=580 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/undocked/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=582 dst=r0 src=r0 offset=26 imm=0
#line 82 "sample/undocked/map.c"
    goto label_39;
label_37:
    // EBPF_OP_MOV64_REG pc=583 dst=r2 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=584 dst=r2 src=r0 offset=0 imm=-4
#line 86 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=585 dst=r1 src=r1 offset=0 imm=5
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_CALL pc=587 dst=r0 src=r0 offset=0 imm=3
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 86 "sample/undocked/map.c"
        return 0;
#line 86 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=588 dst=r6 src=r0 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=589 dst=r3 src=r6 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=590 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=591 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=592 dst=r3 src=r0 offset=40 imm=-1
#line 87 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_40;
#line 87 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=593 dst=r1 src=r0 offset=0 imm=1684369010
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=595 dst=r10 src=r1 offset=-88 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=596 dst=r1 src=r0 offset=0 imm=544040300
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=598 dst=r10 src=r1 offset=-96 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=599 dst=r1 src=r0 offset=0 imm=1701602660
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
label_38:
    // EBPF_OP_STXDW pc=601 dst=r10 src=r1 offset=-104 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=602 dst=r1 src=r0 offset=0 imm=1600548962
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=604 dst=r10 src=r1 offset=-112 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=605 dst=r1 src=r10 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=606 dst=r1 src=r0 offset=0 imm=-112
#line 88 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=607 dst=r2 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=608 dst=r0 src=r0 offset=0 imm=13
#line 88 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/map.c"
        return 0;
#line 88 "sample/undocked/map.c"
    }
label_39:
    // EBPF_OP_MOV64_IMM pc=609 dst=r1 src=r0 offset=0 imm=100
#line 88 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=610 dst=r10 src=r1 offset=-72 imm=0
#line 206 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=611 dst=r1 src=r0 offset=0 imm=1852994932
#line 206 "sample/undocked/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=613 dst=r10 src=r1 offset=-80 imm=0
#line 206 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=614 dst=r1 src=r0 offset=0 imm=1396787295
#line 206 "sample/undocked/map.c"
    r1 = (uint64_t)7309940640182257759;
    // EBPF_OP_STXDW pc=616 dst=r10 src=r1 offset=-88 imm=0
#line 206 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=617 dst=r1 src=r0 offset=0 imm=1885433120
#line 206 "sample/undocked/map.c"
    r1 = (uint64_t)6148060143522245920;
    // EBPF_OP_STXDW pc=619 dst=r10 src=r1 offset=-96 imm=0
#line 206 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=620 dst=r1 src=r0 offset=0 imm=1279349317
#line 206 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=622 dst=r10 src=r1 offset=-104 imm=0
#line 206 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=623 dst=r1 src=r0 offset=0 imm=1953719636
#line 206 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=625 dst=r10 src=r1 offset=-112 imm=0
#line 206 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=626 dst=r3 src=r6 offset=0 imm=0
#line 206 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=627 dst=r3 src=r0 offset=0 imm=32
#line 206 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=628 dst=r3 src=r0 offset=0 imm=32
#line 206 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=629 dst=r1 src=r10 offset=0 imm=0
#line 206 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=630 dst=r1 src=r0 offset=0 imm=-112
#line 206 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=631 dst=r2 src=r0 offset=0 imm=42
#line 206 "sample/undocked/map.c"
    r2 = IMMEDIATE(42);
    // EBPF_OP_JA pc=632 dst=r0 src=r0 offset=-532 imm=0
#line 206 "sample/undocked/map.c"
    goto label_7;
label_40:
    // EBPF_OP_MOV64_REG pc=633 dst=r2 src=r10 offset=0 imm=0
#line 206 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=634 dst=r2 src=r0 offset=0 imm=-4
#line 92 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=635 dst=r3 src=r10 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=636 dst=r3 src=r0 offset=0 imm=-8
#line 92 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=637 dst=r1 src=r1 offset=0 imm=5
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_IMM pc=639 dst=r4 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=640 dst=r0 src=r0 offset=0 imm=2
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 92 "sample/undocked/map.c"
        return 0;
#line 92 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=641 dst=r6 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=642 dst=r3 src=r6 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=643 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=644 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=645 dst=r3 src=r0 offset=1 imm=-1
#line 93 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_41;
#line 93 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=646 dst=r0 src=r0 offset=-100 imm=0
#line 93 "sample/undocked/map.c"
    goto label_34;
label_41:
    // EBPF_OP_MOV64_REG pc=647 dst=r2 src=r10 offset=0 imm=0
#line 93 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=648 dst=r2 src=r0 offset=0 imm=-4
#line 103 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=649 dst=r1 src=r1 offset=0 imm=5
#line 103 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_CALL pc=651 dst=r0 src=r0 offset=0 imm=4
#line 103 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 103 "sample/undocked/map.c"
    if ((runtime_context->helper_data[5].tail_call) && (r0 == 0)) {
#line 103 "sample/undocked/map.c"
        return 0;
#line 103 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=652 dst=r0 src=r0 offset=23 imm=0
#line 104 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 104 "sample/undocked/map.c"
        goto label_42;
#line 104 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=653 dst=r1 src=r0 offset=0 imm=0
#line 104 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=654 dst=r10 src=r1 offset=-68 imm=0
#line 105 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=655 dst=r1 src=r0 offset=0 imm=1280070990
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(1280070990);
    // EBPF_OP_STXW pc=656 dst=r10 src=r1 offset=-72 imm=0
#line 105 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=657 dst=r1 src=r0 offset=0 imm=1920300133
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)2334102031925867621;
    // EBPF_OP_STXDW pc=659 dst=r10 src=r1 offset=-80 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=660 dst=r1 src=r0 offset=0 imm=1818582885
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8223693201956233061;
    // EBPF_OP_STXDW pc=662 dst=r10 src=r1 offset=-88 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=663 dst=r1 src=r0 offset=0 imm=1683973230
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8387229063778886766;
    // EBPF_OP_STXDW pc=665 dst=r10 src=r1 offset=-96 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=666 dst=r1 src=r0 offset=0 imm=1802465132
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)7016450394082471788;
    // EBPF_OP_STXDW pc=668 dst=r10 src=r1 offset=-104 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=669 dst=r1 src=r0 offset=0 imm=1600548962
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=671 dst=r10 src=r1 offset=-112 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=672 dst=r1 src=r10 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=673 dst=r1 src=r0 offset=0 imm=-112
#line 105 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=674 dst=r2 src=r0 offset=0 imm=45
#line 105 "sample/undocked/map.c"
    r2 = IMMEDIATE(45);
    // EBPF_OP_JA pc=675 dst=r0 src=r0 offset=-97 imm=0
#line 105 "sample/undocked/map.c"
    goto label_36;
label_42:
    // EBPF_OP_MOV64_IMM pc=676 dst=r1 src=r0 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=677 dst=r10 src=r1 offset=-4 imm=0
#line 70 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=678 dst=r1 src=r0 offset=0 imm=1
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=679 dst=r10 src=r1 offset=-8 imm=0
#line 71 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=680 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=681 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=682 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=683 dst=r3 src=r0 offset=0 imm=-8
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=684 dst=r1 src=r1 offset=0 imm=6
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_IMM pc=686 dst=r4 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=687 dst=r0 src=r0 offset=0 imm=2
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 74 "sample/undocked/map.c"
        return 0;
#line 74 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=688 dst=r6 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=689 dst=r3 src=r6 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=690 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=691 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=692 dst=r3 src=r0 offset=9 imm=-1
#line 75 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 75 "sample/undocked/map.c"
        goto label_44;
#line 75 "sample/undocked/map.c"
    }
label_43:
    // EBPF_OP_LDDW pc=693 dst=r1 src=r0 offset=0 imm=1684369010
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=695 dst=r10 src=r1 offset=-88 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=696 dst=r1 src=r0 offset=0 imm=544040300
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=698 dst=r10 src=r1 offset=-96 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=699 dst=r1 src=r0 offset=0 imm=1633972341
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=701 dst=r0 src=r0 offset=45 imm=0
#line 75 "sample/undocked/map.c"
    goto label_47;
label_44:
    // EBPF_OP_MOV64_REG pc=702 dst=r2 src=r10 offset=0 imm=0
#line 75 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=703 dst=r2 src=r0 offset=0 imm=-4
#line 80 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=704 dst=r1 src=r1 offset=0 imm=6
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_CALL pc=706 dst=r0 src=r0 offset=0 imm=1
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 80 "sample/undocked/map.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 80 "sample/undocked/map.c"
        return 0;
#line 80 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=707 dst=r0 src=r0 offset=21 imm=0
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_46;
#line 81 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=708 dst=r1 src=r0 offset=0 imm=76
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=709 dst=r10 src=r1 offset=-80 imm=0
#line 82 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=710 dst=r1 src=r0 offset=0 imm=1684369010
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=712 dst=r10 src=r1 offset=-88 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=713 dst=r1 src=r0 offset=0 imm=544040300
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=715 dst=r10 src=r1 offset=-96 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=716 dst=r1 src=r0 offset=0 imm=1802465132
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=718 dst=r10 src=r1 offset=-104 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=719 dst=r1 src=r0 offset=0 imm=1600548962
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=721 dst=r10 src=r1 offset=-112 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=722 dst=r1 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=723 dst=r1 src=r0 offset=0 imm=-112
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=724 dst=r2 src=r0 offset=0 imm=34
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
label_45:
    // EBPF_OP_CALL pc=725 dst=r0 src=r0 offset=0 imm=12
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 82 "sample/undocked/map.c"
        return 0;
#line 82 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=726 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/undocked/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=728 dst=r0 src=r0 offset=26 imm=0
#line 82 "sample/undocked/map.c"
    goto label_48;
label_46:
    // EBPF_OP_MOV64_REG pc=729 dst=r2 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=730 dst=r2 src=r0 offset=0 imm=-4
#line 86 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=731 dst=r1 src=r1 offset=0 imm=6
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_CALL pc=733 dst=r0 src=r0 offset=0 imm=3
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 86 "sample/undocked/map.c"
        return 0;
#line 86 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=734 dst=r6 src=r0 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=735 dst=r3 src=r6 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=736 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=737 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=738 dst=r3 src=r0 offset=43 imm=-1
#line 87 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_49;
#line 87 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=739 dst=r1 src=r0 offset=0 imm=1684369010
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=741 dst=r10 src=r1 offset=-88 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=742 dst=r1 src=r0 offset=0 imm=544040300
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=744 dst=r10 src=r1 offset=-96 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=745 dst=r1 src=r0 offset=0 imm=1701602660
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
label_47:
    // EBPF_OP_STXDW pc=747 dst=r10 src=r1 offset=-104 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=748 dst=r1 src=r0 offset=0 imm=1600548962
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=750 dst=r10 src=r1 offset=-112 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=751 dst=r1 src=r10 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=752 dst=r1 src=r0 offset=0 imm=-112
#line 88 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=753 dst=r2 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=754 dst=r0 src=r0 offset=0 imm=13
#line 88 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/map.c"
        return 0;
#line 88 "sample/undocked/map.c"
    }
label_48:
    // EBPF_OP_MOV64_IMM pc=755 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=756 dst=r10 src=r1 offset=-64 imm=0
#line 207 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=757 dst=r1 src=r0 offset=0 imm=1701737077
#line 207 "sample/undocked/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=759 dst=r10 src=r1 offset=-72 imm=0
#line 207 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=760 dst=r1 src=r0 offset=0 imm=1213415752
#line 207 "sample/undocked/map.c"
    r1 = (uint64_t)8387235364025352520;
    // EBPF_OP_STXDW pc=762 dst=r10 src=r1 offset=-80 imm=0
#line 207 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=763 dst=r1 src=r0 offset=0 imm=1380274271
#line 207 "sample/undocked/map.c"
    r1 = (uint64_t)6869485056696864863;
    // EBPF_OP_STXDW pc=765 dst=r10 src=r1 offset=-88 imm=0
#line 207 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=766 dst=r1 src=r0 offset=0 imm=1885433120
#line 207 "sample/undocked/map.c"
    r1 = (uint64_t)6148060143522245920;
    // EBPF_OP_STXDW pc=768 dst=r10 src=r1 offset=-96 imm=0
#line 207 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=769 dst=r1 src=r0 offset=0 imm=1279349317
#line 207 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=771 dst=r10 src=r1 offset=-104 imm=0
#line 207 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=772 dst=r1 src=r0 offset=0 imm=1953719636
#line 207 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=774 dst=r10 src=r1 offset=-112 imm=0
#line 207 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=775 dst=r3 src=r6 offset=0 imm=0
#line 207 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=776 dst=r3 src=r0 offset=0 imm=32
#line 207 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=777 dst=r3 src=r0 offset=0 imm=32
#line 207 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=778 dst=r1 src=r10 offset=0 imm=0
#line 207 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=779 dst=r1 src=r0 offset=0 imm=-112
#line 207 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=780 dst=r2 src=r0 offset=0 imm=49
#line 207 "sample/undocked/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=781 dst=r0 src=r0 offset=-681 imm=0
#line 207 "sample/undocked/map.c"
    goto label_7;
label_49:
    // EBPF_OP_MOV64_REG pc=782 dst=r2 src=r10 offset=0 imm=0
#line 207 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=783 dst=r2 src=r0 offset=0 imm=-4
#line 92 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=784 dst=r3 src=r10 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=785 dst=r3 src=r0 offset=0 imm=-8
#line 92 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=786 dst=r1 src=r1 offset=0 imm=6
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_IMM pc=788 dst=r4 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=789 dst=r0 src=r0 offset=0 imm=2
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 92 "sample/undocked/map.c"
        return 0;
#line 92 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=790 dst=r6 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=791 dst=r3 src=r6 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=792 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=793 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=794 dst=r3 src=r0 offset=1 imm=-1
#line 93 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_50;
#line 93 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=795 dst=r0 src=r0 offset=-103 imm=0
#line 93 "sample/undocked/map.c"
    goto label_43;
label_50:
    // EBPF_OP_MOV64_REG pc=796 dst=r2 src=r10 offset=0 imm=0
#line 93 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=797 dst=r2 src=r0 offset=0 imm=-4
#line 103 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=798 dst=r1 src=r1 offset=0 imm=6
#line 103 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_CALL pc=800 dst=r0 src=r0 offset=0 imm=4
#line 103 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 103 "sample/undocked/map.c"
    if ((runtime_context->helper_data[5].tail_call) && (r0 == 0)) {
#line 103 "sample/undocked/map.c"
        return 0;
#line 103 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=801 dst=r0 src=r0 offset=23 imm=0
#line 104 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 104 "sample/undocked/map.c"
        goto label_51;
#line 104 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=802 dst=r1 src=r0 offset=0 imm=0
#line 104 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=803 dst=r10 src=r1 offset=-68 imm=0
#line 105 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=804 dst=r1 src=r0 offset=0 imm=1280070990
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(1280070990);
    // EBPF_OP_STXW pc=805 dst=r10 src=r1 offset=-72 imm=0
#line 105 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=806 dst=r1 src=r0 offset=0 imm=1920300133
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)2334102031925867621;
    // EBPF_OP_STXDW pc=808 dst=r10 src=r1 offset=-80 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=809 dst=r1 src=r0 offset=0 imm=1818582885
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8223693201956233061;
    // EBPF_OP_STXDW pc=811 dst=r10 src=r1 offset=-88 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=812 dst=r1 src=r0 offset=0 imm=1683973230
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8387229063778886766;
    // EBPF_OP_STXDW pc=814 dst=r10 src=r1 offset=-96 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=815 dst=r1 src=r0 offset=0 imm=1802465132
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)7016450394082471788;
    // EBPF_OP_STXDW pc=817 dst=r10 src=r1 offset=-104 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=818 dst=r1 src=r0 offset=0 imm=1600548962
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=820 dst=r10 src=r1 offset=-112 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=821 dst=r1 src=r10 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=822 dst=r1 src=r0 offset=0 imm=-112
#line 105 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=823 dst=r2 src=r0 offset=0 imm=45
#line 105 "sample/undocked/map.c"
    r2 = IMMEDIATE(45);
    // EBPF_OP_JA pc=824 dst=r0 src=r0 offset=-100 imm=0
#line 105 "sample/undocked/map.c"
    goto label_45;
label_51:
    // EBPF_OP_MOV64_IMM pc=825 dst=r8 src=r0 offset=0 imm=1
#line 105 "sample/undocked/map.c"
    r8 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=826 dst=r10 src=r8 offset=-8 imm=0
#line 115 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r8;
    // EBPF_OP_MOV64_IMM pc=827 dst=r9 src=r0 offset=0 imm=0
#line 115 "sample/undocked/map.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=828 dst=r10 src=r9 offset=-116 imm=0
#line 121 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-116)) = (uint32_t)r9;
    // EBPF_OP_LDXW pc=829 dst=r1 src=r10 offset=-116 imm=0
#line 121 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-116));
    // EBPF_OP_JGT_IMM pc=830 dst=r1 src=r0 offset=21 imm=10
#line 121 "sample/undocked/map.c"
    if (r1 > IMMEDIATE(10)) {
#line 121 "sample/undocked/map.c"
        goto label_53;
#line 121 "sample/undocked/map.c"
    }
label_52:
    // EBPF_OP_LDXW pc=831 dst=r1 src=r10 offset=-116 imm=0
#line 122 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-116));
    // EBPF_OP_STXW pc=832 dst=r10 src=r1 offset=-4 imm=0
#line 122 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=833 dst=r2 src=r10 offset=0 imm=0
#line 122 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=834 dst=r2 src=r0 offset=0 imm=-4
#line 122 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=835 dst=r3 src=r10 offset=0 imm=0
#line 122 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=836 dst=r3 src=r0 offset=0 imm=-8
#line 122 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=837 dst=r1 src=r1 offset=0 imm=5
#line 123 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_IMM pc=839 dst=r4 src=r0 offset=0 imm=0
#line 123 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=840 dst=r0 src=r0 offset=0 imm=2
#line 123 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 123 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 123 "sample/undocked/map.c"
        return 0;
#line 123 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=841 dst=r6 src=r0 offset=0 imm=0
#line 123 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=842 dst=r7 src=r6 offset=0 imm=0
#line 123 "sample/undocked/map.c"
    r7 = r6;
    // EBPF_OP_LSH64_IMM pc=843 dst=r7 src=r0 offset=0 imm=32
#line 123 "sample/undocked/map.c"
    r7 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=844 dst=r7 src=r0 offset=0 imm=32
#line 123 "sample/undocked/map.c"
    r7 = (int64_t)r7 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=845 dst=r9 src=r7 offset=75 imm=0
#line 124 "sample/undocked/map.c"
    if ((int64_t)r9 > (int64_t)r7) {
#line 124 "sample/undocked/map.c"
        goto label_60;
#line 124 "sample/undocked/map.c"
    }
    // EBPF_OP_LDXW pc=846 dst=r1 src=r10 offset=-116 imm=0
#line 121 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-116));
    // EBPF_OP_ADD64_IMM pc=847 dst=r1 src=r0 offset=0 imm=1
#line 121 "sample/undocked/map.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=848 dst=r10 src=r1 offset=-116 imm=0
#line 121 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-116)) = (uint32_t)r1;
    // EBPF_OP_LDXW pc=849 dst=r1 src=r10 offset=-116 imm=0
#line 121 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-116));
    // EBPF_OP_JGT_IMM pc=850 dst=r1 src=r0 offset=1 imm=10
#line 121 "sample/undocked/map.c"
    if (r1 > IMMEDIATE(10)) {
#line 121 "sample/undocked/map.c"
        goto label_53;
#line 121 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=851 dst=r0 src=r0 offset=-21 imm=0
#line 121 "sample/undocked/map.c"
    goto label_52;
label_53:
    // EBPF_OP_STXW pc=852 dst=r10 src=r8 offset=-8 imm=0
#line 115 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r8;
    // EBPF_OP_STXW pc=853 dst=r10 src=r9 offset=-116 imm=0
#line 121 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-116)) = (uint32_t)r9;
    // EBPF_OP_LDXW pc=854 dst=r1 src=r10 offset=-116 imm=0
#line 121 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-116));
    // EBPF_OP_JGT_IMM pc=855 dst=r1 src=r0 offset=22 imm=10
#line 121 "sample/undocked/map.c"
    if (r1 > IMMEDIATE(10)) {
#line 121 "sample/undocked/map.c"
        goto label_55;
#line 121 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=856 dst=r8 src=r0 offset=0 imm=0
#line 121 "sample/undocked/map.c"
    r8 = IMMEDIATE(0);
label_54:
    // EBPF_OP_LDXW pc=857 dst=r1 src=r10 offset=-116 imm=0
#line 122 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-116));
    // EBPF_OP_STXW pc=858 dst=r10 src=r1 offset=-4 imm=0
#line 122 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=859 dst=r2 src=r10 offset=0 imm=0
#line 122 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=860 dst=r2 src=r0 offset=0 imm=-4
#line 122 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=861 dst=r3 src=r10 offset=0 imm=0
#line 122 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=862 dst=r3 src=r0 offset=0 imm=-8
#line 122 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=863 dst=r1 src=r1 offset=0 imm=6
#line 123 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_IMM pc=865 dst=r4 src=r0 offset=0 imm=0
#line 123 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=866 dst=r0 src=r0 offset=0 imm=2
#line 123 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 123 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 123 "sample/undocked/map.c"
        return 0;
#line 123 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=867 dst=r6 src=r0 offset=0 imm=0
#line 123 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=868 dst=r7 src=r6 offset=0 imm=0
#line 123 "sample/undocked/map.c"
    r7 = r6;
    // EBPF_OP_LSH64_IMM pc=869 dst=r7 src=r0 offset=0 imm=32
#line 123 "sample/undocked/map.c"
    r7 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=870 dst=r7 src=r0 offset=0 imm=32
#line 123 "sample/undocked/map.c"
    r7 = (int64_t)r7 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=871 dst=r8 src=r7 offset=86 imm=0
#line 124 "sample/undocked/map.c"
    if ((int64_t)r8 > (int64_t)r7) {
#line 124 "sample/undocked/map.c"
        goto label_61;
#line 124 "sample/undocked/map.c"
    }
    // EBPF_OP_LDXW pc=872 dst=r1 src=r10 offset=-116 imm=0
#line 121 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-116));
    // EBPF_OP_ADD64_IMM pc=873 dst=r1 src=r0 offset=0 imm=1
#line 121 "sample/undocked/map.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=874 dst=r10 src=r1 offset=-116 imm=0
#line 121 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-116)) = (uint32_t)r1;
    // EBPF_OP_LDXW pc=875 dst=r1 src=r10 offset=-116 imm=0
#line 121 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-116));
    // EBPF_OP_JGT_IMM pc=876 dst=r1 src=r0 offset=1 imm=10
#line 121 "sample/undocked/map.c"
    if (r1 > IMMEDIATE(10)) {
#line 121 "sample/undocked/map.c"
        goto label_55;
#line 121 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=877 dst=r0 src=r0 offset=-21 imm=0
#line 121 "sample/undocked/map.c"
    goto label_54;
label_55:
    // EBPF_OP_MOV64_IMM pc=878 dst=r1 src=r0 offset=0 imm=0
#line 121 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=879 dst=r10 src=r1 offset=-4 imm=0
#line 173 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=880 dst=r2 src=r10 offset=0 imm=0
#line 173 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=881 dst=r2 src=r0 offset=0 imm=-4
#line 173 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=882 dst=r1 src=r1 offset=0 imm=7
#line 173 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=884 dst=r0 src=r0 offset=0 imm=18
#line 173 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 173 "sample/undocked/map.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 173 "sample/undocked/map.c"
        return 0;
#line 173 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=885 dst=r6 src=r0 offset=0 imm=0
#line 173 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=886 dst=r4 src=r6 offset=0 imm=0
#line 173 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=887 dst=r4 src=r0 offset=0 imm=32
#line 173 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=888 dst=r1 src=r4 offset=0 imm=0
#line 173 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=889 dst=r1 src=r0 offset=0 imm=32
#line 173 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=890 dst=r2 src=r0 offset=0 imm=-7
#line 173 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=892 dst=r1 src=r2 offset=1 imm=0
#line 173 "sample/undocked/map.c"
    if (r1 == r2) {
#line 173 "sample/undocked/map.c"
        goto label_56;
#line 173 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=893 dst=r0 src=r0 offset=470 imm=0
#line 173 "sample/undocked/map.c"
    goto label_87;
label_56:
    // EBPF_OP_LDXW pc=894 dst=r3 src=r10 offset=-4 imm=0
#line 173 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=895 dst=r3 src=r0 offset=103 imm=0
#line 173 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 173 "sample/undocked/map.c"
        goto label_63;
#line 173 "sample/undocked/map.c"
    }
label_57:
    // EBPF_OP_LDDW pc=896 dst=r1 src=r0 offset=0 imm=1852404835
#line 173 "sample/undocked/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=898 dst=r10 src=r1 offset=-80 imm=0
#line 173 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=899 dst=r1 src=r0 offset=0 imm=543434016
#line 173 "sample/undocked/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=901 dst=r10 src=r1 offset=-88 imm=0
#line 173 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=902 dst=r1 src=r0 offset=0 imm=1701978221
#line 173 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=904 dst=r10 src=r1 offset=-96 imm=0
#line 173 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=905 dst=r1 src=r0 offset=0 imm=1801807216
#line 173 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=907 dst=r10 src=r1 offset=-104 imm=0
#line 173 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=908 dst=r1 src=r0 offset=0 imm=1600548962
#line 173 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=910 dst=r10 src=r1 offset=-112 imm=0
#line 173 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=911 dst=r1 src=r0 offset=0 imm=0
#line 173 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=912 dst=r10 src=r1 offset=-72 imm=0
#line 173 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint8_t)r1;
    // EBPF_OP_MOV64_REG pc=913 dst=r1 src=r10 offset=0 imm=0
#line 173 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=914 dst=r1 src=r0 offset=0 imm=-112
#line 173 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=915 dst=r2 src=r0 offset=0 imm=41
#line 173 "sample/undocked/map.c"
    r2 = IMMEDIATE(41);
label_58:
    // EBPF_OP_MOV64_IMM pc=916 dst=r4 src=r0 offset=0 imm=0
#line 173 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
label_59:
    // EBPF_OP_CALL pc=917 dst=r0 src=r0 offset=0 imm=14
#line 173 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 173 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 173 "sample/undocked/map.c"
        return 0;
#line 173 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=918 dst=r6 src=r0 offset=0 imm=-1
#line 173 "sample/undocked/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=920 dst=r0 src=r0 offset=118 imm=0
#line 173 "sample/undocked/map.c"
    goto label_67;
label_60:
    // EBPF_OP_LDDW pc=921 dst=r1 src=r0 offset=0 imm=1684369010
#line 173 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=923 dst=r10 src=r1 offset=-88 imm=0
#line 125 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=924 dst=r1 src=r0 offset=0 imm=544040300
#line 125 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=926 dst=r10 src=r1 offset=-96 imm=0
#line 125 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=927 dst=r1 src=r0 offset=0 imm=1633972341
#line 125 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_STXDW pc=929 dst=r10 src=r1 offset=-104 imm=0
#line 125 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=930 dst=r1 src=r0 offset=0 imm=1600548962
#line 125 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=932 dst=r10 src=r1 offset=-112 imm=0
#line 125 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=933 dst=r1 src=r10 offset=0 imm=0
#line 125 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=934 dst=r1 src=r0 offset=0 imm=-112
#line 125 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=935 dst=r2 src=r0 offset=0 imm=32
#line 125 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=936 dst=r3 src=r7 offset=0 imm=0
#line 125 "sample/undocked/map.c"
    r3 = r7;
    // EBPF_OP_CALL pc=937 dst=r0 src=r0 offset=0 imm=13
#line 125 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 125 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 125 "sample/undocked/map.c"
        return 0;
#line 125 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=938 dst=r1 src=r0 offset=0 imm=100
#line 125 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=939 dst=r10 src=r1 offset=-76 imm=0
#line 209 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-76)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=940 dst=r1 src=r0 offset=0 imm=622879845
#line 209 "sample/undocked/map.c"
    r1 = IMMEDIATE(622879845);
    // EBPF_OP_STXW pc=941 dst=r10 src=r1 offset=-80 imm=0
#line 209 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=942 dst=r1 src=r0 offset=0 imm=1701978184
#line 209 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722056;
    // EBPF_OP_STXDW pc=944 dst=r10 src=r1 offset=-88 imm=0
#line 209 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=945 dst=r1 src=r0 offset=0 imm=1431456800
#line 209 "sample/undocked/map.c"
    r1 = (uint64_t)5999155752924761120;
    // EBPF_OP_STXDW pc=947 dst=r10 src=r1 offset=-96 imm=0
#line 209 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=948 dst=r1 src=r0 offset=0 imm=1919903264
#line 209 "sample/undocked/map.c"
    r1 = (uint64_t)8097873591115146784;
    // EBPF_OP_STXDW pc=950 dst=r10 src=r1 offset=-104 imm=0
#line 209 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=951 dst=r1 src=r0 offset=0 imm=1953719636
#line 209 "sample/undocked/map.c"
    r1 = (uint64_t)6148060143590532436;
    // EBPF_OP_STXDW pc=953 dst=r10 src=r1 offset=-112 imm=0
#line 209 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=954 dst=r1 src=r10 offset=0 imm=0
#line 209 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=955 dst=r1 src=r0 offset=0 imm=-112
#line 125 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=956 dst=r2 src=r0 offset=0 imm=38
#line 209 "sample/undocked/map.c"
    r2 = IMMEDIATE(38);
    // EBPF_OP_JA pc=957 dst=r0 src=r0 offset=39 imm=0
#line 209 "sample/undocked/map.c"
    goto label_62;
label_61:
    // EBPF_OP_LDDW pc=958 dst=r1 src=r0 offset=0 imm=1684369010
#line 209 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=960 dst=r10 src=r1 offset=-88 imm=0
#line 125 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=961 dst=r1 src=r0 offset=0 imm=544040300
#line 125 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=963 dst=r10 src=r1 offset=-96 imm=0
#line 125 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=964 dst=r1 src=r0 offset=0 imm=1633972341
#line 125 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_STXDW pc=966 dst=r10 src=r1 offset=-104 imm=0
#line 125 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=967 dst=r1 src=r0 offset=0 imm=1600548962
#line 125 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=969 dst=r10 src=r1 offset=-112 imm=0
#line 125 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=970 dst=r1 src=r10 offset=0 imm=0
#line 125 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=971 dst=r1 src=r0 offset=0 imm=-112
#line 125 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=972 dst=r2 src=r0 offset=0 imm=32
#line 125 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=973 dst=r3 src=r7 offset=0 imm=0
#line 125 "sample/undocked/map.c"
    r3 = r7;
    // EBPF_OP_CALL pc=974 dst=r0 src=r0 offset=0 imm=13
#line 125 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 125 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 125 "sample/undocked/map.c"
        return 0;
#line 125 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=975 dst=r1 src=r0 offset=0 imm=0
#line 125 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=976 dst=r10 src=r1 offset=-68 imm=0
#line 210 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=977 dst=r1 src=r0 offset=0 imm=1680154724
#line 210 "sample/undocked/map.c"
    r1 = IMMEDIATE(1680154724);
    // EBPF_OP_STXW pc=978 dst=r10 src=r1 offset=-72 imm=0
#line 210 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=979 dst=r1 src=r0 offset=0 imm=1952805408
#line 210 "sample/undocked/map.c"
    r1 = (uint64_t)7308905094058439200;
    // EBPF_OP_STXDW pc=981 dst=r10 src=r1 offset=-80 imm=0
#line 210 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=982 dst=r1 src=r0 offset=0 imm=1599426627
#line 210 "sample/undocked/map.c"
    r1 = (uint64_t)5211580972890673219;
    // EBPF_OP_STXDW pc=984 dst=r10 src=r1 offset=-88 imm=0
#line 210 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=985 dst=r1 src=r0 offset=0 imm=1431456800
#line 210 "sample/undocked/map.c"
    r1 = (uint64_t)5928232854886698016;
    // EBPF_OP_STXDW pc=987 dst=r10 src=r1 offset=-96 imm=0
#line 210 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=988 dst=r1 src=r0 offset=0 imm=1919903264
#line 210 "sample/undocked/map.c"
    r1 = (uint64_t)8097873591115146784;
    // EBPF_OP_STXDW pc=990 dst=r10 src=r1 offset=-104 imm=0
#line 210 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=991 dst=r1 src=r0 offset=0 imm=1953719636
#line 210 "sample/undocked/map.c"
    r1 = (uint64_t)6148060143590532436;
    // EBPF_OP_STXDW pc=993 dst=r10 src=r1 offset=-112 imm=0
#line 210 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=994 dst=r1 src=r10 offset=0 imm=0
#line 210 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=995 dst=r1 src=r0 offset=0 imm=-112
#line 125 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=996 dst=r2 src=r0 offset=0 imm=45
#line 210 "sample/undocked/map.c"
    r2 = IMMEDIATE(45);
label_62:
    // EBPF_OP_MOV64_REG pc=997 dst=r3 src=r7 offset=0 imm=0
#line 210 "sample/undocked/map.c"
    r3 = r7;
    // EBPF_OP_JA pc=998 dst=r0 src=r0 offset=-898 imm=0
#line 210 "sample/undocked/map.c"
    goto label_7;
label_63:
    // EBPF_OP_MOV64_IMM pc=999 dst=r7 src=r0 offset=0 imm=0
#line 210 "sample/undocked/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1000 dst=r10 src=r7 offset=-4 imm=0
#line 174 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1001 dst=r2 src=r10 offset=0 imm=0
#line 174 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1002 dst=r2 src=r0 offset=0 imm=-4
#line 174 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1003 dst=r1 src=r1 offset=0 imm=7
#line 174 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=1005 dst=r0 src=r0 offset=0 imm=17
#line 174 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 174 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 174 "sample/undocked/map.c"
        return 0;
#line 174 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1006 dst=r6 src=r0 offset=0 imm=0
#line 174 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1007 dst=r4 src=r6 offset=0 imm=0
#line 174 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1008 dst=r4 src=r0 offset=0 imm=32
#line 174 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1009 dst=r1 src=r4 offset=0 imm=0
#line 174 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1010 dst=r1 src=r0 offset=0 imm=32
#line 174 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=1011 dst=r2 src=r0 offset=0 imm=-7
#line 174 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1013 dst=r1 src=r2 offset=91 imm=0
#line 174 "sample/undocked/map.c"
    if (r1 == r2) {
#line 174 "sample/undocked/map.c"
        goto label_72;
#line 174 "sample/undocked/map.c"
    }
label_64:
    // EBPF_OP_STXB pc=1014 dst=r10 src=r7 offset=-64 imm=0
#line 174 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint8_t)r7;
    // EBPF_OP_LDDW pc=1015 dst=r1 src=r0 offset=0 imm=1701737077
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=1017 dst=r10 src=r1 offset=-72 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1018 dst=r1 src=r0 offset=0 imm=1680154740
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=1020 dst=r10 src=r1 offset=-80 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1021 dst=r1 src=r0 offset=0 imm=1914726254
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=1023 dst=r10 src=r1 offset=-88 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1024 dst=r1 src=r0 offset=0 imm=1886938400
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=1026 dst=r10 src=r1 offset=-96 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1027 dst=r1 src=r0 offset=0 imm=1601204080
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1029 dst=r10 src=r1 offset=-104 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1030 dst=r1 src=r0 offset=0 imm=1600548962
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1032 dst=r10 src=r1 offset=-112 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1033 dst=r4 src=r0 offset=0 imm=32
#line 174 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1034 dst=r1 src=r10 offset=0 imm=0
#line 174 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1035 dst=r1 src=r0 offset=0 imm=-112
#line 174 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1036 dst=r2 src=r0 offset=0 imm=49
#line 174 "sample/undocked/map.c"
    r2 = IMMEDIATE(49);
label_65:
    // EBPF_OP_MOV64_IMM pc=1037 dst=r3 src=r0 offset=0 imm=-7
#line 174 "sample/undocked/map.c"
    r3 = IMMEDIATE(-7);
label_66:
    // EBPF_OP_CALL pc=1038 dst=r0 src=r0 offset=0 imm=14
#line 174 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 174 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 174 "sample/undocked/map.c"
        return 0;
#line 174 "sample/undocked/map.c"
    }
label_67:
    // EBPF_OP_MOV64_REG pc=1039 dst=r3 src=r6 offset=0 imm=0
#line 212 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1040 dst=r3 src=r0 offset=0 imm=32
#line 212 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1041 dst=r3 src=r0 offset=0 imm=32
#line 212 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1042 dst=r3 src=r0 offset=1 imm=-1
#line 212 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 212 "sample/undocked/map.c"
        goto label_68;
#line 212 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1043 dst=r0 src=r0 offset=42 imm=0
#line 212 "sample/undocked/map.c"
    goto label_71;
label_68:
    // EBPF_OP_MOV64_IMM pc=1044 dst=r1 src=r0 offset=0 imm=0
#line 212 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1045 dst=r10 src=r1 offset=-4 imm=0
#line 173 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1046 dst=r2 src=r10 offset=0 imm=0
#line 173 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1047 dst=r2 src=r0 offset=0 imm=-4
#line 173 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1048 dst=r1 src=r1 offset=0 imm=8
#line 173 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=1050 dst=r0 src=r0 offset=0 imm=18
#line 173 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 173 "sample/undocked/map.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 173 "sample/undocked/map.c"
        return 0;
#line 173 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1051 dst=r7 src=r0 offset=0 imm=0
#line 173 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1052 dst=r4 src=r7 offset=0 imm=0
#line 173 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=1053 dst=r4 src=r0 offset=0 imm=32
#line 173 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1054 dst=r1 src=r4 offset=0 imm=0
#line 173 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1055 dst=r1 src=r0 offset=0 imm=32
#line 173 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=1056 dst=r2 src=r0 offset=0 imm=-7
#line 173 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1058 dst=r1 src=r2 offset=421 imm=0
#line 173 "sample/undocked/map.c"
    if (r1 == r2) {
#line 173 "sample/undocked/map.c"
        goto label_94;
#line 173 "sample/undocked/map.c"
    }
label_69:
    // EBPF_OP_MOV64_IMM pc=1059 dst=r1 src=r0 offset=0 imm=100
#line 173 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=1060 dst=r10 src=r1 offset=-64 imm=0
#line 173 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=1061 dst=r1 src=r0 offset=0 imm=1852994932
#line 173 "sample/undocked/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=1063 dst=r10 src=r1 offset=-72 imm=0
#line 173 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1064 dst=r1 src=r0 offset=0 imm=622883948
#line 173 "sample/undocked/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=1066 dst=r10 src=r1 offset=-80 imm=0
#line 173 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1067 dst=r1 src=r0 offset=0 imm=543649385
#line 173 "sample/undocked/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=1069 dst=r10 src=r1 offset=-88 imm=0
#line 173 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1070 dst=r1 src=r0 offset=0 imm=2019893357
#line 173 "sample/undocked/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=1072 dst=r10 src=r1 offset=-96 imm=0
#line 173 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1073 dst=r1 src=r0 offset=0 imm=1801807216
#line 173 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1075 dst=r10 src=r1 offset=-104 imm=0
#line 173 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1076 dst=r1 src=r0 offset=0 imm=1600548962
#line 173 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1078 dst=r10 src=r1 offset=-112 imm=0
#line 173 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1079 dst=r4 src=r0 offset=0 imm=32
#line 173 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1080 dst=r1 src=r10 offset=0 imm=0
#line 173 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1081 dst=r1 src=r0 offset=0 imm=-112
#line 173 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1082 dst=r2 src=r0 offset=0 imm=50
#line 173 "sample/undocked/map.c"
    r2 = IMMEDIATE(50);
label_70:
    // EBPF_OP_MOV64_IMM pc=1083 dst=r3 src=r0 offset=0 imm=-7
#line 173 "sample/undocked/map.c"
    r3 = IMMEDIATE(-7);
    // EBPF_OP_CALL pc=1084 dst=r0 src=r0 offset=0 imm=14
#line 173 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 173 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 173 "sample/undocked/map.c"
        return 0;
#line 173 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1085 dst=r0 src=r0 offset=420 imm=0
#line 173 "sample/undocked/map.c"
    goto label_98;
label_71:
    // EBPF_OP_LDDW pc=1086 dst=r1 src=r0 offset=0 imm=1684369010
#line 173 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=1088 dst=r10 src=r1 offset=-80 imm=0
#line 212 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1089 dst=r1 src=r0 offset=0 imm=541414725
#line 212 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140578096453;
    // EBPF_OP_STXDW pc=1091 dst=r10 src=r1 offset=-88 imm=0
#line 212 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1092 dst=r1 src=r0 offset=0 imm=1634541682
#line 212 "sample/undocked/map.c"
    r1 = (uint64_t)6147730633380405362;
    // EBPF_OP_STXDW pc=1094 dst=r10 src=r1 offset=-96 imm=0
#line 212 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1095 dst=r1 src=r0 offset=0 imm=1330667336
#line 212 "sample/undocked/map.c"
    r1 = (uint64_t)8027138915134627656;
    // EBPF_OP_STXDW pc=1097 dst=r10 src=r1 offset=-104 imm=0
#line 212 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1098 dst=r1 src=r0 offset=0 imm=1953719636
#line 212 "sample/undocked/map.c"
    r1 = (uint64_t)6004793778491319636;
    // EBPF_OP_STXDW pc=1100 dst=r10 src=r1 offset=-112 imm=0
#line 212 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1101 dst=r1 src=r10 offset=0 imm=0
#line 212 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1102 dst=r1 src=r0 offset=0 imm=-112
#line 212 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1103 dst=r2 src=r0 offset=0 imm=40
#line 212 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_JA pc=1104 dst=r0 src=r0 offset=-1004 imm=0
#line 212 "sample/undocked/map.c"
    goto label_7;
label_72:
    // EBPF_OP_LDXW pc=1105 dst=r3 src=r10 offset=-4 imm=0
#line 174 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1106 dst=r3 src=r0 offset=19 imm=0
#line 174 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 174 "sample/undocked/map.c"
        goto label_74;
#line 174 "sample/undocked/map.c"
    }
label_73:
    // EBPF_OP_LDDW pc=1107 dst=r1 src=r0 offset=0 imm=1735289204
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1109 dst=r10 src=r1 offset=-80 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1110 dst=r1 src=r0 offset=0 imm=1696621605
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1112 dst=r10 src=r1 offset=-88 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1113 dst=r1 src=r0 offset=0 imm=1952805408
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1115 dst=r10 src=r1 offset=-96 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1116 dst=r1 src=r0 offset=0 imm=1601204080
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1118 dst=r10 src=r1 offset=-104 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1119 dst=r1 src=r0 offset=0 imm=1600548962
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1121 dst=r10 src=r1 offset=-112 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1122 dst=r1 src=r10 offset=0 imm=0
#line 174 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1123 dst=r1 src=r0 offset=0 imm=-112
#line 174 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1124 dst=r2 src=r0 offset=0 imm=40
#line 174 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_JA pc=1125 dst=r0 src=r0 offset=-210 imm=0
#line 174 "sample/undocked/map.c"
    goto label_58;
label_74:
    // EBPF_OP_MOV64_IMM pc=1126 dst=r1 src=r0 offset=0 imm=0
#line 174 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1127 dst=r10 src=r1 offset=-4 imm=0
#line 178 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_LDXW pc=1128 dst=r1 src=r10 offset=-4 imm=0
#line 178 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LSH64_IMM pc=1129 dst=r1 src=r0 offset=0 imm=32
#line 178 "sample/undocked/map.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1130 dst=r1 src=r0 offset=0 imm=32
#line 178 "sample/undocked/map.c"
    r1 = (int64_t)r1 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1131 dst=r1 src=r0 offset=22 imm=9
#line 178 "sample/undocked/map.c"
    if ((int64_t)r1 > IMMEDIATE(9)) {
#line 178 "sample/undocked/map.c"
        goto label_76;
#line 178 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=1132 dst=r7 src=r0 offset=0 imm=10
#line 178 "sample/undocked/map.c"
    r7 = IMMEDIATE(10);
label_75:
    // EBPF_OP_LDXW pc=1133 dst=r1 src=r10 offset=-4 imm=0
#line 179 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_STXW pc=1134 dst=r10 src=r1 offset=-8 imm=0
#line 179 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1135 dst=r2 src=r10 offset=0 imm=0
#line 179 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1136 dst=r2 src=r0 offset=0 imm=-8
#line 179 "sample/undocked/map.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=1137 dst=r1 src=r1 offset=0 imm=7
#line 179 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_MOV64_IMM pc=1139 dst=r3 src=r0 offset=0 imm=0
#line 179 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1140 dst=r0 src=r0 offset=0 imm=16
#line 179 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 179 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 179 "sample/undocked/map.c"
        return 0;
#line 179 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1141 dst=r6 src=r0 offset=0 imm=0
#line 179 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1142 dst=r5 src=r6 offset=0 imm=0
#line 179 "sample/undocked/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1143 dst=r5 src=r0 offset=0 imm=32
#line 179 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1144 dst=r1 src=r5 offset=0 imm=0
#line 179 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1145 dst=r1 src=r0 offset=0 imm=32
#line 179 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JNE_IMM pc=1146 dst=r1 src=r0 offset=93 imm=0
#line 179 "sample/undocked/map.c"
    if (r1 != IMMEDIATE(0)) {
#line 179 "sample/undocked/map.c"
        goto label_78;
#line 179 "sample/undocked/map.c"
    }
    // EBPF_OP_LDXW pc=1147 dst=r1 src=r10 offset=-4 imm=0
#line 178 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ADD64_IMM pc=1148 dst=r1 src=r0 offset=0 imm=1
#line 178 "sample/undocked/map.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=1149 dst=r10 src=r1 offset=-4 imm=0
#line 178 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_LDXW pc=1150 dst=r1 src=r10 offset=-4 imm=0
#line 178 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LSH64_IMM pc=1151 dst=r1 src=r0 offset=0 imm=32
#line 178 "sample/undocked/map.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1152 dst=r1 src=r0 offset=0 imm=32
#line 178 "sample/undocked/map.c"
    r1 = (int64_t)r1 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=1153 dst=r7 src=r1 offset=-21 imm=0
#line 178 "sample/undocked/map.c"
    if ((int64_t)r7 > (int64_t)r1) {
#line 178 "sample/undocked/map.c"
        goto label_75;
#line 178 "sample/undocked/map.c"
    }
label_76:
    // EBPF_OP_MOV64_IMM pc=1154 dst=r7 src=r0 offset=0 imm=10
#line 178 "sample/undocked/map.c"
    r7 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=1155 dst=r10 src=r7 offset=-4 imm=0
#line 182 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1156 dst=r2 src=r10 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1157 dst=r2 src=r0 offset=0 imm=-4
#line 182 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=1158 dst=r8 src=r0 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=1159 dst=r1 src=r1 offset=0 imm=7
#line 182 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_MOV64_IMM pc=1161 dst=r3 src=r0 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1162 dst=r0 src=r0 offset=0 imm=16
#line 182 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 182 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 182 "sample/undocked/map.c"
        return 0;
#line 182 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1163 dst=r6 src=r0 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1164 dst=r5 src=r6 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1165 dst=r5 src=r0 offset=0 imm=32
#line 182 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1166 dst=r1 src=r5 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1167 dst=r1 src=r0 offset=0 imm=32
#line 182 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=1168 dst=r2 src=r0 offset=0 imm=-29
#line 182 "sample/undocked/map.c"
    r2 = (uint64_t)4294967267;
    // EBPF_OP_JEQ_REG pc=1170 dst=r1 src=r2 offset=30 imm=0
#line 182 "sample/undocked/map.c"
    if (r1 == r2) {
#line 182 "sample/undocked/map.c"
        goto label_77;
#line 182 "sample/undocked/map.c"
    }
    // EBPF_OP_STXB pc=1171 dst=r10 src=r8 offset=-58 imm=0
#line 182 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-58)) = (uint8_t)r8;
    // EBPF_OP_MOV64_IMM pc=1172 dst=r1 src=r0 offset=0 imm=25637
#line 182 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1173 dst=r10 src=r1 offset=-60 imm=0
#line 182 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-60)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1174 dst=r1 src=r0 offset=0 imm=543450478
#line 182 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1175 dst=r10 src=r1 offset=-64 imm=0
#line 182 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1176 dst=r1 src=r0 offset=0 imm=1914725413
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1178 dst=r10 src=r1 offset=-72 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1179 dst=r1 src=r0 offset=0 imm=1667592312
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1181 dst=r10 src=r1 offset=-80 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1182 dst=r1 src=r0 offset=0 imm=543649385
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1184 dst=r10 src=r1 offset=-88 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1185 dst=r1 src=r0 offset=0 imm=1852383341
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1187 dst=r10 src=r1 offset=-96 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1188 dst=r1 src=r0 offset=0 imm=1752397168
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1190 dst=r10 src=r1 offset=-104 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1191 dst=r1 src=r0 offset=0 imm=1600548962
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1193 dst=r10 src=r1 offset=-112 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=1194 dst=r3 src=r10 offset=-4 imm=0
#line 182 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ARSH64_IMM pc=1195 dst=r5 src=r0 offset=0 imm=32
#line 182 "sample/undocked/map.c"
    r5 = (int64_t)r5 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1196 dst=r1 src=r10 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1197 dst=r1 src=r0 offset=0 imm=-112
#line 182 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1198 dst=r2 src=r0 offset=0 imm=55
#line 182 "sample/undocked/map.c"
    r2 = IMMEDIATE(55);
    // EBPF_OP_MOV64_IMM pc=1199 dst=r4 src=r0 offset=0 imm=-29
#line 182 "sample/undocked/map.c"
    r4 = IMMEDIATE(-29);
    // EBPF_OP_JA pc=1200 dst=r0 src=r0 offset=69 imm=0
#line 182 "sample/undocked/map.c"
    goto label_80;
label_77:
    // EBPF_OP_STXW pc=1201 dst=r10 src=r7 offset=-4 imm=0
#line 183 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1202 dst=r2 src=r10 offset=0 imm=0
#line 183 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1203 dst=r2 src=r0 offset=0 imm=-4
#line 183 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1204 dst=r1 src=r1 offset=0 imm=7
#line 183 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_MOV64_IMM pc=1206 dst=r3 src=r0 offset=0 imm=2
#line 183 "sample/undocked/map.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_CALL pc=1207 dst=r0 src=r0 offset=0 imm=16
#line 183 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 183 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 183 "sample/undocked/map.c"
        return 0;
#line 183 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1208 dst=r6 src=r0 offset=0 imm=0
#line 183 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1209 dst=r5 src=r6 offset=0 imm=0
#line 183 "sample/undocked/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1210 dst=r5 src=r0 offset=0 imm=32
#line 183 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1211 dst=r1 src=r5 offset=0 imm=0
#line 183 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1212 dst=r1 src=r0 offset=0 imm=32
#line 183 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1213 dst=r1 src=r0 offset=58 imm=0
#line 183 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 183 "sample/undocked/map.c"
        goto label_81;
#line 183 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=1214 dst=r1 src=r0 offset=0 imm=25637
#line 183 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1215 dst=r10 src=r1 offset=-60 imm=0
#line 183 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-60)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1216 dst=r1 src=r0 offset=0 imm=543450478
#line 183 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1217 dst=r10 src=r1 offset=-64 imm=0
#line 183 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1218 dst=r1 src=r0 offset=0 imm=1914725413
#line 183 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1220 dst=r10 src=r1 offset=-72 imm=0
#line 183 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1221 dst=r1 src=r0 offset=0 imm=1667592312
#line 183 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1223 dst=r10 src=r1 offset=-80 imm=0
#line 183 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1224 dst=r1 src=r0 offset=0 imm=543649385
#line 183 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1226 dst=r10 src=r1 offset=-88 imm=0
#line 183 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1227 dst=r1 src=r0 offset=0 imm=1852383341
#line 183 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1229 dst=r10 src=r1 offset=-96 imm=0
#line 183 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1230 dst=r1 src=r0 offset=0 imm=1752397168
#line 183 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1232 dst=r10 src=r1 offset=-104 imm=0
#line 183 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1233 dst=r1 src=r0 offset=0 imm=1600548962
#line 183 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1235 dst=r10 src=r1 offset=-112 imm=0
#line 183 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=1236 dst=r1 src=r0 offset=0 imm=0
#line 183 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1237 dst=r10 src=r1 offset=-58 imm=0
#line 183 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-58)) = (uint8_t)r1;
    // EBPF_OP_LDXW pc=1238 dst=r3 src=r10 offset=-4 imm=0
#line 183 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JA pc=1239 dst=r0 src=r0 offset=25 imm=0
#line 183 "sample/undocked/map.c"
    goto label_79;
label_78:
    // EBPF_OP_MOV64_IMM pc=1240 dst=r1 src=r0 offset=0 imm=25637
#line 183 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1241 dst=r10 src=r1 offset=-60 imm=0
#line 179 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-60)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1242 dst=r1 src=r0 offset=0 imm=543450478
#line 179 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1243 dst=r10 src=r1 offset=-64 imm=0
#line 179 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1244 dst=r1 src=r0 offset=0 imm=1914725413
#line 179 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1246 dst=r10 src=r1 offset=-72 imm=0
#line 179 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1247 dst=r1 src=r0 offset=0 imm=1667592312
#line 179 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1249 dst=r10 src=r1 offset=-80 imm=0
#line 179 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1250 dst=r1 src=r0 offset=0 imm=543649385
#line 179 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1252 dst=r10 src=r1 offset=-88 imm=0
#line 179 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1253 dst=r1 src=r0 offset=0 imm=1852383341
#line 179 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1255 dst=r10 src=r1 offset=-96 imm=0
#line 179 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1256 dst=r1 src=r0 offset=0 imm=1752397168
#line 179 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1258 dst=r10 src=r1 offset=-104 imm=0
#line 179 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1259 dst=r1 src=r0 offset=0 imm=1600548962
#line 179 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1261 dst=r10 src=r1 offset=-112 imm=0
#line 179 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=1262 dst=r1 src=r0 offset=0 imm=0
#line 179 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1263 dst=r10 src=r1 offset=-58 imm=0
#line 179 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-58)) = (uint8_t)r1;
    // EBPF_OP_LDXW pc=1264 dst=r3 src=r10 offset=-8 imm=0
#line 179 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8));
label_79:
    // EBPF_OP_ARSH64_IMM pc=1265 dst=r5 src=r0 offset=0 imm=32
#line 179 "sample/undocked/map.c"
    r5 = (int64_t)r5 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1266 dst=r1 src=r10 offset=0 imm=0
#line 179 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1267 dst=r1 src=r0 offset=0 imm=-112
#line 179 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1268 dst=r2 src=r0 offset=0 imm=55
#line 179 "sample/undocked/map.c"
    r2 = IMMEDIATE(55);
    // EBPF_OP_MOV64_IMM pc=1269 dst=r4 src=r0 offset=0 imm=0
#line 179 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
label_80:
    // EBPF_OP_CALL pc=1270 dst=r0 src=r0 offset=0 imm=15
#line 179 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[10].address(r1, r2, r3, r4, r5, context);
#line 179 "sample/undocked/map.c"
    if ((runtime_context->helper_data[10].tail_call) && (r0 == 0)) {
#line 179 "sample/undocked/map.c"
        return 0;
#line 179 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1271 dst=r0 src=r0 offset=-233 imm=0
#line 179 "sample/undocked/map.c"
    goto label_67;
label_81:
    // EBPF_OP_MOV64_IMM pc=1272 dst=r1 src=r0 offset=0 imm=0
#line 179 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1273 dst=r10 src=r1 offset=-4 imm=0
#line 185 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1274 dst=r2 src=r10 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1275 dst=r2 src=r0 offset=0 imm=-4
#line 185 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1276 dst=r1 src=r1 offset=0 imm=7
#line 185 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=1278 dst=r0 src=r0 offset=0 imm=18
#line 185 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 185 "sample/undocked/map.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 185 "sample/undocked/map.c"
        return 0;
#line 185 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1279 dst=r6 src=r0 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1280 dst=r4 src=r6 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1281 dst=r4 src=r0 offset=0 imm=32
#line 185 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1282 dst=r1 src=r4 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1283 dst=r1 src=r0 offset=0 imm=32
#line 185 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1284 dst=r1 src=r0 offset=26 imm=0
#line 185 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 185 "sample/undocked/map.c"
        goto label_83;
#line 185 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=1285 dst=r1 src=r0 offset=0 imm=100
#line 185 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=1286 dst=r10 src=r1 offset=-64 imm=0
#line 185 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=1287 dst=r1 src=r0 offset=0 imm=1852994932
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=1289 dst=r10 src=r1 offset=-72 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1290 dst=r1 src=r0 offset=0 imm=622883948
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=1292 dst=r10 src=r1 offset=-80 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1293 dst=r1 src=r0 offset=0 imm=543649385
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=1295 dst=r10 src=r1 offset=-88 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1296 dst=r1 src=r0 offset=0 imm=2019893357
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=1298 dst=r10 src=r1 offset=-96 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1299 dst=r1 src=r0 offset=0 imm=1801807216
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1301 dst=r10 src=r1 offset=-104 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1302 dst=r1 src=r0 offset=0 imm=1600548962
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1304 dst=r10 src=r1 offset=-112 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1305 dst=r4 src=r0 offset=0 imm=32
#line 185 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1306 dst=r1 src=r10 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1307 dst=r1 src=r0 offset=0 imm=-112
#line 185 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1308 dst=r2 src=r0 offset=0 imm=50
#line 185 "sample/undocked/map.c"
    r2 = IMMEDIATE(50);
label_82:
    // EBPF_OP_MOV64_IMM pc=1309 dst=r3 src=r0 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_JA pc=1310 dst=r0 src=r0 offset=-273 imm=0
#line 185 "sample/undocked/map.c"
    goto label_66;
label_83:
    // EBPF_OP_LDXW pc=1311 dst=r3 src=r10 offset=-4 imm=0
#line 185 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1312 dst=r3 src=r0 offset=22 imm=1
#line 185 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(1)) {
#line 185 "sample/undocked/map.c"
        goto label_84;
#line 185 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=1313 dst=r1 src=r0 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1314 dst=r10 src=r1 offset=-72 imm=0
#line 185 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=1315 dst=r1 src=r0 offset=0 imm=1852404835
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=1317 dst=r10 src=r1 offset=-80 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1318 dst=r1 src=r0 offset=0 imm=543434016
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=1320 dst=r10 src=r1 offset=-88 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1321 dst=r1 src=r0 offset=0 imm=1701978221
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=1323 dst=r10 src=r1 offset=-96 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1324 dst=r1 src=r0 offset=0 imm=1801807216
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1326 dst=r10 src=r1 offset=-104 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1327 dst=r1 src=r0 offset=0 imm=1600548962
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1329 dst=r10 src=r1 offset=-112 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1330 dst=r1 src=r10 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1331 dst=r1 src=r0 offset=0 imm=-112
#line 185 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1332 dst=r2 src=r0 offset=0 imm=41
#line 185 "sample/undocked/map.c"
    r2 = IMMEDIATE(41);
    // EBPF_OP_MOV64_IMM pc=1333 dst=r4 src=r0 offset=0 imm=1
#line 185 "sample/undocked/map.c"
    r4 = IMMEDIATE(1);
    // EBPF_OP_JA pc=1334 dst=r0 src=r0 offset=-418 imm=0
#line 185 "sample/undocked/map.c"
    goto label_59;
label_84:
    // EBPF_OP_MOV64_IMM pc=1335 dst=r7 src=r0 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1336 dst=r10 src=r7 offset=-4 imm=0
#line 189 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_LDXW pc=1337 dst=r1 src=r10 offset=-4 imm=0
#line 189 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LSH64_IMM pc=1338 dst=r1 src=r0 offset=0 imm=32
#line 189 "sample/undocked/map.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1339 dst=r1 src=r0 offset=0 imm=32
#line 189 "sample/undocked/map.c"
    r1 = (int64_t)r1 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1340 dst=r1 src=r0 offset=9 imm=9
#line 189 "sample/undocked/map.c"
    if ((int64_t)r1 > IMMEDIATE(9)) {
#line 189 "sample/undocked/map.c"
        goto label_86;
#line 189 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=1341 dst=r8 src=r0 offset=0 imm=10
#line 189 "sample/undocked/map.c"
    r8 = IMMEDIATE(10);
    // EBPF_OP_JA pc=1342 dst=r0 src=r0 offset=46 imm=0
#line 189 "sample/undocked/map.c"
    goto label_88;
label_85:
    // EBPF_OP_LDXW pc=1343 dst=r1 src=r10 offset=-4 imm=0
#line 189 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ADD64_IMM pc=1344 dst=r1 src=r0 offset=0 imm=1
#line 189 "sample/undocked/map.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=1345 dst=r10 src=r1 offset=-4 imm=0
#line 189 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_LDXW pc=1346 dst=r1 src=r10 offset=-4 imm=0
#line 189 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LSH64_IMM pc=1347 dst=r1 src=r0 offset=0 imm=32
#line 189 "sample/undocked/map.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1348 dst=r1 src=r0 offset=0 imm=32
#line 189 "sample/undocked/map.c"
    r1 = (int64_t)r1 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=1349 dst=r8 src=r1 offset=39 imm=0
#line 189 "sample/undocked/map.c"
    if ((int64_t)r8 > (int64_t)r1) {
#line 189 "sample/undocked/map.c"
        goto label_88;
#line 189 "sample/undocked/map.c"
    }
label_86:
    // EBPF_OP_STXW pc=1350 dst=r10 src=r7 offset=-4 imm=0
#line 193 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1351 dst=r2 src=r10 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1352 dst=r2 src=r0 offset=0 imm=-4
#line 193 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1353 dst=r1 src=r1 offset=0 imm=7
#line 193 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=1355 dst=r0 src=r0 offset=0 imm=18
#line 193 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 193 "sample/undocked/map.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 193 "sample/undocked/map.c"
        return 0;
#line 193 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1356 dst=r6 src=r0 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1357 dst=r4 src=r6 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1358 dst=r4 src=r0 offset=0 imm=32
#line 193 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1359 dst=r1 src=r4 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1360 dst=r1 src=r0 offset=0 imm=32
#line 193 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=1361 dst=r2 src=r0 offset=0 imm=-7
#line 193 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1363 dst=r1 src=r2 offset=69 imm=0
#line 193 "sample/undocked/map.c"
    if (r1 == r2) {
#line 193 "sample/undocked/map.c"
        goto label_90;
#line 193 "sample/undocked/map.c"
    }
label_87:
    // EBPF_OP_MOV64_IMM pc=1364 dst=r1 src=r0 offset=0 imm=100
#line 193 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=1365 dst=r10 src=r1 offset=-64 imm=0
#line 193 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=1366 dst=r1 src=r0 offset=0 imm=1852994932
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=1368 dst=r10 src=r1 offset=-72 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1369 dst=r1 src=r0 offset=0 imm=622883948
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=1371 dst=r10 src=r1 offset=-80 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1372 dst=r1 src=r0 offset=0 imm=543649385
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=1374 dst=r10 src=r1 offset=-88 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1375 dst=r1 src=r0 offset=0 imm=2019893357
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=1377 dst=r10 src=r1 offset=-96 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1378 dst=r1 src=r0 offset=0 imm=1801807216
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1380 dst=r10 src=r1 offset=-104 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1381 dst=r1 src=r0 offset=0 imm=1600548962
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1383 dst=r10 src=r1 offset=-112 imm=0
#line 193 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1384 dst=r4 src=r0 offset=0 imm=32
#line 193 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1385 dst=r1 src=r10 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1386 dst=r1 src=r0 offset=0 imm=-112
#line 193 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1387 dst=r2 src=r0 offset=0 imm=50
#line 193 "sample/undocked/map.c"
    r2 = IMMEDIATE(50);
    // EBPF_OP_JA pc=1388 dst=r0 src=r0 offset=-352 imm=0
#line 193 "sample/undocked/map.c"
    goto label_65;
label_88:
    // EBPF_OP_STXW pc=1389 dst=r10 src=r7 offset=-8 imm=0
#line 190 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1390 dst=r2 src=r10 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1391 dst=r2 src=r0 offset=0 imm=-8
#line 190 "sample/undocked/map.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=1392 dst=r1 src=r1 offset=0 imm=7
#line 190 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=1394 dst=r0 src=r0 offset=0 imm=17
#line 190 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 190 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 190 "sample/undocked/map.c"
        return 0;
#line 190 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1395 dst=r6 src=r0 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1396 dst=r4 src=r6 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1397 dst=r4 src=r0 offset=0 imm=32
#line 190 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1398 dst=r1 src=r4 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1399 dst=r1 src=r0 offset=0 imm=32
#line 190 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1400 dst=r1 src=r0 offset=1 imm=0
#line 190 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 190 "sample/undocked/map.c"
        goto label_89;
#line 190 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1401 dst=r0 src=r0 offset=34 imm=0
#line 190 "sample/undocked/map.c"
    goto label_91;
label_89:
    // EBPF_OP_LDXW pc=1402 dst=r1 src=r10 offset=-4 imm=0
#line 190 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ADD64_IMM pc=1403 dst=r1 src=r0 offset=0 imm=1
#line 190 "sample/undocked/map.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_LSH64_IMM pc=1404 dst=r1 src=r0 offset=0 imm=32
#line 190 "sample/undocked/map.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=1405 dst=r1 src=r0 offset=0 imm=32
#line 190 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDXW pc=1406 dst=r3 src=r10 offset=-8 imm=0
#line 190 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8));
    // EBPF_OP_JEQ_REG pc=1407 dst=r3 src=r1 offset=-65 imm=0
#line 190 "sample/undocked/map.c"
    if (r3 == r1) {
#line 190 "sample/undocked/map.c"
        goto label_85;
#line 190 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=1408 dst=r1 src=r0 offset=0 imm=1735289204
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1410 dst=r10 src=r1 offset=-80 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1411 dst=r1 src=r0 offset=0 imm=1696621605
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1413 dst=r10 src=r1 offset=-88 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1414 dst=r1 src=r0 offset=0 imm=1952805408
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1416 dst=r10 src=r1 offset=-96 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1417 dst=r1 src=r0 offset=0 imm=1601204080
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1419 dst=r10 src=r1 offset=-104 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1420 dst=r1 src=r0 offset=0 imm=1600548962
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1422 dst=r10 src=r1 offset=-112 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=1423 dst=r4 src=r10 offset=-4 imm=0
#line 190 "sample/undocked/map.c"
    r4 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LSH64_IMM pc=1424 dst=r4 src=r0 offset=0 imm=32
#line 190 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=1425 dst=r1 src=r0 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)4294967296;
    // EBPF_OP_ADD64_REG pc=1427 dst=r4 src=r1 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r4 += r1;
    // EBPF_OP_ARSH64_IMM pc=1428 dst=r4 src=r0 offset=0 imm=32
#line 190 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1429 dst=r1 src=r10 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1430 dst=r1 src=r0 offset=0 imm=-112
#line 190 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1431 dst=r2 src=r0 offset=0 imm=40
#line 190 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_JA pc=1432 dst=r0 src=r0 offset=-516 imm=0
#line 190 "sample/undocked/map.c"
    goto label_59;
label_90:
    // EBPF_OP_LDXW pc=1433 dst=r3 src=r10 offset=-4 imm=0
#line 193 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1434 dst=r3 src=r0 offset=26 imm=0
#line 193 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 193 "sample/undocked/map.c"
        goto label_92;
#line 193 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1435 dst=r0 src=r0 offset=-540 imm=0
#line 193 "sample/undocked/map.c"
    goto label_57;
label_91:
    // EBPF_OP_LDDW pc=1436 dst=r1 src=r0 offset=0 imm=1701737077
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=1438 dst=r10 src=r1 offset=-72 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1439 dst=r1 src=r0 offset=0 imm=1680154740
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=1441 dst=r10 src=r1 offset=-80 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1442 dst=r1 src=r0 offset=0 imm=1914726254
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=1444 dst=r10 src=r1 offset=-88 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1445 dst=r1 src=r0 offset=0 imm=1886938400
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=1447 dst=r10 src=r1 offset=-96 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1448 dst=r1 src=r0 offset=0 imm=1601204080
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1450 dst=r10 src=r1 offset=-104 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1451 dst=r1 src=r0 offset=0 imm=1600548962
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1453 dst=r10 src=r1 offset=-112 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=1454 dst=r1 src=r0 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1455 dst=r10 src=r1 offset=-64 imm=0
#line 190 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint8_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1456 dst=r4 src=r0 offset=0 imm=32
#line 190 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1457 dst=r1 src=r10 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1458 dst=r1 src=r0 offset=0 imm=-112
#line 190 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1459 dst=r2 src=r0 offset=0 imm=49
#line 190 "sample/undocked/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=1460 dst=r0 src=r0 offset=-152 imm=0
#line 190 "sample/undocked/map.c"
    goto label_82;
label_92:
    // EBPF_OP_MOV64_IMM pc=1461 dst=r7 src=r0 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1462 dst=r10 src=r7 offset=-4 imm=0
#line 194 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1463 dst=r2 src=r10 offset=0 imm=0
#line 194 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1464 dst=r2 src=r0 offset=0 imm=-4
#line 194 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1465 dst=r1 src=r1 offset=0 imm=7
#line 194 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=1467 dst=r0 src=r0 offset=0 imm=17
#line 194 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 194 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 194 "sample/undocked/map.c"
        return 0;
#line 194 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1468 dst=r6 src=r0 offset=0 imm=0
#line 194 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1469 dst=r4 src=r6 offset=0 imm=0
#line 194 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1470 dst=r4 src=r0 offset=0 imm=32
#line 194 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1471 dst=r1 src=r4 offset=0 imm=0
#line 194 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1472 dst=r1 src=r0 offset=0 imm=32
#line 194 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=1473 dst=r2 src=r0 offset=0 imm=-7
#line 194 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1475 dst=r1 src=r2 offset=1 imm=0
#line 194 "sample/undocked/map.c"
    if (r1 == r2) {
#line 194 "sample/undocked/map.c"
        goto label_93;
#line 194 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1476 dst=r0 src=r0 offset=-463 imm=0
#line 194 "sample/undocked/map.c"
    goto label_64;
label_93:
    // EBPF_OP_LDXW pc=1477 dst=r3 src=r10 offset=-4 imm=0
#line 194 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1478 dst=r3 src=r0 offset=-435 imm=0
#line 194 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 194 "sample/undocked/map.c"
        goto label_68;
#line 194 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1479 dst=r0 src=r0 offset=-373 imm=0
#line 194 "sample/undocked/map.c"
    goto label_73;
label_94:
    // EBPF_OP_LDXW pc=1480 dst=r3 src=r10 offset=-4 imm=0
#line 173 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1481 dst=r3 src=r0 offset=50 imm=0
#line 173 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 173 "sample/undocked/map.c"
        goto label_99;
#line 173 "sample/undocked/map.c"
    }
label_95:
    // EBPF_OP_LDDW pc=1482 dst=r1 src=r0 offset=0 imm=1852404835
#line 173 "sample/undocked/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=1484 dst=r10 src=r1 offset=-80 imm=0
#line 173 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1485 dst=r1 src=r0 offset=0 imm=543434016
#line 173 "sample/undocked/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=1487 dst=r10 src=r1 offset=-88 imm=0
#line 173 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1488 dst=r1 src=r0 offset=0 imm=1701978221
#line 173 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=1490 dst=r10 src=r1 offset=-96 imm=0
#line 173 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1491 dst=r1 src=r0 offset=0 imm=1801807216
#line 173 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1493 dst=r10 src=r1 offset=-104 imm=0
#line 173 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1494 dst=r1 src=r0 offset=0 imm=1600548962
#line 173 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1496 dst=r10 src=r1 offset=-112 imm=0
#line 173 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=1497 dst=r1 src=r0 offset=0 imm=0
#line 173 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1498 dst=r10 src=r1 offset=-72 imm=0
#line 173 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint8_t)r1;
    // EBPF_OP_MOV64_REG pc=1499 dst=r1 src=r10 offset=0 imm=0
#line 173 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1500 dst=r1 src=r0 offset=0 imm=-112
#line 173 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1501 dst=r2 src=r0 offset=0 imm=41
#line 173 "sample/undocked/map.c"
    r2 = IMMEDIATE(41);
label_96:
    // EBPF_OP_MOV64_IMM pc=1502 dst=r4 src=r0 offset=0 imm=0
#line 173 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
label_97:
    // EBPF_OP_CALL pc=1503 dst=r0 src=r0 offset=0 imm=14
#line 173 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 173 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 173 "sample/undocked/map.c"
        return 0;
#line 173 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=1504 dst=r7 src=r0 offset=0 imm=-1
#line 173 "sample/undocked/map.c"
    r7 = (uint64_t)4294967295;
label_98:
    // EBPF_OP_MOV64_IMM pc=1506 dst=r6 src=r0 offset=0 imm=0
#line 173 "sample/undocked/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_MOV64_REG pc=1507 dst=r3 src=r7 offset=0 imm=0
#line 213 "sample/undocked/map.c"
    r3 = r7;
    // EBPF_OP_LSH64_IMM pc=1508 dst=r3 src=r0 offset=0 imm=32
#line 213 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1509 dst=r3 src=r0 offset=0 imm=32
#line 213 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1510 dst=r3 src=r0 offset=-1409 imm=-1
#line 213 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 213 "sample/undocked/map.c"
        goto label_8;
#line 213 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=1511 dst=r1 src=r0 offset=0 imm=1684369010
#line 213 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=1513 dst=r10 src=r1 offset=-80 imm=0
#line 213 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1514 dst=r1 src=r0 offset=0 imm=541803329
#line 213 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140578485057;
    // EBPF_OP_STXDW pc=1516 dst=r10 src=r1 offset=-88 imm=0
#line 213 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1517 dst=r1 src=r0 offset=0 imm=1634541682
#line 213 "sample/undocked/map.c"
    r1 = (uint64_t)6076235989295898738;
    // EBPF_OP_STXDW pc=1519 dst=r10 src=r1 offset=-96 imm=0
#line 213 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1520 dst=r1 src=r0 offset=0 imm=1330667336
#line 213 "sample/undocked/map.c"
    r1 = (uint64_t)8027138915134627656;
    // EBPF_OP_STXDW pc=1522 dst=r10 src=r1 offset=-104 imm=0
#line 213 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1523 dst=r1 src=r0 offset=0 imm=1953719636
#line 213 "sample/undocked/map.c"
    r1 = (uint64_t)6004793778491319636;
    // EBPF_OP_STXDW pc=1525 dst=r10 src=r1 offset=-112 imm=0
#line 213 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1526 dst=r1 src=r10 offset=0 imm=0
#line 213 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1527 dst=r1 src=r0 offset=0 imm=-112
#line 213 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1528 dst=r2 src=r0 offset=0 imm=40
#line 213 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_CALL pc=1529 dst=r0 src=r0 offset=0 imm=13
#line 213 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 213 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 213 "sample/undocked/map.c"
        return 0;
#line 213 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1530 dst=r6 src=r7 offset=0 imm=0
#line 213 "sample/undocked/map.c"
    r6 = r7;
    // EBPF_OP_JA pc=1531 dst=r0 src=r0 offset=-1430 imm=0
#line 213 "sample/undocked/map.c"
    goto label_8;
label_99:
    // EBPF_OP_MOV64_IMM pc=1532 dst=r6 src=r0 offset=0 imm=0
#line 213 "sample/undocked/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1533 dst=r10 src=r6 offset=-4 imm=0
#line 174 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=1534 dst=r2 src=r10 offset=0 imm=0
#line 174 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1535 dst=r2 src=r0 offset=0 imm=-4
#line 174 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1536 dst=r1 src=r1 offset=0 imm=8
#line 174 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=1538 dst=r0 src=r0 offset=0 imm=17
#line 174 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 174 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 174 "sample/undocked/map.c"
        return 0;
#line 174 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1539 dst=r7 src=r0 offset=0 imm=0
#line 174 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1540 dst=r4 src=r7 offset=0 imm=0
#line 174 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=1541 dst=r4 src=r0 offset=0 imm=32
#line 174 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1542 dst=r1 src=r4 offset=0 imm=0
#line 174 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1543 dst=r1 src=r0 offset=0 imm=32
#line 174 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=1544 dst=r2 src=r0 offset=0 imm=-7
#line 174 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1546 dst=r1 src=r2 offset=24 imm=0
#line 174 "sample/undocked/map.c"
    if (r1 == r2) {
#line 174 "sample/undocked/map.c"
        goto label_101;
#line 174 "sample/undocked/map.c"
    }
label_100:
    // EBPF_OP_STXB pc=1547 dst=r10 src=r6 offset=-64 imm=0
#line 174 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint8_t)r6;
    // EBPF_OP_LDDW pc=1548 dst=r1 src=r0 offset=0 imm=1701737077
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=1550 dst=r10 src=r1 offset=-72 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1551 dst=r1 src=r0 offset=0 imm=1680154740
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=1553 dst=r10 src=r1 offset=-80 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1554 dst=r1 src=r0 offset=0 imm=1914726254
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=1556 dst=r10 src=r1 offset=-88 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1557 dst=r1 src=r0 offset=0 imm=1886938400
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=1559 dst=r10 src=r1 offset=-96 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1560 dst=r1 src=r0 offset=0 imm=1601204080
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1562 dst=r10 src=r1 offset=-104 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1563 dst=r1 src=r0 offset=0 imm=1600548962
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1565 dst=r10 src=r1 offset=-112 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1566 dst=r4 src=r0 offset=0 imm=32
#line 174 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1567 dst=r1 src=r10 offset=0 imm=0
#line 174 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1568 dst=r1 src=r0 offset=0 imm=-112
#line 174 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1569 dst=r2 src=r0 offset=0 imm=49
#line 174 "sample/undocked/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=1570 dst=r0 src=r0 offset=-488 imm=0
#line 174 "sample/undocked/map.c"
    goto label_70;
label_101:
    // EBPF_OP_LDXW pc=1571 dst=r3 src=r10 offset=-4 imm=0
#line 174 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1572 dst=r3 src=r0 offset=19 imm=0
#line 174 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 174 "sample/undocked/map.c"
        goto label_103;
#line 174 "sample/undocked/map.c"
    }
label_102:
    // EBPF_OP_LDDW pc=1573 dst=r1 src=r0 offset=0 imm=1735289204
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1575 dst=r10 src=r1 offset=-80 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1576 dst=r1 src=r0 offset=0 imm=1696621605
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1578 dst=r10 src=r1 offset=-88 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1579 dst=r1 src=r0 offset=0 imm=1952805408
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1581 dst=r10 src=r1 offset=-96 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1582 dst=r1 src=r0 offset=0 imm=1601204080
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1584 dst=r10 src=r1 offset=-104 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1585 dst=r1 src=r0 offset=0 imm=1600548962
#line 174 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1587 dst=r10 src=r1 offset=-112 imm=0
#line 174 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1588 dst=r1 src=r10 offset=0 imm=0
#line 174 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1589 dst=r1 src=r0 offset=0 imm=-112
#line 174 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1590 dst=r2 src=r0 offset=0 imm=40
#line 174 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_JA pc=1591 dst=r0 src=r0 offset=-90 imm=0
#line 174 "sample/undocked/map.c"
    goto label_96;
label_103:
    // EBPF_OP_MOV64_IMM pc=1592 dst=r1 src=r0 offset=0 imm=0
#line 174 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1593 dst=r10 src=r1 offset=-4 imm=0
#line 178 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_LDXW pc=1594 dst=r1 src=r10 offset=-4 imm=0
#line 178 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LSH64_IMM pc=1595 dst=r1 src=r0 offset=0 imm=32
#line 178 "sample/undocked/map.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1596 dst=r1 src=r0 offset=0 imm=32
#line 178 "sample/undocked/map.c"
    r1 = (int64_t)r1 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1597 dst=r1 src=r0 offset=22 imm=9
#line 178 "sample/undocked/map.c"
    if ((int64_t)r1 > IMMEDIATE(9)) {
#line 178 "sample/undocked/map.c"
        goto label_105;
#line 178 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=1598 dst=r6 src=r0 offset=0 imm=10
#line 178 "sample/undocked/map.c"
    r6 = IMMEDIATE(10);
label_104:
    // EBPF_OP_LDXW pc=1599 dst=r1 src=r10 offset=-4 imm=0
#line 179 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_STXW pc=1600 dst=r10 src=r1 offset=-8 imm=0
#line 179 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1601 dst=r2 src=r10 offset=0 imm=0
#line 179 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1602 dst=r2 src=r0 offset=0 imm=-8
#line 179 "sample/undocked/map.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=1603 dst=r1 src=r1 offset=0 imm=8
#line 179 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_MOV64_IMM pc=1605 dst=r3 src=r0 offset=0 imm=0
#line 179 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1606 dst=r0 src=r0 offset=0 imm=16
#line 179 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 179 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 179 "sample/undocked/map.c"
        return 0;
#line 179 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1607 dst=r7 src=r0 offset=0 imm=0
#line 179 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1608 dst=r5 src=r7 offset=0 imm=0
#line 179 "sample/undocked/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=1609 dst=r5 src=r0 offset=0 imm=32
#line 179 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1610 dst=r1 src=r5 offset=0 imm=0
#line 179 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1611 dst=r1 src=r0 offset=0 imm=32
#line 179 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JNE_IMM pc=1612 dst=r1 src=r0 offset=93 imm=0
#line 179 "sample/undocked/map.c"
    if (r1 != IMMEDIATE(0)) {
#line 179 "sample/undocked/map.c"
        goto label_107;
#line 179 "sample/undocked/map.c"
    }
    // EBPF_OP_LDXW pc=1613 dst=r1 src=r10 offset=-4 imm=0
#line 178 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ADD64_IMM pc=1614 dst=r1 src=r0 offset=0 imm=1
#line 178 "sample/undocked/map.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=1615 dst=r10 src=r1 offset=-4 imm=0
#line 178 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_LDXW pc=1616 dst=r1 src=r10 offset=-4 imm=0
#line 178 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LSH64_IMM pc=1617 dst=r1 src=r0 offset=0 imm=32
#line 178 "sample/undocked/map.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1618 dst=r1 src=r0 offset=0 imm=32
#line 178 "sample/undocked/map.c"
    r1 = (int64_t)r1 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=1619 dst=r6 src=r1 offset=-21 imm=0
#line 178 "sample/undocked/map.c"
    if ((int64_t)r6 > (int64_t)r1) {
#line 178 "sample/undocked/map.c"
        goto label_104;
#line 178 "sample/undocked/map.c"
    }
label_105:
    // EBPF_OP_MOV64_IMM pc=1620 dst=r6 src=r0 offset=0 imm=10
#line 178 "sample/undocked/map.c"
    r6 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=1621 dst=r10 src=r6 offset=-4 imm=0
#line 182 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=1622 dst=r2 src=r10 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1623 dst=r2 src=r0 offset=0 imm=-4
#line 182 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=1624 dst=r8 src=r0 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=1625 dst=r1 src=r1 offset=0 imm=8
#line 182 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_MOV64_IMM pc=1627 dst=r3 src=r0 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1628 dst=r0 src=r0 offset=0 imm=16
#line 182 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 182 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 182 "sample/undocked/map.c"
        return 0;
#line 182 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1629 dst=r7 src=r0 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1630 dst=r5 src=r7 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=1631 dst=r5 src=r0 offset=0 imm=32
#line 182 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1632 dst=r1 src=r5 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1633 dst=r1 src=r0 offset=0 imm=32
#line 182 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=1634 dst=r2 src=r0 offset=0 imm=-29
#line 182 "sample/undocked/map.c"
    r2 = (uint64_t)4294967267;
    // EBPF_OP_JEQ_REG pc=1636 dst=r1 src=r2 offset=30 imm=0
#line 182 "sample/undocked/map.c"
    if (r1 == r2) {
#line 182 "sample/undocked/map.c"
        goto label_106;
#line 182 "sample/undocked/map.c"
    }
    // EBPF_OP_STXB pc=1637 dst=r10 src=r8 offset=-58 imm=0
#line 182 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-58)) = (uint8_t)r8;
    // EBPF_OP_MOV64_IMM pc=1638 dst=r1 src=r0 offset=0 imm=25637
#line 182 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1639 dst=r10 src=r1 offset=-60 imm=0
#line 182 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-60)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1640 dst=r1 src=r0 offset=0 imm=543450478
#line 182 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1641 dst=r10 src=r1 offset=-64 imm=0
#line 182 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1642 dst=r1 src=r0 offset=0 imm=1914725413
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1644 dst=r10 src=r1 offset=-72 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1645 dst=r1 src=r0 offset=0 imm=1667592312
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1647 dst=r10 src=r1 offset=-80 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1648 dst=r1 src=r0 offset=0 imm=543649385
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1650 dst=r10 src=r1 offset=-88 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1651 dst=r1 src=r0 offset=0 imm=1852383341
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1653 dst=r10 src=r1 offset=-96 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1654 dst=r1 src=r0 offset=0 imm=1752397168
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1656 dst=r10 src=r1 offset=-104 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1657 dst=r1 src=r0 offset=0 imm=1600548962
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1659 dst=r10 src=r1 offset=-112 imm=0
#line 182 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=1660 dst=r3 src=r10 offset=-4 imm=0
#line 182 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ARSH64_IMM pc=1661 dst=r5 src=r0 offset=0 imm=32
#line 182 "sample/undocked/map.c"
    r5 = (int64_t)r5 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1662 dst=r1 src=r10 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1663 dst=r1 src=r0 offset=0 imm=-112
#line 182 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1664 dst=r2 src=r0 offset=0 imm=55
#line 182 "sample/undocked/map.c"
    r2 = IMMEDIATE(55);
    // EBPF_OP_MOV64_IMM pc=1665 dst=r4 src=r0 offset=0 imm=-29
#line 182 "sample/undocked/map.c"
    r4 = IMMEDIATE(-29);
    // EBPF_OP_JA pc=1666 dst=r0 src=r0 offset=69 imm=0
#line 182 "sample/undocked/map.c"
    goto label_109;
label_106:
    // EBPF_OP_STXW pc=1667 dst=r10 src=r6 offset=-4 imm=0
#line 183 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=1668 dst=r2 src=r10 offset=0 imm=0
#line 183 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1669 dst=r2 src=r0 offset=0 imm=-4
#line 183 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1670 dst=r1 src=r1 offset=0 imm=8
#line 183 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_MOV64_IMM pc=1672 dst=r3 src=r0 offset=0 imm=2
#line 183 "sample/undocked/map.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_CALL pc=1673 dst=r0 src=r0 offset=0 imm=16
#line 183 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 183 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 183 "sample/undocked/map.c"
        return 0;
#line 183 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1674 dst=r7 src=r0 offset=0 imm=0
#line 183 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1675 dst=r5 src=r7 offset=0 imm=0
#line 183 "sample/undocked/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=1676 dst=r5 src=r0 offset=0 imm=32
#line 183 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1677 dst=r1 src=r5 offset=0 imm=0
#line 183 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1678 dst=r1 src=r0 offset=0 imm=32
#line 183 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1679 dst=r1 src=r0 offset=58 imm=0
#line 183 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 183 "sample/undocked/map.c"
        goto label_110;
#line 183 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=1680 dst=r1 src=r0 offset=0 imm=25637
#line 183 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1681 dst=r10 src=r1 offset=-60 imm=0
#line 183 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-60)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1682 dst=r1 src=r0 offset=0 imm=543450478
#line 183 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1683 dst=r10 src=r1 offset=-64 imm=0
#line 183 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1684 dst=r1 src=r0 offset=0 imm=1914725413
#line 183 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1686 dst=r10 src=r1 offset=-72 imm=0
#line 183 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1687 dst=r1 src=r0 offset=0 imm=1667592312
#line 183 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1689 dst=r10 src=r1 offset=-80 imm=0
#line 183 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1690 dst=r1 src=r0 offset=0 imm=543649385
#line 183 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1692 dst=r10 src=r1 offset=-88 imm=0
#line 183 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1693 dst=r1 src=r0 offset=0 imm=1852383341
#line 183 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1695 dst=r10 src=r1 offset=-96 imm=0
#line 183 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1696 dst=r1 src=r0 offset=0 imm=1752397168
#line 183 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1698 dst=r10 src=r1 offset=-104 imm=0
#line 183 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1699 dst=r1 src=r0 offset=0 imm=1600548962
#line 183 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1701 dst=r10 src=r1 offset=-112 imm=0
#line 183 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=1702 dst=r1 src=r0 offset=0 imm=0
#line 183 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1703 dst=r10 src=r1 offset=-58 imm=0
#line 183 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-58)) = (uint8_t)r1;
    // EBPF_OP_LDXW pc=1704 dst=r3 src=r10 offset=-4 imm=0
#line 183 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JA pc=1705 dst=r0 src=r0 offset=25 imm=0
#line 183 "sample/undocked/map.c"
    goto label_108;
label_107:
    // EBPF_OP_MOV64_IMM pc=1706 dst=r1 src=r0 offset=0 imm=25637
#line 183 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1707 dst=r10 src=r1 offset=-60 imm=0
#line 179 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-60)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1708 dst=r1 src=r0 offset=0 imm=543450478
#line 179 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1709 dst=r10 src=r1 offset=-64 imm=0
#line 179 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1710 dst=r1 src=r0 offset=0 imm=1914725413
#line 179 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1712 dst=r10 src=r1 offset=-72 imm=0
#line 179 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1713 dst=r1 src=r0 offset=0 imm=1667592312
#line 179 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1715 dst=r10 src=r1 offset=-80 imm=0
#line 179 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1716 dst=r1 src=r0 offset=0 imm=543649385
#line 179 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1718 dst=r10 src=r1 offset=-88 imm=0
#line 179 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1719 dst=r1 src=r0 offset=0 imm=1852383341
#line 179 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1721 dst=r10 src=r1 offset=-96 imm=0
#line 179 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1722 dst=r1 src=r0 offset=0 imm=1752397168
#line 179 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1724 dst=r10 src=r1 offset=-104 imm=0
#line 179 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1725 dst=r1 src=r0 offset=0 imm=1600548962
#line 179 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1727 dst=r10 src=r1 offset=-112 imm=0
#line 179 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=1728 dst=r1 src=r0 offset=0 imm=0
#line 179 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1729 dst=r10 src=r1 offset=-58 imm=0
#line 179 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-58)) = (uint8_t)r1;
    // EBPF_OP_LDXW pc=1730 dst=r3 src=r10 offset=-8 imm=0
#line 179 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8));
label_108:
    // EBPF_OP_ARSH64_IMM pc=1731 dst=r5 src=r0 offset=0 imm=32
#line 179 "sample/undocked/map.c"
    r5 = (int64_t)r5 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1732 dst=r1 src=r10 offset=0 imm=0
#line 179 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1733 dst=r1 src=r0 offset=0 imm=-112
#line 179 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1734 dst=r2 src=r0 offset=0 imm=55
#line 179 "sample/undocked/map.c"
    r2 = IMMEDIATE(55);
    // EBPF_OP_MOV64_IMM pc=1735 dst=r4 src=r0 offset=0 imm=0
#line 179 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
label_109:
    // EBPF_OP_CALL pc=1736 dst=r0 src=r0 offset=0 imm=15
#line 179 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[10].address(r1, r2, r3, r4, r5, context);
#line 179 "sample/undocked/map.c"
    if ((runtime_context->helper_data[10].tail_call) && (r0 == 0)) {
#line 179 "sample/undocked/map.c"
        return 0;
#line 179 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1737 dst=r0 src=r0 offset=-232 imm=0
#line 179 "sample/undocked/map.c"
    goto label_98;
label_110:
    // EBPF_OP_MOV64_IMM pc=1738 dst=r1 src=r0 offset=0 imm=0
#line 179 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1739 dst=r10 src=r1 offset=-4 imm=0
#line 185 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1740 dst=r2 src=r10 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1741 dst=r2 src=r0 offset=0 imm=-4
#line 185 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1742 dst=r1 src=r1 offset=0 imm=8
#line 185 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=1744 dst=r0 src=r0 offset=0 imm=18
#line 185 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 185 "sample/undocked/map.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 185 "sample/undocked/map.c"
        return 0;
#line 185 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1745 dst=r7 src=r0 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1746 dst=r4 src=r7 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=1747 dst=r4 src=r0 offset=0 imm=32
#line 185 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1748 dst=r1 src=r4 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1749 dst=r1 src=r0 offset=0 imm=32
#line 185 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1750 dst=r1 src=r0 offset=27 imm=0
#line 185 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 185 "sample/undocked/map.c"
        goto label_112;
#line 185 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=1751 dst=r1 src=r0 offset=0 imm=100
#line 185 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=1752 dst=r10 src=r1 offset=-64 imm=0
#line 185 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=1753 dst=r1 src=r0 offset=0 imm=1852994932
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=1755 dst=r10 src=r1 offset=-72 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1756 dst=r1 src=r0 offset=0 imm=622883948
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=1758 dst=r10 src=r1 offset=-80 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1759 dst=r1 src=r0 offset=0 imm=543649385
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=1761 dst=r10 src=r1 offset=-88 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1762 dst=r1 src=r0 offset=0 imm=2019893357
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=1764 dst=r10 src=r1 offset=-96 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1765 dst=r1 src=r0 offset=0 imm=1801807216
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1767 dst=r10 src=r1 offset=-104 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1768 dst=r1 src=r0 offset=0 imm=1600548962
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1770 dst=r10 src=r1 offset=-112 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1771 dst=r4 src=r0 offset=0 imm=32
#line 185 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1772 dst=r1 src=r10 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1773 dst=r1 src=r0 offset=0 imm=-112
#line 185 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1774 dst=r2 src=r0 offset=0 imm=50
#line 185 "sample/undocked/map.c"
    r2 = IMMEDIATE(50);
label_111:
    // EBPF_OP_MOV64_IMM pc=1775 dst=r3 src=r0 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1776 dst=r0 src=r0 offset=0 imm=14
#line 185 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 185 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 185 "sample/undocked/map.c"
        return 0;
#line 185 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1777 dst=r0 src=r0 offset=-272 imm=0
#line 185 "sample/undocked/map.c"
    goto label_98;
label_112:
    // EBPF_OP_LDXW pc=1778 dst=r3 src=r10 offset=-4 imm=0
#line 185 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1779 dst=r3 src=r0 offset=22 imm=10
#line 185 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(10)) {
#line 185 "sample/undocked/map.c"
        goto label_113;
#line 185 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=1780 dst=r1 src=r0 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1781 dst=r10 src=r1 offset=-72 imm=0
#line 185 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=1782 dst=r1 src=r0 offset=0 imm=1852404835
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=1784 dst=r10 src=r1 offset=-80 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1785 dst=r1 src=r0 offset=0 imm=543434016
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=1787 dst=r10 src=r1 offset=-88 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1788 dst=r1 src=r0 offset=0 imm=1701978221
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=1790 dst=r10 src=r1 offset=-96 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1791 dst=r1 src=r0 offset=0 imm=1801807216
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1793 dst=r10 src=r1 offset=-104 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1794 dst=r1 src=r0 offset=0 imm=1600548962
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1796 dst=r10 src=r1 offset=-112 imm=0
#line 185 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1797 dst=r1 src=r10 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1798 dst=r1 src=r0 offset=0 imm=-112
#line 185 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1799 dst=r2 src=r0 offset=0 imm=41
#line 185 "sample/undocked/map.c"
    r2 = IMMEDIATE(41);
    // EBPF_OP_MOV64_IMM pc=1800 dst=r4 src=r0 offset=0 imm=10
#line 185 "sample/undocked/map.c"
    r4 = IMMEDIATE(10);
    // EBPF_OP_JA pc=1801 dst=r0 src=r0 offset=-299 imm=0
#line 185 "sample/undocked/map.c"
    goto label_97;
label_113:
    // EBPF_OP_MOV64_IMM pc=1802 dst=r6 src=r0 offset=0 imm=0
#line 185 "sample/undocked/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1803 dst=r10 src=r6 offset=-4 imm=0
#line 189 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_LDXW pc=1804 dst=r1 src=r10 offset=-4 imm=0
#line 189 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LSH64_IMM pc=1805 dst=r1 src=r0 offset=0 imm=32
#line 189 "sample/undocked/map.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1806 dst=r1 src=r0 offset=0 imm=32
#line 189 "sample/undocked/map.c"
    r1 = (int64_t)r1 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1807 dst=r1 src=r0 offset=9 imm=9
#line 189 "sample/undocked/map.c"
    if ((int64_t)r1 > IMMEDIATE(9)) {
#line 189 "sample/undocked/map.c"
        goto label_115;
#line 189 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=1808 dst=r8 src=r0 offset=0 imm=10
#line 189 "sample/undocked/map.c"
    r8 = IMMEDIATE(10);
    // EBPF_OP_JA pc=1809 dst=r0 src=r0 offset=22 imm=0
#line 189 "sample/undocked/map.c"
    goto label_116;
label_114:
    // EBPF_OP_LDXW pc=1810 dst=r1 src=r10 offset=-4 imm=0
#line 189 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ADD64_IMM pc=1811 dst=r1 src=r0 offset=0 imm=1
#line 189 "sample/undocked/map.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=1812 dst=r10 src=r1 offset=-4 imm=0
#line 189 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_LDXW pc=1813 dst=r1 src=r10 offset=-4 imm=0
#line 189 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LSH64_IMM pc=1814 dst=r1 src=r0 offset=0 imm=32
#line 189 "sample/undocked/map.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1815 dst=r1 src=r0 offset=0 imm=32
#line 189 "sample/undocked/map.c"
    r1 = (int64_t)r1 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=1816 dst=r8 src=r1 offset=15 imm=0
#line 189 "sample/undocked/map.c"
    if ((int64_t)r8 > (int64_t)r1) {
#line 189 "sample/undocked/map.c"
        goto label_116;
#line 189 "sample/undocked/map.c"
    }
label_115:
    // EBPF_OP_STXW pc=1817 dst=r10 src=r6 offset=-4 imm=0
#line 193 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=1818 dst=r2 src=r10 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1819 dst=r2 src=r0 offset=0 imm=-4
#line 193 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1820 dst=r1 src=r1 offset=0 imm=8
#line 193 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=1822 dst=r0 src=r0 offset=0 imm=18
#line 193 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 193 "sample/undocked/map.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 193 "sample/undocked/map.c"
        return 0;
#line 193 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1823 dst=r7 src=r0 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1824 dst=r4 src=r7 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=1825 dst=r4 src=r0 offset=0 imm=32
#line 193 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1826 dst=r1 src=r4 offset=0 imm=0
#line 193 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1827 dst=r1 src=r0 offset=0 imm=32
#line 193 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=1828 dst=r2 src=r0 offset=0 imm=-7
#line 193 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1830 dst=r1 src=r2 offset=45 imm=0
#line 193 "sample/undocked/map.c"
    if (r1 == r2) {
#line 193 "sample/undocked/map.c"
        goto label_118;
#line 193 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1831 dst=r0 src=r0 offset=-773 imm=0
#line 193 "sample/undocked/map.c"
    goto label_69;
label_116:
    // EBPF_OP_STXW pc=1832 dst=r10 src=r6 offset=-8 imm=0
#line 190 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=1833 dst=r2 src=r10 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1834 dst=r2 src=r0 offset=0 imm=-8
#line 190 "sample/undocked/map.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=1835 dst=r1 src=r1 offset=0 imm=8
#line 190 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=1837 dst=r0 src=r0 offset=0 imm=17
#line 190 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 190 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 190 "sample/undocked/map.c"
        return 0;
#line 190 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1838 dst=r7 src=r0 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1839 dst=r4 src=r7 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=1840 dst=r4 src=r0 offset=0 imm=32
#line 190 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1841 dst=r1 src=r4 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1842 dst=r1 src=r0 offset=0 imm=32
#line 190 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1843 dst=r1 src=r0 offset=1 imm=0
#line 190 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 190 "sample/undocked/map.c"
        goto label_117;
#line 190 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1844 dst=r0 src=r0 offset=34 imm=0
#line 190 "sample/undocked/map.c"
    goto label_119;
label_117:
    // EBPF_OP_LDXW pc=1845 dst=r1 src=r10 offset=-4 imm=0
#line 190 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_MOV64_IMM pc=1846 dst=r2 src=r0 offset=0 imm=10
#line 190 "sample/undocked/map.c"
    r2 = IMMEDIATE(10);
    // EBPF_OP_SUB64_REG pc=1847 dst=r2 src=r1 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r2 -= r1;
    // EBPF_OP_LSH64_IMM pc=1848 dst=r2 src=r0 offset=0 imm=32
#line 190 "sample/undocked/map.c"
    r2 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=1849 dst=r2 src=r0 offset=0 imm=32
#line 190 "sample/undocked/map.c"
    r2 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDXW pc=1850 dst=r3 src=r10 offset=-8 imm=0
#line 190 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8));
    // EBPF_OP_JEQ_REG pc=1851 dst=r3 src=r2 offset=-42 imm=0
#line 190 "sample/undocked/map.c"
    if (r3 == r2) {
#line 190 "sample/undocked/map.c"
        goto label_114;
#line 190 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=1852 dst=r1 src=r0 offset=0 imm=1735289204
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1854 dst=r10 src=r1 offset=-80 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1855 dst=r1 src=r0 offset=0 imm=1696621605
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1857 dst=r10 src=r1 offset=-88 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1858 dst=r1 src=r0 offset=0 imm=1952805408
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1860 dst=r10 src=r1 offset=-96 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1861 dst=r1 src=r0 offset=0 imm=1601204080
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1863 dst=r10 src=r1 offset=-104 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1864 dst=r1 src=r0 offset=0 imm=1600548962
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1866 dst=r10 src=r1 offset=-112 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=1867 dst=r1 src=r10 offset=-4 imm=0
#line 190 "sample/undocked/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_MOV64_IMM pc=1868 dst=r4 src=r0 offset=0 imm=10
#line 190 "sample/undocked/map.c"
    r4 = IMMEDIATE(10);
    // EBPF_OP_SUB64_REG pc=1869 dst=r4 src=r1 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r4 -= r1;
    // EBPF_OP_LSH64_IMM pc=1870 dst=r4 src=r0 offset=0 imm=32
#line 190 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1871 dst=r4 src=r0 offset=0 imm=32
#line 190 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1872 dst=r1 src=r10 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1873 dst=r1 src=r0 offset=0 imm=-112
#line 190 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1874 dst=r2 src=r0 offset=0 imm=40
#line 190 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_JA pc=1875 dst=r0 src=r0 offset=-373 imm=0
#line 190 "sample/undocked/map.c"
    goto label_97;
label_118:
    // EBPF_OP_LDXW pc=1876 dst=r3 src=r10 offset=-4 imm=0
#line 193 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1877 dst=r3 src=r0 offset=26 imm=0
#line 193 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 193 "sample/undocked/map.c"
        goto label_120;
#line 193 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1878 dst=r0 src=r0 offset=-397 imm=0
#line 193 "sample/undocked/map.c"
    goto label_95;
label_119:
    // EBPF_OP_LDDW pc=1879 dst=r1 src=r0 offset=0 imm=1701737077
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=1881 dst=r10 src=r1 offset=-72 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1882 dst=r1 src=r0 offset=0 imm=1680154740
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=1884 dst=r10 src=r1 offset=-80 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1885 dst=r1 src=r0 offset=0 imm=1914726254
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=1887 dst=r10 src=r1 offset=-88 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1888 dst=r1 src=r0 offset=0 imm=1886938400
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=1890 dst=r10 src=r1 offset=-96 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1891 dst=r1 src=r0 offset=0 imm=1601204080
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1893 dst=r10 src=r1 offset=-104 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1894 dst=r1 src=r0 offset=0 imm=1600548962
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1896 dst=r10 src=r1 offset=-112 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=1897 dst=r1 src=r0 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1898 dst=r10 src=r1 offset=-64 imm=0
#line 190 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint8_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1899 dst=r4 src=r0 offset=0 imm=32
#line 190 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1900 dst=r1 src=r10 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1901 dst=r1 src=r0 offset=0 imm=-112
#line 190 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1902 dst=r2 src=r0 offset=0 imm=49
#line 190 "sample/undocked/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=1903 dst=r0 src=r0 offset=-129 imm=0
#line 190 "sample/undocked/map.c"
    goto label_111;
label_120:
    // EBPF_OP_MOV64_IMM pc=1904 dst=r6 src=r0 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1905 dst=r10 src=r6 offset=-4 imm=0
#line 194 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=1906 dst=r2 src=r10 offset=0 imm=0
#line 194 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1907 dst=r2 src=r0 offset=0 imm=-4
#line 194 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1908 dst=r1 src=r1 offset=0 imm=8
#line 194 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=1910 dst=r0 src=r0 offset=0 imm=17
#line 194 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 194 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 194 "sample/undocked/map.c"
        return 0;
#line 194 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1911 dst=r7 src=r0 offset=0 imm=0
#line 194 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1912 dst=r4 src=r7 offset=0 imm=0
#line 194 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=1913 dst=r4 src=r0 offset=0 imm=32
#line 194 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1914 dst=r1 src=r4 offset=0 imm=0
#line 194 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1915 dst=r1 src=r0 offset=0 imm=32
#line 194 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=1916 dst=r2 src=r0 offset=0 imm=-7
#line 194 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1918 dst=r1 src=r2 offset=1 imm=0
#line 194 "sample/undocked/map.c"
    if (r1 == r2) {
#line 194 "sample/undocked/map.c"
        goto label_121;
#line 194 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1919 dst=r0 src=r0 offset=-373 imm=0
#line 194 "sample/undocked/map.c"
    goto label_100;
label_121:
    // EBPF_OP_LDXW pc=1920 dst=r3 src=r10 offset=-4 imm=0
#line 194 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1921 dst=r3 src=r0 offset=-1820 imm=0
#line 194 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 194 "sample/undocked/map.c"
        goto label_8;
#line 194 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1922 dst=r0 src=r0 offset=-350 imm=0
#line 194 "sample/undocked/map.c"
    goto label_102;
#line 199 "sample/undocked/map.c"
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
        1923,
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
