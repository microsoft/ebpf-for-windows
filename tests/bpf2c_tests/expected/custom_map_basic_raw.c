// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from custom_map_basic.o

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
         1,                  // Current Version.
         80,                 // Struct size up to the last field.
         80,                 // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         10,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "array_map"},
    {
     {0, 0},
     {
         1,               // Current Version.
         80,              // Struct size up to the last field.
         80,              // Total struct size including padding.
     },
     {
         15,              // Type of map.
         4,               // Size in bytes of a map key.
         4,               // Size in bytes of a map value.
         1,               // Maximum number of entries allowed in the map.
         0,               // Inner map index.
         LIBBPF_PIN_NONE, // Pinning type for the map.
         14,              // Identifier for a map template.
         0,               // The id of the inner map template.
     },
     "sample_hash_map"},
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
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         16,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "config_map"},
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
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         18,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "result_map"},
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
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         20,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "result_value_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 5;
}

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static helper_function_entry_t test_map_delete_element_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     3,
     "helper_id_3",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID test_map_delete_element_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID test_map_delete_element_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t test_map_delete_element_maps[] = {
    1,
    2,
    3,
};

#pragma code_seg(push, "sample~5")
static uint64_t
test_map_delete_element(void* context, const program_runtime_context_t* runtime_context)
#line 100 "sample/undocked/custom_map_basic.c"
{
#line 100 "sample/undocked/custom_map_basic.c"
    // Prologue.
#line 100 "sample/undocked/custom_map_basic.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r0 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r1 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r2 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r3 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r4 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r5 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r6 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r10 = 0;

#line 100 "sample/undocked/custom_map_basic.c"
    r1 = (uintptr_t)context;
#line 100 "sample/undocked/custom_map_basic.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=0
#line 100 "sample/undocked/custom_map_basic.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r6 offset=-4 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=2 dst=r2 src=r10 offset=0 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=3 dst=r2 src=r0 offset=0 imm=-4
#line 85 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=4 dst=r1 src=r1 offset=0 imm=3
#line 88 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_CALL pc=6 dst=r0 src=r0 offset=0 imm=1
#line 88 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/custom_map_basic.c"
        return 0;
#line 88 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_JEQ_IMM pc=7 dst=r0 src=r0 offset=2 imm=0
#line 89 "sample/undocked/custom_map_basic.c"
    if (r0 == IMMEDIATE(0)) {
#line 89 "sample/undocked/custom_map_basic.c"
        goto label_1;
#line 89 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_LDXW pc=8 dst=r1 src=r0 offset=0 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    READ_ONCE_32(r1, r0, OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=9 dst=r1 src=r0 offset=2 imm=2
#line 92 "sample/undocked/custom_map_basic.c"
    if (r1 == IMMEDIATE(2)) {
#line 92 "sample/undocked/custom_map_basic.c"
        goto label_2;
#line 92 "sample/undocked/custom_map_basic.c"
    }
label_1:
    // EBPF_OP_STXW pc=10 dst=r10 src=r6 offset=-4 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_JA pc=11 dst=r0 src=r0 offset=12 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    goto label_4;
label_2:
    // EBPF_OP_STXW pc=12 dst=r10 src=r6 offset=-12 imm=0
#line 107 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-12));
    // EBPF_OP_MOV64_REG pc=13 dst=r2 src=r10 offset=0 imm=0
#line 107 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=14 dst=r2 src=r0 offset=0 imm=-12
#line 107 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-12);
    // EBPF_OP_LDDW pc=15 dst=r1 src=r1 offset=0 imm=2
#line 108 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=17 dst=r0 src=r0 offset=0 imm=3
#line 108 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 108 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 108 "sample/undocked/custom_map_basic.c"
        return 0;
#line 108 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_LSH64_IMM pc=18 dst=r0 src=r0 offset=0 imm=32
#line 109 "sample/undocked/custom_map_basic.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=19 dst=r0 src=r0 offset=0 imm=32
#line 110 "sample/undocked/custom_map_basic.c"
    r0 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_IMM pc=20 dst=r1 src=r0 offset=0 imm=1
#line 110 "sample/undocked/custom_map_basic.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=21 dst=r0 src=r0 offset=1 imm=0
#line 110 "sample/undocked/custom_map_basic.c"
    if (r0 == IMMEDIATE(0)) {
#line 110 "sample/undocked/custom_map_basic.c"
        goto label_3;
#line 110 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_MOV64_IMM pc=22 dst=r1 src=r0 offset=0 imm=0
#line 110 "sample/undocked/custom_map_basic.c"
    r1 = IMMEDIATE(0);
label_3:
    // EBPF_OP_STXW pc=23 dst=r10 src=r1 offset=-4 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
label_4:
    // EBPF_OP_STXW pc=24 dst=r10 src=r6 offset=-8 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=25 dst=r2 src=r10 offset=0 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=26 dst=r2 src=r0 offset=0 imm=-8
#line 71 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=27 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/custom_map_basic.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=28 dst=r3 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/custom_map_basic.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=29 dst=r1 src=r1 offset=0 imm=4
#line 71 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_MOV64_IMM pc=31 dst=r4 src=r0 offset=0 imm=0
#line 72 "sample/undocked/custom_map_basic.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=32 dst=r0 src=r0 offset=0 imm=2
#line 72 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 72 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 72 "sample/undocked/custom_map_basic.c"
        return 0;
#line 72 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_MOV64_IMM pc=33 dst=r0 src=r0 offset=0 imm=0
#line 72 "sample/undocked/custom_map_basic.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=34 dst=r0 src=r0 offset=0 imm=0
#line 72 "sample/undocked/custom_map_basic.c"
    return r0;
#line 100 "sample/undocked/custom_map_basic.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t test_map_find_and_delete_element_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     4,
     "helper_id_4",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID test_map_find_and_delete_element_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID test_map_find_and_delete_element_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t test_map_find_and_delete_element_maps[] = {
    1,
    2,
    3,
};

#pragma code_seg(push, "sample~4")
static uint64_t
test_map_find_and_delete_element(void* context, const program_runtime_context_t* runtime_context)
#line 100 "sample/undocked/custom_map_basic.c"
{
#line 100 "sample/undocked/custom_map_basic.c"
    // Prologue.
#line 100 "sample/undocked/custom_map_basic.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r0 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r1 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r2 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r3 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r4 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r5 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r6 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r10 = 0;

#line 100 "sample/undocked/custom_map_basic.c"
    r1 = (uintptr_t)context;
#line 100 "sample/undocked/custom_map_basic.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=0
#line 100 "sample/undocked/custom_map_basic.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r6 offset=-4 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=2 dst=r2 src=r10 offset=0 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=3 dst=r2 src=r0 offset=0 imm=-4
#line 85 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=4 dst=r1 src=r1 offset=0 imm=3
#line 88 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_CALL pc=6 dst=r0 src=r0 offset=0 imm=1
#line 88 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/custom_map_basic.c"
        return 0;
#line 88 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_JEQ_IMM pc=7 dst=r0 src=r0 offset=2 imm=0
#line 89 "sample/undocked/custom_map_basic.c"
    if (r0 == IMMEDIATE(0)) {
#line 89 "sample/undocked/custom_map_basic.c"
        goto label_1;
#line 89 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_LDXW pc=8 dst=r1 src=r0 offset=0 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    READ_ONCE_32(r1, r0, OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=9 dst=r1 src=r0 offset=2 imm=2
#line 92 "sample/undocked/custom_map_basic.c"
    if (r1 == IMMEDIATE(2)) {
#line 92 "sample/undocked/custom_map_basic.c"
        goto label_2;
#line 92 "sample/undocked/custom_map_basic.c"
    }
label_1:
    // EBPF_OP_STXW pc=10 dst=r10 src=r6 offset=-4 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_JA pc=11 dst=r0 src=r0 offset=10 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    goto label_4;
label_2:
    // EBPF_OP_STXW pc=12 dst=r10 src=r6 offset=-12 imm=0
#line 107 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-12));
    // EBPF_OP_MOV64_REG pc=13 dst=r2 src=r10 offset=0 imm=0
#line 107 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=14 dst=r2 src=r0 offset=0 imm=-12
#line 107 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-12);
    // EBPF_OP_LDDW pc=15 dst=r1 src=r1 offset=0 imm=2
#line 108 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=17 dst=r0 src=r0 offset=0 imm=4
#line 108 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 108 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 108 "sample/undocked/custom_map_basic.c"
        return 0;
#line 108 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_MOV64_IMM pc=18 dst=r1 src=r0 offset=0 imm=1
#line 109 "sample/undocked/custom_map_basic.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_JNE_IMM pc=19 dst=r0 src=r0 offset=1 imm=0
#line 110 "sample/undocked/custom_map_basic.c"
    if (r0 != IMMEDIATE(0)) {
#line 110 "sample/undocked/custom_map_basic.c"
        goto label_3;
#line 110 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_MOV64_IMM pc=20 dst=r1 src=r0 offset=0 imm=0
#line 110 "sample/undocked/custom_map_basic.c"
    r1 = IMMEDIATE(0);
label_3:
    // EBPF_OP_STXW pc=21 dst=r10 src=r1 offset=-4 imm=0
#line 110 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
label_4:
    // EBPF_OP_STXW pc=22 dst=r10 src=r6 offset=-8 imm=0
#line 110 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=23 dst=r2 src=r10 offset=0 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=24 dst=r2 src=r0 offset=0 imm=-8
#line 109 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=25 dst=r3 src=r10 offset=0 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=26 dst=r3 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/custom_map_basic.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=27 dst=r1 src=r1 offset=0 imm=4
#line 71 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_MOV64_IMM pc=29 dst=r4 src=r0 offset=0 imm=0
#line 71 "sample/undocked/custom_map_basic.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=30 dst=r0 src=r0 offset=0 imm=2
#line 71 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 71 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 71 "sample/undocked/custom_map_basic.c"
        return 0;
#line 71 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_MOV64_IMM pc=31 dst=r0 src=r0 offset=0 imm=0
#line 72 "sample/undocked/custom_map_basic.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=32 dst=r0 src=r0 offset=0 imm=0
#line 72 "sample/undocked/custom_map_basic.c"
    return r0;
#line 100 "sample/undocked/custom_map_basic.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t test_map_peek_elem_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     18,
     "helper_id_18",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID test_map_peek_elem_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID test_map_peek_elem_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t test_map_peek_elem_maps[] = {
    1,
    2,
    3,
};

#pragma code_seg(push, "sample~1")
static uint64_t
test_map_peek_elem(void* context, const program_runtime_context_t* runtime_context)
#line 100 "sample/undocked/custom_map_basic.c"
{
#line 100 "sample/undocked/custom_map_basic.c"
    // Prologue.
#line 100 "sample/undocked/custom_map_basic.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r0 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r1 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r2 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r3 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r4 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r5 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r6 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r10 = 0;

#line 100 "sample/undocked/custom_map_basic.c"
    r1 = (uintptr_t)context;
#line 100 "sample/undocked/custom_map_basic.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=0
#line 100 "sample/undocked/custom_map_basic.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r6 offset=-4 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=2 dst=r2 src=r10 offset=0 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=3 dst=r2 src=r0 offset=0 imm=-4
#line 85 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=4 dst=r1 src=r1 offset=0 imm=3
#line 88 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_CALL pc=6 dst=r0 src=r0 offset=0 imm=1
#line 88 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/custom_map_basic.c"
        return 0;
#line 88 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_JEQ_IMM pc=7 dst=r0 src=r0 offset=2 imm=0
#line 89 "sample/undocked/custom_map_basic.c"
    if (r0 == IMMEDIATE(0)) {
#line 89 "sample/undocked/custom_map_basic.c"
        goto label_1;
#line 89 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_LDXW pc=8 dst=r1 src=r0 offset=0 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    READ_ONCE_32(r1, r0, OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=9 dst=r1 src=r0 offset=2 imm=2
#line 92 "sample/undocked/custom_map_basic.c"
    if (r1 == IMMEDIATE(2)) {
#line 92 "sample/undocked/custom_map_basic.c"
        goto label_2;
#line 92 "sample/undocked/custom_map_basic.c"
    }
label_1:
    // EBPF_OP_STXW pc=10 dst=r10 src=r6 offset=-4 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_JA pc=11 dst=r0 src=r0 offset=12 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    goto label_4;
label_2:
    // EBPF_OP_STXW pc=12 dst=r10 src=r6 offset=-12 imm=0
#line 107 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-12));
    // EBPF_OP_MOV64_REG pc=13 dst=r2 src=r10 offset=0 imm=0
#line 107 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=14 dst=r2 src=r0 offset=0 imm=-12
#line 107 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-12);
    // EBPF_OP_LDDW pc=15 dst=r1 src=r1 offset=0 imm=2
#line 108 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=17 dst=r0 src=r0 offset=0 imm=18
#line 108 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 108 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 108 "sample/undocked/custom_map_basic.c"
        return 0;
#line 108 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_LSH64_IMM pc=18 dst=r0 src=r0 offset=0 imm=32
#line 109 "sample/undocked/custom_map_basic.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=19 dst=r0 src=r0 offset=0 imm=32
#line 110 "sample/undocked/custom_map_basic.c"
    r0 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_IMM pc=20 dst=r1 src=r0 offset=0 imm=1
#line 110 "sample/undocked/custom_map_basic.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=21 dst=r0 src=r0 offset=1 imm=0
#line 110 "sample/undocked/custom_map_basic.c"
    if (r0 == IMMEDIATE(0)) {
#line 110 "sample/undocked/custom_map_basic.c"
        goto label_3;
#line 110 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_MOV64_IMM pc=22 dst=r1 src=r0 offset=0 imm=0
#line 110 "sample/undocked/custom_map_basic.c"
    r1 = IMMEDIATE(0);
label_3:
    // EBPF_OP_STXW pc=23 dst=r10 src=r1 offset=-4 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
label_4:
    // EBPF_OP_STXW pc=24 dst=r10 src=r6 offset=-8 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=25 dst=r2 src=r10 offset=0 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=26 dst=r2 src=r0 offset=0 imm=-8
#line 71 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=27 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/custom_map_basic.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=28 dst=r3 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/custom_map_basic.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=29 dst=r1 src=r1 offset=0 imm=4
#line 71 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_MOV64_IMM pc=31 dst=r4 src=r0 offset=0 imm=0
#line 72 "sample/undocked/custom_map_basic.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=32 dst=r0 src=r0 offset=0 imm=2
#line 72 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 72 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 72 "sample/undocked/custom_map_basic.c"
        return 0;
#line 72 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_MOV64_IMM pc=33 dst=r0 src=r0 offset=0 imm=0
#line 72 "sample/undocked/custom_map_basic.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=34 dst=r0 src=r0 offset=0 imm=0
#line 72 "sample/undocked/custom_map_basic.c"
    return r0;
#line 100 "sample/undocked/custom_map_basic.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t test_map_pop_elem_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     17,
     "helper_id_17",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID test_map_pop_elem_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID test_map_pop_elem_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t test_map_pop_elem_maps[] = {
    1,
    2,
    3,
};

#pragma code_seg(push, "sample~2")
static uint64_t
test_map_pop_elem(void* context, const program_runtime_context_t* runtime_context)
#line 100 "sample/undocked/custom_map_basic.c"
{
#line 100 "sample/undocked/custom_map_basic.c"
    // Prologue.
#line 100 "sample/undocked/custom_map_basic.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r0 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r1 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r2 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r3 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r4 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r5 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r6 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r10 = 0;

#line 100 "sample/undocked/custom_map_basic.c"
    r1 = (uintptr_t)context;
#line 100 "sample/undocked/custom_map_basic.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=0
#line 100 "sample/undocked/custom_map_basic.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r6 offset=-4 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=2 dst=r2 src=r10 offset=0 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=3 dst=r2 src=r0 offset=0 imm=-4
#line 85 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=4 dst=r1 src=r1 offset=0 imm=3
#line 88 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_CALL pc=6 dst=r0 src=r0 offset=0 imm=1
#line 88 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/custom_map_basic.c"
        return 0;
#line 88 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_JEQ_IMM pc=7 dst=r0 src=r0 offset=2 imm=0
#line 89 "sample/undocked/custom_map_basic.c"
    if (r0 == IMMEDIATE(0)) {
#line 89 "sample/undocked/custom_map_basic.c"
        goto label_1;
#line 89 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_LDXW pc=8 dst=r1 src=r0 offset=0 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    READ_ONCE_32(r1, r0, OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=9 dst=r1 src=r0 offset=2 imm=2
#line 92 "sample/undocked/custom_map_basic.c"
    if (r1 == IMMEDIATE(2)) {
#line 92 "sample/undocked/custom_map_basic.c"
        goto label_2;
#line 92 "sample/undocked/custom_map_basic.c"
    }
label_1:
    // EBPF_OP_STXW pc=10 dst=r10 src=r6 offset=-4 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_JA pc=11 dst=r0 src=r0 offset=12 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    goto label_4;
label_2:
    // EBPF_OP_STXW pc=12 dst=r10 src=r6 offset=-12 imm=0
#line 107 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-12));
    // EBPF_OP_MOV64_REG pc=13 dst=r2 src=r10 offset=0 imm=0
#line 107 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=14 dst=r2 src=r0 offset=0 imm=-12
#line 107 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-12);
    // EBPF_OP_LDDW pc=15 dst=r1 src=r1 offset=0 imm=2
#line 108 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=17 dst=r0 src=r0 offset=0 imm=17
#line 108 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 108 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 108 "sample/undocked/custom_map_basic.c"
        return 0;
#line 108 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_LSH64_IMM pc=18 dst=r0 src=r0 offset=0 imm=32
#line 109 "sample/undocked/custom_map_basic.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=19 dst=r0 src=r0 offset=0 imm=32
#line 110 "sample/undocked/custom_map_basic.c"
    r0 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_IMM pc=20 dst=r1 src=r0 offset=0 imm=1
#line 110 "sample/undocked/custom_map_basic.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=21 dst=r0 src=r0 offset=1 imm=0
#line 110 "sample/undocked/custom_map_basic.c"
    if (r0 == IMMEDIATE(0)) {
#line 110 "sample/undocked/custom_map_basic.c"
        goto label_3;
#line 110 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_MOV64_IMM pc=22 dst=r1 src=r0 offset=0 imm=0
#line 110 "sample/undocked/custom_map_basic.c"
    r1 = IMMEDIATE(0);
label_3:
    // EBPF_OP_STXW pc=23 dst=r10 src=r1 offset=-4 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
label_4:
    // EBPF_OP_STXW pc=24 dst=r10 src=r6 offset=-8 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=25 dst=r2 src=r10 offset=0 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=26 dst=r2 src=r0 offset=0 imm=-8
#line 71 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=27 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/custom_map_basic.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=28 dst=r3 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/custom_map_basic.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=29 dst=r1 src=r1 offset=0 imm=4
#line 71 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_MOV64_IMM pc=31 dst=r4 src=r0 offset=0 imm=0
#line 72 "sample/undocked/custom_map_basic.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=32 dst=r0 src=r0 offset=0 imm=2
#line 72 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 72 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 72 "sample/undocked/custom_map_basic.c"
        return 0;
#line 72 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_MOV64_IMM pc=33 dst=r0 src=r0 offset=0 imm=0
#line 72 "sample/undocked/custom_map_basic.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=34 dst=r0 src=r0 offset=0 imm=0
#line 72 "sample/undocked/custom_map_basic.c"
    return r0;
#line 100 "sample/undocked/custom_map_basic.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t test_map_push_elem_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     16,
     "helper_id_16",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID test_map_push_elem_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID test_map_push_elem_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t test_map_push_elem_maps[] = {
    1,
    2,
    3,
};

#pragma code_seg(push, "sample~3")
static uint64_t
test_map_push_elem(void* context, const program_runtime_context_t* runtime_context)
#line 100 "sample/undocked/custom_map_basic.c"
{
#line 100 "sample/undocked/custom_map_basic.c"
    // Prologue.
#line 100 "sample/undocked/custom_map_basic.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r0 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r1 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r2 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r3 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r4 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r5 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r6 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r10 = 0;

#line 100 "sample/undocked/custom_map_basic.c"
    r1 = (uintptr_t)context;
#line 100 "sample/undocked/custom_map_basic.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=0
#line 100 "sample/undocked/custom_map_basic.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r6 offset=-4 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=2 dst=r2 src=r10 offset=0 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=3 dst=r2 src=r0 offset=0 imm=-4
#line 85 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=4 dst=r1 src=r1 offset=0 imm=3
#line 88 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_CALL pc=6 dst=r0 src=r0 offset=0 imm=1
#line 88 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/custom_map_basic.c"
        return 0;
#line 88 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_JEQ_IMM pc=7 dst=r0 src=r0 offset=2 imm=0
#line 89 "sample/undocked/custom_map_basic.c"
    if (r0 == IMMEDIATE(0)) {
#line 89 "sample/undocked/custom_map_basic.c"
        goto label_1;
#line 89 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_LDXW pc=8 dst=r1 src=r0 offset=0 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    READ_ONCE_32(r1, r0, OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=9 dst=r1 src=r0 offset=2 imm=2
#line 92 "sample/undocked/custom_map_basic.c"
    if (r1 == IMMEDIATE(2)) {
#line 92 "sample/undocked/custom_map_basic.c"
        goto label_2;
#line 92 "sample/undocked/custom_map_basic.c"
    }
label_1:
    // EBPF_OP_STXW pc=10 dst=r10 src=r6 offset=-4 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_JA pc=11 dst=r0 src=r0 offset=14 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    goto label_4;
label_2:
    // EBPF_OP_MOV64_IMM pc=12 dst=r1 src=r0 offset=0 imm=100
#line 107 "sample/undocked/custom_map_basic.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXW pc=13 dst=r10 src=r1 offset=-12 imm=0
#line 107 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-12));
    // EBPF_OP_MOV64_REG pc=14 dst=r2 src=r10 offset=0 imm=0
#line 107 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=15 dst=r2 src=r0 offset=0 imm=-12
#line 108 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-12);
    // EBPF_OP_LDDW pc=16 dst=r1 src=r1 offset=0 imm=2
#line 108 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=18 dst=r3 src=r0 offset=0 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=19 dst=r0 src=r0 offset=0 imm=16
#line 110 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 110 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 110 "sample/undocked/custom_map_basic.c"
        return 0;
#line 110 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_LSH64_IMM pc=20 dst=r0 src=r0 offset=0 imm=32
#line 110 "sample/undocked/custom_map_basic.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=21 dst=r0 src=r0 offset=0 imm=32
#line 110 "sample/undocked/custom_map_basic.c"
    r0 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_IMM pc=22 dst=r1 src=r0 offset=0 imm=1
#line 110 "sample/undocked/custom_map_basic.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=23 dst=r0 src=r0 offset=1 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    if (r0 == IMMEDIATE(0)) {
#line 109 "sample/undocked/custom_map_basic.c"
        goto label_3;
#line 109 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_MOV64_IMM pc=24 dst=r1 src=r0 offset=0 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    r1 = IMMEDIATE(0);
label_3:
    // EBPF_OP_STXW pc=25 dst=r10 src=r1 offset=-4 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
label_4:
    // EBPF_OP_STXW pc=26 dst=r10 src=r6 offset=-8 imm=0
#line 71 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=27 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=28 dst=r2 src=r0 offset=0 imm=-8
#line 71 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=29 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/custom_map_basic.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=30 dst=r3 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/custom_map_basic.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=31 dst=r1 src=r1 offset=0 imm=4
#line 72 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r4 src=r0 offset=0 imm=0
#line 72 "sample/undocked/custom_map_basic.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=2
#line 72 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 72 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 72 "sample/undocked/custom_map_basic.c"
        return 0;
#line 72 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_MOV64_IMM pc=35 dst=r0 src=r0 offset=0 imm=0
#line 114 "sample/undocked/custom_map_basic.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 114 "sample/undocked/custom_map_basic.c"
    return r0;
#line 100 "sample/undocked/custom_map_basic.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t test_map_read_helper_increment_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     65541,
     "helper_id_65541",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID test_map_read_helper_increment_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID test_map_read_helper_increment_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t test_map_read_helper_increment_maps[] = {
    1,
    2,
    3,
};

#pragma code_seg(push, "sample~9")
static uint64_t
test_map_read_helper_increment(void* context, const program_runtime_context_t* runtime_context)
#line 100 "sample/undocked/custom_map_basic.c"
{
#line 100 "sample/undocked/custom_map_basic.c"
    // Prologue.
#line 100 "sample/undocked/custom_map_basic.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r0 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r1 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r2 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r3 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r4 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r5 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r6 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r10 = 0;

#line 100 "sample/undocked/custom_map_basic.c"
    r1 = (uintptr_t)context;
#line 100 "sample/undocked/custom_map_basic.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=0
#line 100 "sample/undocked/custom_map_basic.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r6 offset=-4 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=2 dst=r2 src=r10 offset=0 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=3 dst=r2 src=r0 offset=0 imm=-4
#line 85 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=4 dst=r1 src=r1 offset=0 imm=3
#line 88 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_CALL pc=6 dst=r0 src=r0 offset=0 imm=1
#line 88 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/custom_map_basic.c"
        return 0;
#line 88 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_JEQ_IMM pc=7 dst=r0 src=r0 offset=2 imm=0
#line 89 "sample/undocked/custom_map_basic.c"
    if (r0 == IMMEDIATE(0)) {
#line 89 "sample/undocked/custom_map_basic.c"
        goto label_1;
#line 89 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_LDXW pc=8 dst=r1 src=r0 offset=0 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    READ_ONCE_32(r1, r0, OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=9 dst=r1 src=r0 offset=2 imm=2
#line 92 "sample/undocked/custom_map_basic.c"
    if (r1 == IMMEDIATE(2)) {
#line 92 "sample/undocked/custom_map_basic.c"
        goto label_2;
#line 92 "sample/undocked/custom_map_basic.c"
    }
label_1:
    // EBPF_OP_STXW pc=10 dst=r10 src=r6 offset=-4 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_JA pc=11 dst=r0 src=r0 offset=14 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    goto label_5;
label_2:
    // EBPF_OP_STXW pc=12 dst=r10 src=r6 offset=-12 imm=0
#line 107 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-12));
    // EBPF_OP_MOV64_REG pc=13 dst=r2 src=r10 offset=0 imm=0
#line 107 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=14 dst=r2 src=r0 offset=0 imm=-12
#line 107 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-12);
    // EBPF_OP_LDDW pc=15 dst=r1 src=r1 offset=0 imm=2
#line 108 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=17 dst=r0 src=r0 offset=0 imm=65541
#line 108 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 108 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 108 "sample/undocked/custom_map_basic.c"
        return 0;
#line 108 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_JEQ_IMM pc=18 dst=r0 src=r0 offset=3 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    if (r0 == IMMEDIATE(0)) {
#line 109 "sample/undocked/custom_map_basic.c"
        goto label_3;
#line 109 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_LDXW pc=19 dst=r1 src=r0 offset=0 imm=0
#line 110 "sample/undocked/custom_map_basic.c"
    READ_ONCE_32(r1, r0, OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=20 dst=r1 src=r0 offset=0 imm=1
#line 110 "sample/undocked/custom_map_basic.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=21 dst=r0 src=r1 offset=0 imm=0
#line 110 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r0, (uint32_t)r1, OFFSET(0));
label_3:
    // EBPF_OP_MOV64_IMM pc=22 dst=r1 src=r0 offset=0 imm=1
#line 110 "sample/undocked/custom_map_basic.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_JNE_IMM pc=23 dst=r0 src=r0 offset=1 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    if (r0 != IMMEDIATE(0)) {
#line 109 "sample/undocked/custom_map_basic.c"
        goto label_4;
#line 109 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_MOV64_IMM pc=24 dst=r1 src=r0 offset=0 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    r1 = IMMEDIATE(0);
label_4:
    // EBPF_OP_STXW pc=25 dst=r10 src=r1 offset=-4 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
label_5:
    // EBPF_OP_STXW pc=26 dst=r10 src=r6 offset=-8 imm=0
#line 71 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=27 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=28 dst=r2 src=r0 offset=0 imm=-8
#line 71 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=29 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/custom_map_basic.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=30 dst=r3 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/custom_map_basic.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=31 dst=r1 src=r1 offset=0 imm=4
#line 72 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r4 src=r0 offset=0 imm=0
#line 72 "sample/undocked/custom_map_basic.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=2
#line 72 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 72 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 72 "sample/undocked/custom_map_basic.c"
        return 0;
#line 72 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_MOV64_IMM pc=35 dst=r0 src=r0 offset=0 imm=0
#line 114 "sample/undocked/custom_map_basic.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 114 "sample/undocked/custom_map_basic.c"
    return r0;
#line 100 "sample/undocked/custom_map_basic.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t test_map_read_helper_increment_invalid_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     65541,
     "helper_id_65541",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID test_map_read_helper_increment_invalid_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID test_map_read_helper_increment_invalid_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t test_map_read_helper_increment_invalid_maps[] = {
    0,
    3,
};

#pragma code_seg(push, "sample~7")
static uint64_t
test_map_read_helper_increment_invalid(void* context, const program_runtime_context_t* runtime_context)
#line 100 "sample/undocked/custom_map_basic.c"
{
#line 100 "sample/undocked/custom_map_basic.c"
    // Prologue.
#line 100 "sample/undocked/custom_map_basic.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r0 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r1 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r2 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r3 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r4 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r5 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r6 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r10 = 0;

#line 100 "sample/undocked/custom_map_basic.c"
    r1 = (uintptr_t)context;
#line 100 "sample/undocked/custom_map_basic.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=0
#line 100 "sample/undocked/custom_map_basic.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r6 offset=-12 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-12));
    // EBPF_OP_MOV64_REG pc=2 dst=r2 src=r10 offset=0 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=3 dst=r2 src=r0 offset=0 imm=-12
#line 85 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-12);
    // EBPF_OP_LDDW pc=4 dst=r1 src=r1 offset=0 imm=1
#line 88 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=6 dst=r0 src=r0 offset=0 imm=65541
#line 88 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/custom_map_basic.c"
        return 0;
#line 88 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_JEQ_IMM pc=7 dst=r0 src=r0 offset=3 imm=0
#line 89 "sample/undocked/custom_map_basic.c"
    if (r0 == IMMEDIATE(0)) {
#line 89 "sample/undocked/custom_map_basic.c"
        goto label_1;
#line 89 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_LDXW pc=8 dst=r1 src=r0 offset=0 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    READ_ONCE_32(r1, r0, OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=9 dst=r1 src=r0 offset=0 imm=1
#line 92 "sample/undocked/custom_map_basic.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=10 dst=r0 src=r1 offset=0 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r0, (uint32_t)r1, OFFSET(0));
label_1:
    // EBPF_OP_MOV64_IMM pc=11 dst=r1 src=r0 offset=0 imm=1
#line 92 "sample/undocked/custom_map_basic.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_JNE_IMM pc=12 dst=r0 src=r0 offset=1 imm=0
#line 107 "sample/undocked/custom_map_basic.c"
    if (r0 != IMMEDIATE(0)) {
#line 107 "sample/undocked/custom_map_basic.c"
        goto label_2;
#line 107 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_MOV64_IMM pc=13 dst=r1 src=r0 offset=0 imm=0
#line 107 "sample/undocked/custom_map_basic.c"
    r1 = IMMEDIATE(0);
label_2:
    // EBPF_OP_STXW pc=14 dst=r10 src=r1 offset=-4 imm=0
#line 107 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_STXW pc=15 dst=r10 src=r6 offset=-8 imm=0
#line 108 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=16 dst=r2 src=r10 offset=0 imm=0
#line 108 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=17 dst=r2 src=r0 offset=0 imm=-8
#line 108 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=18 dst=r3 src=r10 offset=0 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=19 dst=r3 src=r0 offset=0 imm=-4
#line 110 "sample/undocked/custom_map_basic.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=20 dst=r1 src=r1 offset=0 imm=4
#line 110 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_MOV64_IMM pc=22 dst=r4 src=r0 offset=0 imm=0
#line 110 "sample/undocked/custom_map_basic.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=23 dst=r0 src=r0 offset=0 imm=2
#line 109 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 109 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 109 "sample/undocked/custom_map_basic.c"
        return 0;
#line 109 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_MOV64_IMM pc=24 dst=r0 src=r0 offset=0 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=25 dst=r0 src=r0 offset=0 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    return r0;
#line 100 "sample/undocked/custom_map_basic.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t test_map_read_helper_value_helpers[] = {
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
     65542,
     "helper_id_65542",
    },
};

static GUID test_map_read_helper_value_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID test_map_read_helper_value_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t test_map_read_helper_value_maps[] = {
    1,
    2,
    3,
    4,
};

#pragma code_seg(push, "sample~8")
static uint64_t
test_map_read_helper_value(void* context, const program_runtime_context_t* runtime_context)
#line 100 "sample/undocked/custom_map_basic.c"
{
#line 100 "sample/undocked/custom_map_basic.c"
    // Prologue.
#line 100 "sample/undocked/custom_map_basic.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r0 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r1 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r2 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r3 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r4 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r5 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r6 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r10 = 0;

#line 100 "sample/undocked/custom_map_basic.c"
    r1 = (uintptr_t)context;
#line 100 "sample/undocked/custom_map_basic.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=0
#line 100 "sample/undocked/custom_map_basic.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r6 offset=-4 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_STXW pc=2 dst=r10 src=r6 offset=-8 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-8
#line 88 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=5 dst=r3 src=r10 offset=0 imm=0
#line 88 "sample/undocked/custom_map_basic.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=6 dst=r3 src=r0 offset=0 imm=-4
#line 88 "sample/undocked/custom_map_basic.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=7 dst=r1 src=r1 offset=0 imm=5
#line 89 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_IMM pc=9 dst=r4 src=r0 offset=0 imm=0
#line 89 "sample/undocked/custom_map_basic.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=10 dst=r0 src=r0 offset=0 imm=2
#line 89 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 89 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 89 "sample/undocked/custom_map_basic.c"
        return 0;
#line 89 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_STXW pc=11 dst=r10 src=r6 offset=-4 imm=0
#line 89 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=12 dst=r2 src=r10 offset=0 imm=0
#line 107 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=13 dst=r2 src=r0 offset=0 imm=-4
#line 107 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=14 dst=r1 src=r1 offset=0 imm=3
#line 107 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_CALL pc=16 dst=r0 src=r0 offset=0 imm=1
#line 107 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 107 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 107 "sample/undocked/custom_map_basic.c"
        return 0;
#line 107 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_JEQ_IMM pc=17 dst=r0 src=r0 offset=2 imm=0
#line 107 "sample/undocked/custom_map_basic.c"
    if (r0 == IMMEDIATE(0)) {
#line 107 "sample/undocked/custom_map_basic.c"
        goto label_1;
#line 107 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_LDXW pc=18 dst=r1 src=r0 offset=0 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    READ_ONCE_32(r1, r0, OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=19 dst=r1 src=r0 offset=12 imm=2
#line 110 "sample/undocked/custom_map_basic.c"
    if (r1 == IMMEDIATE(2)) {
#line 110 "sample/undocked/custom_map_basic.c"
        goto label_3;
#line 110 "sample/undocked/custom_map_basic.c"
    }
label_1:
    // EBPF_OP_STXW pc=20 dst=r10 src=r6 offset=-4 imm=0
#line 110 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
label_2:
    // EBPF_OP_STXW pc=21 dst=r10 src=r6 offset=-8 imm=0
#line 110 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=22 dst=r2 src=r10 offset=0 imm=0
#line 110 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r2 src=r0 offset=0 imm=-8
#line 109 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=24 dst=r3 src=r10 offset=0 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=25 dst=r3 src=r0 offset=0 imm=-4
#line 109 "sample/undocked/custom_map_basic.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=26 dst=r1 src=r1 offset=0 imm=4
#line 71 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_MOV64_IMM pc=28 dst=r4 src=r0 offset=0 imm=0
#line 71 "sample/undocked/custom_map_basic.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=29 dst=r0 src=r0 offset=0 imm=2
#line 71 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 71 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 71 "sample/undocked/custom_map_basic.c"
        return 0;
#line 71 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_MOV64_IMM pc=30 dst=r0 src=r0 offset=0 imm=0
#line 71 "sample/undocked/custom_map_basic.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=31 dst=r0 src=r0 offset=0 imm=0
#line 72 "sample/undocked/custom_map_basic.c"
    return r0;
label_3:
    // EBPF_OP_STXW pc=32 dst=r10 src=r6 offset=-12 imm=0
#line 72 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-12));
    // EBPF_OP_STXW pc=33 dst=r10 src=r6 offset=-16 imm=0
#line 72 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=34 dst=r2 src=r10 offset=0 imm=0
#line 72 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=35 dst=r2 src=r0 offset=0 imm=-12
#line 114 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-12);
    // EBPF_OP_MOV64_REG pc=36 dst=r3 src=r10 offset=0 imm=0
#line 114 "sample/undocked/custom_map_basic.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=37 dst=r3 src=r0 offset=0 imm=-16
#line 118 "sample/undocked/custom_map_basic.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=38 dst=r1 src=r1 offset=0 imm=2
#line 85 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=40 dst=r4 src=r0 offset=0 imm=4
#line 85 "sample/undocked/custom_map_basic.c"
    r4 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=41 dst=r0 src=r0 offset=0 imm=65542
#line 88 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/custom_map_basic.c"
        return 0;
#line 88 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_LSH64_IMM pc=42 dst=r0 src=r0 offset=0 imm=32
#line 88 "sample/undocked/custom_map_basic.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=43 dst=r0 src=r0 offset=0 imm=32
#line 88 "sample/undocked/custom_map_basic.c"
    r0 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JNE_IMM pc=44 dst=r0 src=r0 offset=-25 imm=0
#line 89 "sample/undocked/custom_map_basic.c"
    if (r0 != IMMEDIATE(0)) {
#line 89 "sample/undocked/custom_map_basic.c"
        goto label_1;
#line 89 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_LDXW pc=45 dst=r1 src=r10 offset=-16 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    READ_ONCE_32(r1, r10, OFFSET(-16));
    // EBPF_OP_STXW pc=46 dst=r10 src=r1 offset=-4 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_STXW pc=47 dst=r10 src=r6 offset=-8 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=48 dst=r2 src=r10 offset=0 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=49 dst=r2 src=r0 offset=0 imm=-8
#line 125 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=50 dst=r3 src=r10 offset=0 imm=0
#line 125 "sample/undocked/custom_map_basic.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=51 dst=r3 src=r0 offset=0 imm=-4
#line 125 "sample/undocked/custom_map_basic.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=52 dst=r1 src=r1 offset=0 imm=5
#line 126 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_IMM pc=54 dst=r4 src=r0 offset=0 imm=0
#line 126 "sample/undocked/custom_map_basic.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=55 dst=r0 src=r0 offset=0 imm=2
#line 127 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 127 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 127 "sample/undocked/custom_map_basic.c"
        return 0;
#line 127 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_MOV64_IMM pc=56 dst=r1 src=r0 offset=0 imm=1
#line 128 "sample/undocked/custom_map_basic.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=57 dst=r10 src=r1 offset=-4 imm=0
#line 128 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_JA pc=58 dst=r0 src=r0 offset=-38 imm=0
#line 128 "sample/undocked/custom_map_basic.c"
    goto label_2;
#line 100 "sample/undocked/custom_map_basic.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t test_map_read_increment_helpers[] = {
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

static GUID test_map_read_increment_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID test_map_read_increment_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t test_map_read_increment_maps[] = {
    1,
    2,
    3,
};

#pragma code_seg(push, "sampl~10")
static uint64_t
test_map_read_increment(void* context, const program_runtime_context_t* runtime_context)
#line 100 "sample/undocked/custom_map_basic.c"
{
#line 100 "sample/undocked/custom_map_basic.c"
    // Prologue.
#line 100 "sample/undocked/custom_map_basic.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r0 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r1 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r2 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r3 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r4 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r5 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r6 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r10 = 0;

#line 100 "sample/undocked/custom_map_basic.c"
    r1 = (uintptr_t)context;
#line 100 "sample/undocked/custom_map_basic.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=0
#line 100 "sample/undocked/custom_map_basic.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r6 offset=-4 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=2 dst=r2 src=r10 offset=0 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=3 dst=r2 src=r0 offset=0 imm=-4
#line 85 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=4 dst=r1 src=r1 offset=0 imm=3
#line 88 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_CALL pc=6 dst=r0 src=r0 offset=0 imm=1
#line 88 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/custom_map_basic.c"
        return 0;
#line 88 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_JEQ_IMM pc=7 dst=r0 src=r0 offset=2 imm=0
#line 89 "sample/undocked/custom_map_basic.c"
    if (r0 == IMMEDIATE(0)) {
#line 89 "sample/undocked/custom_map_basic.c"
        goto label_1;
#line 89 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_LDXW pc=8 dst=r1 src=r0 offset=0 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    READ_ONCE_32(r1, r0, OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=9 dst=r1 src=r0 offset=2 imm=2
#line 92 "sample/undocked/custom_map_basic.c"
    if (r1 == IMMEDIATE(2)) {
#line 92 "sample/undocked/custom_map_basic.c"
        goto label_2;
#line 92 "sample/undocked/custom_map_basic.c"
    }
label_1:
    // EBPF_OP_STXW pc=10 dst=r10 src=r6 offset=-4 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_JA pc=11 dst=r0 src=r0 offset=14 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    goto label_5;
label_2:
    // EBPF_OP_STXW pc=12 dst=r10 src=r6 offset=-12 imm=0
#line 107 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-12));
    // EBPF_OP_MOV64_REG pc=13 dst=r2 src=r10 offset=0 imm=0
#line 107 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=14 dst=r2 src=r0 offset=0 imm=-12
#line 107 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-12);
    // EBPF_OP_LDDW pc=15 dst=r1 src=r1 offset=0 imm=2
#line 108 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=17 dst=r0 src=r0 offset=0 imm=1
#line 108 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 108 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 108 "sample/undocked/custom_map_basic.c"
        return 0;
#line 108 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_JEQ_IMM pc=18 dst=r0 src=r0 offset=3 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    if (r0 == IMMEDIATE(0)) {
#line 109 "sample/undocked/custom_map_basic.c"
        goto label_3;
#line 109 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_LDXW pc=19 dst=r1 src=r0 offset=0 imm=0
#line 110 "sample/undocked/custom_map_basic.c"
    READ_ONCE_32(r1, r0, OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=20 dst=r1 src=r0 offset=0 imm=1
#line 110 "sample/undocked/custom_map_basic.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=21 dst=r0 src=r1 offset=0 imm=0
#line 110 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r0, (uint32_t)r1, OFFSET(0));
label_3:
    // EBPF_OP_MOV64_IMM pc=22 dst=r1 src=r0 offset=0 imm=1
#line 110 "sample/undocked/custom_map_basic.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_JNE_IMM pc=23 dst=r0 src=r0 offset=1 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    if (r0 != IMMEDIATE(0)) {
#line 109 "sample/undocked/custom_map_basic.c"
        goto label_4;
#line 109 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_MOV64_IMM pc=24 dst=r1 src=r0 offset=0 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    r1 = IMMEDIATE(0);
label_4:
    // EBPF_OP_STXW pc=25 dst=r10 src=r1 offset=-4 imm=0
#line 109 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
label_5:
    // EBPF_OP_STXW pc=26 dst=r10 src=r6 offset=-8 imm=0
#line 71 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=27 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=28 dst=r2 src=r0 offset=0 imm=-8
#line 71 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=29 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/custom_map_basic.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=30 dst=r3 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/custom_map_basic.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=31 dst=r1 src=r1 offset=0 imm=4
#line 72 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_MOV64_IMM pc=33 dst=r4 src=r0 offset=0 imm=0
#line 72 "sample/undocked/custom_map_basic.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=2
#line 72 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 72 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 72 "sample/undocked/custom_map_basic.c"
        return 0;
#line 72 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_MOV64_IMM pc=35 dst=r0 src=r0 offset=0 imm=0
#line 114 "sample/undocked/custom_map_basic.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=36 dst=r0 src=r0 offset=0 imm=0
#line 114 "sample/undocked/custom_map_basic.c"
    return r0;
#line 100 "sample/undocked/custom_map_basic.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t test_map_update_element_helpers[] = {
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

static GUID test_map_update_element_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID test_map_update_element_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t test_map_update_element_maps[] = {
    1,
    2,
    3,
};

#pragma code_seg(push, "sample~6")
static uint64_t
test_map_update_element(void* context, const program_runtime_context_t* runtime_context)
#line 100 "sample/undocked/custom_map_basic.c"
{
#line 100 "sample/undocked/custom_map_basic.c"
    // Prologue.
#line 100 "sample/undocked/custom_map_basic.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r0 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r1 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r2 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r3 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r4 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r5 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r6 = 0;
#line 100 "sample/undocked/custom_map_basic.c"
    register uint64_t r10 = 0;

#line 100 "sample/undocked/custom_map_basic.c"
    r1 = (uintptr_t)context;
#line 100 "sample/undocked/custom_map_basic.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=0
#line 100 "sample/undocked/custom_map_basic.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r6 offset=-4 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=2 dst=r2 src=r10 offset=0 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=3 dst=r2 src=r0 offset=0 imm=-4
#line 85 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=4 dst=r1 src=r1 offset=0 imm=3
#line 88 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_CALL pc=6 dst=r0 src=r0 offset=0 imm=1
#line 88 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/custom_map_basic.c"
        return 0;
#line 88 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_JEQ_IMM pc=7 dst=r0 src=r0 offset=2 imm=0
#line 89 "sample/undocked/custom_map_basic.c"
    if (r0 == IMMEDIATE(0)) {
#line 89 "sample/undocked/custom_map_basic.c"
        goto label_1;
#line 89 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_LDXW pc=8 dst=r1 src=r0 offset=0 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    READ_ONCE_32(r1, r0, OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=9 dst=r1 src=r0 offset=2 imm=2
#line 92 "sample/undocked/custom_map_basic.c"
    if (r1 == IMMEDIATE(2)) {
#line 92 "sample/undocked/custom_map_basic.c"
        goto label_2;
#line 92 "sample/undocked/custom_map_basic.c"
    }
label_1:
    // EBPF_OP_STXW pc=10 dst=r10 src=r6 offset=-4 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_JA pc=11 dst=r0 src=r0 offset=17 imm=0
#line 92 "sample/undocked/custom_map_basic.c"
    goto label_4;
label_2:
    // EBPF_OP_STXW pc=12 dst=r10 src=r6 offset=-12 imm=0
#line 107 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-12));
    // EBPF_OP_MOV64_IMM pc=13 dst=r1 src=r0 offset=0 imm=42
#line 107 "sample/undocked/custom_map_basic.c"
    r1 = IMMEDIATE(42);
    // EBPF_OP_STXW pc=14 dst=r10 src=r1 offset=-16 imm=0
#line 107 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=15 dst=r2 src=r10 offset=0 imm=0
#line 108 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=16 dst=r2 src=r0 offset=0 imm=-12
#line 108 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-12);
    // EBPF_OP_MOV64_REG pc=17 dst=r3 src=r10 offset=0 imm=0
#line 108 "sample/undocked/custom_map_basic.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=18 dst=r3 src=r0 offset=0 imm=-16
#line 109 "sample/undocked/custom_map_basic.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=19 dst=r1 src=r1 offset=0 imm=2
#line 110 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=21 dst=r4 src=r0 offset=0 imm=0
#line 110 "sample/undocked/custom_map_basic.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=22 dst=r0 src=r0 offset=0 imm=2
#line 110 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 110 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 110 "sample/undocked/custom_map_basic.c"
        return 0;
#line 110 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_LSH64_IMM pc=23 dst=r0 src=r0 offset=0 imm=32
#line 109 "sample/undocked/custom_map_basic.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=24 dst=r0 src=r0 offset=0 imm=32
#line 109 "sample/undocked/custom_map_basic.c"
    r0 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_IMM pc=25 dst=r1 src=r0 offset=0 imm=1
#line 109 "sample/undocked/custom_map_basic.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=26 dst=r0 src=r0 offset=1 imm=0
#line 71 "sample/undocked/custom_map_basic.c"
    if (r0 == IMMEDIATE(0)) {
#line 71 "sample/undocked/custom_map_basic.c"
        goto label_3;
#line 71 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=0
#line 71 "sample/undocked/custom_map_basic.c"
    r1 = IMMEDIATE(0);
label_3:
    // EBPF_OP_STXW pc=28 dst=r10 src=r1 offset=-4 imm=0
#line 71 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
label_4:
    // EBPF_OP_STXW pc=29 dst=r10 src=r6 offset=-8 imm=0
#line 71 "sample/undocked/custom_map_basic.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=30 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/custom_map_basic.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=31 dst=r2 src=r0 offset=0 imm=-8
#line 72 "sample/undocked/custom_map_basic.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=32 dst=r3 src=r10 offset=0 imm=0
#line 72 "sample/undocked/custom_map_basic.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=33 dst=r3 src=r0 offset=0 imm=-4
#line 72 "sample/undocked/custom_map_basic.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=34 dst=r1 src=r1 offset=0 imm=4
#line 72 "sample/undocked/custom_map_basic.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_MOV64_IMM pc=36 dst=r4 src=r0 offset=0 imm=0
#line 72 "sample/undocked/custom_map_basic.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=37 dst=r0 src=r0 offset=0 imm=2
#line 118 "sample/undocked/custom_map_basic.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 118 "sample/undocked/custom_map_basic.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 118 "sample/undocked/custom_map_basic.c"
        return 0;
#line 118 "sample/undocked/custom_map_basic.c"
    }
    // EBPF_OP_MOV64_IMM pc=38 dst=r0 src=r0 offset=0 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=39 dst=r0 src=r0 offset=0 imm=0
#line 85 "sample/undocked/custom_map_basic.c"
    return r0;
#line 100 "sample/undocked/custom_map_basic.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        test_map_delete_element,
        "sample~5",
        "sample_ext",
        "test_map_delete_element",
        test_map_delete_element_maps,
        3,
        test_map_delete_element_helpers,
        3,
        35,
        &test_map_delete_element_program_type_guid,
        &test_map_delete_element_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        test_map_find_and_delete_element,
        "sample~4",
        "sample_ext",
        "test_map_find_and_delete_element",
        test_map_find_and_delete_element_maps,
        3,
        test_map_find_and_delete_element_helpers,
        3,
        33,
        &test_map_find_and_delete_element_program_type_guid,
        &test_map_find_and_delete_element_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        test_map_peek_elem,
        "sample~1",
        "sample_ext",
        "test_map_peek_elem",
        test_map_peek_elem_maps,
        3,
        test_map_peek_elem_helpers,
        3,
        35,
        &test_map_peek_elem_program_type_guid,
        &test_map_peek_elem_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        test_map_pop_elem,
        "sample~2",
        "sample_ext",
        "test_map_pop_elem",
        test_map_pop_elem_maps,
        3,
        test_map_pop_elem_helpers,
        3,
        35,
        &test_map_pop_elem_program_type_guid,
        &test_map_pop_elem_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        test_map_push_elem,
        "sample~3",
        "sample_ext",
        "test_map_push_elem",
        test_map_push_elem_maps,
        3,
        test_map_push_elem_helpers,
        3,
        37,
        &test_map_push_elem_program_type_guid,
        &test_map_push_elem_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        test_map_read_helper_increment,
        "sample~9",
        "sample_ext",
        "test_map_read_helper_increment",
        test_map_read_helper_increment_maps,
        3,
        test_map_read_helper_increment_helpers,
        3,
        37,
        &test_map_read_helper_increment_program_type_guid,
        &test_map_read_helper_increment_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        test_map_read_helper_increment_invalid,
        "sample~7",
        "sample_ext",
        "test_map_read_helper_increment_invalid",
        test_map_read_helper_increment_invalid_maps,
        2,
        test_map_read_helper_increment_invalid_helpers,
        2,
        26,
        &test_map_read_helper_increment_invalid_program_type_guid,
        &test_map_read_helper_increment_invalid_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        test_map_read_helper_value,
        "sample~8",
        "sample_ext",
        "test_map_read_helper_value",
        test_map_read_helper_value_maps,
        4,
        test_map_read_helper_value_helpers,
        3,
        59,
        &test_map_read_helper_value_program_type_guid,
        &test_map_read_helper_value_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        test_map_read_increment,
        "sampl~10",
        "sample_ext",
        "test_map_read_increment",
        test_map_read_increment_maps,
        3,
        test_map_read_increment_helpers,
        2,
        37,
        &test_map_read_increment_program_type_guid,
        &test_map_read_increment_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        test_map_update_element,
        "sample~6",
        "sample_ext",
        "test_map_update_element",
        test_map_update_element_maps,
        3,
        test_map_update_element_helpers,
        2,
        40,
        &test_map_update_element_program_type_guid,
        &test_map_update_element_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 10;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = 1;
    version->minor = 2;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t custom_map_basic_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
