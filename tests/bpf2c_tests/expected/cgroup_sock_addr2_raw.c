// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from cgroup_sock_addr2.o

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

#line 130 "sample/cgroup_sock_addr2.c"
    r6 = r1;
#line 130 "sample/cgroup_sock_addr2.c"
    r0 = IMMEDIATE(0);
#line 58 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r0;
#line 58 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint32_t)r0;
#line 58 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r0;
#line 58 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint32_t)r0;
#line 58 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(25959);
#line 59 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint16_t)r1;
#line 59 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7022083122929103717;
#line 59 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
#line 59 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)6085621373624807235;
#line 59 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
#line 59 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)8386658473162859858;
#line 59 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
#line 59 "sample/cgroup_sock_addr2.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-38)) = (uint8_t)r0;
#line 61 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
#line 61 "sample/cgroup_sock_addr2.c"
    if (r1 == IMMEDIATE(17)) {
#line 61 "sample/cgroup_sock_addr2.c"
        goto label_1;
#line 61 "sample/cgroup_sock_addr2.c"
    }
#line 61 "sample/cgroup_sock_addr2.c"
    if (r1 != IMMEDIATE(6)) {
#line 61 "sample/cgroup_sock_addr2.c"
        goto label_3;
#line 61 "sample/cgroup_sock_addr2.c"
    }
label_1:
#line 61 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(0));
#line 61 "sample/cgroup_sock_addr2.c"
    if (r2 != IMMEDIATE(2)) {
#line 61 "sample/cgroup_sock_addr2.c"
        goto label_3;
#line 61 "sample/cgroup_sock_addr2.c"
    }
#line 65 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(24));
#line 65 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r2;
#line 66 "sample/cgroup_sock_addr2.c"
    r2 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(40));
#line 67 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint32_t)r1;
#line 66 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r2;
#line 66 "sample/cgroup_sock_addr2.c"
    r2 = r10;
#line 65 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-32);
#line 70 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(runtime_context->map_data[0].address);
#line 70 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 70 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 70 "sample/cgroup_sock_addr2.c"
        return 0;
#line 70 "sample/cgroup_sock_addr2.c"
    }
#line 70 "sample/cgroup_sock_addr2.c"
    r7 = r0;
#line 70 "sample/cgroup_sock_addr2.c"
    r8 = IMMEDIATE(0);
#line 70 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(0);
#line 71 "sample/cgroup_sock_addr2.c"
    if (r7 == IMMEDIATE(0)) {
#line 71 "sample/cgroup_sock_addr2.c"
        goto label_2;
#line 71 "sample/cgroup_sock_addr2.c"
    }
#line 71 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(29989);
#line 72 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint16_t)r1;
#line 72 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)2318356710503900533;
#line 72 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
#line 72 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7809653110685725806;
#line 72 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
#line 72 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7286957755258269728;
#line 72 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
#line 72 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)3780244552946118470;
#line 72 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
#line 72 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(0);
#line 72 "sample/cgroup_sock_addr2.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-70)) = (uint8_t)r1;
#line 72 "sample/cgroup_sock_addr2.c"
    r4 = *(uint16_t*)(uintptr_t)(r7 + OFFSET(16));
#line 72 "sample/cgroup_sock_addr2.c"
    r3 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
#line 72 "sample/cgroup_sock_addr2.c"
    r1 = r10;
#line 72 "sample/cgroup_sock_addr2.c"
    r1 += IMMEDIATE(-104);
#line 72 "sample/cgroup_sock_addr2.c"
    r2 = IMMEDIATE(35);
#line 72 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 72 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 72 "sample/cgroup_sock_addr2.c"
        return 0;
#line 72 "sample/cgroup_sock_addr2.c"
    }
#line 72 "sample/cgroup_sock_addr2.c"
    r2 = r10;
#line 72 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-64);
#line 75 "sample/cgroup_sock_addr2.c"
    r1 = r6;
#line 75 "sample/cgroup_sock_addr2.c"
    r3 = IMMEDIATE(27);
#line 75 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 75 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 75 "sample/cgroup_sock_addr2.c"
        return 0;
#line 75 "sample/cgroup_sock_addr2.c"
    }
#line 75 "sample/cgroup_sock_addr2.c"
    r1 = r0;
#line 75 "sample/cgroup_sock_addr2.c"
    r0 = IMMEDIATE(0);
#line 75 "sample/cgroup_sock_addr2.c"
    r1 <<= (IMMEDIATE(32) & 63);
#line 75 "sample/cgroup_sock_addr2.c"
    r1 = (int64_t)r1 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 75 "sample/cgroup_sock_addr2.c"
    if ((int64_t)r0 > (int64_t)r1) {
#line 75 "sample/cgroup_sock_addr2.c"
        goto label_3;
#line 75 "sample/cgroup_sock_addr2.c"
    }
#line 79 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
#line 79 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r6 + OFFSET(24)) = (uint32_t)r1;
#line 80 "sample/cgroup_sock_addr2.c"
    r1 = *(uint16_t*)(uintptr_t)(r7 + OFFSET(16));
#line 80 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(40)) = (uint16_t)r1;
#line 80 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(1);
label_2:
#line 43 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r8;
#line 43 "sample/cgroup_sock_addr2.c"
    r8 = r1;
#line 44 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 44 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 44 "sample/cgroup_sock_addr2.c"
        return 0;
#line 44 "sample/cgroup_sock_addr2.c"
    }
#line 44 "sample/cgroup_sock_addr2.c"
    r7 = r0;
#line 44 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r7;
#line 45 "sample/cgroup_sock_addr2.c"
    r1 = r6;
#line 45 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 45 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 45 "sample/cgroup_sock_addr2.c"
        return 0;
#line 45 "sample/cgroup_sock_addr2.c"
    }
#line 45 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r0;
#line 46 "sample/cgroup_sock_addr2.c"
    r1 = r6;
#line 46 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 46 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[5].tail_call) && (r0 == 0)) {
#line 46 "sample/cgroup_sock_addr2.c"
        return 0;
#line 46 "sample/cgroup_sock_addr2.c"
    }
#line 46 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint32_t)r0;
#line 47 "sample/cgroup_sock_addr2.c"
    r1 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(20));
#line 47 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-84)) = (uint16_t)r1;
#line 48 "sample/cgroup_sock_addr2.c"
    r1 = r6;
#line 48 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 48 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 48 "sample/cgroup_sock_addr2.c"
        return 0;
#line 48 "sample/cgroup_sock_addr2.c"
    }
#line 48 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r0;
#line 50 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r7;
#line 50 "sample/cgroup_sock_addr2.c"
    r2 = r10;
#line 50 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-8);
#line 50 "sample/cgroup_sock_addr2.c"
    r3 = r10;
#line 50 "sample/cgroup_sock_addr2.c"
    r3 += IMMEDIATE(-104);
#line 51 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(runtime_context->map_data[1].address);
#line 51 "sample/cgroup_sock_addr2.c"
    r4 = IMMEDIATE(0);
#line 51 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 51 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 51 "sample/cgroup_sock_addr2.c"
        return 0;
#line 51 "sample/cgroup_sock_addr2.c"
    }
#line 51 "sample/cgroup_sock_addr2.c"
    r0 = r8;
label_3:
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

#line 137 "sample/cgroup_sock_addr2.c"
    r6 = r1;
#line 137 "sample/cgroup_sock_addr2.c"
    r0 = IMMEDIATE(0);
#line 94 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint32_t)r0;
#line 94 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(25959);
#line 95 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint16_t)r1;
#line 95 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7022083122929103717;
#line 95 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
#line 95 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)6085621373624807235;
#line 95 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
#line 95 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)8386658473162859858;
#line 95 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
#line 95 "sample/cgroup_sock_addr2.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-70)) = (uint8_t)r0;
#line 97 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
#line 97 "sample/cgroup_sock_addr2.c"
    if (r1 == IMMEDIATE(17)) {
#line 97 "sample/cgroup_sock_addr2.c"
        goto label_1;
#line 97 "sample/cgroup_sock_addr2.c"
    }
#line 97 "sample/cgroup_sock_addr2.c"
    if (r1 != IMMEDIATE(6)) {
#line 97 "sample/cgroup_sock_addr2.c"
        goto label_3;
#line 97 "sample/cgroup_sock_addr2.c"
    }
label_1:
#line 97 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(0));
#line 97 "sample/cgroup_sock_addr2.c"
    if (r2 != IMMEDIATE(23)) {
#line 97 "sample/cgroup_sock_addr2.c"
        goto label_3;
#line 97 "sample/cgroup_sock_addr2.c"
    }
#line 104 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(36));
#line 104 "sample/cgroup_sock_addr2.c"
    r2 <<= (IMMEDIATE(32) & 63);
#line 104 "sample/cgroup_sock_addr2.c"
    r3 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(32));
#line 104 "sample/cgroup_sock_addr2.c"
    r2 |= r3;
#line 104 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r2;
#line 104 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(28));
#line 104 "sample/cgroup_sock_addr2.c"
    r2 <<= (IMMEDIATE(32) & 63);
#line 104 "sample/cgroup_sock_addr2.c"
    r3 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(24));
#line 104 "sample/cgroup_sock_addr2.c"
    r2 |= r3;
#line 104 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r2;
#line 105 "sample/cgroup_sock_addr2.c"
    r2 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(40));
#line 105 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint16_t)r2;
#line 106 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-44)) = (uint32_t)r1;
#line 106 "sample/cgroup_sock_addr2.c"
    r2 = r10;
#line 104 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-64);
#line 109 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(runtime_context->map_data[0].address);
#line 109 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 109 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 109 "sample/cgroup_sock_addr2.c"
        return 0;
#line 109 "sample/cgroup_sock_addr2.c"
    }
#line 109 "sample/cgroup_sock_addr2.c"
    r7 = r0;
#line 109 "sample/cgroup_sock_addr2.c"
    r8 = IMMEDIATE(0);
#line 109 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(0);
#line 110 "sample/cgroup_sock_addr2.c"
    if (r7 == IMMEDIATE(0)) {
#line 110 "sample/cgroup_sock_addr2.c"
        goto label_2;
#line 110 "sample/cgroup_sock_addr2.c"
    }
#line 110 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(25973);
#line 111 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r1;
#line 111 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7809653110685725806;
#line 111 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
#line 111 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7286957755258269728;
#line 111 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
#line 111 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)3924359741021974342;
#line 111 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
#line 111 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(0);
#line 111 "sample/cgroup_sock_addr2.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-14)) = (uint8_t)r1;
#line 111 "sample/cgroup_sock_addr2.c"
    r1 = r10;
#line 111 "sample/cgroup_sock_addr2.c"
    r1 += IMMEDIATE(-40);
#line 111 "sample/cgroup_sock_addr2.c"
    r2 = IMMEDIATE(27);
#line 111 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 111 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 111 "sample/cgroup_sock_addr2.c"
        return 0;
#line 111 "sample/cgroup_sock_addr2.c"
    }
#line 111 "sample/cgroup_sock_addr2.c"
    r2 = r10;
#line 111 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-96);
#line 114 "sample/cgroup_sock_addr2.c"
    r1 = r6;
#line 114 "sample/cgroup_sock_addr2.c"
    r3 = IMMEDIATE(27);
#line 114 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 114 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 114 "sample/cgroup_sock_addr2.c"
        return 0;
#line 114 "sample/cgroup_sock_addr2.c"
    }
#line 114 "sample/cgroup_sock_addr2.c"
    r1 = r0;
#line 114 "sample/cgroup_sock_addr2.c"
    r0 = IMMEDIATE(0);
#line 114 "sample/cgroup_sock_addr2.c"
    r1 <<= (IMMEDIATE(32) & 63);
#line 114 "sample/cgroup_sock_addr2.c"
    r1 = (int64_t)r1 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 114 "sample/cgroup_sock_addr2.c"
    if ((int64_t)r0 > (int64_t)r1) {
#line 114 "sample/cgroup_sock_addr2.c"
        goto label_3;
#line 114 "sample/cgroup_sock_addr2.c"
    }
#line 114 "sample/cgroup_sock_addr2.c"
    r1 = r6;
#line 114 "sample/cgroup_sock_addr2.c"
    r1 += IMMEDIATE(24);
#line 117 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(12));
#line 117 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(12)) = (uint32_t)r2;
#line 117 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(8));
#line 117 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(8)) = (uint32_t)r2;
#line 117 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(4));
#line 117 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(4)) = (uint32_t)r2;
#line 117 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
#line 117 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(0)) = (uint32_t)r2;
#line 118 "sample/cgroup_sock_addr2.c"
    r1 = *(uint16_t*)(uintptr_t)(r7 + OFFSET(16));
#line 118 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(40)) = (uint16_t)r1;
#line 118 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(1);
label_2:
#line 43 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r8;
#line 43 "sample/cgroup_sock_addr2.c"
    r8 = r1;
#line 44 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 44 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 44 "sample/cgroup_sock_addr2.c"
        return 0;
#line 44 "sample/cgroup_sock_addr2.c"
    }
#line 44 "sample/cgroup_sock_addr2.c"
    r7 = r0;
#line 44 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r7;
#line 45 "sample/cgroup_sock_addr2.c"
    r1 = r6;
#line 45 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 45 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 45 "sample/cgroup_sock_addr2.c"
        return 0;
#line 45 "sample/cgroup_sock_addr2.c"
    }
#line 45 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r0;
#line 46 "sample/cgroup_sock_addr2.c"
    r1 = r6;
#line 46 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 46 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[5].tail_call) && (r0 == 0)) {
#line 46 "sample/cgroup_sock_addr2.c"
        return 0;
#line 46 "sample/cgroup_sock_addr2.c"
    }
#line 46 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r0;
#line 47 "sample/cgroup_sock_addr2.c"
    r1 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(20));
#line 47 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint16_t)r1;
#line 48 "sample/cgroup_sock_addr2.c"
    r1 = r6;
#line 48 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 48 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 48 "sample/cgroup_sock_addr2.c"
        return 0;
#line 48 "sample/cgroup_sock_addr2.c"
    }
#line 48 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r0;
#line 50 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r7;
#line 50 "sample/cgroup_sock_addr2.c"
    r2 = r10;
#line 50 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-8);
#line 50 "sample/cgroup_sock_addr2.c"
    r3 = r10;
#line 50 "sample/cgroup_sock_addr2.c"
    r3 += IMMEDIATE(-40);
#line 51 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(runtime_context->map_data[1].address);
#line 51 "sample/cgroup_sock_addr2.c"
    r4 = IMMEDIATE(0);
#line 51 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 51 "sample/cgroup_sock_addr2.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 51 "sample/cgroup_sock_addr2.c"
        return 0;
#line 51 "sample/cgroup_sock_addr2.c"
    }
#line 51 "sample/cgroup_sock_addr2.c"
    r0 = r8;
label_3:
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
