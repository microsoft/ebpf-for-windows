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
         28,                // Size in bytes of a map value.
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
         28,                // Size in bytes of a map value.
         100,               // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         32,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "authorization_policy_map"},
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

static helper_function_entry_t connect_authorization4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID connect_authorization4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID connect_authorization4_attach_type_guid = {
    0x6076c13a, 0xf04f, 0x4ff8, {0x83, 0x80, 0x90, 0x85, 0x53, 0xf2, 0x22, 0x76}};
static uint16_t connect_authorization4_maps[] = {
    2,
};

#pragma code_seg(push, "cgroup~2")
static uint64_t
connect_authorization4(void* context, const program_runtime_context_t* runtime_context)
#line 206 "sample/cgroup_sock_addr2.c"
{
#line 206 "sample/cgroup_sock_addr2.c"
    // Prologue.
#line 206 "sample/cgroup_sock_addr2.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 206 "sample/cgroup_sock_addr2.c"
    register uint64_t r0 = 0;
#line 206 "sample/cgroup_sock_addr2.c"
    register uint64_t r1 = 0;
#line 206 "sample/cgroup_sock_addr2.c"
    register uint64_t r2 = 0;
#line 206 "sample/cgroup_sock_addr2.c"
    register uint64_t r3 = 0;
#line 206 "sample/cgroup_sock_addr2.c"
    register uint64_t r4 = 0;
#line 206 "sample/cgroup_sock_addr2.c"
    register uint64_t r5 = 0;
#line 206 "sample/cgroup_sock_addr2.c"
    register uint64_t r10 = 0;

#line 206 "sample/cgroup_sock_addr2.c"
    r1 = (uintptr_t)context;
#line 206 "sample/cgroup_sock_addr2.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 206 "sample/cgroup_sock_addr2.c"
    r2 = IMMEDIATE(0);
#line 168 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-8));
#line 168 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-12));
#line 168 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-16));
#line 168 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-20));
#line 168 "sample/cgroup_sock_addr2.c"
    r0 = IMMEDIATE(1);
#line 168 "sample/cgroup_sock_addr2.c"
    r0 &= UINT32_MAX;
#line 170 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r2, r1, OFFSET(44));
#line 170 "sample/cgroup_sock_addr2.c"
    if ((uint32_t)r2 == IMMEDIATE(17)) {
#line 170 "sample/cgroup_sock_addr2.c"
        goto label_1;
#line 170 "sample/cgroup_sock_addr2.c"
    }
#line 170 "sample/cgroup_sock_addr2.c"
    if ((uint32_t)r2 != IMMEDIATE(6)) {
#line 170 "sample/cgroup_sock_addr2.c"
        goto label_2;
#line 170 "sample/cgroup_sock_addr2.c"
    }
label_1:
#line 170 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r3, r1, OFFSET(0));
#line 170 "sample/cgroup_sock_addr2.c"
    if ((uint32_t)r3 != IMMEDIATE(2)) {
#line 170 "sample/cgroup_sock_addr2.c"
        goto label_2;
#line 170 "sample/cgroup_sock_addr2.c"
    }
#line 57 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r3, r1, OFFSET(24));
#line 57 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r10, (uint32_t)r3, OFFSET(-24));
#line 58 "sample/cgroup_sock_addr2.c"
    READ_ONCE_16(r1, r1, OFFSET(40));
#line 59 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-4));
#line 58 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-8));
#line 58 "sample/cgroup_sock_addr2.c"
    r2 = r10;
#line 58 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-24);
#line 176 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(runtime_context->map_data[2].address);
#line 176 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 176 "sample/cgroup_sock_addr2.c"
    r1 = r0;
#line 176 "sample/cgroup_sock_addr2.c"
    r0 = IMMEDIATE(1);
#line 176 "sample/cgroup_sock_addr2.c"
    r0 &= UINT32_MAX;
#line 177 "sample/cgroup_sock_addr2.c"
    if (r1 == IMMEDIATE(0)) {
#line 177 "sample/cgroup_sock_addr2.c"
        goto label_2;
#line 177 "sample/cgroup_sock_addr2.c"
    }
#line 178 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r0, r1, OFFSET(24));
label_2:
#line 208 "sample/cgroup_sock_addr2.c"
    return r0;
#line 206 "sample/cgroup_sock_addr2.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t connect_authorization6_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID connect_authorization6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID connect_authorization6_attach_type_guid = {
    0x54b0b6ed, 0x432a, 0x4674, {0x8b, 0x27, 0x8d, 0x9f, 0x5b, 0x40, 0xc6, 0x75}};
static uint16_t connect_authorization6_maps[] = {
    2,
};

#pragma code_seg(push, "cgroup~1")
static uint64_t
connect_authorization6(void* context, const program_runtime_context_t* runtime_context)
#line 213 "sample/cgroup_sock_addr2.c"
{
#line 213 "sample/cgroup_sock_addr2.c"
    // Prologue.
#line 213 "sample/cgroup_sock_addr2.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 213 "sample/cgroup_sock_addr2.c"
    register uint64_t r0 = 0;
#line 213 "sample/cgroup_sock_addr2.c"
    register uint64_t r1 = 0;
#line 213 "sample/cgroup_sock_addr2.c"
    register uint64_t r2 = 0;
#line 213 "sample/cgroup_sock_addr2.c"
    register uint64_t r3 = 0;
#line 213 "sample/cgroup_sock_addr2.c"
    register uint64_t r4 = 0;
#line 213 "sample/cgroup_sock_addr2.c"
    register uint64_t r5 = 0;
#line 213 "sample/cgroup_sock_addr2.c"
    register uint64_t r10 = 0;

#line 213 "sample/cgroup_sock_addr2.c"
    r1 = (uintptr_t)context;
#line 213 "sample/cgroup_sock_addr2.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 213 "sample/cgroup_sock_addr2.c"
    r2 = IMMEDIATE(0);
#line 213 "sample/cgroup_sock_addr2.c"
    r2 &= UINT32_MAX;
#line 188 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-8));
#line 188 "sample/cgroup_sock_addr2.c"
    r0 = IMMEDIATE(1);
#line 188 "sample/cgroup_sock_addr2.c"
    r0 &= UINT32_MAX;
#line 190 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r2, r1, OFFSET(44));
#line 190 "sample/cgroup_sock_addr2.c"
    if ((uint32_t)r2 == IMMEDIATE(17)) {
#line 190 "sample/cgroup_sock_addr2.c"
        goto label_1;
#line 190 "sample/cgroup_sock_addr2.c"
    }
#line 190 "sample/cgroup_sock_addr2.c"
    if ((uint32_t)r2 != IMMEDIATE(6)) {
#line 190 "sample/cgroup_sock_addr2.c"
        goto label_2;
#line 190 "sample/cgroup_sock_addr2.c"
    }
label_1:
#line 190 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r3, r1, OFFSET(0));
#line 190 "sample/cgroup_sock_addr2.c"
    if ((uint32_t)r3 != IMMEDIATE(23)) {
#line 190 "sample/cgroup_sock_addr2.c"
        goto label_2;
#line 190 "sample/cgroup_sock_addr2.c"
    }
#line 68 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r3, r1, OFFSET(32));
#line 68 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r4, r1, OFFSET(36));
#line 68 "sample/cgroup_sock_addr2.c"
    r4 <<= (IMMEDIATE(32) & 63);
#line 68 "sample/cgroup_sock_addr2.c"
    r4 |= r3;
#line 68 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r4, OFFSET(-16));
#line 68 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r3, r1, OFFSET(24));
#line 68 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r4, r1, OFFSET(28));
#line 68 "sample/cgroup_sock_addr2.c"
    r4 <<= (IMMEDIATE(32) & 63);
#line 68 "sample/cgroup_sock_addr2.c"
    r4 |= r3;
#line 68 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r4, OFFSET(-24));
#line 69 "sample/cgroup_sock_addr2.c"
    READ_ONCE_16(r1, r1, OFFSET(40));
#line 69 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-8));
#line 70 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-4));
#line 70 "sample/cgroup_sock_addr2.c"
    r2 = r10;
#line 70 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-24);
#line 196 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(runtime_context->map_data[2].address);
#line 196 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 196 "sample/cgroup_sock_addr2.c"
    r1 = r0;
#line 196 "sample/cgroup_sock_addr2.c"
    r0 = IMMEDIATE(1);
#line 196 "sample/cgroup_sock_addr2.c"
    r0 &= UINT32_MAX;
#line 197 "sample/cgroup_sock_addr2.c"
    if (r1 == IMMEDIATE(0)) {
#line 197 "sample/cgroup_sock_addr2.c"
        goto label_2;
#line 197 "sample/cgroup_sock_addr2.c"
    }
#line 198 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r0, r1, OFFSET(24));
label_2:
#line 215 "sample/cgroup_sock_addr2.c"
    return r0;
#line 213 "sample/cgroup_sock_addr2.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

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

#pragma code_seg(push, "cgroup~4")
static uint64_t
connect_redirect4(void* context, const program_runtime_context_t* runtime_context)
#line 142 "sample/cgroup_sock_addr2.c"
{
#line 142 "sample/cgroup_sock_addr2.c"
    // Prologue.
#line 142 "sample/cgroup_sock_addr2.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 142 "sample/cgroup_sock_addr2.c"
    register uint64_t r0 = 0;
#line 142 "sample/cgroup_sock_addr2.c"
    register uint64_t r1 = 0;
#line 142 "sample/cgroup_sock_addr2.c"
    register uint64_t r2 = 0;
#line 142 "sample/cgroup_sock_addr2.c"
    register uint64_t r3 = 0;
#line 142 "sample/cgroup_sock_addr2.c"
    register uint64_t r4 = 0;
#line 142 "sample/cgroup_sock_addr2.c"
    register uint64_t r5 = 0;
#line 142 "sample/cgroup_sock_addr2.c"
    register uint64_t r6 = 0;
#line 142 "sample/cgroup_sock_addr2.c"
    register uint64_t r7 = 0;
#line 142 "sample/cgroup_sock_addr2.c"
    register uint64_t r8 = 0;
#line 142 "sample/cgroup_sock_addr2.c"
    register uint64_t r10 = 0;

#line 142 "sample/cgroup_sock_addr2.c"
    r1 = (uintptr_t)context;
#line 142 "sample/cgroup_sock_addr2.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 142 "sample/cgroup_sock_addr2.c"
    r6 = r1;
#line 142 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(0);
#line 77 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
#line 77 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-20));
#line 77 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 77 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-28));
#line 77 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(25959);
#line 77 "sample/cgroup_sock_addr2.c"
    r1 &= UINT32_MAX;
#line 78 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-40));
#line 78 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7022083122929103717;
#line 78 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 78 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)6085621373624807235;
#line 78 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-56));
#line 78 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)8386658473162859858;
#line 78 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-64));
#line 78 "sample/cgroup_sock_addr2.c"
    r7 = IMMEDIATE(0);
#line 78 "sample/cgroup_sock_addr2.c"
    r7 &= UINT32_MAX;
#line 78 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_8(r10, (uint8_t)r7, OFFSET(-38));
#line 80 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r1, r6, OFFSET(44));
#line 80 "sample/cgroup_sock_addr2.c"
    if ((uint32_t)r1 == IMMEDIATE(17)) {
#line 80 "sample/cgroup_sock_addr2.c"
        goto label_1;
#line 80 "sample/cgroup_sock_addr2.c"
    }
#line 80 "sample/cgroup_sock_addr2.c"
    if ((uint32_t)r1 != IMMEDIATE(6)) {
#line 80 "sample/cgroup_sock_addr2.c"
        goto label_3;
#line 80 "sample/cgroup_sock_addr2.c"
    }
label_1:
#line 80 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r2, r6, OFFSET(0));
#line 80 "sample/cgroup_sock_addr2.c"
    if ((uint32_t)r2 != IMMEDIATE(2)) {
#line 80 "sample/cgroup_sock_addr2.c"
        goto label_3;
#line 80 "sample/cgroup_sock_addr2.c"
    }
#line 57 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r2, r6, OFFSET(24));
#line 57 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-32));
#line 58 "sample/cgroup_sock_addr2.c"
    READ_ONCE_16(r2, r6, OFFSET(40));
#line 59 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-12));
#line 58 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_16(r10, (uint16_t)r2, OFFSET(-16));
#line 58 "sample/cgroup_sock_addr2.c"
    r2 = r10;
#line 58 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-32);
#line 87 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(runtime_context->map_data[0].address);
#line 87 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 87 "sample/cgroup_sock_addr2.c"
    r8 = r0;
#line 88 "sample/cgroup_sock_addr2.c"
    if (r8 == IMMEDIATE(0)) {
#line 88 "sample/cgroup_sock_addr2.c"
        goto label_2;
#line 88 "sample/cgroup_sock_addr2.c"
    }
#line 88 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(29989);
#line 88 "sample/cgroup_sock_addr2.c"
    r1 &= UINT32_MAX;
#line 89 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-72));
#line 89 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)2318356710503900533;
#line 89 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
#line 89 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7809653110685725806;
#line 89 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 89 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7286957755258269728;
#line 89 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 89 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)3780244552946118470;
#line 89 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 89 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_8(r10, (uint8_t)r7, OFFSET(-70));
#line 89 "sample/cgroup_sock_addr2.c"
    READ_ONCE_16(r4, r8, OFFSET(16));
#line 89 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r3, r8, OFFSET(0));
#line 89 "sample/cgroup_sock_addr2.c"
    r1 = r10;
#line 89 "sample/cgroup_sock_addr2.c"
    r1 += IMMEDIATE(-104);
#line 89 "sample/cgroup_sock_addr2.c"
    r2 = IMMEDIATE(35);
#line 89 "sample/cgroup_sock_addr2.c"
    r2 &= UINT32_MAX;
#line 89 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 89 "sample/cgroup_sock_addr2.c"
    r2 = r10;
#line 89 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-64);
#line 92 "sample/cgroup_sock_addr2.c"
    r1 = r6;
#line 92 "sample/cgroup_sock_addr2.c"
    r3 = IMMEDIATE(27);
#line 92 "sample/cgroup_sock_addr2.c"
    r3 &= UINT32_MAX;
#line 92 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/cgroup_sock_addr2.c"
    if ((int32_t)r0 < IMMEDIATE(0)) {
#line 92 "sample/cgroup_sock_addr2.c"
        goto label_3;
#line 92 "sample/cgroup_sock_addr2.c"
    }
#line 96 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r1, r8, OFFSET(0));
#line 96 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r6, (uint32_t)r1, OFFSET(24));
#line 97 "sample/cgroup_sock_addr2.c"
    READ_ONCE_16(r1, r8, OFFSET(16));
#line 97 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_16(r6, (uint16_t)r1, OFFSET(40));
#line 99 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r7, r8, OFFSET(24));
label_2:
#line 99 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(0);
#line 43 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 44 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 44 "sample/cgroup_sock_addr2.c"
    r8 = r0;
#line 44 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-96));
#line 45 "sample/cgroup_sock_addr2.c"
    r1 = r6;
#line 45 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 45 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-104));
#line 46 "sample/cgroup_sock_addr2.c"
    r1 = r6;
#line 46 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 46 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-88));
#line 47 "sample/cgroup_sock_addr2.c"
    READ_ONCE_16(r1, r6, OFFSET(20));
#line 47 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-84));
#line 48 "sample/cgroup_sock_addr2.c"
    r1 = r6;
#line 48 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 48 "sample/cgroup_sock_addr2.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[1].address);
#line 48 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-80));
#line 50 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-8));
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
label_3:
#line 144 "sample/cgroup_sock_addr2.c"
    r0 = r7;
#line 144 "sample/cgroup_sock_addr2.c"
    r0 &= UINT32_MAX;
#line 144 "sample/cgroup_sock_addr2.c"
    return r0;
#line 142 "sample/cgroup_sock_addr2.c"
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

#pragma code_seg(push, "cgroup~3")
static uint64_t
connect_redirect6(void* context, const program_runtime_context_t* runtime_context)
#line 149 "sample/cgroup_sock_addr2.c"
{
#line 149 "sample/cgroup_sock_addr2.c"
    // Prologue.
#line 149 "sample/cgroup_sock_addr2.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 149 "sample/cgroup_sock_addr2.c"
    register uint64_t r0 = 0;
#line 149 "sample/cgroup_sock_addr2.c"
    register uint64_t r1 = 0;
#line 149 "sample/cgroup_sock_addr2.c"
    register uint64_t r2 = 0;
#line 149 "sample/cgroup_sock_addr2.c"
    register uint64_t r3 = 0;
#line 149 "sample/cgroup_sock_addr2.c"
    register uint64_t r4 = 0;
#line 149 "sample/cgroup_sock_addr2.c"
    register uint64_t r5 = 0;
#line 149 "sample/cgroup_sock_addr2.c"
    register uint64_t r6 = 0;
#line 149 "sample/cgroup_sock_addr2.c"
    register uint64_t r7 = 0;
#line 149 "sample/cgroup_sock_addr2.c"
    register uint64_t r8 = 0;
#line 149 "sample/cgroup_sock_addr2.c"
    register uint64_t r10 = 0;

#line 149 "sample/cgroup_sock_addr2.c"
    r1 = (uintptr_t)context;
#line 149 "sample/cgroup_sock_addr2.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 149 "sample/cgroup_sock_addr2.c"
    r6 = r1;
#line 149 "sample/cgroup_sock_addr2.c"
    r7 = IMMEDIATE(0);
#line 149 "sample/cgroup_sock_addr2.c"
    r7 &= UINT32_MAX;
#line 111 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-48));
#line 111 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(25959);
#line 111 "sample/cgroup_sock_addr2.c"
    r1 &= UINT32_MAX;
#line 112 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-72));
#line 112 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7022083122929103717;
#line 112 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
#line 112 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)6085621373624807235;
#line 112 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 112 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)8386658473162859858;
#line 112 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 112 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_8(r10, (uint8_t)r7, OFFSET(-70));
#line 114 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r1, r6, OFFSET(44));
#line 114 "sample/cgroup_sock_addr2.c"
    if ((uint32_t)r1 == IMMEDIATE(17)) {
#line 114 "sample/cgroup_sock_addr2.c"
        goto label_1;
#line 114 "sample/cgroup_sock_addr2.c"
    }
#line 114 "sample/cgroup_sock_addr2.c"
    if ((uint32_t)r1 != IMMEDIATE(6)) {
#line 114 "sample/cgroup_sock_addr2.c"
        goto label_3;
#line 114 "sample/cgroup_sock_addr2.c"
    }
label_1:
#line 114 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r2, r6, OFFSET(0));
#line 114 "sample/cgroup_sock_addr2.c"
    if ((uint32_t)r2 != IMMEDIATE(23)) {
#line 114 "sample/cgroup_sock_addr2.c"
        goto label_3;
#line 114 "sample/cgroup_sock_addr2.c"
    }
#line 68 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r2, r6, OFFSET(32));
#line 68 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r3, r6, OFFSET(36));
#line 68 "sample/cgroup_sock_addr2.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 68 "sample/cgroup_sock_addr2.c"
    r3 |= r2;
#line 68 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r3, OFFSET(-56));
#line 68 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r2, r6, OFFSET(24));
#line 68 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r3, r6, OFFSET(28));
#line 68 "sample/cgroup_sock_addr2.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 68 "sample/cgroup_sock_addr2.c"
    r3 |= r2;
#line 68 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r3, OFFSET(-64));
#line 69 "sample/cgroup_sock_addr2.c"
    READ_ONCE_16(r2, r6, OFFSET(40));
#line 69 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_16(r10, (uint16_t)r2, OFFSET(-48));
#line 70 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-44));
#line 70 "sample/cgroup_sock_addr2.c"
    r2 = r10;
#line 70 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-64);
#line 121 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(runtime_context->map_data[0].address);
#line 121 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 121 "sample/cgroup_sock_addr2.c"
    r8 = r0;
#line 122 "sample/cgroup_sock_addr2.c"
    if (r8 == IMMEDIATE(0)) {
#line 122 "sample/cgroup_sock_addr2.c"
        goto label_2;
#line 122 "sample/cgroup_sock_addr2.c"
    }
#line 122 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(25973);
#line 122 "sample/cgroup_sock_addr2.c"
    r1 &= UINT32_MAX;
#line 123 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-16));
#line 123 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7809653110685725806;
#line 123 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 123 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7286957755258269728;
#line 123 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 123 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)3924359741021974342;
#line 123 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 123 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_8(r10, (uint8_t)r7, OFFSET(-14));
#line 123 "sample/cgroup_sock_addr2.c"
    r1 = r10;
#line 123 "sample/cgroup_sock_addr2.c"
    r1 += IMMEDIATE(-40);
#line 123 "sample/cgroup_sock_addr2.c"
    r2 = IMMEDIATE(27);
#line 123 "sample/cgroup_sock_addr2.c"
    r2 &= UINT32_MAX;
#line 123 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 123 "sample/cgroup_sock_addr2.c"
    r2 = r10;
#line 123 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-96);
#line 126 "sample/cgroup_sock_addr2.c"
    r1 = r6;
#line 126 "sample/cgroup_sock_addr2.c"
    r3 = IMMEDIATE(27);
#line 126 "sample/cgroup_sock_addr2.c"
    r3 &= UINT32_MAX;
#line 126 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 126 "sample/cgroup_sock_addr2.c"
    if ((int32_t)r0 < IMMEDIATE(0)) {
#line 126 "sample/cgroup_sock_addr2.c"
        goto label_3;
#line 126 "sample/cgroup_sock_addr2.c"
    }
#line 126 "sample/cgroup_sock_addr2.c"
    r1 = r6;
#line 126 "sample/cgroup_sock_addr2.c"
    r1 += IMMEDIATE(24);
#line 129 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r2, r8, OFFSET(12));
#line 129 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r1, (uint32_t)r2, OFFSET(12));
#line 129 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r2, r8, OFFSET(8));
#line 129 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r1, (uint32_t)r2, OFFSET(8));
#line 129 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r2, r8, OFFSET(4));
#line 129 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r1, (uint32_t)r2, OFFSET(4));
#line 129 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r2, r8, OFFSET(0));
#line 129 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r1, (uint32_t)r2, OFFSET(0));
#line 130 "sample/cgroup_sock_addr2.c"
    READ_ONCE_16(r1, r8, OFFSET(16));
#line 130 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_16(r6, (uint16_t)r1, OFFSET(40));
#line 132 "sample/cgroup_sock_addr2.c"
    READ_ONCE_32(r7, r8, OFFSET(24));
label_2:
#line 132 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(0);
#line 43 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 44 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 44 "sample/cgroup_sock_addr2.c"
    r8 = r0;
#line 44 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-32));
#line 45 "sample/cgroup_sock_addr2.c"
    r1 = r6;
#line 45 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 45 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-40));
#line 46 "sample/cgroup_sock_addr2.c"
    r1 = r6;
#line 46 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 46 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-24));
#line 47 "sample/cgroup_sock_addr2.c"
    READ_ONCE_16(r1, r6, OFFSET(20));
#line 47 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-20));
#line 48 "sample/cgroup_sock_addr2.c"
    r1 = r6;
#line 48 "sample/cgroup_sock_addr2.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 48 "sample/cgroup_sock_addr2.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[1].address);
#line 48 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-16));
#line 50 "sample/cgroup_sock_addr2.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-8));
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
label_3:
#line 151 "sample/cgroup_sock_addr2.c"
    r0 = r7;
#line 151 "sample/cgroup_sock_addr2.c"
    r0 &= UINT32_MAX;
#line 151 "sample/cgroup_sock_addr2.c"
    return r0;
#line 149 "sample/cgroup_sock_addr2.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        connect_authorization4,
        "cgroup~2",
        "cgroup/connect_authorization4",
        "connect_authorization4",
        connect_authorization4_maps,
        1,
        connect_authorization4_helpers,
        1,
        26,
        &connect_authorization4_program_type_guid,
        &connect_authorization4_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        connect_authorization6,
        "cgroup~1",
        "cgroup/connect_authorization6",
        "connect_authorization6",
        connect_authorization6_maps,
        1,
        connect_authorization6_helpers,
        1,
        31,
        &connect_authorization6_program_type_guid,
        &connect_authorization6_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        connect_redirect4,
        "cgroup~4",
        "cgroup/connect4",
        "connect_redirect4",
        connect_redirect4_maps,
        2,
        connect_redirect4_helpers,
        8,
        95,
        &connect_redirect4_program_type_guid,
        &connect_redirect4_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        connect_redirect6,
        "cgroup~3",
        "cgroup/connect6",
        "connect_redirect6",
        connect_redirect6_maps,
        2,
        connect_redirect6_helpers,
        8,
        102,
        &connect_redirect6_program_type_guid,
        &connect_redirect6_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 4;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = 1;
    version->minor = 3;
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
