// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from bind_policy.o

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
         16,                // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         100,               // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         21,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "bind_policy_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 1;
}

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static helper_function_entry_t authorize_bind_helpers[] = {
    {
        {1, 40, 40}, // Version header.
        15,
        "helper_id_15",
    },
    {
        {1, 40, 40}, // Version header.
        1,
        "helper_id_1",
    },
    {
        {1, 40, 40}, // Version header.
        13,
        "helper_id_13",
    },
};

static GUID authorize_bind_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID authorize_bind_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t authorize_bind_maps[] = {
    0,
};

#pragma code_seg(push, "bind")
static uint64_t
authorize_bind(void* context, const program_runtime_context_t* runtime_context)
#line 165 "sample/bind_policy.c"
{
#line 165 "sample/bind_policy.c"
    // Prologue.
#line 165 "sample/bind_policy.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 165 "sample/bind_policy.c"
    register uint64_t r0 = 0;
#line 165 "sample/bind_policy.c"
    register uint64_t r1 = 0;
#line 165 "sample/bind_policy.c"
    register uint64_t r2 = 0;
#line 165 "sample/bind_policy.c"
    register uint64_t r3 = 0;
#line 165 "sample/bind_policy.c"
    register uint64_t r4 = 0;
#line 165 "sample/bind_policy.c"
    register uint64_t r5 = 0;
#line 165 "sample/bind_policy.c"
    register uint64_t r6 = 0;
#line 165 "sample/bind_policy.c"
    register uint64_t r7 = 0;
#line 165 "sample/bind_policy.c"
    register uint64_t r8 = 0;
#line 165 "sample/bind_policy.c"
    register uint64_t r10 = 0;

#line 165 "sample/bind_policy.c"
    r1 = (uintptr_t)context;
#line 165 "sample/bind_policy.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 165 "sample/bind_policy.c"
    r0 = IMMEDIATE(0);
#line 168 "sample/bind_policy.c"
    READ_ONCE_32(r2, r1, OFFSET(44));
#line 168 "sample/bind_policy.c"
    if (r2 != IMMEDIATE(0)) {
#line 168 "sample/bind_policy.c"
        goto label_5;
#line 168 "sample/bind_policy.c"
    }
#line 168 "sample/bind_policy.c"
    r8 = IMMEDIATE(0);
#line 90 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-8));
#line 102 "sample/bind_policy.c"
    READ_ONCE_64(r3, r1, OFFSET(16));
#line 95 "sample/bind_policy.c"
    READ_ONCE_16(r4, r1, OFFSET(26));
#line 103 "sample/bind_policy.c"
    WRITE_ONCE_16(r10, (uint16_t)r4, OFFSET(-8));
#line 102 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r3, OFFSET(-16));
#line 102 "sample/bind_policy.c"
    r7 = r1;
#line 104 "sample/bind_policy.c"
    READ_ONCE_8(r5, r1, OFFSET(48));
#line 104 "sample/bind_policy.c"
    WRITE_ONCE_8(r10, (uint8_t)r5, OFFSET(-6));
#line 105 "sample/bind_policy.c"
    WRITE_ONCE_8(r10, (uint8_t)r8, OFFSET(-24));
#line 105 "sample/bind_policy.c"
    r1 = (uint64_t)753549458396898159;
#line 105 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 105 "sample/bind_policy.c"
    r1 = (uint64_t)8390050319277238644;
#line 105 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 105 "sample/bind_policy.c"
    r1 = (uint64_t)7308823365138333044;
#line 105 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 105 "sample/bind_policy.c"
    r1 = (uint64_t)8245897541853736044;
#line 105 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-56));
#line 105 "sample/bind_policy.c"
    r1 = (uint64_t)2683376034650288751;
#line 105 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-64));
#line 105 "sample/bind_policy.c"
    r1 = (uint64_t)7359015259000827760;
#line 105 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-72));
#line 105 "sample/bind_policy.c"
    r1 = (uint64_t)2334111905781674101;
#line 105 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
#line 105 "sample/bind_policy.c"
    r1 = (uint64_t)2334956330867978060;
#line 105 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 105 "sample/bind_policy.c"
    r1 = r10;
#line 105 "sample/bind_policy.c"
    r1 += IMMEDIATE(-88);
#line 105 "sample/bind_policy.c"
    r2 = IMMEDIATE(65);
#line 105 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 105 "sample/bind_policy.c"
    r2 = r10;
#line 105 "sample/bind_policy.c"
    r2 += IMMEDIATE(-16);
#line 108 "sample/bind_policy.c"
    r1 = POINTER(runtime_context->map_data[0].address);
#line 108 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 108 "sample/bind_policy.c"
    r6 = r0;
#line 109 "sample/bind_policy.c"
    if (r6 == IMMEDIATE(0)) {
#line 109 "sample/bind_policy.c"
        goto label_1;
#line 109 "sample/bind_policy.c"
    }
#line 109 "sample/bind_policy.c"
    r1 = IMMEDIATE(10);
#line 110 "sample/bind_policy.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-48));
#line 110 "sample/bind_policy.c"
    r1 = (uint64_t)8441220621100741731;
#line 110 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-56));
#line 110 "sample/bind_policy.c"
    r1 = (uint64_t)4692815104753364079;
#line 110 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-64));
#line 110 "sample/bind_policy.c"
    r1 = (uint64_t)8079568156879888488;
#line 110 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-72));
#line 110 "sample/bind_policy.c"
    r1 = (uint64_t)7166460028377129825;
#line 110 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
#line 110 "sample/bind_policy.c"
    r1 = (uint64_t)8675375872921136966;
#line 110 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 110 "sample/bind_policy.c"
    READ_ONCE_32(r3, r6, OFFSET(0));
#line 110 "sample/bind_policy.c"
    r1 = r10;
#line 110 "sample/bind_policy.c"
    r1 += IMMEDIATE(-88);
#line 110 "sample/bind_policy.c"
    r2 = IMMEDIATE(42);
#line 110 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 110 "sample/bind_policy.c"
    goto label_4;
label_1:
#line 117 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-16));
#line 117 "sample/bind_policy.c"
    r2 = r10;
#line 117 "sample/bind_policy.c"
    r2 += IMMEDIATE(-16);
#line 118 "sample/bind_policy.c"
    r1 = POINTER(runtime_context->map_data[0].address);
#line 118 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 118 "sample/bind_policy.c"
    r6 = r0;
#line 119 "sample/bind_policy.c"
    if (r6 == IMMEDIATE(0)) {
#line 119 "sample/bind_policy.c"
        goto label_2;
#line 119 "sample/bind_policy.c"
    }
#line 119 "sample/bind_policy.c"
    r1 = IMMEDIATE(0);
#line 120 "sample/bind_policy.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-48));
#line 120 "sample/bind_policy.c"
    r1 = (uint64_t)753549458430454132;
#line 120 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-56));
#line 120 "sample/bind_policy.c"
    r1 = (uint64_t)7152033118757808492;
#line 120 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-64));
#line 120 "sample/bind_policy.c"
    r1 = (uint64_t)8029953751322812960;
#line 120 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-72));
#line 120 "sample/bind_policy.c"
    r1 = (uint64_t)7234315238536737906;
#line 120 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
#line 120 "sample/bind_policy.c"
    r1 = (uint64_t)8029953751323602758;
#line 120 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 120 "sample/bind_policy.c"
    READ_ONCE_32(r3, r6, OFFSET(0));
#line 120 "sample/bind_policy.c"
    r1 = r10;
#line 120 "sample/bind_policy.c"
    r1 += IMMEDIATE(-88);
#line 120 "sample/bind_policy.c"
    r2 = IMMEDIATE(41);
#line 120 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 120 "sample/bind_policy.c"
    goto label_4;
label_2:
#line 127 "sample/bind_policy.c"
    READ_ONCE_64(r1, r7, OFFSET(16));
#line 127 "sample/bind_policy.c"
    r2 = IMMEDIATE(0);
#line 129 "sample/bind_policy.c"
    WRITE_ONCE_8(r10, (uint8_t)r2, OFFSET(-6));
#line 128 "sample/bind_policy.c"
    WRITE_ONCE_16(r10, (uint16_t)r2, OFFSET(-8));
#line 127 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 127 "sample/bind_policy.c"
    r2 = r10;
#line 127 "sample/bind_policy.c"
    r2 += IMMEDIATE(-16);
#line 130 "sample/bind_policy.c"
    r1 = POINTER(runtime_context->map_data[0].address);
#line 130 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 130 "sample/bind_policy.c"
    r6 = r0;
#line 131 "sample/bind_policy.c"
    if (r6 == IMMEDIATE(0)) {
#line 131 "sample/bind_policy.c"
        goto label_3;
#line 131 "sample/bind_policy.c"
    }
#line 131 "sample/bind_policy.c"
    r1 = IMMEDIATE(685349);
#line 132 "sample/bind_policy.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-48));
#line 132 "sample/bind_policy.c"
    r1 = (uint64_t)4426597982466687264;
#line 132 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-56));
#line 132 "sample/bind_policy.c"
    r1 = (uint64_t)4213508230823768096;
#line 132 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-64));
#line 132 "sample/bind_policy.c"
    r1 = (uint64_t)7236837521402127731;
#line 132 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-72));
#line 132 "sample/bind_policy.c"
    r1 = (uint64_t)7017221143277167471;
#line 132 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
#line 132 "sample/bind_policy.c"
    r1 = (uint64_t)8246126533437386566;
#line 132 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 132 "sample/bind_policy.c"
    READ_ONCE_32(r3, r6, OFFSET(0));
#line 132 "sample/bind_policy.c"
    r1 = r10;
#line 132 "sample/bind_policy.c"
    r1 += IMMEDIATE(-88);
#line 132 "sample/bind_policy.c"
    r2 = IMMEDIATE(44);
#line 132 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 132 "sample/bind_policy.c"
    goto label_4;
label_3:
#line 132 "sample/bind_policy.c"
    r1 = IMMEDIATE(0);
#line 139 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 139 "sample/bind_policy.c"
    r2 = r10;
#line 139 "sample/bind_policy.c"
    r2 += IMMEDIATE(-16);
#line 140 "sample/bind_policy.c"
    r1 = POINTER(runtime_context->map_data[0].address);
#line 140 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 140 "sample/bind_policy.c"
    r6 = r0;
#line 140 "sample/bind_policy.c"
    r0 = IMMEDIATE(0);
#line 141 "sample/bind_policy.c"
    if (r6 == IMMEDIATE(0)) {
#line 141 "sample/bind_policy.c"
        goto label_5;
#line 141 "sample/bind_policy.c"
    }
label_4:
#line 141 "sample/bind_policy.c"
    READ_ONCE_32(r0, r6, OFFSET(0));
label_5:
#line 174 "sample/bind_policy.c"
    return r0;
#line 165 "sample/bind_policy.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        authorize_bind,
        "bind",
        "bind",
        "authorize_bind",
        authorize_bind_maps,
        1,
        authorize_bind_helpers,
        3,
        149,
        &authorize_bind_program_type_guid,
        &authorize_bind_attach_type_guid,
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

metadata_table_t bind_policy_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
