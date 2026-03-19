// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from test_sample_implicit_helpers.o

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
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         32,                 // Size in bytes of a map value.
         2,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         10,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "test_map"},
    {{0, 0},
     {
         1,  // Current Version.
         80, // Struct size up to the last field.
         80, // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         16,                 // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         16,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "output_map"},
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

static helper_function_entry_t test_program_entry_helpers[] = {
    {
        {1, 40, 40}, // Version header.
        1,
        "helper_id_1",
    },
    {
        {1, 40, 40}, // Version header.
        65537,
        "helper_id_65537",
    },
    {
        {1, 40, 40}, // Version header.
        65538,
        "helper_id_65538",
    },
    {
        {1, 40, 40}, // Version header.
        65539,
        "helper_id_65539",
    },
    {
        {1, 40, 40}, // Version header.
        65540,
        "helper_id_65540",
    },
    {
        {1, 40, 40}, // Version header.
        2,
        "helper_id_2",
    },
    {
        {1, 40, 40}, // Version header.
        65536,
        "helper_id_65536",
    },
};

static GUID test_program_entry_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID test_program_entry_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t test_program_entry_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sample~1")
static uint64_t
test_program_entry(void* context, const program_runtime_context_t* runtime_context)
#line 41 "sample/undocked/test_sample_implicit_helpers.c"
{
#line 41 "sample/undocked/test_sample_implicit_helpers.c"
    // Prologue.
#line 41 "sample/undocked/test_sample_implicit_helpers.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 41 "sample/undocked/test_sample_implicit_helpers.c"
    register uint64_t r0 = 0;
#line 41 "sample/undocked/test_sample_implicit_helpers.c"
    register uint64_t r1 = 0;
#line 41 "sample/undocked/test_sample_implicit_helpers.c"
    register uint64_t r2 = 0;
#line 41 "sample/undocked/test_sample_implicit_helpers.c"
    register uint64_t r3 = 0;
#line 41 "sample/undocked/test_sample_implicit_helpers.c"
    register uint64_t r4 = 0;
#line 41 "sample/undocked/test_sample_implicit_helpers.c"
    register uint64_t r5 = 0;
#line 41 "sample/undocked/test_sample_implicit_helpers.c"
    register uint64_t r6 = 0;
#line 41 "sample/undocked/test_sample_implicit_helpers.c"
    register uint64_t r7 = 0;
#line 41 "sample/undocked/test_sample_implicit_helpers.c"
    register uint64_t r8 = 0;
#line 41 "sample/undocked/test_sample_implicit_helpers.c"
    register uint64_t r10 = 0;

#line 41 "sample/undocked/test_sample_implicit_helpers.c"
    r1 = (uintptr_t)context;
#line 41 "sample/undocked/test_sample_implicit_helpers.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 41 "sample/undocked/test_sample_implicit_helpers.c"
    r6 = r1;
#line 41 "sample/undocked/test_sample_implicit_helpers.c"
    r1 = (uint64_t)4294967296;
#line 44 "sample/undocked/test_sample_implicit_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-8));
#line 44 "sample/undocked/test_sample_implicit_helpers.c"
    r2 = r10;
#line 44 "sample/undocked/test_sample_implicit_helpers.c"
    r2 += IMMEDIATE(-8);
#line 47 "sample/undocked/test_sample_implicit_helpers.c"
    r1 = POINTER(runtime_context->map_data[0].address);
#line 47 "sample/undocked/test_sample_implicit_helpers.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 47 "sample/undocked/test_sample_implicit_helpers.c"
    r8 = r0;
#line 48 "sample/undocked/test_sample_implicit_helpers.c"
    r2 = r10;
#line 48 "sample/undocked/test_sample_implicit_helpers.c"
    r2 += IMMEDIATE(-4);
#line 48 "sample/undocked/test_sample_implicit_helpers.c"
    r1 = POINTER(runtime_context->map_data[0].address);
#line 48 "sample/undocked/test_sample_implicit_helpers.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 48 "sample/undocked/test_sample_implicit_helpers.c"
    r7 = r0;
#line 50 "sample/undocked/test_sample_implicit_helpers.c"
    READ_ONCE_64(r1, r6, OFFSET(0));
#line 50 "sample/undocked/test_sample_implicit_helpers.c"
    READ_ONCE_64(r2, r6, OFFSET(8));
#line 50 "sample/undocked/test_sample_implicit_helpers.c"
    if (r1 >= r2) {
#line 50 "sample/undocked/test_sample_implicit_helpers.c"
        goto label_1;
#line 50 "sample/undocked/test_sample_implicit_helpers.c"
    }
#line 50 "sample/undocked/test_sample_implicit_helpers.c"
    if (r8 == IMMEDIATE(0)) {
#line 50 "sample/undocked/test_sample_implicit_helpers.c"
        goto label_1;
#line 50 "sample/undocked/test_sample_implicit_helpers.c"
    }
#line 55 "sample/undocked/test_sample_implicit_helpers.c"
    r2 -= r1;
#line 54 "sample/undocked/test_sample_implicit_helpers.c"
    r3 = r8;
#line 54 "sample/undocked/test_sample_implicit_helpers.c"
    r4 = IMMEDIATE(32);
#line 54 "sample/undocked/test_sample_implicit_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 56 "sample/undocked/test_sample_implicit_helpers.c"
    if (r7 == IMMEDIATE(0)) {
#line 56 "sample/undocked/test_sample_implicit_helpers.c"
        goto label_1;
#line 56 "sample/undocked/test_sample_implicit_helpers.c"
    }
#line 58 "sample/undocked/test_sample_implicit_helpers.c"
    READ_ONCE_64(r1, r6, OFFSET(0));
#line 58 "sample/undocked/test_sample_implicit_helpers.c"
    READ_ONCE_64(r2, r6, OFFSET(8));
#line 58 "sample/undocked/test_sample_implicit_helpers.c"
    r2 -= r1;
#line 57 "sample/undocked/test_sample_implicit_helpers.c"
    r3 = r0;
#line 57 "sample/undocked/test_sample_implicit_helpers.c"
    r4 = r7;
#line 57 "sample/undocked/test_sample_implicit_helpers.c"
    r5 = IMMEDIATE(32);
#line 57 "sample/undocked/test_sample_implicit_helpers.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 57 "sample/undocked/test_sample_implicit_helpers.c"
    r1 = IMMEDIATE(0);
#line 59 "sample/undocked/test_sample_implicit_helpers.c"
    if ((int64_t)r1 > (int64_t)r0) {
#line 59 "sample/undocked/test_sample_implicit_helpers.c"
        goto label_2;
#line 59 "sample/undocked/test_sample_implicit_helpers.c"
    }
label_1:
#line 68 "sample/undocked/test_sample_implicit_helpers.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 68 "sample/undocked/test_sample_implicit_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-24));
#line 69 "sample/undocked/test_sample_implicit_helpers.c"
    r1 = IMMEDIATE(10);
#line 69 "sample/undocked/test_sample_implicit_helpers.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 69 "sample/undocked/test_sample_implicit_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-16));
#line 69 "sample/undocked/test_sample_implicit_helpers.c"
    r2 = r10;
#line 69 "sample/undocked/test_sample_implicit_helpers.c"
    r2 += IMMEDIATE(-8);
#line 69 "sample/undocked/test_sample_implicit_helpers.c"
    r3 = r10;
#line 69 "sample/undocked/test_sample_implicit_helpers.c"
    r3 += IMMEDIATE(-24);
#line 69 "sample/undocked/test_sample_implicit_helpers.c"
    r7 = IMMEDIATE(0);
#line 72 "sample/undocked/test_sample_implicit_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
#line 72 "sample/undocked/test_sample_implicit_helpers.c"
    r4 = IMMEDIATE(0);
#line 72 "sample/undocked/test_sample_implicit_helpers.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/test_sample_implicit_helpers.c"
    r1 = r6;
#line 74 "sample/undocked/test_sample_implicit_helpers.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 75 "sample/undocked/test_sample_implicit_helpers.c"
    if ((int64_t)r7 > (int64_t)r0) {
#line 75 "sample/undocked/test_sample_implicit_helpers.c"
        goto label_2;
#line 75 "sample/undocked/test_sample_implicit_helpers.c"
    }
#line 75 "sample/undocked/test_sample_implicit_helpers.c"
    r0 = IMMEDIATE(42);
label_2:
#line 84 "sample/undocked/test_sample_implicit_helpers.c"
    return r0;
#line 41 "sample/undocked/test_sample_implicit_helpers.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        test_program_entry,
        "sample~1",
        "sample_ext",
        "test_program_entry",
        test_program_entry_maps,
        2,
        test_program_entry_helpers,
        7,
        53,
        &test_program_entry_program_type_guid,
        &test_program_entry_attach_type_guid,
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

metadata_table_t test_sample_implicit_helpers_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
