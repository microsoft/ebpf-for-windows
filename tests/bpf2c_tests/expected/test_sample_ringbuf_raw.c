// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from test_sample_ringbuf.o

#include "bpf2c.h"
#include "ebpf_version.h"

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
         1,                    // Current Version.
         80,                   // Struct size up to the last field.
         80,                   // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_RINGBUF, // Type of map.
         0,                    // Size in bytes of a map key.
         0,                    // Size in bytes of a map value.
         65536,                // Maximum number of entries allowed in the map.
         0,                    // Inner map index.
         LIBBPF_PIN_NONE,      // Pinning type for the map.
         7,                    // Identifier for a map template.
         0,                    // The id of the inner map template.
     },
     "test_map"},
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

static helper_function_entry_t test_program_entry_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     11,
     "helper_id_11",
    },
};

static GUID test_program_entry_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID test_program_entry_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t test_program_entry_maps[] = {
    0,
};

#pragma code_seg(push, "sample~1")
static uint64_t
test_program_entry(void* context, const program_runtime_context_t* runtime_context)
#line 31 "sample/undocked/test_sample_ringbuf.c"
{
#line 31 "sample/undocked/test_sample_ringbuf.c"
    // Prologue.
#line 31 "sample/undocked/test_sample_ringbuf.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 31 "sample/undocked/test_sample_ringbuf.c"
    register uint64_t r0 = 0;
#line 31 "sample/undocked/test_sample_ringbuf.c"
    register uint64_t r1 = 0;
#line 31 "sample/undocked/test_sample_ringbuf.c"
    register uint64_t r2 = 0;
#line 31 "sample/undocked/test_sample_ringbuf.c"
    register uint64_t r3 = 0;
#line 31 "sample/undocked/test_sample_ringbuf.c"
    register uint64_t r4 = 0;
#line 31 "sample/undocked/test_sample_ringbuf.c"
    register uint64_t r5 = 0;
#line 31 "sample/undocked/test_sample_ringbuf.c"
    register uint64_t r10 = 0;

#line 31 "sample/undocked/test_sample_ringbuf.c"
    r1 = (uintptr_t)context;
#line 31 "sample/undocked/test_sample_ringbuf.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 31 "sample/undocked/test_sample_ringbuf.c"
    READ_ONCE_64(r2, r1, OFFSET(0));
#line 31 "sample/undocked/test_sample_ringbuf.c"
    READ_ONCE_64(r3, r1, OFFSET(8));
#line 31 "sample/undocked/test_sample_ringbuf.c"
    if (r2 >= r3) {
#line 31 "sample/undocked/test_sample_ringbuf.c"
        goto label_1;
#line 31 "sample/undocked/test_sample_ringbuf.c"
    }
#line 32 "sample/undocked/test_sample_ringbuf.c"
    r3 -= r2;
#line 32 "sample/undocked/test_sample_ringbuf.c"
    r1 = POINTER(runtime_context->map_data[0].address);
#line 32 "sample/undocked/test_sample_ringbuf.c"
    r4 = IMMEDIATE(0);
#line 32 "sample/undocked/test_sample_ringbuf.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
label_1:
#line 35 "sample/undocked/test_sample_ringbuf.c"
    r0 = IMMEDIATE(0);
#line 35 "sample/undocked/test_sample_ringbuf.c"
    return r0;
#line 31 "sample/undocked/test_sample_ringbuf.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 154, 160}, // Version header.
        test_program_entry,
        "sample~1",
        "sample_ext",
        "test_program_entry",
        test_program_entry_maps,
        1,
        test_program_entry_helpers,
        1,
        10,
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
    version->major = EBPF_VERSION_MAJOR;
    version->minor = EBPF_VERSION_MINOR;
    version->revision = EBPF_VERSION_REVISION;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t test_sample_ringbuf_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
