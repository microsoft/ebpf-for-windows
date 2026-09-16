// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from strings.o

#include "bpf2c.h"

static void
_get_hash(_Outptr_result_buffer_maybenull_(*size) const uint8_t** hash, _Out_ size_t* size)
{
    *hash = NULL;
    *size = 0;
}

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = NULL;
    *count = 0;
}

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static helper_function_entry_t StringOpsTest_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     29,
     "helper_id_29",
    },
    {
     {1, 40, 40}, // Version header.
     27,
     "helper_id_27",
    },
    {
     {1, 40, 40}, // Version header.
     23,
     "helper_id_23",
    },
    {
     {1, 40, 40}, // Version header.
     28,
     "helper_id_28",
    },
};

static GUID StringOpsTest_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID StringOpsTest_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
#pragma code_seg(push, "sample~1")
static uint64_t
StringOpsTest(void* context, const program_runtime_context_t* runtime_context)
#line 19 "sample/strings.c"
{
#line 19 "sample/strings.c"
    // Prologue.
#line 19 "sample/strings.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 19 "sample/strings.c"
    register uint64_t r0 = 0;
#line 19 "sample/strings.c"
    register uint64_t r1 = 0;
#line 19 "sample/strings.c"
    register uint64_t r2 = 0;
#line 19 "sample/strings.c"
    register uint64_t r3 = 0;
#line 19 "sample/strings.c"
    register uint64_t r4 = 0;
#line 19 "sample/strings.c"
    register uint64_t r5 = 0;
#line 19 "sample/strings.c"
    register uint64_t r10 = 0;

#line 19 "sample/strings.c"
    r1 = (uintptr_t)context;
#line 19 "sample/strings.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 19 "sample/strings.c"
    r1 = IMMEDIATE(0);
#line 21 "sample/strings.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 21 "sample/strings.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 21 "sample/strings.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 21 "sample/strings.c"
    r2 = IMMEDIATE(97);
#line 22 "sample/strings.c"
    WRITE_ONCE_16(r10, (uint16_t)r2, OFFSET(-28));
#line 22 "sample/strings.c"
    r2 = IMMEDIATE(1752198241);
#line 22 "sample/strings.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-32));
#line 22 "sample/strings.c"
    r2 = IMMEDIATE(1634102369);
#line 23 "sample/strings.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-40));
#line 23 "sample/strings.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-36));
#line 23 "sample/strings.c"
    r2 = IMMEDIATE(7304801);
#line 24 "sample/strings.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-48));
#line 24 "sample/strings.c"
    r2 = (uint64_t)8242150686405454945;
#line 24 "sample/strings.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-56));
#line 25 "sample/strings.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-57));
#line 25 "sample/strings.c"
    r1 = r10;
#line 25 "sample/strings.c"
    r1 += IMMEDIATE(-57);
#line 27 "sample/strings.c"
    r2 = IMMEDIATE(0);
#line 27 "sample/strings.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 27 "sample/strings.c"
    r1 = r0;
#line 27 "sample/strings.c"
    r0 = IMMEDIATE(1);
#line 27 "sample/strings.c"
    if (r1 != IMMEDIATE(0)) {
#line 27 "sample/strings.c"
        goto label_2;
#line 27 "sample/strings.c"
    }
#line 27 "sample/strings.c"
    r1 = r10;
#line 31 "sample/strings.c"
    r1 += IMMEDIATE(-24);
#line 31 "sample/strings.c"
    r2 = IMMEDIATE(20);
#line 31 "sample/strings.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 31 "sample/strings.c"
    r1 = r0;
#line 31 "sample/strings.c"
    r0 = IMMEDIATE(2);
#line 31 "sample/strings.c"
    if (r1 != IMMEDIATE(0)) {
#line 31 "sample/strings.c"
        goto label_2;
#line 31 "sample/strings.c"
    }
#line 31 "sample/strings.c"
    r1 = r10;
#line 35 "sample/strings.c"
    r1 += IMMEDIATE(-32);
#line 35 "sample/strings.c"
    r2 = IMMEDIATE(6);
#line 35 "sample/strings.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 35 "sample/strings.c"
    r1 = r0;
#line 35 "sample/strings.c"
    r0 = IMMEDIATE(3);
#line 35 "sample/strings.c"
    if (r1 != IMMEDIATE(5)) {
#line 35 "sample/strings.c"
        goto label_2;
#line 35 "sample/strings.c"
    }
#line 35 "sample/strings.c"
    r1 = r10;
#line 39 "sample/strings.c"
    r1 += IMMEDIATE(-56);
#line 39 "sample/strings.c"
    r2 = IMMEDIATE(12);
#line 39 "sample/strings.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 39 "sample/strings.c"
    r1 = r0;
#line 39 "sample/strings.c"
    r0 = IMMEDIATE(4);
#line 39 "sample/strings.c"
    if (r1 != IMMEDIATE(5)) {
#line 39 "sample/strings.c"
        goto label_2;
#line 39 "sample/strings.c"
    }
#line 39 "sample/strings.c"
    r1 = r10;
#line 43 "sample/strings.c"
    r1 += IMMEDIATE(-24);
#line 43 "sample/strings.c"
    r3 = r10;
#line 43 "sample/strings.c"
    r3 += IMMEDIATE(-32);
#line 43 "sample/strings.c"
    r2 = IMMEDIATE(20);
#line 43 "sample/strings.c"
    r4 = IMMEDIATE(6);
#line 43 "sample/strings.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 43 "sample/strings.c"
    r1 = r0;
#line 43 "sample/strings.c"
    r0 = IMMEDIATE(5);
#line 43 "sample/strings.c"
    r1 <<= (IMMEDIATE(32) & 63);
#line 43 "sample/strings.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 43 "sample/strings.c"
    if (r1 != IMMEDIATE(0)) {
#line 43 "sample/strings.c"
        goto label_2;
#line 43 "sample/strings.c"
    }
#line 43 "sample/strings.c"
    r1 = r10;
#line 49 "sample/strings.c"
    r1 += IMMEDIATE(-24);
#line 49 "sample/strings.c"
    r3 = r10;
#line 49 "sample/strings.c"
    r3 += IMMEDIATE(-32);
#line 49 "sample/strings.c"
    r2 = IMMEDIATE(6);
#line 49 "sample/strings.c"
    r4 = IMMEDIATE(6);
#line 49 "sample/strings.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 49 "sample/strings.c"
    r1 = r0;
#line 49 "sample/strings.c"
    r1 <<= (IMMEDIATE(32) & 63);
#line 49 "sample/strings.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 49 "sample/strings.c"
    r0 = IMMEDIATE(6);
#line 49 "sample/strings.c"
    if (r1 != IMMEDIATE(0)) {
#line 49 "sample/strings.c"
        goto label_2;
#line 49 "sample/strings.c"
    }
#line 49 "sample/strings.c"
    r1 = r10;
#line 53 "sample/strings.c"
    r1 += IMMEDIATE(-24);
#line 53 "sample/strings.c"
    r3 = r10;
#line 53 "sample/strings.c"
    r3 += IMMEDIATE(-40);
#line 53 "sample/strings.c"
    r2 = IMMEDIATE(20);
#line 53 "sample/strings.c"
    r4 = IMMEDIATE(5);
#line 53 "sample/strings.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 53 "sample/strings.c"
    r1 = r0;
#line 53 "sample/strings.c"
    r0 = IMMEDIATE(7);
#line 53 "sample/strings.c"
    r1 <<= (IMMEDIATE(32) & 63);
#line 53 "sample/strings.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 53 "sample/strings.c"
    if (r1 != IMMEDIATE(0)) {
#line 53 "sample/strings.c"
        goto label_2;
#line 53 "sample/strings.c"
    }
#line 53 "sample/strings.c"
    r1 = IMMEDIATE(97);
#line 58 "sample/strings.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-64));
#line 58 "sample/strings.c"
    r1 = (uint64_t)7380380960345320545;
#line 58 "sample/strings.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-72));
#line 58 "sample/strings.c"
    r1 = r10;
#line 58 "sample/strings.c"
    r1 += IMMEDIATE(-24);
#line 58 "sample/strings.c"
    r3 = r10;
#line 58 "sample/strings.c"
    r3 += IMMEDIATE(-72);
#line 62 "sample/strings.c"
    r2 = IMMEDIATE(10);
#line 62 "sample/strings.c"
    r4 = IMMEDIATE(10);
#line 62 "sample/strings.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 62 "sample/strings.c"
    r1 = r0;
#line 62 "sample/strings.c"
    r1 <<= (IMMEDIATE(32) & 63);
#line 62 "sample/strings.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 62 "sample/strings.c"
    r0 = IMMEDIATE(1);
#line 62 "sample/strings.c"
    if (r1 != IMMEDIATE(0)) {
#line 62 "sample/strings.c"
        goto label_1;
#line 62 "sample/strings.c"
    }
#line 62 "sample/strings.c"
    r0 = IMMEDIATE(0);
label_1:
#line 62 "sample/strings.c"
    r0 <<= (IMMEDIATE(3) & 63);
label_2:
#line 67 "sample/strings.c"
    return r0;
#line 19 "sample/strings.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 154, 160}, // Version header.
        StringOpsTest,
        "sample~1",
        "sample_ext",
        "StringOpsTest",
        NULL,
        0,
        StringOpsTest_helpers,
        4,
        101,
        &StringOpsTest_program_type_guid,
        &StringOpsTest_attach_type_guid,
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
    version->minor = 6;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t strings_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
