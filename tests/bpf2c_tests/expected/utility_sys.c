// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from utility.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table utility##_metadata_table

static GUID _bpf2c_npi_id = {/* c847aac8-a6f2-4b53-aea3-f4a94b9a80cb */
                             0xc847aac8,
                             0xa6f2,
                             0x4b53,
                             {0xae, 0xa3, 0xf4, 0xa9, 0x4b, 0x9a, 0x80, 0xcb}};
static NPI_MODULEID _bpf2c_module_id = {sizeof(_bpf2c_module_id), MIT_GUID, {0}};
static HANDLE _bpf2c_nmr_client_handle;
static HANDLE _bpf2c_nmr_provider_handle;
extern metadata_table_t metadata_table;

static NTSTATUS
_bpf2c_npi_client_attach_provider(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* client_context,
    _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance);

static NTSTATUS
_bpf2c_npi_client_detach_provider(_In_ void* client_binding_context);

static const NPI_CLIENT_CHARACTERISTICS _bpf2c_npi_client_characteristics = {
    0,                                  // Version
    sizeof(NPI_CLIENT_CHARACTERISTICS), // Length
    _bpf2c_npi_client_attach_provider,
    _bpf2c_npi_client_detach_provider,
    NULL,
    {0,                                 // Version
     sizeof(NPI_REGISTRATION_INSTANCE), // Length
     &_bpf2c_npi_id,
     &_bpf2c_module_id,
     0,
     NULL}};

static NTSTATUS
_bpf2c_query_npi_module_id(
    _In_ const wchar_t* value_name,
    unsigned long value_type,
    _In_ const void* value_data,
    unsigned long value_length,
    _Inout_ void* context,
    _Inout_ void* entry_context)
{
    UNREFERENCED_PARAMETER(value_name);
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(entry_context);

    if (value_type != REG_BINARY) {
        return STATUS_INVALID_PARAMETER;
    }
    if (value_length != sizeof(_bpf2c_module_id.Guid)) {
        return STATUS_INVALID_PARAMETER;
    }

    memcpy(&_bpf2c_module_id.Guid, value_data, value_length);
    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(_In_ DRIVER_OBJECT* driver_object, _In_ UNICODE_STRING* registry_path)
{
    NTSTATUS status;
    RTL_QUERY_REGISTRY_TABLE query_table[] = {
        {
            NULL,                      // Query routine
            RTL_QUERY_REGISTRY_SUBKEY, // Flags
            L"Parameters",             // Name
            NULL,                      // Entry context
            REG_NONE,                  // Default type
            NULL,                      // Default data
            0,                         // Default length
        },
        {
            _bpf2c_query_npi_module_id,  // Query routine
            RTL_QUERY_REGISTRY_REQUIRED, // Flags
            L"NpiModuleId",              // Name
            NULL,                        // Entry context
            REG_NONE,                    // Default type
            NULL,                        // Default data
            0,                           // Default length
        },
        {0}};

    status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, registry_path->Buffer, query_table, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = NmrRegisterClient(&_bpf2c_npi_client_characteristics, NULL, &_bpf2c_nmr_client_handle);

Exit:
    if (NT_SUCCESS(status)) {
        driver_object->DriverUnload = DriverUnload;
    }

    return status;
}

void
DriverUnload(_In_ DRIVER_OBJECT* driver_object)
{
    NTSTATUS status = NmrDeregisterClient(_bpf2c_nmr_client_handle);
    if (status == STATUS_PENDING) {
        NmrWaitForClientDeregisterComplete(_bpf2c_nmr_client_handle);
    }
    UNREFERENCED_PARAMETER(driver_object);
}

static NTSTATUS
_bpf2c_npi_client_attach_provider(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* client_context,
    _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance)
{
    NTSTATUS status = STATUS_SUCCESS;
    void* provider_binding_context = NULL;
    void* provider_dispatch_table = NULL;

    UNREFERENCED_PARAMETER(client_context);
    UNREFERENCED_PARAMETER(provider_registration_instance);

    if (_bpf2c_nmr_provider_handle != NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = NmrClientAttachProvider(
        nmr_binding_handle, client_context, &metadata_table, &provider_binding_context, &provider_dispatch_table);
    if (status != STATUS_SUCCESS) {
        goto Done;
    }
    _bpf2c_nmr_provider_handle = nmr_binding_handle;

Done:
    return status;
}

static NTSTATUS
_bpf2c_npi_client_detach_provider(_In_ void* client_binding_context)
{
    _bpf2c_nmr_provider_handle = NULL;
    UNREFERENCED_PARAMETER(client_binding_context);
    return STATUS_SUCCESS;
}

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

static helper_function_entry_t UtilityTest_helpers[] = {
    {
        {1, 40, 40}, // Version header.
        23,
        "helper_id_23",
    },
    {
        {1, 40, 40}, // Version header.
        22,
        "helper_id_22",
    },
    {
        {1, 40, 40}, // Version header.
        24,
        "helper_id_24",
    },
    {
        {1, 40, 40}, // Version header.
        25,
        "helper_id_25",
    },
};

static GUID UtilityTest_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID UtilityTest_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
#pragma code_seg(push, "bind")
static uint64_t
UtilityTest(void* context, const program_runtime_context_t* runtime_context)
#line 24 "sample/utility.c"
{
#line 24 "sample/utility.c"
    // Prologue.
#line 24 "sample/utility.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 24 "sample/utility.c"
    register uint64_t r0 = 0;
#line 24 "sample/utility.c"
    register uint64_t r1 = 0;
#line 24 "sample/utility.c"
    register uint64_t r2 = 0;
#line 24 "sample/utility.c"
    register uint64_t r3 = 0;
#line 24 "sample/utility.c"
    register uint64_t r4 = 0;
#line 24 "sample/utility.c"
    register uint64_t r5 = 0;
#line 24 "sample/utility.c"
    register uint64_t r10 = 0;

#line 24 "sample/utility.c"
    r1 = (uintptr_t)context;
#line 24 "sample/utility.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 24 "sample/utility.c"
    r1 = IMMEDIATE(0);
#line 26 "sample/utility.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-4));
#line 26 "sample/utility.c"
    r2 = IMMEDIATE(1953719668);
#line 26 "sample/utility.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-8));
#line 27 "sample/utility.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-16));
#line 27 "sample/utility.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-12));
#line 28 "sample/utility.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-22));
#line 28 "sample/utility.c"
    r1 = IMMEDIATE(12345);
#line 28 "sample/utility.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-24));
#line 28 "sample/utility.c"
    r1 = (uint64_t)4050765991979987505;
#line 28 "sample/utility.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 28 "sample/utility.c"
    r1 = r10;
#line 28 "sample/utility.c"
    r1 += IMMEDIATE(-8);
#line 28 "sample/utility.c"
    r3 = r10;
#line 28 "sample/utility.c"
    r3 += IMMEDIATE(-16);
#line 31 "sample/utility.c"
    r2 = IMMEDIATE(4);
#line 31 "sample/utility.c"
    r4 = IMMEDIATE(4);
#line 31 "sample/utility.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 31 "sample/utility.c"
    r1 = r0;
#line 31 "sample/utility.c"
    r0 = IMMEDIATE(1);
#line 31 "sample/utility.c"
    r1 <<= (IMMEDIATE(32) & 63);
#line 31 "sample/utility.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 31 "sample/utility.c"
    if (r1 != IMMEDIATE(0)) {
#line 31 "sample/utility.c"
        goto label_1;
#line 31 "sample/utility.c"
    }
#line 31 "sample/utility.c"
    r1 = IMMEDIATE(84);
#line 35 "sample/utility.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-8));
#line 35 "sample/utility.c"
    r1 = r10;
#line 35 "sample/utility.c"
    r1 += IMMEDIATE(-8);
#line 35 "sample/utility.c"
    r3 = r10;
#line 35 "sample/utility.c"
    r3 += IMMEDIATE(-16);
#line 37 "sample/utility.c"
    r2 = IMMEDIATE(4);
#line 37 "sample/utility.c"
    r4 = IMMEDIATE(4);
#line 37 "sample/utility.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 37 "sample/utility.c"
    r1 = r0;
#line 37 "sample/utility.c"
    r0 = IMMEDIATE(2);
#line 37 "sample/utility.c"
    r1 <<= (IMMEDIATE(32) & 63);
#line 37 "sample/utility.c"
    r1 = (int64_t)r1 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 37 "sample/utility.c"
    if ((int64_t)r1 > IMMEDIATE(-1)) {
#line 37 "sample/utility.c"
        goto label_1;
#line 37 "sample/utility.c"
    }
#line 37 "sample/utility.c"
    r1 = r10;
#line 43 "sample/utility.c"
    r1 += IMMEDIATE(-8);
#line 43 "sample/utility.c"
    r3 = r10;
#line 43 "sample/utility.c"
    r3 += IMMEDIATE(-16);
#line 43 "sample/utility.c"
    r2 = IMMEDIATE(3);
#line 43 "sample/utility.c"
    r4 = IMMEDIATE(4);
#line 43 "sample/utility.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 43 "sample/utility.c"
    r1 = r0;
#line 43 "sample/utility.c"
    r0 = IMMEDIATE(3);
#line 43 "sample/utility.c"
    r1 <<= (IMMEDIATE(32) & 63);
#line 43 "sample/utility.c"
    r1 = (int64_t)r1 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 43 "sample/utility.c"
    if ((int64_t)r1 > IMMEDIATE(-1)) {
#line 43 "sample/utility.c"
        goto label_1;
#line 43 "sample/utility.c"
    }
#line 43 "sample/utility.c"
    r1 = IMMEDIATE(1414743380);
#line 48 "sample/utility.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 48 "sample/utility.c"
    r1 = r10;
#line 48 "sample/utility.c"
    r1 += IMMEDIATE(-8);
#line 48 "sample/utility.c"
    r3 = r10;
#line 48 "sample/utility.c"
    r3 += IMMEDIATE(-16);
#line 54 "sample/utility.c"
    r2 = IMMEDIATE(4);
#line 54 "sample/utility.c"
    r4 = IMMEDIATE(4);
#line 54 "sample/utility.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 54 "sample/utility.c"
    r1 = r0;
#line 54 "sample/utility.c"
    r2 = IMMEDIATE(0);
#line 54 "sample/utility.c"
    r0 = IMMEDIATE(4);
#line 54 "sample/utility.c"
    if ((int64_t)r2 > (int64_t)r1) {
#line 54 "sample/utility.c"
        goto label_1;
#line 54 "sample/utility.c"
    }
#line 54 "sample/utility.c"
    r0 = IMMEDIATE(5);
#line 59 "sample/utility.c"
    READ_ONCE_8(r1, r10, OFFSET(-8));
#line 59 "sample/utility.c"
    if (r1 != IMMEDIATE(116)) {
#line 59 "sample/utility.c"
        goto label_1;
#line 59 "sample/utility.c"
    }
#line 59 "sample/utility.c"
    READ_ONCE_8(r1, r10, OFFSET(-7));
#line 59 "sample/utility.c"
    if (r1 != IMMEDIATE(101)) {
#line 59 "sample/utility.c"
        goto label_1;
#line 59 "sample/utility.c"
    }
#line 59 "sample/utility.c"
    READ_ONCE_8(r1, r10, OFFSET(-6));
#line 59 "sample/utility.c"
    if (r1 != IMMEDIATE(115)) {
#line 59 "sample/utility.c"
        goto label_1;
#line 59 "sample/utility.c"
    }
#line 59 "sample/utility.c"
    READ_ONCE_8(r1, r10, OFFSET(-5));
#line 59 "sample/utility.c"
    if (r1 != IMMEDIATE(116)) {
#line 59 "sample/utility.c"
        goto label_1;
#line 59 "sample/utility.c"
    }
#line 59 "sample/utility.c"
    r1 = r10;
#line 64 "sample/utility.c"
    r1 += IMMEDIATE(-8);
#line 64 "sample/utility.c"
    r2 = IMMEDIATE(4);
#line 64 "sample/utility.c"
    r3 = IMMEDIATE(0);
#line 64 "sample/utility.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 64 "sample/utility.c"
    r1 = r0;
#line 64 "sample/utility.c"
    r0 = IMMEDIATE(6);
#line 64 "sample/utility.c"
    if (r1 == IMMEDIATE(0)) {
#line 64 "sample/utility.c"
        goto label_1;
#line 64 "sample/utility.c"
    }
#line 64 "sample/utility.c"
    r0 = IMMEDIATE(7);
#line 69 "sample/utility.c"
    READ_ONCE_8(r1, r10, OFFSET(-8));
#line 69 "sample/utility.c"
    if (r1 != IMMEDIATE(0)) {
#line 69 "sample/utility.c"
        goto label_1;
#line 69 "sample/utility.c"
    }
#line 69 "sample/utility.c"
    READ_ONCE_8(r1, r10, OFFSET(-7));
#line 69 "sample/utility.c"
    if (r1 != IMMEDIATE(0)) {
#line 69 "sample/utility.c"
        goto label_1;
#line 69 "sample/utility.c"
    }
#line 69 "sample/utility.c"
    READ_ONCE_8(r1, r10, OFFSET(-6));
#line 69 "sample/utility.c"
    if (r1 != IMMEDIATE(0)) {
#line 69 "sample/utility.c"
        goto label_1;
#line 69 "sample/utility.c"
    }
#line 69 "sample/utility.c"
    READ_ONCE_8(r1, r10, OFFSET(-5));
#line 69 "sample/utility.c"
    if (r1 != IMMEDIATE(0)) {
#line 69 "sample/utility.c"
        goto label_1;
#line 69 "sample/utility.c"
    }
#line 74 "sample/utility.c"
    r1 = r10;
#line 74 "sample/utility.c"
    r1 += IMMEDIATE(-30);
#line 74 "sample/utility.c"
    r3 = r10;
#line 74 "sample/utility.c"
    r3 += IMMEDIATE(-32);
#line 74 "sample/utility.c"
    r2 = IMMEDIATE(4);
#line 74 "sample/utility.c"
    r4 = IMMEDIATE(4);
#line 74 "sample/utility.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/utility.c"
    r1 = r0;
#line 74 "sample/utility.c"
    r0 = IMMEDIATE(8);
#line 74 "sample/utility.c"
    r2 = IMMEDIATE(0);
#line 74 "sample/utility.c"
    if ((int64_t)r2 > (int64_t)r1) {
#line 74 "sample/utility.c"
        goto label_1;
#line 74 "sample/utility.c"
    }
#line 74 "sample/utility.c"
    r0 = IMMEDIATE(9);
#line 79 "sample/utility.c"
    READ_ONCE_8(r1, r10, OFFSET(-30));
#line 79 "sample/utility.c"
    if (r1 != IMMEDIATE(49)) {
#line 79 "sample/utility.c"
        goto label_1;
#line 79 "sample/utility.c"
    }
#line 79 "sample/utility.c"
    READ_ONCE_8(r1, r10, OFFSET(-29));
#line 79 "sample/utility.c"
    if (r1 != IMMEDIATE(50)) {
#line 79 "sample/utility.c"
        goto label_1;
#line 79 "sample/utility.c"
    }
#line 79 "sample/utility.c"
    READ_ONCE_8(r1, r10, OFFSET(-28));
#line 79 "sample/utility.c"
    if (r1 != IMMEDIATE(51)) {
#line 79 "sample/utility.c"
        goto label_1;
#line 79 "sample/utility.c"
    }
#line 79 "sample/utility.c"
    READ_ONCE_8(r1, r10, OFFSET(-27));
#line 79 "sample/utility.c"
    if (r1 != IMMEDIATE(52)) {
#line 79 "sample/utility.c"
        goto label_1;
#line 79 "sample/utility.c"
    }
#line 79 "sample/utility.c"
    r0 = IMMEDIATE(0);
label_1:
#line 84 "sample/utility.c"
    return r0;
#line 24 "sample/utility.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        UtilityTest,
        "bind",
        "bind",
        "UtilityTest",
        NULL,
        0,
        UtilityTest_helpers,
        4,
        111,
        &UtilityTest_program_type_guid,
        &UtilityTest_attach_type_guid,
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

metadata_table_t utility_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
