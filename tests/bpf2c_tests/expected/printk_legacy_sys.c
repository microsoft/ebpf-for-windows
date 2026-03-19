// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from printk_legacy.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table printk_legacy##_metadata_table

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

static helper_function_entry_t func_helpers[] = {
    {
        {1, 40, 40}, // Version header.
        12,
        "helper_id_12",
    },
    {
        {1, 40, 40}, // Version header.
        13,
        "helper_id_13",
    },
    {
        {1, 40, 40}, // Version header.
        14,
        "helper_id_14",
    },
    {
        {1, 40, 40}, // Version header.
        15,
        "helper_id_15",
    },
};

static GUID func_program_type_guid = {0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID func_attach_type_guid = {0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
#pragma code_seg(push, "bind")
static uint64_t
func(void* context, const program_runtime_context_t* runtime_context)
#line 26 "sample/printk_legacy.c"
{
#line 26 "sample/printk_legacy.c"
    // Prologue.
#line 26 "sample/printk_legacy.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 26 "sample/printk_legacy.c"
    register uint64_t r0 = 0;
#line 26 "sample/printk_legacy.c"
    register uint64_t r1 = 0;
#line 26 "sample/printk_legacy.c"
    register uint64_t r2 = 0;
#line 26 "sample/printk_legacy.c"
    register uint64_t r3 = 0;
#line 26 "sample/printk_legacy.c"
    register uint64_t r4 = 0;
#line 26 "sample/printk_legacy.c"
    register uint64_t r5 = 0;
#line 26 "sample/printk_legacy.c"
    register uint64_t r6 = 0;
#line 26 "sample/printk_legacy.c"
    register uint64_t r7 = 0;
#line 26 "sample/printk_legacy.c"
    register uint64_t r8 = 0;
#line 26 "sample/printk_legacy.c"
    register uint64_t r9 = 0;
#line 26 "sample/printk_legacy.c"
    register uint64_t r10 = 0;

#line 26 "sample/printk_legacy.c"
    r1 = (uintptr_t)context;
#line 26 "sample/printk_legacy.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 26 "sample/printk_legacy.c"
    r7 = r1;
#line 26 "sample/printk_legacy.c"
    r1 = IMMEDIATE(0);
#line 31 "sample/printk_legacy.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-20));
#line 31 "sample/printk_legacy.c"
    r6 = IMMEDIATE(1684828783);
#line 31 "sample/printk_legacy.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-24));
#line 31 "sample/printk_legacy.c"
    r9 = (uint64_t)8583909746840200520;
#line 31 "sample/printk_legacy.c"
    WRITE_ONCE_64(r10, (uint64_t)r9, OFFSET(-32));
#line 31 "sample/printk_legacy.c"
    r1 = r10;
#line 31 "sample/printk_legacy.c"
    r1 += IMMEDIATE(-32);
#line 31 "sample/printk_legacy.c"
    r2 = IMMEDIATE(13);
#line 31 "sample/printk_legacy.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 31 "sample/printk_legacy.c"
    r8 = r0;
#line 31 "sample/printk_legacy.c"
    r1 = IMMEDIATE(10);
#line 32 "sample/printk_legacy.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-20));
#line 32 "sample/printk_legacy.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-24));
#line 32 "sample/printk_legacy.c"
    WRITE_ONCE_64(r10, (uint64_t)r9, OFFSET(-32));
#line 32 "sample/printk_legacy.c"
    r1 = r10;
#line 32 "sample/printk_legacy.c"
    r1 += IMMEDIATE(-32);
#line 32 "sample/printk_legacy.c"
    r2 = IMMEDIATE(14);
#line 32 "sample/printk_legacy.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 32 "sample/printk_legacy.c"
    r6 = r0;
#line 32 "sample/printk_legacy.c"
    r1 = (uint64_t)32973392621881680;
#line 35 "sample/printk_legacy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 32 "sample/printk_legacy.c"
    r6 += r8;
#line 35 "sample/printk_legacy.c"
    READ_ONCE_64(r3, r7, OFFSET(16));
#line 35 "sample/printk_legacy.c"
    r1 = r10;
#line 35 "sample/printk_legacy.c"
    r1 += IMMEDIATE(-32);
#line 35 "sample/printk_legacy.c"
    r2 = IMMEDIATE(8);
#line 35 "sample/printk_legacy.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 35 "sample/printk_legacy.c"
    r6 += r0;
#line 35 "sample/printk_legacy.c"
    r9 = IMMEDIATE(117);
#line 36 "sample/printk_legacy.c"
    WRITE_ONCE_16(r10, (uint16_t)r9, OFFSET(-16));
#line 36 "sample/printk_legacy.c"
    r1 = (uint64_t)2675202291049386576;
#line 36 "sample/printk_legacy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 36 "sample/printk_legacy.c"
    r8 = (uint64_t)2338816401835575632;
#line 36 "sample/printk_legacy.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-32));
#line 36 "sample/printk_legacy.c"
    READ_ONCE_8(r4, r7, OFFSET(48));
#line 36 "sample/printk_legacy.c"
    READ_ONCE_64(r3, r7, OFFSET(16));
#line 36 "sample/printk_legacy.c"
    r1 = r10;
#line 36 "sample/printk_legacy.c"
    r1 += IMMEDIATE(-32);
#line 36 "sample/printk_legacy.c"
    r2 = IMMEDIATE(18);
#line 36 "sample/printk_legacy.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 38 "sample/printk_legacy.c"
    WRITE_ONCE_16(r10, (uint16_t)r9, OFFSET(-4));
#line 38 "sample/printk_legacy.c"
    r1 = IMMEDIATE(622869070);
#line 38 "sample/printk_legacy.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 38 "sample/printk_legacy.c"
    r1 = (uint64_t)4993456540003410037;
#line 38 "sample/printk_legacy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 38 "sample/printk_legacy.c"
    r1 = (uint64_t)2675202291049386576;
#line 38 "sample/printk_legacy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 38 "sample/printk_legacy.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-32));
#line 36 "sample/printk_legacy.c"
    r6 += r0;
#line 38 "sample/printk_legacy.c"
    READ_ONCE_8(r5, r7, OFFSET(40));
#line 38 "sample/printk_legacy.c"
    READ_ONCE_8(r4, r7, OFFSET(48));
#line 38 "sample/printk_legacy.c"
    READ_ONCE_64(r3, r7, OFFSET(16));
#line 38 "sample/printk_legacy.c"
    r1 = r10;
#line 38 "sample/printk_legacy.c"
    r1 += IMMEDIATE(-32);
#line 38 "sample/printk_legacy.c"
    r2 = IMMEDIATE(30);
#line 38 "sample/printk_legacy.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 38 "sample/printk_legacy.c"
    r1 = IMMEDIATE(9504);
#line 42 "sample/printk_legacy.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-28));
#line 42 "sample/printk_legacy.c"
    r1 = IMMEDIATE(826556738);
#line 42 "sample/printk_legacy.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-32));
#line 37 "sample/printk_legacy.c"
    r6 += r0;
#line 37 "sample/printk_legacy.c"
    r8 = IMMEDIATE(0);
#line 42 "sample/printk_legacy.c"
    WRITE_ONCE_8(r10, (uint8_t)r8, OFFSET(-26));
#line 42 "sample/printk_legacy.c"
    r1 = r10;
#line 42 "sample/printk_legacy.c"
    r1 += IMMEDIATE(-32);
#line 42 "sample/printk_legacy.c"
    r2 = IMMEDIATE(7);
#line 42 "sample/printk_legacy.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 42 "sample/printk_legacy.c"
    r1 = (uint64_t)7812660273793483074;
#line 43 "sample/printk_legacy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 42 "sample/printk_legacy.c"
    r6 += r0;
#line 43 "sample/printk_legacy.c"
    WRITE_ONCE_8(r10, (uint8_t)r8, OFFSET(-24));
#line 43 "sample/printk_legacy.c"
    r1 = r10;
#line 43 "sample/printk_legacy.c"
    r1 += IMMEDIATE(-32);
#line 43 "sample/printk_legacy.c"
    r2 = IMMEDIATE(9);
#line 43 "sample/printk_legacy.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 43 "sample/printk_legacy.c"
    r1 = (uint64_t)7220718397787750722;
#line 44 "sample/printk_legacy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 43 "sample/printk_legacy.c"
    r6 += r0;
#line 44 "sample/printk_legacy.c"
    WRITE_ONCE_8(r10, (uint8_t)r8, OFFSET(-24));
#line 44 "sample/printk_legacy.c"
    READ_ONCE_64(r3, r7, OFFSET(16));
#line 44 "sample/printk_legacy.c"
    r1 = r10;
#line 44 "sample/printk_legacy.c"
    r1 += IMMEDIATE(-32);
#line 44 "sample/printk_legacy.c"
    r2 = IMMEDIATE(9);
#line 44 "sample/printk_legacy.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 44 "sample/printk_legacy.c"
    r1 = (uint64_t)31566017637663042;
#line 45 "sample/printk_legacy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 44 "sample/printk_legacy.c"
    r6 += r0;
#line 45 "sample/printk_legacy.c"
    READ_ONCE_64(r3, r7, OFFSET(16));
#line 45 "sample/printk_legacy.c"
    r1 = r10;
#line 45 "sample/printk_legacy.c"
    r1 += IMMEDIATE(-32);
#line 45 "sample/printk_legacy.c"
    r2 = IMMEDIATE(8);
#line 45 "sample/printk_legacy.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 45 "sample/printk_legacy.c"
    r1 = IMMEDIATE(893665602);
#line 49 "sample/printk_legacy.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-32));
#line 45 "sample/printk_legacy.c"
    r6 += r0;
#line 49 "sample/printk_legacy.c"
    WRITE_ONCE_8(r10, (uint8_t)r8, OFFSET(-28));
#line 49 "sample/printk_legacy.c"
    READ_ONCE_64(r3, r7, OFFSET(16));
#line 49 "sample/printk_legacy.c"
    r1 = r10;
#line 49 "sample/printk_legacy.c"
    r1 += IMMEDIATE(-32);
#line 49 "sample/printk_legacy.c"
    r2 = IMMEDIATE(5);
#line 49 "sample/printk_legacy.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 49 "sample/printk_legacy.c"
    r1 = (uint64_t)32973392554770754;
#line 50 "sample/printk_legacy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 49 "sample/printk_legacy.c"
    r6 += r0;
#line 49 "sample/printk_legacy.c"
    r1 = r10;
#line 49 "sample/printk_legacy.c"
    r1 += IMMEDIATE(-32);
#line 50 "sample/printk_legacy.c"
    r2 = IMMEDIATE(8);
#line 50 "sample/printk_legacy.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 53 "sample/printk_legacy.c"
    WRITE_ONCE_8(r10, (uint8_t)r8, OFFSET(-22));
#line 53 "sample/printk_legacy.c"
    r1 = IMMEDIATE(25966);
#line 53 "sample/printk_legacy.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-24));
#line 53 "sample/printk_legacy.c"
    r1 = (uint64_t)8026575779790860337;
#line 53 "sample/printk_legacy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 50 "sample/printk_legacy.c"
    r6 += r0;
#line 50 "sample/printk_legacy.c"
    r1 = r10;
#line 50 "sample/printk_legacy.c"
    r1 += IMMEDIATE(-32);
#line 53 "sample/printk_legacy.c"
    r2 = IMMEDIATE(11);
#line 53 "sample/printk_legacy.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 53 "sample/printk_legacy.c"
    r6 += r0;
#line 55 "sample/printk_legacy.c"
    r0 = r6;
#line 55 "sample/printk_legacy.c"
    return r0;
#line 26 "sample/printk_legacy.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        func,
        "bind",
        "bind",
        "func",
        NULL,
        0,
        func_helpers,
        4,
        134,
        &func_program_type_guid,
        &func_attach_type_guid,
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

metadata_table_t printk_legacy_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
